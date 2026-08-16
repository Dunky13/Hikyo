package importer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The shared sanitized subprocess spawn path (import-paths ADR § Trust, rule 4:
// "Every subprocess a connector invokes runs in a sanitized environment ... A
// connector-interface invariant, not a per-connector courtesy: the subprocess
// spawn path is shared and the stripping happens there").
//
// Client-go and Vault retain ownership of their authentication protocols while
// pointing their external command at RunInternalSubprocess. Libraries such as
// SOPS that can spawn deeper helpers remain covered by WithSanitized's scoped
// process-environment scrub. Both paths strip the same namespace here.

// hikyoEnvPrefix is the whole of Hikyo's environment namespace: credentials
// (HIKYO_TOKEN), context selection (HIKYO_INSTANCE, HIKYO_ORG, HIKYO_PROJECT,
// HIKYO_ENV, HIKYO_CONTEXT), trust material (HIKYO_TRUST_BUNDLE), state
// (HIKYO_STATE_DIR) and server configuration (HIKYO_ROOT_KEY, HIKYO_DB). One
// prefix rather than a name list: a list is a thing to forget to extend, and
// every variable this binary reads is under the prefix.
const hikyoEnvPrefix = "HIKYO_"

const (
	internalSubprocessMode = "__hikyo-import-subprocess"
	subprocessSpecEnv      = "HIKYO_IMPORT_SUBPROCESS_SPEC"
	subprocessExitTimeout  = 124
	subprocessExitOverflow = 125
)

type subprocessSpec struct {
	Command             string   `json:"command"`
	Args                []string `json:"args"`
	MaxBytes            int      `json:"max_bytes"`
	RunDeadlineUnixNano int64    `json:"run_deadline_unix_nano,omitempty"`
}

func newSubprocessSpec(ctx context.Context, command string, args []string, maxBytes int) subprocessSpec {
	runDeadline := int64(0)
	if deadline, ok := ctx.Deadline(); ok {
		runDeadline = deadline.UnixNano()
	}
	return subprocessSpec{
		Command: command, Args: append([]string{}, args...), MaxBytes: maxBytes,
		RunDeadlineUnixNano: runDeadline,
	}
}

func subprocessDeadline(spec subprocessSpec, now time.Time) time.Time {
	deadline := now.Add(RequestDeadline)
	if spec.RunDeadlineUnixNano > 0 {
		runDeadline := time.Unix(0, spec.RunDeadlineUnixNano)
		if runDeadline.Before(deadline) {
			deadline = runDeadline
		}
	}
	return deadline
}

func encodeSubprocessSpec(spec subprocessSpec) (string, error) {
	raw, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// RunInternalSubprocess handles the hidden re-exec mode used by client
// libraries. The library still owns its authentication protocol; this wrapper
// owns only process policy: sanitized environment, deadline, output cap, and
// content-free failures.
func RunInternalSubprocess(args []string, stdout io.Writer) (bool, int) {
	if len(args) == 0 || args[0] != internalSubprocessMode {
		return false, 0
	}
	encoded := os.Getenv(subprocessSpecEnv)
	_ = os.Unsetenv(subprocessSpecEnv)
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return true, 1
	}
	var spec subprocessSpec
	if err := json.Unmarshal(raw, &spec); err != nil || spec.Command == "" ||
		spec.MaxBytes < 1 || spec.MaxBytes > MaxResponseBytes || spec.RunDeadlineUnixNano < 0 {
		return true, 1
	}

	deadline := subprocessDeadline(spec, time.Now())
	if !time.Now().Before(deadline) {
		return true, subprocessExitTimeout
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	commandArgs := append(append([]string{}, spec.Args...), args[1:]...)
	cmd := exec.CommandContext(ctx, spec.Command, commandArgs...)
	cmd.Env = SanitizedEnv(os.Environ())
	cmd.Stderr = io.Discard
	pipe, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		return true, 1
	}
	type readResult struct {
		output []byte
		err    error
	}
	readDone := make(chan readResult, 1)
	go func() {
		output, err := io.ReadAll(io.LimitReader(pipe, int64(spec.MaxBytes)+1))
		readDone <- readResult{output: output, err: err}
	}()
	var read readResult
	select {
	case read = <-readDone:
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = pipe.Close()
		_ = cmd.Wait()
		return true, subprocessExitTimeout
	}
	output, readErr := read.output, read.err
	if len(output) > spec.MaxBytes {
		_ = cmd.Process.Kill()
		_ = pipe.Close()
		_ = cmd.Wait()
		return true, subprocessExitOverflow
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return true, subprocessExitTimeout
	}
	if readErr != nil || waitErr != nil {
		return true, 1
	}
	if _, err := stdout.Write(output); err != nil {
		return true, 1
	}
	return true, 0
}

func replaceEnv(env []string, name, value string) []string {
	prefix := name + "="
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			out = append(out, item)
		}
	}
	return append(out, prefix+value)
}

func boundedSubprocessExit(err error) (int, bool) {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitCode()
		return code, code == subprocessExitTimeout || code == subprocessExitOverflow
	}
	for _, code := range []int{subprocessExitTimeout, subprocessExitOverflow} {
		message := err.Error()
		if strings.Contains(message, "getting credentials: exec: executable ") &&
			strings.Contains(message, " failed with exit code "+strconv.Itoa(code)) {
			return code, true
		}
	}
	return 0, false
}

// Stripped reports whether an environment variable is removed before any
// external program a connector's work pulls in can see it. Exported so the
// acceptance test asserts the rule at the shared path rather than restating it.
func Stripped(name string) bool {
	return strings.HasPrefix(name, hikyoEnvPrefix)
}

// SanitizedEnv returns env with every stripped variable removed. env is in
// os.Environ form ("NAME=value").
func SanitizedEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, ok := strings.Cut(kv, "=")
		if ok && Stripped(name) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// spawnMu serializes sanitized scopes. The scrub is process-global, so two
// concurrent scopes would restore each other's saved state; the CLI runs one
// import at a time, and the mutex makes that a property rather than an
// assumption.
var spawnMu sync.Mutex

// WithSanitized runs fn with this process's environment stripped of Hikyo
// credentials, contexts and trust material, and restores it afterwards —
// including on panic, because leaving a scrubbed environment behind would break
// every later verb in the same process.
func WithSanitized(fn func() error) error {
	spawnMu.Lock()
	defer spawnMu.Unlock()

	var saved []string
	for _, kv := range os.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || !Stripped(name) {
			continue
		}
		saved = append(saved, kv)
		os.Unsetenv(name)
	}
	defer func() {
		for _, kv := range saved {
			name, value, _ := strings.Cut(kv, "=")
			os.Setenv(name, value)
		}
	}()
	return fn()
}
