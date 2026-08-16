package importer

import (
	"os"
	"strings"
	"sync"
)

// The shared sanitized subprocess spawn path (import-paths ADR § Trust, rule 4:
// "Every subprocess a connector invokes runs in a sanitized environment ... A
// connector-interface invariant, not a per-connector courtesy: the subprocess
// spawn path is shared and the stripping happens there").
//
// SOPS GPG, kubeconfig exec plugins and Vault/OpenBao token helpers may spawn
// inside client libraries that expose no common command-builder hook. The
// sanitized path is therefore a scope: WithSanitized removes Hikyo material
// from THIS PROCESS's environment for the duration, so every inherited child
// is covered regardless of which library starts it.
//
// That is a deliberately blunt instrument and it is the right one here: the
// import verb is client-local, single-purpose and short-lived, and a scrub that
// covers the children we do not spawn ourselves is worth more than a builder
// that only covers the ones we do.

// hikyoEnvPrefix is the whole of Hikyo's environment namespace: credentials
// (HIKYO_TOKEN), context selection (HIKYO_INSTANCE, HIKYO_ORG, HIKYO_PROJECT,
// HIKYO_ENV, HIKYO_CONTEXT), trust material (HIKYO_TRUST_BUNDLE), state
// (HIKYO_STATE_DIR) and server configuration (HIKYO_ROOT_KEY, HIKYO_DB). One
// prefix rather than a name list: a list is a thing to forget to extend, and
// every variable this binary reads is under the prefix.
const hikyoEnvPrefix = "HIKYO_"

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
