package compose

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
)

// Doctor checks as pure functions (compose-integration ADR § "Missing or stale
// stamps are errors"). The CLI gathers the inputs (runs docker, stats files);
// this package keeps docker OUT and takes the JSON/text/version/mode as data,
// so every check is unit-testable with no process invocation.
//
// The load-bearing rule: agreement on one side and disagreement on another is a
// FAILURE, not a pass — config, stamp file, generation on disk, and server
// manifest must all name the same generation.

// Severity levels.
type Severity string

const (
	SeverityError Severity = "error"
	SeverityWarn  Severity = "warn"
)

// ComposeVersionFloor is the path-2 minimum (format: raw landed in 2.30.0).
var ComposeVersionFloor = [3]int{2, 30, 0}

// Finding is one doctor result.
type Finding struct {
	Severity Severity
	Code     string
	Message  string
}

// ComposeConfig is the subset of `docker compose config --format json` doctor
// needs. It is intentionally lenient about unknown fields (a service carries
// many), but typed for the parts it reads.
type ComposeConfig struct {
	Services map[string]ComposeService `json:"services"`
}

// ComposeService is one service's env_file entries and labels.
type ComposeService struct {
	EnvFile []EnvFileRef      `json:"env_file"`
	Labels  map[string]string `json:"labels"`
}

// EnvFileRef is a resolved env_file entry.
type EnvFileRef struct {
	Path     string `json:"path"`
	Format   string `json:"format"`
	Required bool   `json:"required"`
}

// ParseComposeConfig decodes the resolved compose JSON.
func ParseComposeConfig(data []byte) (*ComposeConfig, error) {
	var c ComposeConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("compose: parse `docker compose config` JSON: %w", err)
	}
	return &c, nil
}

// FileMode carries a token/state file's permission bits and whether the euid
// owns it — the CLI computes ownership so this package stays cross-platform.
type FileMode struct {
	Perm        os.FileMode
	OwnedByEUID bool
}

// StateEntry is one client state-directory node.
type StateEntry struct {
	Path        string
	Perm        os.FileMode
	IsDir       bool
	OwnedByEUID bool
}

// DoctorInput is everything doctor checks against.
type DoctorInput struct {
	ComposeVersion string         // `docker compose version --short`, e.g. "2.29.7"/"v2.30.0"
	Config         *ComposeConfig // resolved `docker compose config --format json`
	RawComposeYAML string         // raw compose text, where ${HIKYO_GEN_*:?} is visible
	ManagedStamps  map[string]string
	RuntimeDir     string
	ServerStamps   map[string]string // target -> stamp over the server's current content
	ConfigTargets  map[string]Target
	ExistingKeyIDs map[string]bool // server's current key ids
	TokenFile      *FileMode
	StateEntries   []StateEntry

	SystemdInvocation       bool // INVOCATION_ID set
	TokenFromCredentialsDir bool // token passed from $CREDENTIALS_DIRECTORY
}

// Doctor runs every check and returns findings sorted by (Code, Message) for a
// deterministic report.
func Doctor(in DoctorInput) []Finding {
	var f []Finding
	f = append(f, checkComposeVersion(in.ComposeVersion)...)
	f = append(f, checkTargets(in)...)
	f = append(f, checkServiceEntries(in)...)
	f = append(f, checkTokenFile(in.TokenFile)...)
	f = append(f, checkStateEntries(in.StateEntries)...)
	f = append(f, checkSystemd(in)...)

	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Code != f[j].Code {
			return f[i].Code < f[j].Code
		}
		return f[i].Message < f[j].Message
	})
	return f
}

func checkComposeVersion(v string) []Finding {
	parsed, ok := parseComposeVersion(v)
	if !ok {
		return []Finding{{SeverityError, "compose_version_below_floor",
			fmt.Sprintf("could not parse Compose version %q; the path-2 floor is 2.30.0", v)}}
	}
	if less(parsed, ComposeVersionFloor) {
		return []Finding{{SeverityError, "compose_version_below_floor",
			fmt.Sprintf("Compose %d.%d.%d is below the 2.30.0 floor for `format: raw`; use `hikyo run` or upgrade",
				parsed[0], parsed[1], parsed[2])}}
	}
	return nil
}

// checkTargets runs the per-target stamp-variable, grammar, generation, drift,
// and key-existence checks.
func checkTargets(in DoctorInput) []Finding {
	var f []Finding
	for _, target := range sortedTargetSet(in) {
		v := varName(target)
		present, requiredForm := stampVarUsage(in.RawComposeYAML, v)
		if !present {
			f = append(f, Finding{SeverityError, "env_file_missing_stamp_var",
				fmt.Sprintf("target %q: no service interpolates %s", target, v)})
		} else if !requiredForm {
			f = append(f, Finding{SeverityError, "stamp_var_not_required_form",
				fmt.Sprintf("target %q: %s must use the required form ${%s:?…}", target, v, v)})
		}

		stamp, hasStamp := in.ManagedStamps[target]
		if !hasStamp {
			// No managed stamp for a configured target: nothing renders it.
			continue
		}
		if err := crypto.ParseStamp(stamp); err != nil {
			f = append(f, Finding{SeverityError, "stamp_grammar",
				fmt.Sprintf("target %q: managed stamp %q is malformed", target, stamp)})
			continue
		}
		present, complete := GenerationState(in.RuntimeDir, stamp)
		switch {
		case !present:
			f = append(f, Finding{SeverityError, "generation_absent",
				fmt.Sprintf("target %q: generation %s is absent under %s", target, stamp, in.RuntimeDir)})
		case !complete:
			f = append(f, Finding{SeverityError, "generation_incomplete",
				fmt.Sprintf("target %q: generation %s lacks its completion marker", target, stamp)})
		}
		if srv, ok := in.ServerStamps[target]; ok && srv != stamp {
			f = append(f, Finding{SeverityError, "server_manifest_drift",
				fmt.Sprintf("target %q: local stamp %s != server manifest stamp %s", target, stamp, srv)})
		}
		for _, keyID := range in.ConfigTargets[target].Keys {
			if !in.ExistingKeyIDs[keyID] {
				f = append(f, Finding{SeverityError, "target_key_missing",
					fmt.Sprintf("target %q: recorded key id %q no longer exists", target, keyID)})
			}
		}
	}
	return f
}

// checkServiceEntries checks each hikyo-managed env_file entry for `format:
// raw` and that the generation the resolved config interpolates to matches the
// managed stamp.
func checkServiceEntries(in DoctorInput) []Finding {
	if in.Config == nil {
		return nil
	}
	var f []Finding
	for _, svcName := range sortedKeys(in.Config.Services) {
		svc := in.Config.Services[svcName]
		for _, ef := range svc.EnvFile {
			target, ok := targetFromEnvFilePath(ef.Path, in)
			if !ok {
				continue // not a hikyo-managed entry
			}
			if ef.Format != "raw" {
				f = append(f, Finding{SeverityError, "format_raw_missing",
					fmt.Sprintf("service %q target %q: env_file must use `format: raw`, got %q", svcName, target, ef.Format)})
			}
			interpolated, ok := stampSegment(ef.Path)
			if !ok {
				f = append(f, Finding{SeverityError, "stamp_grammar",
					fmt.Sprintf("service %q target %q: env_file path has no valid generation segment: %s", svcName, target, ef.Path)})
				continue
			}
			if managed, has := in.ManagedStamps[target]; has && interpolated != managed {
				f = append(f, Finding{SeverityError, "stamp_mismatch",
					fmt.Sprintf("service %q target %q: config interpolates %s but the stamp file names %s", svcName, target, interpolated, managed)})
			}
		}
	}
	return f
}

func checkTokenFile(tf *FileMode) []Finding {
	if tf == nil {
		return nil
	}
	var f []Finding
	if tf.Perm&0o077 != 0 {
		f = append(f, Finding{SeverityError, "token_file_mode",
			fmt.Sprintf("token file is readable beyond its owner (mode %04o); tighten to 0600", tf.Perm.Perm())})
	}
	if !tf.OwnedByEUID {
		f = append(f, Finding{SeverityError, "token_file_mode",
			"token file is not owned by the invoking user"})
	}
	return f
}

func checkStateEntries(entries []StateEntry) []Finding {
	var f []Finding
	for _, e := range entries {
		want := os.FileMode(0o600)
		if e.IsDir {
			want = 0o700
		}
		if e.Perm.Perm() != want {
			f = append(f, Finding{SeverityError, "state_dir_mode",
				fmt.Sprintf("%s has mode %04o, want %04o", e.Path, e.Perm.Perm(), want)})
		}
		if !e.OwnedByEUID {
			f = append(f, Finding{SeverityError, "state_dir_mode",
				fmt.Sprintf("%s is not owned by the invoking user", e.Path)})
		}
	}
	return f
}

func checkSystemd(in DoctorInput) []Finding {
	// Warn (not error): a systemd-managed stack passing the token as a plain
	// file rather than a credential. The ADR requires doctor NOT to error on a
	// box lacking TPM/systemd-creds support.
	if in.SystemdInvocation && !in.TokenFromCredentialsDir {
		return []Finding{{SeverityWarn, "systemd_plain_token_file",
			"running under systemd but the token was not passed via $CREDENTIALS_DIRECTORY; prefer LoadCredentialEncrypted="}}
	}
	return nil
}

// --- helpers -------------------------------------------------------------

// parseComposeVersion parses "2.29.7", "v2.30.0", "2.30" into a 3-int tuple.
func parseComposeVersion(s string) ([3]int, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	// Keep only the leading dotted-number run (ignore any build suffix).
	end := 0
	for end < len(s) && (s[end] == '.' || (s[end] >= '0' && s[end] <= '9')) {
		end++
	}
	s = s[:end]
	if s == "" {
		return [3]int{}, false
	}
	parts := strings.Split(s, ".")
	var out [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

func less(a, b [3]int) bool {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// stampVarUsage reports whether ${varName…} appears in raw text and whether
// EVERY occurrence uses the required ${varName:?…} form. A use without `:?`
// (e.g. ${VAR} or ${VAR:-default}) fails the required-form check.
func stampVarUsage(raw, varName string) (present, requiredForm bool) {
	needle := "${" + varName
	present = false
	requiredForm = true
	rest := raw
	for {
		i := strings.Index(rest, needle)
		if i < 0 {
			break
		}
		present = true
		after := rest[i+len(needle):]
		// The next two chars must be ":?" for the required form. Anything else
		// (":-", "}", ":+", …) is not the required form.
		if !strings.HasPrefix(after, ":?") {
			requiredForm = false
		}
		rest = after
	}
	return present, requiredForm
}

// targetFromEnvFilePath maps an env_file path to a hikyo target if its basename
// is "<target>.env" and that target is one we manage.
func targetFromEnvFilePath(p string, in DoctorInput) (string, bool) {
	base := path.Base(p)
	if !strings.HasSuffix(base, ".env") {
		return "", false
	}
	target := strings.TrimSuffix(base, ".env")
	if _, ok := in.ManagedStamps[target]; ok {
		return target, true
	}
	if _, ok := in.ConfigTargets[target]; ok {
		return target, true
	}
	return "", false
}

// stampSegment returns the first path segment that is a valid stamp.
func stampSegment(p string) (string, bool) {
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if crypto.ParseStamp(seg) == nil {
			return seg, true
		}
	}
	return "", false
}

func sortedTargetSet(in DoctorInput) []string {
	set := map[string]struct{}{}
	for t := range in.ConfigTargets {
		set[t] = struct{}{}
	}
	for t := range in.ManagedStamps {
		set[t] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
