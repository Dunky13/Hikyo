package compose

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"gopkg.in/yaml.v3"
)

// Doctor checks as pure functions (compose-integration ADR § "Missing or stale
// stamps are errors"). The CLI gathers the inputs (runs docker, stats files,
// probes tmpfs); this package keeps docker and I/O OUT and takes the
// JSON/text/version/mode/tmpfs facts as data, so every check is unit-testable
// with no process invocation.
//
// The load-bearing rule: agreement on one side and disagreement on another is a
// FAILURE, not a pass — the RAW compose text, the RESOLVED compose config, the
// managed stamp file, the generation on disk, and the server manifest must ALL
// name the same generation. The stamp variable's required `:?` form is detected
// STRUCTURALLY by parsing the raw YAML into scalar nodes, so a `:?` hiding in a
// comment cannot satisfy the check.

// Severity levels.
type Severity string

const (
	SeverityError Severity = "error"
	SeverityWarn  Severity = "warn"
)

// ComposeVersionFloor is the path-2 minimum (format: raw landed in 2.30.0).
var ComposeVersionFloor = [3]int{2, 30, 0}

// stampLabel is the load-bearing label carrying the stamp into the config hash.
const stampLabel = "hikyo.stamp"

// Finding is one doctor result.
type Finding struct {
	Severity Severity
	Code     string
	Message  string
}

// ComposeConfig is the subset of `docker compose config --format json` doctor
// needs — the RESOLVED (interpolated) config.
type ComposeConfig struct {
	Services map[string]ComposeService `json:"services"`
}

// ComposeService is one service's resolved env_file entries and labels.
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
	RuntimeTmpfs   bool              // CLI probes IsTmpfs(RuntimeDir) and passes the result
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
	f = append(f, checkRuntime(in)...)
	f = append(f, checkStructural(in)...)
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

// checkRuntime verifies the runtime dir is absolute and tmpfs-backed. The
// renderer does NOT refuse a non-tmpfs path (the CLI decides — a default path
// must be tmpfs, an explicitly configured one is the operator's call); doctor
// surfaces it so the operator sees plaintext is landing on persistent disk.
func checkRuntime(in DoctorInput) []Finding {
	var f []Finding
	if !filepath.IsAbs(in.RuntimeDir) {
		f = append(f, Finding{SeverityError, "runtime_dir_not_absolute",
			fmt.Sprintf("runtime_dir %q must be an absolute path (env_file resolves relative to the compose file)", in.RuntimeDir)})
	}
	if !in.RuntimeTmpfs {
		f = append(f, Finding{SeverityError, "runtime_not_tmpfs",
			fmt.Sprintf("runtime_dir %q is not backed by tmpfs; rendered plaintext must live only on tmpfs (ops-spec § 6)", in.RuntimeDir)})
	}
	return f
}

// checkStructural is the core agreement check: for every service in a target's
// services list, the raw path/label must interpolate the target's generation
// variable in the required `:?` form, use `format: raw`, and resolve to the
// generation the managed stamp names, present and complete, and agreeing with
// the server.
func checkStructural(in DoctorInput) []Finding {
	var f []Finding
	rawSvcs, err := parseRawServices(in.RawComposeYAML)
	if err != nil {
		return []Finding{{SeverityError, "compose_yaml_parse",
			fmt.Sprintf("could not parse the raw compose YAML: %v", err)}}
	}

	for _, target := range sortedTargetSet(in) {
		v := varName(target)

		stamp, hasStamp := in.ManagedStamps[target]
		if !hasStamp {
			f = append(f, Finding{SeverityError, "managed_stamp_absent",
				fmt.Sprintf("target %q: no managed stamp — nothing renders it (run `hikyo compose render`)", target)})
			continue
		}
		if err := crypto.ParseStamp(stamp); err != nil {
			f = append(f, Finding{SeverityError, "stamp_grammar",
				fmt.Sprintf("target %q: managed stamp %q is malformed", target, stamp)})
			continue
		}

		switch present, complete := GenerationState(in.RuntimeDir, stamp); {
		case !present:
			f = append(f, Finding{SeverityError, "generation_absent",
				fmt.Sprintf("target %q: generation %s is absent under %s", target, stamp, in.RuntimeDir)})
		case !complete:
			f = append(f, Finding{SeverityError, "generation_incomplete",
				fmt.Sprintf("target %q: generation %s lacks its completion marker", target, stamp)})
		}

		if srv, ok := in.ServerStamps[target]; !ok {
			f = append(f, Finding{SeverityError, "server_stamp_unknown",
				fmt.Sprintf("target %q: no server manifest stamp available — cannot confirm agreement", target)})
		} else if srv != stamp {
			f = append(f, Finding{SeverityError, "server_manifest_drift",
				fmt.Sprintf("target %q: local stamp %s != server manifest stamp %s", target, stamp, srv)})
		}

		for _, keyID := range in.ConfigTargets[target].Keys {
			if !in.ExistingKeyIDs[keyID] {
				f = append(f, Finding{SeverityError, "target_key_missing",
					fmt.Sprintf("target %q: recorded key id %q no longer exists", target, keyID)})
			}
		}

		wantResolved := path.Join(in.RuntimeDir, stamp, target+".env")
		for _, svcName := range in.ConfigTargets[target].Services {
			f = append(f, checkServiceForTarget(in, rawSvcs, svcName, target, v, stamp, wantResolved)...)
		}
	}
	return f
}

// checkServiceForTarget runs the per-service structural checks for one target.
func checkServiceForTarget(in DoctorInput, rawSvcs map[string]rawService, svcName, target, v, stamp, wantResolved string) []Finding {
	var f []Finding
	rs := rawSvcs[svcName]

	// --- env_file path (raw form + resolved path) ---
	rawPath, refsVar := rawPathForTarget(rs, in.RuntimeDir, v, target)
	switch {
	case rawPath == "":
		f = append(f, Finding{SeverityError, "env_file_missing_stamp_var",
			fmt.Sprintf("service %q target %q: no env_file entry interpolates %s in its path", svcName, target, v)})
	case !rawStampPathOK(rawPath, in.RuntimeDir, v, target):
		if refsVar {
			f = append(f, Finding{SeverityError, "stamp_var_not_required_form",
				fmt.Sprintf("service %q target %q: env_file path must be exactly %s/${%s:?…}/%s.env", svcName, target, in.RuntimeDir, v, target)})
		} else {
			f = append(f, Finding{SeverityError, "env_file_missing_stamp_var",
				fmt.Sprintf("service %q target %q: env_file path does not interpolate %s", svcName, target, v)})
		}
	default:
		// Raw form is correct; check format: raw and the resolved path.
		if fmtVal, ok := rawFormatForPath(rs, rawPath); !ok || fmtVal != "raw" {
			f = append(f, Finding{SeverityError, "format_raw_missing",
				fmt.Sprintf("service %q target %q: env_file must use `format: raw`, got %q", svcName, target, fmtVal)})
		}
		if resolved, ok := resolvedEnvFilePath(in.Config, rs, svcName, target, v, rawPath); !ok {
			f = append(f, Finding{SeverityWarn, "compose_env_file_resolution_unavailable",
				fmt.Sprintf("service %q target %q: Compose %q omitted env_file from config JSON and did not expose the same %s value through %s; this Compose version cannot prove the resolved env_file path", svcName, target, in.ComposeVersion, v, stampLabel)})
		} else if resolved != wantResolved {
			f = append(f, Finding{SeverityError, "stamp_mismatch",
				fmt.Sprintf("service %q target %q: env_file resolves to %q, want %q", svcName, target, resolved, wantResolved)})
		}
	}

	// --- hikyo.stamp label (raw form + resolved value) ---
	rawLabel, hasLabel := rs.labels[stampLabel]
	switch {
	case !hasLabel:
		f = append(f, Finding{SeverityError, "label_absent",
			fmt.Sprintf("service %q target %q: missing the load-bearing %s label", svcName, target, stampLabel)})
	case !rawLabelRequiredForm(rawLabel, v):
		f = append(f, Finding{SeverityError, "label_wrong_var",
			fmt.Sprintf("service %q target %q: %s label must be exactly ${%s:?…}, got %q", svcName, target, stampLabel, v, rawLabel)})
	default:
		if resolved := resolvedLabel(in.Config, svcName); resolved != stamp {
			f = append(f, Finding{SeverityError, "label_stamp_mismatch",
				fmt.Sprintf("service %q target %q: %s label resolves to %q, want %s", svcName, target, stampLabel, resolved, stamp)})
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

// --- raw YAML structural extraction --------------------------------------

// rawService is one service's raw env_file entries and labels as WRITTEN in the
// compose file (interpolation visible, comments excluded because only scalar
// nodes are read).
type rawService struct {
	envFiles []rawEnvFile
	labels   map[string]string
}

type rawEnvFile struct {
	path   string
	format string
}

// parseRawServices parses the raw compose YAML into per-service env_file/label
// scalar strings. Only scalar node VALUES are read, so a `:?` in a comment is
// invisible to every check.
func parseRawServices(text string) (map[string]rawService, error) {
	if strings.TrimSpace(text) == "" {
		return map[string]rawService{}, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, err
	}
	out := map[string]rawService{}
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return out, nil
	}
	services := mapValue(root, "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return out, nil
	}
	for i := 0; i+1 < len(services.Content); i += 2 {
		name := services.Content[i].Value
		svc := services.Content[i+1]
		if svc.Kind != yaml.MappingNode {
			out[name] = rawService{labels: map[string]string{}}
			continue
		}
		out[name] = rawService{
			envFiles: rawEnvFiles(mapValue(svc, "env_file")),
			labels:   rawLabels(mapValue(svc, "labels")),
		}
	}
	return out, nil
}

// mapValue returns the value node for key in a mapping node, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// rawEnvFiles reads an env_file node, accepting the short (scalar / seq of
// scalars) and long (seq of {path, format}) forms.
func rawEnvFiles(n *yaml.Node) []rawEnvFile {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return []rawEnvFile{{path: n.Value}}
	case yaml.SequenceNode:
		var out []rawEnvFile
		for _, e := range n.Content {
			switch e.Kind {
			case yaml.ScalarNode:
				out = append(out, rawEnvFile{path: e.Value})
			case yaml.MappingNode:
				out = append(out, rawEnvFile{
					path:   scalarValue(mapValue(e, "path")),
					format: scalarValue(mapValue(e, "format")),
				})
			}
		}
		return out
	}
	return nil
}

// rawLabels reads a labels node in either the mapping (name: value) or the
// sequence ("name=value") form.
func rawLabels(n *yaml.Node) map[string]string {
	out := map[string]string{}
	if n == nil {
		return out
	}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			out[n.Content[i].Value] = n.Content[i+1].Value
		}
	case yaml.SequenceNode:
		for _, e := range n.Content {
			if e.Kind == yaml.ScalarNode {
				if k, v, ok := strings.Cut(e.Value, "="); ok {
					out[k] = v
				}
			}
		}
	}
	return out
}

func scalarValue(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// rawPathForTarget finds the env_file raw path for this target (basename
// <target>.env, or a path interpolating the target's var), and whether it
// references the var at all.
func rawPathForTarget(rs rawService, runtimeDir, varName, target string) (rawPath string, refsVar bool) {
	base := target + ".env"
	for _, ef := range rs.envFiles {
		refs := rawPathReferencesVar(ef.path, varName)
		if refs || path.Base(ef.path) == base {
			return ef.path, refs
		}
	}
	return "", false
}

// rawFormatForPath returns the raw `format` scalar recorded for the entry whose
// path equals rawPath.
func rawFormatForPath(rs rawService, rawPath string) (string, bool) {
	for _, ef := range rs.envFiles {
		if ef.path == rawPath {
			return ef.format, ef.format != ""
		}
	}
	return "", false
}

// rawStampPathOK reports whether raw is exactly
// <runtimeDir>/${<varName>:?…}/<target>.env with the required `:?` form.
func rawStampPathOK(raw, runtimeDir, varName, target string) bool {
	prefix := runtimeDir + "/${" + varName + ":?"
	suffix := "}/" + target + ".env"
	if !strings.HasPrefix(raw, prefix) || !strings.HasSuffix(raw, suffix) {
		return false
	}
	mid := raw[len(prefix) : len(raw)-len(suffix)]
	return !strings.Contains(mid, "}") && !strings.Contains(mid, "${")
}

// rawLabelRequiredForm reports whether the whole label value is exactly
// ${<varName>:?…}.
func rawLabelRequiredForm(raw, varName string) bool {
	prefix := "${" + varName + ":?"
	if !strings.HasPrefix(raw, prefix) || !strings.HasSuffix(raw, "}") {
		return false
	}
	mid := raw[len(prefix) : len(raw)-1]
	return !strings.Contains(mid, "}") && !strings.Contains(mid, "${")
}

// rawPathReferencesVar reports whether raw interpolates ${varName…} in any form
// (used to distinguish a missing var from a wrong form).
func rawPathReferencesVar(raw, varName string) bool {
	needle := "${" + varName
	rest := raw
	for {
		i := strings.Index(rest, needle)
		if i < 0 {
			return false
		}
		after := rest[i+len(needle):]
		if len(after) == 0 || !isVarNameChar(after[0]) {
			return true
		}
		rest = after
	}
}

// resolvedEnvFilePath returns the resolved env_file path for svc whose basename
// is <target>.env. Compose 2.38 folds env_file into environment and omits the
// env_file node from config JSON. In that shape we deliberately choose the raw
// source-path fallback: interpolate it with Docker's resolved hikyo.stamp label,
// which is required to reference the same variable. This loses only proof that
// Docker parsed the env_file node; the raw structural check and resolved label
// still prove the entry and actual variable value. If either proof is absent,
// the caller emits an explicit version-limitation warning rather than silently
// skipping the check or fabricating stamp_mismatch.
func resolvedEnvFilePath(cfg *ComposeConfig, raw rawService, svcName, target, varName, rawPath string) (string, bool) {
	if cfg == nil {
		return "", false
	}
	base := target + ".env"
	for _, ef := range cfg.Services[svcName].EnvFile {
		if path.Base(ef.Path) == base {
			return ef.Path, true
		}
	}
	rawLabel, hasLabel := raw.labels[stampLabel]
	if !hasLabel || !rawLabelRequiredForm(rawLabel, varName) {
		return "", false
	}
	value := resolvedLabel(cfg, svcName)
	if value == "" {
		return "", false
	}
	prefix := "${" + varName + ":?"
	start := strings.Index(rawPath, prefix)
	if start < 0 {
		return "", false
	}
	end := strings.IndexByte(rawPath[start+len(prefix):], '}')
	if end < 0 {
		return "", false
	}
	end += start + len(prefix)
	return rawPath[:start] + value + rawPath[end+1:], true
}

// resolvedLabel returns the resolved hikyo.stamp label for svc.
func resolvedLabel(cfg *ComposeConfig, svcName string) string {
	if cfg == nil {
		return ""
	}
	return cfg.Services[svcName].Labels[stampLabel]
}

// --- helpers -------------------------------------------------------------

// parseComposeVersion parses "2.29.7", "v2.30.0", "2.30" into a 3-int tuple.
func parseComposeVersion(s string) ([3]int, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
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

func isVarNameChar(b byte) bool {
	return b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

func less(a, b [3]int) bool {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
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
