// Package compose is the client-side library for Hikyo's Docker Compose
// delivery path (compose-integration ADR). It holds pure logic and filesystem
// primitives only — no network, no store/service/server/cli imports — so every
// piece is unit-testable in isolation. The CLI verbs (hikyo run, hikyo compose
// render|sync|doctor) are thin wiring over this package.
//
// # hikyo-compose.yaml — the project config file
//
// A committed, NON-SECRET file at the compose project root, located by the
// verbs by walking up from --project-directory/cwd the way Compose finds
// compose.yaml. It holds no credential and the spec says so explicitly, because
// a file that *could* hold a token eventually does — the token reaches the CLI
// through --token-file and HIKYO_TOKEN only.
//
//	version: 1
//	instance: https://hikyo.example.internal   # origin; must match the trust store
//	org: org_…
//	project: prj_…
//	environment: env_…
//	runtime_dir: /run/hikyo/acme-web-production # optional; default per ops-spec § 6
//	snapshot:
//	  offline_serve: false     # opt-in per stack
//	  max_age: 168h            # optional, DOWNWARD-only override of the 7 d default
//	targets:
//	  api:
//	    keys: [key_…, key_…]                 # immutable key ids (schema ADR)
//	    services: [api, worker]
//	    acknowledge_loader_control: [PATH]   # per-target, by name
//
// Parsing is STRICT: unknown fields are errors (yaml.v3 KnownFields). instance
// must be an https origin (loopback http permitted for local dev). Target names
// match ^[a-z][a-z0-9-]*$ because they become path segments and the stamp
// variable HIKYO_GEN_<UPPER_SNAKE>. A token/token_file/credential key anywhere
// is refused, naming the two real channels.
package compose

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultSnapshotMaxAge is the ADR's hard maximum (ops-spec § 6: 7 d). A
// per-stack max_age may only lower it.
const DefaultSnapshotMaxAge = 7 * 24 * time.Hour

var targetNameGrammar = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// slugGrammar constrains an explicit `slug`: it becomes a filesystem path
// segment, so `/`, `..` and whitespace are refused rather than allowed to
// escape the state directory.
var slugGrammar = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// Config is a parsed, validated hikyo-compose.yaml.
type Config struct {
	Version     int    `yaml:"version"`
	Instance    string `yaml:"instance"`
	Org         string `yaml:"org"`
	Project     string `yaml:"project"`
	Environment string `yaml:"environment"`
	RuntimeDir  string `yaml:"runtime_dir"`
	// Slug is the OPTIONAL explicit project slug. When empty the CLI derives
	// one from the org/project/env ids; when set it becomes the state-dir and
	// default-runtime-dir path segment, so it is grammar-checked as a path
	// segment. It carries no delivery meaning.
	Slug     string            `yaml:"slug"`
	Snapshot SnapshotSettings  `yaml:"snapshot"`
	Run      RunSettings       `yaml:"run"`
	Targets  map[string]Target `yaml:"targets"`

	// maxAge is the parsed, clamped snapshot max age, filled by ParseConfig.
	maxAge time.Duration
}

// RunSettings is the top-level `run:` block: policy for `hikyo run --`, which
// delivers the whole environment rather than a per-target subset. Its
// loader-control acknowledgement mirrors the per-target field (compose ADR
// § "Loader-control keys"): `run` has no target, so the acknowledgement lives
// at the stack level.
type RunSettings struct {
	AcknowledgeLoaderControl []string `yaml:"acknowledge_loader_control"`
}

// SnapshotSettings is the per-stack offline snapshot policy.
type SnapshotSettings struct {
	OfflineServe bool   `yaml:"offline_serve"`
	MaxAge       string `yaml:"max_age"` // e.g. "168h"; validated downward-only
}

// Target is one render target: the immutable key ids it delivers, the services
// that consume it, and any per-target loader-control acknowledgements.
type Target struct {
	Keys                     []string `yaml:"keys"`
	Services                 []string `yaml:"services"`
	AcknowledgeLoaderControl []string `yaml:"acknowledge_loader_control"`
}

// SnapshotMaxAge is the effective snapshot max age (default or the downward
// override).
func (c *Config) SnapshotMaxAge() time.Duration { return c.maxAge }

// forbiddenKeys must never appear: a credential does not live in this file.
var forbiddenKeys = map[string]struct{}{
	"token": {}, "token_file": {}, "credential": {},
}

// ParseConfig strictly parses and validates a hikyo-compose.yaml document.
func ParseConfig(data []byte) (*Config, error) {
	// First scan the raw node tree for credential keys at any depth, so the
	// message can name the two real channels rather than the generic
	// "unknown field" KnownFields would produce.
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("hikyo-compose.yaml: %w", err)
	}
	if k := findForbiddenKey(&root); k != "" {
		return nil, fmt.Errorf("hikyo-compose.yaml: %q is not allowed here — this file holds no credential; "+
			"pass the token via --token-file or HIKYO_TOKEN", k)
	}

	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("hikyo-compose.yaml: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	if c.Version != 1 {
		return fmt.Errorf("hikyo-compose.yaml: `version` must be 1, got %d", c.Version)
	}
	if err := validateOrigin(c.Instance); err != nil {
		return fmt.Errorf("hikyo-compose.yaml: `instance` %w", err)
	}
	for field, v := range map[string]string{"org": c.Org, "project": c.Project, "environment": c.Environment} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("hikyo-compose.yaml: `%s` is required", field)
		}
	}
	if s := strings.TrimSpace(c.Slug); s != "" && !slugGrammar.MatchString(s) {
		return fmt.Errorf("hikyo-compose.yaml: `slug` %q must match ^[a-z0-9][a-z0-9-]*$ (it is a filesystem path segment)", c.Slug)
	}
	if len(c.Targets) == 0 {
		return fmt.Errorf("hikyo-compose.yaml: at least one target is required under `targets`")
	}
	// runtime_dir is optional (the CLI resolves a default per ops-spec § 6);
	// when set it MUST be absolute, because env_file resolves relative to the
	// compose file and plaintext must land at a known tmpfs path, never a
	// git-worktree-relative one.
	if c.RuntimeDir != "" && !filepath.IsAbs(c.RuntimeDir) {
		return fmt.Errorf("hikyo-compose.yaml: `runtime_dir` %q must be an absolute path", c.RuntimeDir)
	}
	for name, tgt := range c.Targets {
		if !targetNameGrammar.MatchString(name) {
			return fmt.Errorf("hikyo-compose.yaml: target name %q must match ^[a-z][a-z0-9-]*$", name)
		}
		if len(tgt.Keys) == 0 {
			return fmt.Errorf("hikyo-compose.yaml: target %q has no `keys`", name)
		}
		for _, k := range tgt.Keys {
			if strings.TrimSpace(k) == "" {
				return fmt.Errorf("hikyo-compose.yaml: target %q has an empty key id", name)
			}
		}
		if len(tgt.Services) == 0 {
			return fmt.Errorf("hikyo-compose.yaml: target %q lists no `services`", name)
		}
	}

	// Snapshot max age: downward-only override of the 7 d default.
	c.maxAge = DefaultSnapshotMaxAge
	if s := strings.TrimSpace(c.Snapshot.MaxAge); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("hikyo-compose.yaml: `snapshot.max_age` %q is not a valid duration: %w", s, err)
		}
		if d <= 0 {
			return fmt.Errorf("hikyo-compose.yaml: `snapshot.max_age` must be positive")
		}
		if d > DefaultSnapshotMaxAge {
			return fmt.Errorf("hikyo-compose.yaml: `snapshot.max_age` %s exceeds the %s maximum; it may only lower it",
				d, DefaultSnapshotMaxAge)
		}
		c.maxAge = d
	}
	return nil
}

// TargetNames returns the configured target names, sorted.
func (c *Config) TargetNames() []string {
	names := make([]string, 0, len(c.Targets))
	for n := range c.Targets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// validateOrigin requires an https origin, or a loopback http origin for local
// development. It must be a bare origin: no path, query, fragment, or userinfo.
func validateOrigin(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("is not a valid URL: %w", err)
	}
	if u.Host == "" {
		return fmt.Errorf("must include a host (an origin like https://hikyo.example)")
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must be a bare origin (scheme + host), not %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("must be https (http is permitted only for loopback), got %q", raw)
	default:
		return fmt.Errorf("must use https, got scheme %q", u.Scheme)
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// findForbiddenKey walks the YAML node tree and returns the first
// credential-bearing key name it finds (at any depth), or "".
func findForbiddenKey(n *yaml.Node) string {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			if k := findForbiddenKey(c); k != "" {
				return k
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			if _, bad := forbiddenKeys[key.Value]; bad {
				return key.Value
			}
			if k := findForbiddenKey(n.Content[i+1]); k != "" {
				return k
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if k := findForbiddenKey(c); k != "" {
				return k
			}
		}
	}
	return ""
}
