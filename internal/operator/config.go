package operator

import (
	"fmt"
	"regexp"
	"strings"
)

// dns1123Label is the Kubernetes namespace-name grammar (RFC 1123 label). A
// namespace that does not match cannot exist, so accepting one is a silent
// misconfiguration that would surface only as a cache/RBAC failure later.
var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// Version identifies the operator build in the fetch User-Agent
// (`hikyo-operator/<version>`). Set from cmd/hikyo/main.go, mirroring app.Version
// — the operator does not import internal/app for one string.
var Version = "dev"

// Config is the operator's whole configuration surface: HIKYO_OPERATOR_* env
// only (§ 0.7). No keyring, no root key, no datastore. Missing required config is
// a hard error at boot — nothing is silently defaulted into existence.
type Config struct {
	// Namespaces is the explicit watch/authority set. Empty means cluster-wide.
	// It is DERIVED, not authoritative: the install tooling generates the
	// RoleBindings AND this list from one input, and effective reach is the
	// intersection with what RBAC grants (ADR § Scoping).
	Namespaces []string

	// TriggerRollouts gates the workload-patch path (default true). When false
	// the operator neither lists nor patches workloads and the chart omits the
	// patch verbs entirely.
	TriggerRollouts bool

	// OwnNamespace is the operator's own namespace, where the stamp-root Secret
	// lives. From HIKYO_OPERATOR_NAMESPACE, falling back to POD_NAMESPACE
	// (downward API). Missing is a hard error — the operator cannot derive or
	// store its stamp root without it.
	OwnNamespace string

	MetricsAddr string
	HealthAddr  string
}

// LoadConfig parses HIKYO_OPERATOR_* env with fail-fast validation. getenv is
// injected so tests need no process environment.
func LoadConfig(getenv func(string) string) (Config, error) {
	cfg := Config{
		MetricsAddr: ":8080",
		HealthAddr:  ":8081",
	}

	if ns := strings.TrimSpace(getenv("HIKYO_OPERATOR_NAMESPACES")); ns != "" {
		seen := map[string]bool{}
		for _, part := range strings.Split(ns, ",") {
			p := strings.TrimSpace(part)
			// Fail fast: an empty segment (a stray or trailing comma), an invalid
			// namespace name, or a duplicate is a configuration mistake, never
			// silently dropped — the watch set is the authority-derivation input.
			if p == "" {
				return Config{}, fmt.Errorf("HIKYO_OPERATOR_NAMESPACES: empty namespace segment in %q", ns)
			}
			if len(p) > 63 || !dns1123Label.MatchString(p) {
				return Config{}, fmt.Errorf("HIKYO_OPERATOR_NAMESPACES: %q is not a valid Kubernetes namespace name", p)
			}
			if seen[p] {
				return Config{}, fmt.Errorf("HIKYO_OPERATOR_NAMESPACES: duplicate namespace %q", p)
			}
			seen[p] = true
			cfg.Namespaces = append(cfg.Namespaces, p)
		}
	}

	trigger, err := parseBoolDefault(getenv("HIKYO_OPERATOR_TRIGGER_ROLLOUTS"), true)
	if err != nil {
		return Config{}, fmt.Errorf("HIKYO_OPERATOR_TRIGGER_ROLLOUTS: %w", err)
	}
	cfg.TriggerRollouts = trigger

	// Own namespace: explicit override wins, else the downward-API POD_NAMESPACE.
	own := strings.TrimSpace(getenv("HIKYO_OPERATOR_NAMESPACE"))
	if own == "" {
		own = strings.TrimSpace(getenv("POD_NAMESPACE"))
	}
	if own == "" {
		return Config{}, fmt.Errorf("operator namespace unknown: set HIKYO_OPERATOR_NAMESPACE or POD_NAMESPACE (downward API) — the stamp root has nowhere to live otherwise")
	}
	cfg.OwnNamespace = own

	if m := strings.TrimSpace(getenv("HIKYO_OPERATOR_METRICS_ADDR")); m != "" {
		cfg.MetricsAddr = m
	}
	if h := strings.TrimSpace(getenv("HIKYO_OPERATOR_HEALTH_ADDR")); h != "" {
		cfg.HealthAddr = h
	}
	return cfg, nil
}

// parseBoolDefault parses a permissive boolean, returning def for the empty
// string. Anything else that is not a boolean is an error, not a silent default
// — a typo'd flag must fail loud.
func parseBoolDefault(s string, def bool) (bool, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	switch strings.ToLower(s) {
	case "1", "t", "true", "yes", "on":
		return true, nil
	case "0", "f", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("not a boolean: %q", s)
	}
}
