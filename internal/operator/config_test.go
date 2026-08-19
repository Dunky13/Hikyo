package operator

import (
	"reflect"
	"testing"
)

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := LoadConfig(envFrom(map[string]string{"POD_NAMESPACE": "hikyo-system"}))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.OwnNamespace != "hikyo-system" {
		t.Errorf("OwnNamespace = %q", cfg.OwnNamespace)
	}
	if !cfg.TriggerRollouts {
		t.Error("TriggerRollouts should default true")
	}
	if len(cfg.Namespaces) != 0 {
		t.Errorf("Namespaces = %v, want cluster-wide (empty)", cfg.Namespaces)
	}
	if cfg.MetricsAddr != ":8080" || cfg.HealthAddr != ":8081" {
		t.Errorf("addrs = %q / %q", cfg.MetricsAddr, cfg.HealthAddr)
	}
}

func TestLoadConfigNamespacesAndOverrides(t *testing.T) {
	cfg, err := LoadConfig(envFrom(map[string]string{
		"HIKYO_OPERATOR_NAMESPACE":        "ops",
		"HIKYO_OPERATOR_NAMESPACES":       "team-a, team-b ",
		"HIKYO_OPERATOR_TRIGGER_ROLLOUTS": "false",
		"HIKYO_OPERATOR_METRICS_ADDR":     ":9000",
	}))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.TriggerRollouts {
		t.Error("TriggerRollouts should be false")
	}
	if !reflect.DeepEqual(cfg.Namespaces, []string{"team-a", "team-b"}) {
		t.Errorf("Namespaces = %v", cfg.Namespaces)
	}
	if cfg.MetricsAddr != ":9000" {
		t.Errorf("MetricsAddr = %q", cfg.MetricsAddr)
	}
	// Explicit HIKYO_OPERATOR_NAMESPACE wins over POD_NAMESPACE.
	if cfg.OwnNamespace != "ops" {
		t.Errorf("OwnNamespace = %q", cfg.OwnNamespace)
	}
}

func TestLoadConfigRejectsBadNamespaces(t *testing.T) {
	for name, ns := range map[string]string{
		"empty segment (trailing comma)": "team-a,",
		"empty segment (double comma)":   "team-a,,team-b",
		"duplicate":                      "team-a,team-a",
		"invalid uppercase":              "Team-A",
		"invalid underscore":             "team_a",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(envFrom(map[string]string{
				"POD_NAMESPACE":             "ops",
				"HIKYO_OPERATOR_NAMESPACES": ns,
			})); err == nil {
				t.Fatalf("namespaces %q must be rejected", ns)
			}
		})
	}
}

func TestLoadConfigMissingNamespaceIsHardError(t *testing.T) {
	if _, err := LoadConfig(envFrom(map[string]string{})); err == nil {
		t.Fatal("missing operator namespace must be a hard error")
	}
}

func TestLoadConfigBadBool(t *testing.T) {
	_, err := LoadConfig(envFrom(map[string]string{
		"POD_NAMESPACE":                   "ns",
		"HIKYO_OPERATOR_TRIGGER_ROLLOUTS": "maybe",
	}))
	if err == nil {
		t.Fatal("a non-boolean TRIGGER_ROLLOUTS must fail loud")
	}
}
