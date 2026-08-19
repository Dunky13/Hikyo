package compose

import (
	"strings"
	"testing"
	"time"
)

const validConfig = `
version: 1
instance: https://hikyo.example.internal
org: org_1
project: prj_1
environment: env_1
runtime_dir: /run/hikyo/acme-web-production
snapshot:
  offline_serve: true
  max_age: 24h
targets:
  api:
    keys: [key_1, key_2]
    services: [api, worker]
    acknowledge_loader_control: [PATH]
`

func TestParseConfigValid(t *testing.T) {
	c, err := ParseConfig([]byte(validConfig))
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if c.Org != "org_1" || c.Project != "prj_1" || c.Environment != "env_1" {
		t.Errorf("bad ids: %+v", c)
	}
	if !c.Snapshot.OfflineServe {
		t.Error("offline_serve should be true")
	}
	if c.SnapshotMaxAge() != 24*time.Hour {
		t.Errorf("max age = %s, want 24h", c.SnapshotMaxAge())
	}
	if got := c.Targets["api"]; len(got.Keys) != 2 || got.AcknowledgeLoaderControl[0] != "PATH" {
		t.Errorf("bad target: %+v", got)
	}
	if names := c.TargetNames(); len(names) != 1 || names[0] != "api" {
		t.Errorf("target names = %v", names)
	}
}

func TestParseConfigRunBlockAndSlug(t *testing.T) {
	src := validConfig + "run:\n  acknowledge_loader_control: [NODE_OPTIONS]\nslug: acme-web-production\n"
	c, err := ParseConfig([]byte(src))
	if err != nil {
		t.Fatalf("config with run/slug rejected: %v", err)
	}
	if got := c.Run.AcknowledgeLoaderControl; len(got) != 1 || got[0] != "NODE_OPTIONS" {
		t.Errorf("run.acknowledge_loader_control = %v", got)
	}
	if c.Slug != "acme-web-production" {
		t.Errorf("slug = %q", c.Slug)
	}
}

func TestParseConfigRejectsBadSlug(t *testing.T) {
	for _, bad := range []string{"../escape", "Has Space", "UPPER", "-leading"} {
		src := validConfig + "slug: " + `"` + bad + `"` + "\n"
		if _, err := ParseConfig([]byte(src)); err == nil {
			t.Errorf("slug %q: expected rejection", bad)
		}
	}
}

func TestParseConfigDefaultsMaxAge(t *testing.T) {
	src := strings.Replace(validConfig, "  offline_serve: true\n  max_age: 24h\n", "  offline_serve: false\n", 1)
	c, err := ParseConfig([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if c.SnapshotMaxAge() != DefaultSnapshotMaxAge {
		t.Errorf("default max age = %s, want %s", c.SnapshotMaxAge(), DefaultSnapshotMaxAge)
	}
}

func TestParseConfigRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":       strings.Replace(validConfig, "version: 1", "version: 1\nnope: x", 1),
		"wrong version":       strings.Replace(validConfig, "version: 1", "version: 2", 1),
		"http non-loopback":   strings.Replace(validConfig, "https://hikyo.example.internal", "http://hikyo.example.internal", 1),
		"instance with path":  strings.Replace(validConfig, "https://hikyo.example.internal", "https://hikyo.example/api", 1),
		"bad target name":     strings.Replace(validConfig, "  api:", "  API_X:", 1),
		"max_age above floor": strings.Replace(validConfig, "max_age: 24h", "max_age: 240h", 1),
		"negative max_age":    strings.Replace(validConfig, "max_age: 24h", "max_age: -1h", 1),
	}
	for name, src := range cases {
		if _, err := ParseConfig([]byte(src)); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestParseConfigLoopbackHTTP(t *testing.T) {
	for _, host := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		src := strings.Replace(validConfig, "https://hikyo.example.internal", host, 1)
		if _, err := ParseConfig([]byte(src)); err != nil {
			t.Errorf("loopback %s rejected: %v", host, err)
		}
	}
}

func TestParseConfigRejectsCredentialKeys(t *testing.T) {
	for _, key := range []string{"token", "token_file", "credential"} {
		// Top-level and nested-under-target placements both refused.
		top := strings.Replace(validConfig, "version: 1", "version: 1\n"+key+": secret", 1)
		nested := strings.Replace(validConfig, "    services: [api, worker]", "    services: [api, worker]\n    "+key+": secret", 1)
		for _, src := range []string{top, nested} {
			_, err := ParseConfig([]byte(src))
			if err == nil {
				t.Errorf("key %q: expected rejection", key)
				continue
			}
			if !strings.Contains(err.Error(), "--token-file") || !strings.Contains(err.Error(), "HIKYO_TOKEN") {
				t.Errorf("key %q: message must name both channels, got: %v", key, err)
			}
		}
	}
}
