package compose

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func codes(f []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, x := range f {
		m[x.Code] = x
	}
	return m
}

func hasCode(f []Finding, code string) bool {
	_, ok := codes(f)[code]
	return ok
}

// healthyServiceYAML writes one service's env_file + label in the required form.
func healthyServiceYAML(runtimeDir, svc, v, target string) string {
	return fmt.Sprintf(`  %s:
    env_file:
      - path: %s/${%s:?render}/%s.env
        format: raw
    labels:
      hikyo.stamp: "${%s:?render}"
`, svc, runtimeDir, v, target, v)
}

// resolvedService builds the resolved config for a service/target/stamp.
func resolvedService(runtimeDir, stamp, target string) ComposeService {
	return ComposeService{
		EnvFile: []EnvFileRef{{Path: filepath.Join(runtimeDir, stamp, target+".env"), Format: "raw", Required: true}},
		Labels:  map[string]string{"hikyo.stamp": stamp},
	}
}

func TestParseComposeVersion(t *testing.T) {
	cases := map[string][3]int{
		"2.29.7":         {2, 29, 7},
		"v2.30.0":        {2, 30, 0},
		"2.30":           {2, 30, 0},
		"2.31.1-desktop": {2, 31, 1},
	}
	for in, want := range cases {
		got, ok := parseComposeVersion(in)
		if !ok || got != want {
			t.Errorf("parseComposeVersion(%q) = %v,%v want %v", in, got, ok, want)
		}
	}
	if _, ok := parseComposeVersion("garbage"); ok {
		t.Error("garbage should not parse")
	}
}

func TestCheckComposeVersionFloor(t *testing.T) {
	if hasCode(checkComposeVersion("2.30.0"), "compose_version_below_floor") {
		t.Error("2.30.0 is at the floor, not below")
	}
	if !hasCode(checkComposeVersion("2.29.9"), "compose_version_below_floor") {
		t.Error("2.29.9 is below the floor")
	}
}

// fullyHealthyInput builds a doctor input with no findings.
func fullyHealthyInput(t *testing.T) DoctorInput {
	t.Helper()
	runtime := filepath.Join(t.TempDir(), "runtime")
	keys := testKeys(t)
	rl := begin(t, t.TempDir(), nil)
	stamp, err := rl.WriteGeneration(runtime, keys, "api", []byte("content"))
	if err != nil {
		t.Fatal(err)
	}
	rawYAML := "services:\n" + healthyServiceYAML(runtime, "api", "HIKYO_GEN_API", "api")
	cfg := &ComposeConfig{Services: map[string]ComposeService{
		"api": resolvedService(runtime, stamp, "api"),
	}}
	return DoctorInput{
		ComposeVersion: "2.31.0",
		Config:         cfg,
		RawComposeYAML: rawYAML,
		ManagedStamps:  map[string]string{"api": stamp},
		RuntimeDir:     runtime,
		RuntimeTmpfs:   true,
		ServerStamps:   map[string]string{"api": stamp},
		ConfigTargets:  map[string]Target{"api": {Keys: []string{"key_1"}, Services: []string{"api"}}},
		ExistingKeyIDs: map[string]bool{"key_1": true},
		TokenFile:      &FileMode{Perm: 0o600, OwnedByEUID: true},
		StateEntries: []StateEntry{
			{Path: "/state", Perm: 0o700, IsDir: true, OwnedByEUID: true},
			{Path: "/state/local.key", Perm: 0o600, IsDir: false, OwnedByEUID: true},
		},
	}
}

func TestDoctorHealthy(t *testing.T) {
	if f := Doctor(fullyHealthyInput(t)); len(f) != 0 {
		t.Fatalf("healthy input produced findings: %+v", f)
	}
}

func TestDoctorPrefixCollisionTargets(t *testing.T) {
	runtime := filepath.Join(t.TempDir(), "runtime")
	keys := testKeys(t)
	rl := begin(t, t.TempDir(), nil)
	sApi, err := rl.WriteGeneration(runtime, keys, "api", []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	sSrv, err := rl.WriteGeneration(runtime, keys, "api-server", []byte("b"))
	if err != nil {
		t.Fatal(err)
	}
	rawYAML := "services:\n" +
		healthyServiceYAML(runtime, "api", "HIKYO_GEN_API", "api") +
		healthyServiceYAML(runtime, "api-server", "HIKYO_GEN_API_SERVER", "api-server")
	cfg := &ComposeConfig{Services: map[string]ComposeService{
		"api":        resolvedService(runtime, sApi, "api"),
		"api-server": resolvedService(runtime, sSrv, "api-server"),
	}}
	in := DoctorInput{
		ComposeVersion: "2.31.0",
		Config:         cfg,
		RawComposeYAML: rawYAML,
		ManagedStamps:  map[string]string{"api": sApi, "api-server": sSrv},
		RuntimeDir:     runtime,
		RuntimeTmpfs:   true,
		ServerStamps:   map[string]string{"api": sApi, "api-server": sSrv},
		ConfigTargets: map[string]Target{
			"api":        {Keys: []string{"key_1"}, Services: []string{"api"}},
			"api-server": {Keys: []string{"key_2"}, Services: []string{"api-server"}},
		},
		ExistingKeyIDs: map[string]bool{"key_1": true, "key_2": true},
	}
	if f := Doctor(in); len(f) != 0 {
		t.Fatalf("prefix-collision pair produced findings: %+v", f)
	}
}

func TestDoctorRuntimeChecks(t *testing.T) {
	in := fullyHealthyInput(t)
	in.RuntimeTmpfs = false
	if !hasCode(Doctor(in), "runtime_not_tmpfs") {
		t.Error("expected runtime_not_tmpfs")
	}
	in = fullyHealthyInput(t)
	in.RuntimeDir = "relative/runtime"
	if !hasCode(Doctor(in), "runtime_dir_not_absolute") {
		t.Error("expected runtime_dir_not_absolute")
	}
}

func TestDoctorStampMismatch(t *testing.T) {
	in := fullyHealthyInput(t)
	// Resolved env_file points at a different (valid) generation than the stamp.
	other := TargetStamp(testKeys(t), []byte("other"))
	svc := in.Config.Services["api"]
	svc.EnvFile[0].Path = filepath.Join(in.RuntimeDir, other, "api.env")
	in.Config.Services["api"] = svc
	if !hasCode(Doctor(in), "stamp_mismatch") {
		t.Error("expected stamp_mismatch")
	}
}

func TestDoctorFormatRawMissing(t *testing.T) {
	in := fullyHealthyInput(t)
	// Drop `format: raw` from the raw YAML.
	in.RawComposeYAML = fmt.Sprintf(`services:
  api:
    env_file:
      - path: %s/${HIKYO_GEN_API:?render}/api.env
    labels:
      hikyo.stamp: "${HIKYO_GEN_API:?render}"
`, in.RuntimeDir)
	if !hasCode(Doctor(in), "format_raw_missing") {
		t.Error("expected format_raw_missing")
	}
}

func TestDoctorGenerationAbsentAndDrift(t *testing.T) {
	in := fullyHealthyInput(t)
	ghost := TargetStamp(testKeys(t), []byte("ghost"))
	in.ManagedStamps["api"] = ghost
	f := Doctor(in)
	if !hasCode(f, "generation_absent") {
		t.Error("expected generation_absent")
	}
	if !hasCode(f, "server_manifest_drift") {
		t.Error("expected server_manifest_drift")
	}
}

func TestDoctorServerStampUnknown(t *testing.T) {
	in := fullyHealthyInput(t)
	in.ServerStamps = map[string]string{} // no server agreement input
	if !hasCode(Doctor(in), "server_stamp_unknown") {
		t.Error("a missing server stamp must be a finding, never a pass")
	}
}

func TestDoctorRequiredFormAndMissingVar(t *testing.T) {
	in := fullyHealthyInput(t)
	// Path uses ${VAR} without :?.
	in.RawComposeYAML = fmt.Sprintf(`services:
  api:
    env_file:
      - path: %s/${HIKYO_GEN_API}/api.env
        format: raw
    labels:
      hikyo.stamp: "${HIKYO_GEN_API:?r}"
`, in.RuntimeDir)
	if !hasCode(Doctor(in), "stamp_var_not_required_form") {
		t.Error("expected stamp_var_not_required_form for ${VAR}")
	}
	// Path uses ${VAR:-default} — also not the required form.
	in.RawComposeYAML = fmt.Sprintf(`services:
  api:
    env_file:
      - path: %s/${HIKYO_GEN_API:-x}/api.env
        format: raw
    labels:
      hikyo.stamp: "${HIKYO_GEN_API:?r}"
`, in.RuntimeDir)
	if !hasCode(Doctor(in), "stamp_var_not_required_form") {
		t.Error("expected stamp_var_not_required_form for ${VAR:-x}")
	}
	// Service absent from compose entirely → env_file_missing_stamp_var.
	in.RawComposeYAML = "services: {}\n"
	if !hasCode(Doctor(in), "env_file_missing_stamp_var") {
		t.Error("expected env_file_missing_stamp_var")
	}
}

// TestDoctorVarInCommentOnly: a :? form present only in a comment must NOT
// satisfy the check — only scalar nodes are inspected.
func TestDoctorVarInCommentOnly(t *testing.T) {
	in := fullyHealthyInput(t)
	in.RawComposeYAML = fmt.Sprintf(`services:
  api:
    # env_file path was: %s/${HIKYO_GEN_API:?render}/api.env
    env_file:
      - path: %s/static/api.env
        format: raw
    labels:
      hikyo.stamp: "${HIKYO_GEN_API:?render}"
`, in.RuntimeDir, in.RuntimeDir)
	if !hasCode(Doctor(in), "env_file_missing_stamp_var") {
		t.Error("a :? form in a comment must not satisfy the stamp-var check")
	}
}

func TestDoctorLabelChecks(t *testing.T) {
	// Label absent.
	in := fullyHealthyInput(t)
	in.RawComposeYAML = fmt.Sprintf(`services:
  api:
    env_file:
      - path: %s/${HIKYO_GEN_API:?render}/api.env
        format: raw
`, in.RuntimeDir)
	if !hasCode(Doctor(in), "label_absent") {
		t.Error("expected label_absent")
	}

	// Label references the wrong variable.
	in = fullyHealthyInput(t)
	in.RawComposeYAML = fmt.Sprintf(`services:
  api:
    env_file:
      - path: %s/${HIKYO_GEN_API:?render}/api.env
        format: raw
    labels:
      hikyo.stamp: "${HIKYO_GEN_WORKER:?render}"
`, in.RuntimeDir)
	if !hasCode(Doctor(in), "label_wrong_var") {
		t.Error("expected label_wrong_var")
	}

	// Label resolves to the wrong stamp.
	in = fullyHealthyInput(t)
	svc := in.Config.Services["api"]
	svc.Labels = map[string]string{"hikyo.stamp": TargetStamp(testKeys(t), []byte("nope"))}
	in.Config.Services["api"] = svc
	if !hasCode(Doctor(in), "label_stamp_mismatch") {
		t.Error("expected label_stamp_mismatch")
	}
}

func TestDoctorTokenAndStateModes(t *testing.T) {
	in := fullyHealthyInput(t)
	in.TokenFile = &FileMode{Perm: 0o644, OwnedByEUID: true}
	in.StateEntries = []StateEntry{{Path: "/state", Perm: 0o755, IsDir: true, OwnedByEUID: true}}
	f := Doctor(in)
	if !hasCode(f, "token_file_mode") {
		t.Error("expected token_file_mode")
	}
	if !hasCode(f, "state_dir_mode") {
		t.Error("expected state_dir_mode")
	}
}

func TestDoctorTargetKeyMissing(t *testing.T) {
	in := fullyHealthyInput(t)
	in.ExistingKeyIDs = map[string]bool{} // key_1 gone
	if !hasCode(Doctor(in), "target_key_missing") {
		t.Error("expected target_key_missing")
	}
}

func TestDoctorManagedStampAbsent(t *testing.T) {
	in := fullyHealthyInput(t)
	in.ManagedStamps = map[string]string{} // configured target with no stamp
	if !hasCode(Doctor(in), "managed_stamp_absent") {
		t.Error("expected managed_stamp_absent")
	}
}

func TestDoctorSystemdWarn(t *testing.T) {
	in := fullyHealthyInput(t)
	in.SystemdInvocation = true
	in.TokenFromCredentialsDir = false
	f := codes(Doctor(in))
	got, ok := f["systemd_plain_token_file"]
	if !ok || got.Severity != SeverityWarn {
		t.Errorf("expected a systemd_plain_token_file warn, got %+v", got)
	}
	in.TokenFromCredentialsDir = true
	if hasCode(Doctor(in), "systemd_plain_token_file") {
		t.Error("credential-sourced token should not warn")
	}
}

func TestParseComposeConfigJSON(t *testing.T) {
	data := []byte(`{"services":{"api":{"image":"x","env_file":[{"path":"/a/v1-` + hex32() + `/api.env","format":"raw","required":true}],"labels":{"hikyo.stamp":"v1-` + hex32() + `"}}}}`)
	c, err := ParseComposeConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	svc, ok := c.Services["api"]
	if !ok || len(svc.EnvFile) != 1 || svc.EnvFile[0].Format != "raw" {
		t.Fatalf("bad parse: %+v", c)
	}
}

func TestDoctorGenerationIncomplete(t *testing.T) {
	in := fullyHealthyInput(t)
	stamp := in.ManagedStamps["api"]
	if err := os.Remove(filepath.Join(in.RuntimeDir, stamp, completeMarker)); err != nil {
		t.Fatal(err)
	}
	if !hasCode(Doctor(in), "generation_incomplete") {
		t.Error("expected generation_incomplete")
	}
}
