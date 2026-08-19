package compose

import (
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

func TestStampVarUsage(t *testing.T) {
	yaml := `
services:
  api:
    env_file:
      - path: /run/hikyo/p/${HIKYO_GEN_API:?run hikyo compose render}/api.env
`
	present, req := stampVarUsage(yaml, "HIKYO_GEN_API")
	if !present || !req {
		t.Errorf("required form should be present: present=%v req=%v", present, req)
	}
	present, req = stampVarUsage("x ${HIKYO_GEN_API} y", "HIKYO_GEN_API")
	if !present || req {
		t.Errorf("bare form should be present but not required: present=%v req=%v", present, req)
	}
	present, _ = stampVarUsage("no var here", "HIKYO_GEN_API")
	if present {
		t.Error("absent var should not be present")
	}
	// One good and one bad occurrence → not required form.
	_, req = stampVarUsage("${HIKYO_GEN_API:?ok} and ${HIKYO_GEN_API:-bad}", "HIKYO_GEN_API")
	if req {
		t.Error("any non-required occurrence fails the check")
	}
	// Prefix-collision: HIKYO_GEN_API must NOT match inside HIKYO_GEN_API_SERVER.
	yaml2 := "path: /p/${HIKYO_GEN_API_SERVER:?render}/x.env"
	if present, _ := stampVarUsage(yaml2, "HIKYO_GEN_API"); present {
		t.Error("HIKYO_GEN_API must not match inside HIKYO_GEN_API_SERVER")
	}
	if present, req := stampVarUsage(yaml2, "HIKYO_GEN_API_SERVER"); !present || !req {
		t.Errorf("HIKYO_GEN_API_SERVER should match its own var: present=%v req=%v", present, req)
	}
}

func TestDoctorPrefixCollisionTargets(t *testing.T) {
	// A correct compose file for both `api` and `api-server` must produce no
	// stamp-var findings for either.
	runtime := filepath.Join(t.TempDir(), "runtime")
	keys := testKeys(t)
	sApi := TargetStamp(keys, []byte("a"))
	sSrv := TargetStamp(keys, []byte("b"))
	w := NewWriter(t.TempDir(), nil)
	if err := w.WriteGeneration(runtime, sApi, map[string][]byte{"api": []byte("a")}); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteGeneration(runtime, sSrv, map[string][]byte{"api-server": []byte("b")}); err != nil {
		t.Fatal(err)
	}
	in := DoctorInput{
		ComposeVersion: "2.31.0",
		RawComposeYAML: "a: ${HIKYO_GEN_API:?r}\nb: ${HIKYO_GEN_API_SERVER:?r}\n",
		ManagedStamps:  map[string]string{"api": sApi, "api-server": sSrv},
		RuntimeDir:     runtime,
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

// fullyHealthyInput builds a doctor input with no findings.
func fullyHealthyInput(t *testing.T) DoctorInput {
	t.Helper()
	runtime := filepath.Join(t.TempDir(), "runtime")
	keys := testKeys(t)
	stamp := TargetStamp(keys, []byte("content"))
	w := NewWriter(t.TempDir(), nil)
	if err := w.WriteGeneration(runtime, stamp, map[string][]byte{"api": []byte("content")}); err != nil {
		t.Fatal(err)
	}
	rawYAML := "services:\n  api:\n    env_file:\n      - path: /run/hikyo/p/${HIKYO_GEN_API:?render}/api.env\n"
	cfg := &ComposeConfig{Services: map[string]ComposeService{
		"api": {EnvFile: []EnvFileRef{{Path: "/run/hikyo/p/" + stamp + "/api.env", Format: "raw", Required: true}}},
	}}
	return DoctorInput{
		ComposeVersion: "2.31.0",
		Config:         cfg,
		RawComposeYAML: rawYAML,
		ManagedStamps:  map[string]string{"api": stamp},
		RuntimeDir:     runtime,
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

func TestDoctorStampMismatch(t *testing.T) {
	in := fullyHealthyInput(t)
	// Config interpolates a different (valid) generation than the stamp file.
	other := TargetStamp(testKeys(t), []byte("other"))
	in.Config.Services["api"] = ComposeService{EnvFile: []EnvFileRef{
		{Path: "/run/hikyo/p/" + other + "/api.env", Format: "raw"},
	}}
	if !hasCode(Doctor(in), "stamp_mismatch") {
		t.Error("expected stamp_mismatch")
	}
}

func TestDoctorFormatRawMissing(t *testing.T) {
	in := fullyHealthyInput(t)
	svc := in.Config.Services["api"]
	svc.EnvFile[0].Format = "" // default parsing, not raw
	in.Config.Services["api"] = svc
	if !hasCode(Doctor(in), "format_raw_missing") {
		t.Error("expected format_raw_missing")
	}
}

func TestDoctorGenerationAbsentAndDrift(t *testing.T) {
	in := fullyHealthyInput(t)
	// Point managed + config at a generation that was never written.
	ghost := TargetStamp(testKeys(t), []byte("ghost"))
	in.ManagedStamps["api"] = ghost
	in.Config.Services["api"] = ComposeService{EnvFile: []EnvFileRef{
		{Path: "/run/hikyo/p/" + ghost + "/api.env", Format: "raw"},
	}}
	// server still names the old stamp → drift too.
	f := Doctor(in)
	if !hasCode(f, "generation_absent") {
		t.Error("expected generation_absent")
	}
	if !hasCode(f, "server_manifest_drift") {
		t.Error("expected server_manifest_drift")
	}
}

func TestDoctorRequiredFormAndMissingVar(t *testing.T) {
	in := fullyHealthyInput(t)
	in.RawComposeYAML = "services:\n  api:\n    env_file:\n      - path: /run/hikyo/p/${HIKYO_GEN_API}/api.env\n"
	if !hasCode(Doctor(in), "stamp_var_not_required_form") {
		t.Error("expected stamp_var_not_required_form")
	}
	in.RawComposeYAML = "services: {}\n"
	if !hasCode(Doctor(in), "env_file_missing_stamp_var") {
		t.Error("expected env_file_missing_stamp_var")
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

func TestDoctorSystemdWarn(t *testing.T) {
	in := fullyHealthyInput(t)
	in.SystemdInvocation = true
	in.TokenFromCredentialsDir = false
	f := codes(Doctor(in))
	got, ok := f["systemd_plain_token_file"]
	if !ok || got.Severity != SeverityWarn {
		t.Errorf("expected a systemd_plain_token_file warn, got %+v", got)
	}
	// From CREDENTIALS_DIRECTORY → no warning.
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
	// Remove the completion marker of the current generation.
	stamp := in.ManagedStamps["api"]
	if err := os.Remove(filepath.Join(in.RuntimeDir, stamp, completeMarker)); err != nil {
		t.Fatal(err)
	}
	if !hasCode(Doctor(in), "generation_incomplete") {
		t.Error("expected generation_incomplete")
	}
}
