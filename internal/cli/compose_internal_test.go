package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/compose"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
)

// The Compose delivery verbs (#63). These exercise the CLI wiring against a
// fake delivery server (httptest) or through the injected Exec/Env seams, so no
// real server, docker, or exec is touched.

func strPtr(s string) *string { return &s }

// deliveryJSON marshals a DeliveryResponse the fake server returns.
func deliveryJSON(t *testing.T, resp apigen.DeliveryResponse) string {
	t.Helper()
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// composeIO builds an IO with the given state dir, workdir, token, and captured
// streams.
func composeIO(stateDir, workdir, token string, extra map[string]string) (IO, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	get := func(k string) string {
		switch k {
		case "HIKYO_STATE_DIR":
			return stateDir
		case "HIKYO_TOKEN":
			return token
		}
		if extra != nil {
			return extra[k]
		}
		return ""
	}
	return IO{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Env:     Env{Getenv: get},
		Workdir: workdir,
	}, &stdout, &stderr
}

func machineState(t *testing.T, origin string) (*State, string) {
	t.Helper()
	stateDir := t.TempDir()
	st := &State{dir: stateDir}
	if err := st.Trust().Put(TrustEntry{Name: "local", Origin: origin}); err != nil {
		t.Fatal(err)
	}
	return st, stateDir
}

func TestRunRefusesWithoutMachineCredential(t *testing.T) {
	// A stored human session exists; run must not use it.
	stateDir := t.TempDir()
	st := &State{dir: stateDir}
	if err := st.Trust().Put(TrustEntry{Name: "local", Origin: "https://hikyo.example"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutSession(SessionArtifact{Instance: "local", Origin: "https://hikyo.example", Token: "human-session", Principal: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	ios, _, stderr := composeIO(stateDir, t.TempDir(), "", nil)
	code := Run(t.Context(), ios, []string{"run", "--instance", "local", "--org", "org_1", "--project", "prj_1", "--env", "env_1", "--", "true"})
	if code != ExitAuth {
		t.Fatalf("exit=%d, want ExitAuth; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "accepts only a machine credential") {
		t.Fatalf("message did not name the machine-only refusal: %s", stderr)
	}
}

func TestRunAllOrNothingRefusal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/delivery") {
			_, _ = w.Write([]byte(deliveryJSON(t, deliveryResp([]apigen.DeliveredKey{
				{KeyId: "key_s", Name: "DB_PASSWORD", Classification: apigen.KeyClassificationSecret, Presence: apigen.DeliveredKeyPresenceSet, Value: nil},
			}))))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	_, stateDir := machineState(t, server.URL)
	ios, _, stderr := composeIO(stateDir, t.TempDir(), "wl_token", nil)
	code := Run(t.Context(), ios, []string{"run", "--instance", "local", "--org", "org_1", "--project", "prj_1", "--env", "env_1", "--", "true"})
	if code != ExitRefused {
		t.Fatalf("exit=%d, want ExitRefused; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "DB_PASSWORD") || !strings.Contains(stderr.String(), "opt-in") {
		t.Fatalf("all-or-nothing message wrong: %s", stderr)
	}
}

func TestRunLoaderControlRefusal(t *testing.T) {
	server := deliveryServer(t, deliveryResp([]apigen.DeliveredKey{
		{KeyId: "key_p", Name: "LD_PRELOAD", Classification: apigen.KeyClassificationConfig, Presence: apigen.DeliveredKeyPresenceSet, Value: strPtr("/evil.so")},
	}))
	defer server.Close()

	st, stateDir := machineState(t, server.URL)
	ios, _, stderr := composeIO(stateDir, t.TempDir(), "wl_token", nil)
	code := Run(t.Context(), ios, []string{"run", "--instance", "local", "--org", "org_1", "--project", "prj_1", "--env", "env_1", "--", "true"})
	if code != ExitRefused {
		t.Fatalf("exit=%d, want ExitRefused; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "LD_PRELOAD") || !strings.Contains(stderr.String(), "acknowledge_loader_control") {
		t.Fatalf("loader-control message wrong: %s", stderr)
	}
	_ = st
}

func TestRunMergeCollisionAndAllowOverride(t *testing.T) {
	t.Setenv("HIKYO_TEST_COLLIDE", "inherited")
	server := deliveryServer(t, deliveryResp([]apigen.DeliveredKey{
		{KeyId: "key_c", Name: "HIKYO_TEST_COLLIDE", Classification: apigen.KeyClassificationConfig, Presence: apigen.DeliveredKeyPresenceSet, Value: strPtr("fetched")},
	}))
	defer server.Close()

	st, stateDir := machineState(t, server.URL)

	// Without --allow-override: hard refusal.
	ios, _, stderr := composeIO(stateDir, t.TempDir(), "wl_token", nil)
	code := Run(t.Context(), ios, []string{"run", "--instance", "local", "--org", "org_1", "--project", "prj_1", "--env", "env_1", "--", "true"})
	if code != ExitRefused {
		t.Fatalf("collision without override exit=%d, want ExitRefused; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "HIKYO_TEST_COLLIDE") || !strings.Contains(stderr.String(), "--allow-override") {
		t.Fatalf("collision message must name key and --allow-override: %s", stderr)
	}

	// With --allow-override: fetched wins, exec proceeds (captured via seam).
	ios2, _, stderr2 := composeIO(stateDir, t.TempDir(), "wl_token", nil)
	var gotEnv []string
	ios2.Exec = func(_ string, _, env []string) error { gotEnv = env; return nil }
	code = Run(t.Context(), ios2, []string{"run", "--instance", "local", "--org", "org_1", "--project", "prj_1", "--env", "env_1", "--allow-override", "HIKYO_TEST_COLLIDE", "--", "true"})
	if code != ExitOK {
		t.Fatalf("allow-override exit=%d, want ExitOK; stderr=%s", code, stderr2)
	}
	if !hasEnv(gotEnv, "HIKYO_TEST_COLLIDE=fetched") {
		t.Fatalf("fetched value did not win: %v", envFilter(gotEnv, "HIKYO_TEST_COLLIDE"))
	}
	_ = st
}

func TestRunExecNotFoundAndNotExecutable(t *testing.T) {
	server := deliveryServer(t, deliveryResp(nil))
	defer server.Close()
	_, stateDir := machineState(t, server.URL)

	// 127: command not found.
	ios, _, stderr := composeIO(stateDir, t.TempDir(), "wl_token", nil)
	code := Run(t.Context(), ios, []string{"run", "--instance", "local", "--org", "org_1", "--project", "prj_1", "--env", "env_1", "--", "hikyo-nope-xyzzy-cmd"})
	if code != ExitCommandNotFound {
		t.Fatalf("missing command exit=%d, want 127; stderr=%s", code, stderr)
	}

	// 126: found but Exec fails.
	ios2, _, stderr2 := composeIO(stateDir, t.TempDir(), "wl_token", nil)
	ios2.Exec = func(_ string, _, _ []string) error { return os.ErrPermission }
	code = Run(t.Context(), ios2, []string{"run", "--instance", "local", "--org", "org_1", "--project", "prj_1", "--env", "env_1", "--", "sh"})
	if code != ExitCommandNotExecutable {
		t.Fatalf("non-executable exit=%d, want 126; stderr=%s", code, stderr2)
	}
}

func TestRunConfigResolveDisagreement(t *testing.T) {
	dir := t.TempDir()
	writeComposeConfig(t, dir, "https://hikyo.example", "org_cfg", "prj_1", "env_1", "", "")
	stateDir := t.TempDir()
	st := &State{dir: stateDir}
	if err := st.Trust().Put(TrustEntry{Name: "local", Origin: "https://hikyo.example"}); err != nil {
		t.Fatal(err)
	}
	ios, _, stderr := composeIO(stateDir, dir, "wl_token", nil)
	// Flag says org_flag; config says org_cfg → disagreement, exit usage.
	code := Run(t.Context(), ios, []string{"run", "--org", "org_flag", "--", "true"})
	if code != ExitUsage {
		t.Fatalf("disagreement exit=%d, want ExitUsage; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "org_flag") || !strings.Contains(stderr.String(), "org_cfg") {
		t.Fatalf("message must name both sources: %s", stderr)
	}
	_ = st
}

func TestRunArgMaxRefusal(t *testing.T) {
	// A single fetched value larger than the whole exec budget forces the
	// preflight to refuse before any exec.
	// Larger than the clamped ARG_MAX budget (≤ 6 MiB) on any platform, yet
	// under the client's 8 MiB response cap.
	huge := strings.Repeat("x", 7*1024*1024)
	server := deliveryServer(t, deliveryResp([]apigen.DeliveredKey{
		{KeyId: "key_big", Name: "BIG", Classification: apigen.KeyClassificationConfig, Presence: apigen.DeliveredKeyPresenceSet, Value: strPtr(huge)},
	}))
	defer server.Close()
	_, stateDir := machineState(t, server.URL)
	ios, _, stderr := composeIO(stateDir, t.TempDir(), "wl_token", nil)
	ios.Exec = func(_ string, _, _ []string) error {
		t.Fatal("exec must not be reached past an ARG_MAX refusal")
		return nil
	}
	code := Run(t.Context(), ios, []string{"run", "--instance", "local", "--org", "org_1", "--project", "prj_1", "--env", "env_1", "--", "true"})
	if code != ExitRefused {
		t.Fatalf("ARG_MAX exit=%d, want ExitRefused; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "over the") || !strings.Contains(stderr.String(), "budget") {
		t.Fatalf("ARG_MAX message wrong: %s", stderr)
	}
}

func TestComposeRenderCursorEligibility(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "runtime")
	var fetchCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasSuffix(r.URL.Path, "/delivery") {
			http.NotFound(w, r)
			return
		}
		fetchCount++
		if r.URL.Query().Get("cursor") == "v1:c1" {
			_, _ = w.Write([]byte(deliveryJSON(t, apigen.DeliveryResponse{
				ChangeToken: "v1:t1", CredentialId: "cred_1", Current: true, Cursor: "v1:c1",
				IssuedAt: time.Now().UTC(), SnapshotExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
				SchemaRevision: 1, Keys: []apigen.DeliveredKey{},
			})))
			return
		}
		_, _ = w.Write([]byte(deliveryJSON(t, apigen.DeliveryResponse{
			ChangeToken: "v1:t1", CredentialId: "cred_1", Current: false, Cursor: "v1:c1",
			IssuedAt: time.Now().UTC(), SnapshotExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
			SchemaRevision: 1,
			Keys: []apigen.DeliveredKey{
				{KeyId: "key_1", Name: "DATABASE_URL", Classification: apigen.KeyClassificationConfig, Presence: apigen.DeliveredKeyPresenceSet, Value: strPtr("postgres://x")},
			},
		})))
	}))
	defer server.Close()

	dir := t.TempDir()
	writeComposeConfig(t, dir, server.URL, "org_1", "prj_1", "env_1", runtimeDir, "acme")
	_, stateDir := machineState(t, server.URL)

	ios, _, stderr := composeIO(stateDir, dir, "wl_token", nil)
	if code := Run(t.Context(), ios, []string{"compose", "render"}); code != ExitOK {
		t.Fatalf("first render exit=%d; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "rendered api generation v1-") {
		t.Fatalf("first render did not report a generation: %s", stderr)
	}

	ios2, _, stderr2 := composeIO(stateDir, dir, "wl_token", nil)
	if code := Run(t.Context(), ios2, []string{"compose", "render"}); code != ExitOK {
		t.Fatalf("second render exit=%d; stderr=%s", code, stderr2)
	}
	if !strings.Contains(stderr2.String(), "up to date (generation v1-") {
		t.Fatalf("second render did not present the cursor: %s", stderr2)
	}
	if fetchCount != 2 {
		t.Fatalf("fetchCount=%d, want 2", fetchCount)
	}
}

func TestRunStaleLineOnOfflineServe(t *testing.T) {
	// Save a snapshot + offline meta, then point the fetch at a closed server so
	// the offline path serves and prints the stale line.
	origin := "http://127.0.0.1:1" // closed port
	dir := t.TempDir()
	writeComposeConfigOffline(t, dir, origin, "org_1", "prj_1", "env_1", "acme")
	_, stateDir := machineState(t, origin)

	// Pre-seed the snapshot for slug "acme".
	slug := "acme"
	sd := filepath.Join(stateDir, "compose", slug)
	seedRunSnapshot(t, sd, origin)

	ios, _, stderr := composeIO(stateDir, dir, "wl_token", nil)
	var captured []string
	ios.Exec = func(_ string, _, env []string) error { captured = env; return nil }
	code := Run(t.Context(), ios, []string{"run", "--", "true"})
	if code != ExitOK {
		t.Fatalf("offline run exit=%d; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "serving stale from ") || !strings.Contains(stderr.String(), "generation v1-") {
		t.Fatalf("stale line missing/wrong: %s", stderr)
	}
	if !hasEnv(captured, "DATABASE_URL=postgres://cached") {
		t.Fatalf("offline value not delivered to child env: %v", captured)
	}
}

func TestRunOfflineExpiredRefused(t *testing.T) {
	origin := "http://127.0.0.1:1"
	dir := t.TempDir()
	writeComposeConfigOffline(t, dir, origin, "org_1", "prj_1", "env_1", "acme")
	_, stateDir := machineState(t, origin)
	seedRunSnapshot(t, filepath.Join(stateDir, "compose", "acme"), origin)

	ios, _, stderr := composeIO(stateDir, dir, "wl_token", nil)
	// The snapshot was issued ~1h ago; advance the clock past the 7 d maximum.
	ios.Now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
	ios.Exec = func(_ string, _, _ []string) error { t.Fatal("exec must not run past an expired snapshot"); return nil }
	code := Run(t.Context(), ios, []string{"run", "--", "true"})
	if code != ExitRefused {
		t.Fatalf("expired offline run exit=%d, want ExitRefused; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "maximum stale age") {
		t.Fatalf("expiry refusal message wrong: %s", stderr)
	}
}

func TestRunOfflineNotEnabledRefused(t *testing.T) {
	origin := "http://127.0.0.1:1"
	dir := t.TempDir()
	// offline_serve defaults false.
	writeComposeConfig(t, dir, origin, "org_1", "prj_1", "env_1", "", "acme")
	_, stateDir := machineState(t, origin)
	ios, _, stderr := composeIO(stateDir, dir, "wl_token", nil)
	code := Run(t.Context(), ios, []string{"run", "--", "true"})
	if code != ExitUnavailable {
		t.Fatalf("closed-server run exit=%d, want ExitUnavailable; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "offline serve is not enabled") {
		t.Fatalf("not-enabled message wrong: %s", stderr)
	}
}

// TestRunStripsTokenFromChildEnv proves the workload credential (HIKYO_TOKEN)
// in the REAL process environment never reaches the child (finding 1). It uses a
// real os.Setenv (t.Setenv), not the injected Env getter, because sanitizedEnviron
// reads the process environment the child would inherit.
func TestRunStripsTokenFromChildEnv(t *testing.T) {
	t.Setenv("HIKYO_TOKEN", "super-secret-workload-token")
	t.Setenv("HIKYO_RUN_MARKER", "kept")
	server := deliveryServer(t, deliveryResp([]apigen.DeliveredKey{
		{KeyId: "key_c", Name: "APP_CONFIG", Classification: apigen.KeyClassificationConfig, Presence: apigen.DeliveredKeyPresenceSet, Value: strPtr("v")},
	}))
	defer server.Close()
	_, stateDir := machineState(t, server.URL)
	ios, _, stderr := composeIO(stateDir, t.TempDir(), "super-secret-workload-token", nil)
	var gotEnv []string
	ios.Exec = func(_ string, _, env []string) error { gotEnv = env; return nil }
	code := Run(t.Context(), ios, []string{"run", "--instance", "local", "--org", "org_1", "--project", "prj_1", "--env", "env_1", "--", "true"})
	if code != ExitOK {
		t.Fatalf("exit=%d; stderr=%s", code, stderr)
	}
	for _, e := range gotEnv {
		if strings.HasPrefix(e, "HIKYO_TOKEN=") {
			t.Fatalf("HIKYO_TOKEN leaked into the child environment: %q", e)
		}
	}
	if !hasEnv(gotEnv, "HIKYO_RUN_MARKER=kept") {
		t.Fatalf("a non-credential env var was dropped: %v", envFilter(gotEnv, "HIKYO_RUN_MARKER"))
	}
	if !hasEnv(gotEnv, "APP_CONFIG=v") {
		t.Fatalf("delivered value missing from child env: %v", envFilter(gotEnv, "APP_CONFIG"))
	}
}

// TestRunNonExecutableIs126 puts a real non-executable file on PATH and asserts
// the found-but-not-executable classification (126), which exec.LookPath alone
// does not report for a bare name (finding 13).
func TestRunNonExecutableIs126(t *testing.T) {
	server := deliveryServer(t, deliveryResp(nil))
	defer server.Close()
	_, stateDir := machineState(t, server.URL)

	binDir := t.TempDir()
	prog := filepath.Join(binDir, "hikyo-nox-prog")
	if err := os.WriteFile(prog, []byte("#!/bin/sh\n"), 0o644); err != nil { // no +x
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	ios, _, stderr := composeIO(stateDir, t.TempDir(), "wl_token", nil)
	ios.Exec = func(_ string, _, _ []string) error { t.Fatal("exec must not run a non-executable"); return nil }
	code := Run(t.Context(), ios, []string{"run", "--instance", "local", "--org", "org_1", "--project", "prj_1", "--env", "env_1", "--", "hikyo-nox-prog"})
	if code != ExitCommandNotExecutable {
		t.Fatalf("non-executable exit=%d, want 126; stderr=%s", code, stderr)
	}
}

// TestComposeRenderCursorRebindsOnCredentialChange: rendering with token A then
// token B must NOT present the cursor — the cursor binds to a local fingerprint
// of the presented token, so a different token forces a full fetch (finding 8).
func TestComposeRenderCursorRebindsOnCredentialChange(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "runtime")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasSuffix(r.URL.Path, "/delivery") {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("cursor") == "v1:c1" {
			_, _ = w.Write([]byte(deliveryJSON(t, apigen.DeliveryResponse{
				ChangeToken: "v1:t1", CredentialId: "cred_1", Current: true, Cursor: "v1:c1",
				IssuedAt: time.Now().UTC(), SnapshotExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
				SchemaRevision: 1, Keys: []apigen.DeliveredKey{},
			})))
			return
		}
		_, _ = w.Write([]byte(deliveryJSON(t, apigen.DeliveryResponse{
			ChangeToken: "v1:t1", CredentialId: "cred_1", Current: false, Cursor: "v1:c1",
			IssuedAt: time.Now().UTC(), SnapshotExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
			SchemaRevision: 1,
			Keys: []apigen.DeliveredKey{
				{KeyId: "key_1", Name: "DATABASE_URL", Classification: apigen.KeyClassificationConfig, Presence: apigen.DeliveredKeyPresenceSet, Value: strPtr("postgres://x")},
			},
		})))
	}))
	defer server.Close()

	dir := t.TempDir()
	writeComposeConfig(t, dir, server.URL, "org_1", "prj_1", "env_1", runtimeDir, "acme")
	_, stateDir := machineState(t, server.URL)

	// Token A: full fetch → render.
	iosA, _, stderrA := composeIO(stateDir, dir, "token-A", nil)
	if code := Run(t.Context(), iosA, []string{"compose", "render"}); code != ExitOK {
		t.Fatalf("render A exit=%d; stderr=%s", code, stderrA)
	}
	// Token B: the cursor fingerprint differs → no cursor presented → full fetch,
	// NOT "up to date".
	iosB, _, stderrB := composeIO(stateDir, dir, "token-B", nil)
	if code := Run(t.Context(), iosB, []string{"compose", "render"}); code != ExitOK {
		t.Fatalf("render B exit=%d; stderr=%s", code, stderrB)
	}
	if strings.Contains(stderrB.String(), "up to date") {
		t.Fatalf("cursor was presented after a credential change: %s", stderrB)
	}
}

// TestOfflineSnapshotModeBinding proves a run snapshot cannot be served for a
// render (and the context refusal is by name) — the snapshot's TargetNames bind
// its delivery mode (finding 3).
func TestOfflineSnapshotModeBinding(t *testing.T) {
	origin := "http://127.0.0.1:1" // closed
	dir := t.TempDir()
	// Explicit runtime_dir so render does not stop at runtime resolution / the
	// default-tmpfs gate before it reaches the snapshot's context check.
	runtimeDir := filepath.Join(t.TempDir(), "runtime")
	content := "version: 1\ninstance: " + origin + "\norg: org_1\nproject: prj_1\nenvironment: env_1\n" +
		"slug: acme\nruntime_dir: " + runtimeDir + "\nsnapshot:\n  offline_serve: true\n" +
		"targets:\n  api:\n    keys: [key_1]\n    services: [api]\n"
	if err := os.WriteFile(filepath.Join(dir, composeConfigName), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stateDir := machineState(t, origin)
	// Seed a RUN snapshot (TargetNames ["__run__"]) at the render slug.
	seedRunSnapshot(t, filepath.Join(stateDir, "compose", "acme"), origin)

	ios, _, stderr := composeIO(stateDir, dir, "wl_token", nil)
	code := Run(t.Context(), ios, []string{"compose", "render"})
	if code != ExitRefused {
		t.Fatalf("render off a run snapshot exit=%d, want ExitRefused; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "different context") {
		t.Fatalf("mode-mismatch refusal not surfaced by name: %s", stderr)
	}
}

// TestComposeRenderConfigOnlyMixedTarget: under --config-only a target that
// declares both a config and a secret key renders from the config alone — the
// server omits the secret entirely, and its absence is a SKIP, not a refusal
// (finding 7).
func TestComposeRenderConfigOnlyMixedTarget(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "runtime")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasSuffix(r.URL.Path, "/delivery") {
			http.NotFound(w, r)
			return
		}
		// config_only projection: only the config key is delivered; the secret is
		// omitted entirely.
		_, _ = w.Write([]byte(deliveryJSON(t, apigen.DeliveryResponse{
			ChangeToken: "v1:t1", CredentialId: "cred_1", Current: false, Cursor: "v1:c1",
			IssuedAt: time.Now().UTC(), SnapshotExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
			SchemaRevision: 1,
			Keys: []apigen.DeliveredKey{
				{KeyId: "key_cfg", Name: "DATABASE_URL", Classification: apigen.KeyClassificationConfig, Presence: apigen.DeliveredKeyPresenceSet, Value: strPtr("postgres://x")},
				// A delivered config key with NO value (genuinely unset): must never
				// be emitted as OPTIONAL= (finding 7).
				{KeyId: "key_opt", Name: "OPTIONAL", Classification: apigen.KeyClassificationConfig, Presence: apigen.DeliveredKeyPresenceOptional, Value: nil},
			},
		})))
	}))
	defer server.Close()

	dir := t.TempDir()
	content := "version: 1\ninstance: " + server.URL + "\norg: org_1\nproject: prj_1\nenvironment: env_1\n" +
		"slug: acme\nruntime_dir: " + runtimeDir + "\n" +
		"targets:\n  api:\n    keys: [key_cfg, key_opt, key_sec]\n    services: [api]\n"
	if err := os.WriteFile(filepath.Join(dir, composeConfigName), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stateDir := machineState(t, server.URL)
	ios, _, stderr := composeIO(stateDir, dir, "wl_token", nil)
	code := Run(t.Context(), ios, []string{"compose", "render", "--config-only"})
	if code != ExitOK {
		t.Fatalf("config-only mixed render exit=%d, want ExitOK; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "rendered api generation v1-") {
		t.Fatalf("config-only render did not render the target: %s", stderr)
	}
	// The rendered env holds the config value and NOT an empty secret line.
	var envBody string
	_ = filepath.WalkDir(runtimeDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, "api.env") {
			b, _ := os.ReadFile(p)
			envBody = string(b)
		}
		return nil
	})
	if !strings.Contains(envBody, "DATABASE_URL=") {
		t.Fatalf("config value not rendered: %q", envBody)
	}
	if strings.Contains(envBody, "key_sec") || strings.Contains(envBody, "=\n\n") {
		t.Fatalf("an omitted secret produced an env entry: %q", envBody)
	}
	if strings.Contains(envBody, "OPTIONAL") {
		t.Fatalf("an unset delivered value was emitted as NAME=: %q", envBody)
	}
}

// TestComposeRenderFlushesBeforeFetch asserts the reconciliation POST precedes
// every GET on a render (finding 9): the fake server records method+path order.
func TestComposeRenderFlushesBeforeFetch(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "runtime")
	var order []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		order = append(order, r.Method+" "+r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/offline-records"):
			_, _ = w.Write([]byte(`{}`))
		case strings.HasSuffix(r.URL.Path, "/delivery"):
			_, _ = w.Write([]byte(deliveryJSON(t, deliveryResp([]apigen.DeliveredKey{
				{KeyId: "key_1", Name: "DATABASE_URL", Classification: apigen.KeyClassificationConfig, Presence: apigen.DeliveredKeyPresenceSet, Value: strPtr("postgres://x")},
			}))))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	writeComposeConfig(t, dir, server.URL, "org_1", "prj_1", "env_1", runtimeDir, "acme")
	_, stateDir := machineState(t, server.URL)

	// Seed a pending offline record under the stack's state dir.
	sd := filepath.Join(stateDir, "compose", "acme")
	if err := os.MkdirAll(sd, 0o700); err != nil {
		t.Fatal(err)
	}
	rid, err := compose.NewRecordID()
	if err != nil {
		t.Fatal(err)
	}
	if err := compose.Append(sd, []compose.OfflineRecord{{
		RecordID: rid, KeyID: "key_1", KeyName: "DATABASE_URL", Classification: "config",
		OccurredAt: "2026-08-19T10:00:00Z", CredentialID: "cred_1",
		Generation: "v1-00000000000000000000000000000000", ServedFrom: "2026-08-19T10:00:00Z",
	}}); err != nil {
		t.Fatal(err)
	}

	ios, _, stderr := composeIO(stateDir, dir, "wl_token", nil)
	if code := Run(t.Context(), ios, []string{"compose", "render"}); code != ExitOK {
		t.Fatalf("render exit=%d; stderr=%s", code, stderr)
	}
	if len(order) < 2 {
		t.Fatalf("expected at least a POST and a GET, got %v", order)
	}
	if !strings.HasPrefix(order[0], "POST ") || !strings.Contains(order[0], "/offline-records") {
		t.Fatalf("reconciliation POST did not precede the fetch: %v", order)
	}
	// No GET may appear before the reconciliation POST.
	for _, req := range order {
		if strings.HasPrefix(req, "GET ") {
			t.Fatalf("a GET preceded the reconciliation POST: %v", order)
		}
		if strings.Contains(req, "/offline-records") {
			break
		}
	}
}

// TestComposeRenderIdenticalContentDistinctStamps: two targets that render
// byte-identical content get DISTINCT stamps and DISTINCT generation dirs — the
// stamp binds the target name (finding 5).
func TestComposeRenderIdenticalContentDistinctStamps(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "runtime")
	server := deliveryServer(t, deliveryResp([]apigen.DeliveredKey{
		{KeyId: "key_a", Name: "SHARED", Classification: apigen.KeyClassificationConfig, Presence: apigen.DeliveredKeyPresenceSet, Value: strPtr("v")},
		{KeyId: "key_b", Name: "SHARED", Classification: apigen.KeyClassificationConfig, Presence: apigen.DeliveredKeyPresenceSet, Value: strPtr("v")},
	}))
	defer server.Close()

	dir := t.TempDir()
	content := "version: 1\ninstance: " + server.URL + "\norg: org_1\nproject: prj_1\nenvironment: env_1\n" +
		"slug: acme\nruntime_dir: " + runtimeDir + "\n" +
		"targets:\n  api:\n    keys: [key_a]\n    services: [api]\n  worker:\n    keys: [key_b]\n    services: [worker]\n"
	if err := os.WriteFile(filepath.Join(dir, composeConfigName), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stateDir := machineState(t, server.URL)
	ios, _, stderr := composeIO(stateDir, dir, "wl_token", nil)
	if code := Run(t.Context(), ios, []string{"compose", "render"}); code != ExitOK {
		t.Fatalf("render exit=%d; stderr=%s", code, stderr)
	}
	// Two distinct generation directories under the runtime dir.
	dirs := map[string]bool{}
	entries, err := os.ReadDir(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			dirs[e.Name()] = true
		}
	}
	if len(dirs) != 2 {
		t.Fatalf("identical content did not produce two distinct generation dirs: %v", dirs)
	}
}

// TestComposeRenderOfflineRefusesUnacknowledged: a snapshot saved with a
// loader-control key acknowledged, then a config with the ack removed, must be
// refused by name on offline render BEFORE any offline record is written
// (finding 6).
func TestComposeRenderOfflineRefusesUnacknowledged(t *testing.T) {
	origin := "http://127.0.0.1:1" // closed
	dir := t.TempDir()
	runtimeDir := filepath.Join(t.TempDir(), "runtime")
	// No acknowledge_loader_control for the target.
	content := "version: 1\ninstance: " + origin + "\norg: org_1\nproject: prj_1\nenvironment: env_1\n" +
		"slug: acme\nruntime_dir: " + runtimeDir + "\nsnapshot:\n  offline_serve: true\n" +
		"targets:\n  api:\n    keys: [key_ld]\n    services: [api]\n"
	if err := os.WriteFile(filepath.Join(dir, composeConfigName), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stateDir := machineState(t, origin)
	sd := filepath.Join(stateDir, "compose", "acme")
	seedRenderSnapshot(t, sd, origin, "api",
		[]compose.SnapshotRow{{Name: "LD_PRELOAD", KeyID: "key_ld", Classification: "config", Value: "/evil.so"}})

	ios, _, stderr := composeIO(stateDir, dir, "wl_token", nil)
	code := Run(t.Context(), ios, []string{"compose", "render"})
	if code != ExitRefused {
		t.Fatalf("offline render with unacknowledged loader-control exit=%d, want ExitRefused; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "LD_PRELOAD") || !strings.Contains(stderr.String(), "acknowledge_loader_control") {
		t.Fatalf("refusal did not name the loader-control key: %s", stderr)
	}
	// No offline record was written (the refusal precedes any disclosure).
	if _, files, _ := compose.Pending(sd); len(files) != 0 {
		t.Fatalf("an offline record was written before the refusal: %d files", len(files))
	}
}

// TestOfflineRenderSnapshotRefusedForRun is the review's BLOCKER direction: a
// RENDER snapshot (target-selected rows) must NOT be served to offline `run`,
// which would bypass run's full-manifest all-or-nothing check (finding 3).
func TestOfflineRenderSnapshotRefusedForRun(t *testing.T) {
	origin := "http://127.0.0.1:1" // closed
	dir := t.TempDir()
	writeComposeConfigOffline(t, dir, origin, "org_1", "prj_1", "env_1", "acme")
	_, stateDir := machineState(t, origin)
	// Seed a RENDER snapshot (TargetNames ["api"]) at the run slug.
	seedRenderSnapshot(t, filepath.Join(stateDir, "compose", "acme"), origin, "api",
		[]compose.SnapshotRow{{Name: "DATABASE_URL", KeyID: "key_1", Classification: "config", Value: "postgres://cached"}})

	ios, _, stderr := composeIO(stateDir, dir, "wl_token", nil)
	ios.Exec = func(_ string, _, _ []string) error { t.Fatal("run must not exec off a render snapshot"); return nil }
	code := Run(t.Context(), ios, []string{"run", "--", "true"})
	if code != ExitRefused {
		t.Fatalf("run off a render snapshot exit=%d, want ExitRefused; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "different context") {
		t.Fatalf("mode-mismatch refusal not surfaced by name: %s", stderr)
	}
}

// seedRenderSnapshot writes a render-mode snapshot (TargetNames [target]) with
// the given rows, plus the server-credential record, so an offline render can
// open it.
func seedRenderSnapshot(t *testing.T, stateDir, origin, target string, rows []compose.SnapshotRow) {
	t.Helper()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keys, err := crypto.LoadOrCreateLocalKey(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Now().UTC().Add(-time.Hour)
	aad := crypto.SnapshotAAD{
		InstanceOrigin: origin, OrgID: "org_1", ProjectID: "prj_1", EnvironmentID: "env_1",
		CredentialID: "cred_1", ChangeToken: "v1:tok", Projection: []string{"read"},
		TargetNames: []string{target},
		IssuedAt:    issued.Format(time.RFC3339), ExpiresAt: issued.Add(7 * 24 * time.Hour).Format(time.RFC3339),
	}
	payload := compose.SnapshotPayload{Rows: rows, GenerationStamps: map[string]string{target: "v1-00000000000000000000000000000000"}}
	if err := compose.SaveSnapshot(stateDir, keys, aad, payload); err != nil {
		t.Fatal(err)
	}
	if err := saveServerCredential(stateDir, "cred_1"); err != nil {
		t.Fatal(err)
	}
}

// ---- helpers ----

func deliveryResp(keys []apigen.DeliveredKey) apigen.DeliveryResponse {
	return apigen.DeliveryResponse{
		ChangeToken: "v1:tok", CredentialId: "cred_1", Current: false, Cursor: "v1:c1",
		IssuedAt: time.Now().UTC(), SnapshotExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
		SchemaRevision: 1, Keys: keys,
	}
}

func deliveryServer(t *testing.T, resp apigen.DeliveryResponse) *httptest.Server {
	t.Helper()
	body := deliveryJSON(t, resp)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/delivery") {
			_, _ = w.Write([]byte(body))
			return
		}
		http.NotFound(w, r)
	}))
}

func writeComposeConfig(t *testing.T, dir, instance, org, project, env, runtimeDir, slug string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("version: 1\n")
	b.WriteString("instance: " + instance + "\n")
	b.WriteString("org: " + org + "\n")
	b.WriteString("project: " + project + "\n")
	b.WriteString("environment: " + env + "\n")
	if runtimeDir != "" {
		b.WriteString("runtime_dir: " + runtimeDir + "\n")
	}
	if slug != "" {
		b.WriteString("slug: " + slug + "\n")
	}
	b.WriteString("targets:\n  api:\n    keys: [key_1]\n    services: [api]\n")
	if err := os.WriteFile(filepath.Join(dir, composeConfigName), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeComposeConfigOffline(t *testing.T, dir, instance, org, project, env, slug string) {
	t.Helper()
	content := "version: 1\ninstance: " + instance + "\norg: " + org + "\nproject: " + project +
		"\nenvironment: " + env + "\nslug: " + slug + "\nsnapshot:\n  offline_serve: true\n" +
		"targets:\n  api:\n    keys: [key_1]\n    services: [api]\n"
	if err := os.WriteFile(filepath.Join(dir, composeConfigName), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func seedRunSnapshot(t *testing.T, stateDir, origin string) {
	t.Helper()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keys, err := crypto.LoadOrCreateLocalKey(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	rows := []compose.SnapshotRow{{Name: "DATABASE_URL", KeyID: "key_1", Classification: "config", Value: "postgres://cached"}}
	// run's generation stamp is keyed to the run generation sentinel.
	stamp := compose.TargetStamp(keys, runGenerationKey, canonicalRows(rows))
	issued := time.Now().UTC().Add(-time.Hour)
	aad := crypto.SnapshotAAD{
		InstanceOrigin: origin, OrgID: "org_1", ProjectID: "prj_1", EnvironmentID: "env_1",
		CredentialID: "cred_1", PinnedRevision: 0, ChangeToken: "v1:tok",
		Projection: []string{"read"}, TargetNames: []string{runGenerationKey},
		IssuedAt: issued.Format(time.RFC3339), ExpiresAt: issued.Add(7 * 24 * time.Hour).Format(time.RFC3339),
	}
	payload := compose.SnapshotPayload{Rows: rows, GenerationStamps: map[string]string{runGenerationKey: stamp}}
	if err := compose.SaveSnapshot(stateDir, keys, aad, payload); err != nil {
		t.Fatal(err)
	}
	if err := saveServerCredential(stateDir, "cred_1"); err != nil {
		t.Fatal(err)
	}
}

func hasEnv(env []string, want string) bool {
	for _, e := range env {
		if e == want {
			return true
		}
	}
	return false
}

func envFilter(env []string, prefix string) []string {
	var out []string
	for _, e := range env {
		if strings.HasPrefix(e, prefix+"=") {
			out = append(out, e)
		}
	}
	return out
}
