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
	if !strings.Contains(stderr.String(), "exec budget") {
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
	rows := []compose.SnapshotRow{{Name: "DATABASE_URL", Classification: "config", Value: "postgres://cached"}}
	stamp := compose.TargetStamp(keys, canonicalRows(rows))
	issued := time.Now().UTC().Add(-time.Hour)
	aad := crypto.SnapshotAAD{
		InstanceOrigin: origin, OrgID: "org_1", ProjectID: "prj_1", EnvironmentID: "env_1",
		CredentialID: "cred_1", Revision: 1, Projection: []string{"read"}, TargetNames: []string{"api"},
		IssuedAt: issued.Format(time.RFC3339), ExpiresAt: issued.Add(7 * 24 * time.Hour).Format(time.RFC3339),
	}
	payload := compose.SnapshotPayload{Rows: rows, GenerationStamps: map[string]string{runGenerationKey: stamp}}
	if err := compose.SaveSnapshot(stateDir, keys, aad, payload); err != nil {
		t.Fatal(err)
	}
	if err := saveOfflineMeta(stateDir, aad, []apigen.DeliveredKey{{KeyId: "key_1", Name: "DATABASE_URL"}}); err != nil {
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
