package isolation

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/app"
	"github.com/Hikyo-Org/hikyo/internal/cli"
	"github.com/Hikyo-Org/hikyo/internal/config"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/disclose"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/keyring"
)

const (
	retentionCLIOrg        = "org_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0f11"
	retentionCLIProject    = "prj_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0f12"
	retentionCLIInherited  = "prj_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0f13"
	retentionCLIEnv        = "env_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0f14"
	retentionCLIEnvInherit = "env_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0f15"
)

// The retention C6 seam is intentionally separate from runRetentionGCC6:
// that test gives the direct-store proof in a compact fixture, while this one
// proves the normative path — real app.Boot server, real CLI, restart, and the
// scheduler's startup catch-up run — on both engines.
func TestRetentionCLIStartupSweepSQLite(t *testing.T) {
	runRetentionCLIStartupSweep(t, store.EngineSQLite)
}

func TestRetentionCLIStartupSweepPostgres(t *testing.T) {
	runRetentionCLIStartupSweep(t, store.EnginePostgres)
}

func runRetentionCLIStartupSweep(t *testing.T, engine store.Engine) {
	t.Helper()
	cfg := retentionAppConfig(t, engine)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	first, err := app.Boot(t.Context(), cfg, log)
	if err != nil {
		t.Fatalf("first boot: %v", err)
	}
	origin := "http://" + first.Addr
	cfg.Listen = first.Addr
	stopFirst := serveRetentionApp(t, first)
	waitHTTP(t, origin+"/healthz")

	db, err := store.Open(t.Context(), retentionStoreConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	waitForCount(t, db, "SELECT COUNT(*) FROM retention_runtime WHERE id = 1 AND last_prune_success IS NOT NULL", 1)

	rootKey, err := crypto.ReadRootKey(cfg.RootKeyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	kdf, limiter, err := app.AuthComponents(cfg)
	if err != nil {
		t.Fatal(err)
	}
	auth := &service.Auth{
		DB: db, Keyring: kr, KDF: kdf, Admission: limiter,
		ExternalOrigin: cfg.ExternalOrigin,
	}
	boot, err := auth.BootstrapAdmin(t.Context(), "retention-admin", "Retention Admin", "terminal")
	if err != nil {
		t.Fatal(err)
	}
	seedRetentionCLITenant(t, db)
	execRaw(t, db, fmt.Sprintf(`INSERT INTO grants
        (id, principal_id, capability, org_id, project_id, env_id, created_at)
        VALUES ('g_retention_cli_read', '%s', 'read', '%s', NULL, NULL, %s)`, boot.PrincipalID, retentionCLIOrg, ts))
	execRaw(t, db, fmt.Sprintf(`INSERT INTO grants
        (id, principal_id, capability, org_id, project_id, env_id, created_at)
        VALUES ('g_retention_cli_settings', '%s', 'project-settings', '%s', NULL, NULL, %s)`, boot.PrincipalID, retentionCLIOrg, ts))
	seedOrigins(t, db)

	const password = "retention e2e ordinary passphrase"
	stateDir, workDir := t.TempDir(), t.TempDir()
	prompts := map[string]string{
		"authority":    boot.Authority,
		"New password": password,
		"Repeat":       password,
	}
	ios := func() cli.IO {
		var terminal fakeTerminal
		terminalSession, err := disclose.NewTerminalSession(&terminal)
		if err != nil {
			t.Fatal(err)
		}
		return cli.IO{
			Stdout: io.Discard, Stderr: io.Discard, Workdir: workDir,
			Env: cli.Env{Getenv: func(key string) string {
				if key == "HIKYO_STATE_DIR" {
					return stateDir
				}
				return ""
			}},
			ReadPassword: func(prompt string) (string, error) {
				for match, answer := range prompts {
					if strings.Contains(prompt, match) {
						return answer, nil
					}
				}
				t.Fatalf("unexpected prompt: %q", prompt)
				return "", nil
			},
			TerminalSession: terminalSession,
		}
	}
	runCLI := func(want int, args ...string) (string, string) {
		t.Helper()
		stdout, stderr := &strings.Builder{}, &strings.Builder{}
		invocation := ios()
		invocation.Stdout, invocation.Stderr = stdout, stderr
		if got := cli.Run(t.Context(), invocation, args); got != want {
			t.Fatalf("hikyo %s exited %d, want %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), got, want, stdout, stderr)
		}
		return stdout.String(), stderr.String()
	}

	runCLI(cli.ExitOK, "account", "establish-credential", "--instance", origin, "--as", "retention-admin")
	clear(prompts)
	prompts["Password for retention-admin"] = password
	runCLI(cli.ExitOK, "login", origin, "--local", "--as", "retention-admin")

	totpFile := filepath.Join(workDir, "retention-totp.uri")
	prompts["to authorize enrolment"] = password
	runCLI(cli.ExitOK, "account", "factor", "enrol-totp", "--output-file", totpFile)
	uri, err := os.ReadFile(totpFile)
	if err != nil {
		t.Fatal(err)
	}
	// Confirmation must consume a step strictly after the enrolment step. The
	// real app clock is not injectable, so use its accepted +1 window, then
	// cross one real boundary before step-up consumes the following step.
	initialStep := crypto.TOTPStep(time.Now().UTC())
	prompts["to confirm"] = totpCode(t, strings.TrimSpace(string(uri)), time.Now().UTC().Add(30*time.Second))
	runCLI(cli.ExitOK, "account", "factor", "confirm-totp")
	waitForTOTPStep(t, initialStep+1)
	prompts["authenticator:"] = totpCode(t, strings.TrimSpace(string(uri)), time.Now().UTC().Add(30*time.Second))
	runCLI(cli.ExitOK, "account", "factor", "step-up")

	runCLI(cli.ExitOK, "org", "retention", "set", "--org", retentionCLIOrg, "--max-age", "720h", "--last-revisions", "3", "-o", "json")
	runCLI(cli.ExitOK, "org", "retention", "get", "--org", retentionCLIOrg, "-o", "json")
	runCLI(cli.ExitOK, "project", "retention", "set", "--org", retentionCLIOrg, "--project", retentionCLIProject, "--max-age", "480h", "--last-revisions", "2", "-o", "json")
	runCLI(cli.ExitOK, "project", "retention", "get", "--org", retentionCLIOrg, "--project", retentionCLIProject, "-o", "json")

	seedRetentionCLICorpus(t, db, boot.PrincipalID, time.Now().UTC())
	stopFirst()

	second, err := app.Boot(t.Context(), cfg, log)
	if err != nil {
		t.Fatalf("restart boot: %v", err)
	}
	if second.Addr != first.Addr {
		t.Fatalf("restart address = %s, want %s so the CLI trust binding stays exact", second.Addr, first.Addr)
	}
	stopSecond := serveRetentionApp(t, second)
	defer stopSecond()
	waitHTTP(t, origin+"/healthz")
	waitForCount(t, db, "SELECT COUNT(*) FROM snapshots WHERE collected_at IS NOT NULL", 3)

	for _, pair := range []string{retentionCLIEnv + ":1", retentionCLIEnv + ":3", retentionCLIEnvInherit + ":1"} {
		env, revision, _ := strings.Cut(pair, ":")
		if got := queryInt(t, db, fmt.Sprintf(`SELECT COUNT(*) FROM snapshots
            WHERE environment_id = '%s' AND revision = %s AND payload_present = FALSE
              AND collected_at IS NOT NULL AND collected_policy <> ''`, env, revision)); got != 1 {
			t.Errorf("collected marker %s = %d, want 1", pair, got)
		}
		if got := queryInt(t, db, fmt.Sprintf(`SELECT COUNT(*) FROM snapshot_entries
            WHERE snapshot_id = (SELECT id FROM snapshots WHERE environment_id = '%s' AND revision = %s)`, env, revision)); got != 0 {
			t.Errorf("collected payload rows %s = %d, want 0", pair, got)
		}
	}
	for _, pair := range []string{
		retentionCLIEnv + ":2",        // live pin
		retentionCLIEnv + ":4",        // age window
		retentionCLIEnv + ":5",        // project last-N
		retentionCLIEnv + ":6",        // current
		retentionCLIEnvInherit + ":2", // inherited last-N
		retentionCLIEnvInherit + ":3", // inherited age window
		retentionCLIEnvInherit + ":4", // current
	} {
		env, revision, _ := strings.Cut(pair, ":")
		if got := queryInt(t, db, fmt.Sprintf(`SELECT COUNT(*) FROM snapshot_entries
            WHERE environment_id = '%s'
              AND snapshot_id = (SELECT id FROM snapshots WHERE environment_id = '%s' AND revision = %s)`,
			env, env, revision)); got != 1 {
			t.Errorf("survivor payload rows %s = %d, want 1", pair, got)
		}
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM snapshots WHERE environment_id IN ('"+retentionCLIEnv+"', '"+retentionCLIEnvInherit+"')"); got != 10 {
		t.Errorf("lineage snapshots = %d, want 10", got)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM revision_key_changes WHERE environment_id IN ('"+retentionCLIEnv+"', '"+retentionCLIEnvInherit+"')"); got != 10 {
		t.Errorf("lineage key changes = %d, want 10", got)
	}

	_, revisionErr := runCLI(cli.ExitRefused, "revision", "show", "1", "--org", retentionCLIOrg, "--project", retentionCLIProject, "--env", retentionCLIEnv)
	if !strings.Contains(revisionErr, "revision 1") || !strings.Contains(revisionErr, "keep-if-either(max_age=480h0m0s,last_revisions=2)") {
		t.Errorf("collected revision refusal does not name revision and policy: %s", revisionErr)
	}
	doctor, _ := runCLI(cli.ExitOK, "doctor", "-o", "json")
	if !strings.Contains(doctor, `"status": "ok"`) || !strings.Contains(doctor, `"code": "retention-prune"`) || !strings.Contains(doctor, `"severity": "ok"`) {
		t.Errorf("doctor did not report fresh prune health: %s", doctor)
	}
	staleAt := time.Now().UTC().Add(-25 * time.Hour).Format(time.RFC3339Nano)
	execRaw(t, db, "UPDATE retention_runtime SET last_prune_success = '"+staleAt+"' WHERE id = 1")
	doctor, _ = runCLI(cli.ExitOK, "doctor", "-o", "json")
	if !strings.Contains(doctor, `"status": "warning"`) || !strings.Contains(doctor, `"severity": "warn"`) ||
		!strings.Contains(doctor, `old (\u003e 24h)`) {
		t.Errorf("doctor did not report stale prune health: %s", doctor)
	}
	execRaw(t, db, "DELETE FROM retention_runtime WHERE id = 1")
	doctor, _ = runCLI(cli.ExitOK, "doctor", "-o", "json")
	if !strings.Contains(doctor, `"status": "warning"`) || !strings.Contains(doctor, `"message": "never recorded"`) {
		t.Errorf("doctor did not report absent prune health: %s", doctor)
	}

	for _, eventType := range []string{"settings.org_retention_changed", "settings.project_retention_changed"} {
		if got := queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE type = '"+eventType+"'"); got != 1 {
			t.Errorf("%s events = %d, want 1", eventType, got)
		}
	}
	if got := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events
        WHERE type = 'retention.payload_gc' AND actor_class = 'system'
		  AND scope_class = 'env' AND org_id = '`+retentionCLIOrg+`'
          AND payload LIKE '%"snapshot_id"%' AND payload LIKE '%"policy"%'`); got != 3 {
		t.Errorf("payload GC audit events = %d, want 3", got)
	}
	if got := queryInt(t, db, `SELECT COUNT(*) FROM audit_instance_events
        WHERE type = 'retention.prune_run' AND outcome = 'success'
          AND payload LIKE '%"revision_payloads":3%'`); got != 1 {
		t.Errorf("completed startup prune-run events with 3 collections = %d, want 1", got)
	}
}

func retentionAppConfig(t *testing.T, engine store.Engine) *config.Config {
	t.Helper()
	rootKey, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(t.TempDir(), "root.key")
	if err := os.WriteFile(rootPath, []byte(crypto.EncodeRootKey(rootKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	crypto.Zero(rootKey)

	storeCfg := config.Datastore{Engine: config.EngineSQLite, Path: filepath.Join(t.TempDir(), "retention-cli.db")}
	if engine == store.EnginePostgres {
		dsn := os.Getenv("HIKYO_TEST_POSTGRES_DSN")
		if dsn == "" {
			if os.Getenv("CI") != "" {
				t.Fatal("CI run without HIKYO_TEST_POSTGRES_DSN: the postgres retention CLI leg must not silently skip in CI")
			}
			t.Skip("HIKYO_TEST_POSTGRES_DSN not set")
		}
		dsn = derivedDatabase(t, dsn, "_retention_cli")
		reset, err := store.Open(t.Context(), store.Config{Engine: store.EnginePostgres, DSN: dsn})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reset.PG().Exec(t.Context(), "DROP SCHEMA public CASCADE; CREATE SCHEMA public"); err != nil {
			reset.Close()
			t.Fatal(err)
		}
		reset.Close()
		storeCfg = config.Datastore{Engine: config.EnginePostgres, DSN: dsn}
	}
	return &config.Config{
		Dev: true, Listen: "127.0.0.1:0", AutoMigrate: true, Store: storeCfg,
		ExternalOrigin: "http://127.0.0.1", RootKeyFile: rootPath,
		Argon2MemoryKiB: crypto.PasswordFloor.MemoryKiB,
		Argon2Time:      crypto.PasswordFloor.Time, Argon2Parallelism: crypto.PasswordFloor.Parallelism,
		AdmissionBudgetMiB: 272, DevAdmissionPerIPPerMinute: 100,
	}
}

func retentionStoreConfig(cfg *config.Config) store.Config {
	return store.Config{Engine: store.Engine(cfg.Store.Engine), Path: cfg.Store.Path, DSN: cfg.Store.DSN}
}

func seedRetentionCLITenant(t *testing.T, db *store.DB) {
	t.Helper()
	execRaw(t, db, fmt.Sprintf(`INSERT INTO orgs (id, name, active, metadata, created_at)
        VALUES ('%s', 'retention-cli', TRUE, '{}', %s)`, retentionCLIOrg, ts))
	for _, project := range []string{retentionCLIProject, retentionCLIInherited} {
		execRaw(t, db, fmt.Sprintf(`INSERT INTO projects (id, org_id, name, created_at)
            VALUES ('%s', '%s', '%s', %s)`, project, retentionCLIOrg, project, ts))
		execRaw(t, db, fmt.Sprintf(`INSERT INTO project_schema_revisions (org_id, project_id, revision)
            VALUES ('%s', '%s', 1)`, retentionCLIOrg, project))
	}
	for id, project := range map[string]string{
		"key_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0f16": retentionCLIProject,
		"key_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0f17": retentionCLIInherited,
	} {
		execRaw(t, db, fmt.Sprintf(`INSERT INTO keys
            (id, org_id, project_id, name, folder_path, classification, description,
             deprecated, deprecation_note, declaration, required_mode, forbidden_mode, group_id, created_at)
            VALUES ('%s', '%s', '%s', 'GC_VALUE', '', 'config', '', FALSE, '',
                    '{"rule":{"type":"string"}}', 'none', 'none', NULL, %s)`, id, retentionCLIOrg, project, ts))
	}
}

func seedRetentionCLICorpus(t *testing.T, db *store.DB, principal domain.PrincipalID, now time.Time) {
	t.Helper()
	old := func(days int) string { return now.Add(-time.Duration(days) * 24 * time.Hour).Format(time.RFC3339Nano) }
	recent := now.Add(-24 * time.Hour).Format(time.RFC3339Nano)
	pinExpiry := now.Add(30 * 24 * time.Hour).Format(time.RFC3339Nano)
	for env, project := range map[string]string{
		retentionCLIEnv:        retentionCLIProject,
		retentionCLIEnvInherit: retentionCLIInherited,
	} {
		execRaw(t, db, fmt.Sprintf(`INSERT INTO environments
            (id, org_id, project_id, name, note, created_at, display_order)
            VALUES ('%s', '%s', '%s', 'retention-gc', '', %s, 10)`, env, retentionCLIOrg, project, ts))
	}

	type corpus struct {
		env, project, key, prefix string
		revisions                 []struct {
			revision int
			at       string
		}
	}
	sets := []corpus{
		{env: retentionCLIEnv, project: retentionCLIProject, key: "key_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0f16", prefix: "retention_cli", revisions: []struct {
			revision int
			at       string
		}{{1, old(60)}, {2, old(59)}, {3, old(58)}, {4, recent}, {5, old(56)}, {6, old(55)}}},
		{env: retentionCLIEnvInherit, project: retentionCLIInherited, key: "key_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0f17", prefix: "retention_cli_inherited", revisions: []struct {
			revision int
			at       string
		}{{1, old(60)}, {2, old(59)}, {3, recent}, {4, old(57)}}},
	}
	for _, set := range sets {
		for _, revision := range set.revisions {
			snapshot := fmt.Sprintf("snp_%s_%d", set.prefix, revision.revision)
			execRaw(t, db, fmt.Sprintf(`INSERT INTO snapshots
                (id, org_id, project_id, environment_id, revision, schema_revision, published_by, published_at)
                VALUES ('%s', '%s', '%s', '%s', %d, 1, '%s', '%s')`,
				snapshot, retentionCLIOrg, set.project, set.env, revision.revision, principal, revision.at))
			execRaw(t, db, fmt.Sprintf(`INSERT INTO snapshot_entries
                (id, org_id, project_id, environment_id, snapshot_id, key_id, key_name,
                 classification, ciphertext, value_entry_id)
                VALUES ('sen_%s_%d', '%s', '%s', '%s', '%s', '%s', 'GC_VALUE',
                        'config', 'payload-%d', 'val_%s_%d')`, set.prefix, revision.revision,
				retentionCLIOrg, set.project, set.env, snapshot, set.key, revision.revision, set.prefix, revision.revision))
			execRaw(t, db, fmt.Sprintf(`INSERT INTO revision_key_changes
                (org_id, project_id, environment_id, revision, key_id, key_name, change)
                VALUES ('%s', '%s', '%s', %d, '%s', 'GC_VALUE', 'edited')`,
				retentionCLIOrg, set.project, set.env, revision.revision, set.key))
		}
	}
	execRaw(t, db, fmt.Sprintf(`INSERT INTO principals (id, kind, class, created_at)
        VALUES ('mch_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0f18', 'machine', 'workload', %s)`, ts))
	execRaw(t, db, fmt.Sprintf(`INSERT INTO service_accounts
        (id, principal_id, org_id, project_id, name, kind, created_at, created_by)
        VALUES ('svc_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0f19',
                'mch_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0f18', '%s', '%s',
                'retention-workload', 'workload', %s, '%s')`, retentionCLIOrg, retentionCLIProject, ts, principal))
	execRaw(t, db, fmt.Sprintf(`INSERT INTO revision_pins
        (id, org_id, project_id, environment_id, workload_principal_id,
         snapshot_id, revision, authority_principal_id, expires_at, created_at,
         authorized_at, history_authorized, schema_override)
        VALUES ('pin_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0f20', '%s', '%s', '%s',
                'mch_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0f18', 'snp_retention_cli_2', 2,
				'%s', '%s', %s, %s, TRUE, FALSE)`,
		retentionCLIOrg, retentionCLIProject, retentionCLIEnv, principal, pinExpiry, ts, ts))
}

func serveRetentionApp(t *testing.T, srv *app.Server) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve shutdown: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("server did not shut down within 10s")
		}
	}
	t.Cleanup(stop)
	return stop
}

func waitHTTP(t *testing.T, target string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(target)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s did not become healthy within 10s", target)
}

func waitForCount(t *testing.T, db *store.DB, query string, want int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if queryInt(t, db, query) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("query did not reach %d within 10s: %s", want, query)
}

func waitForTOTPStep(t *testing.T, want int64) {
	t.Helper()
	deadline := time.Now().Add(35 * time.Second)
	for time.Now().Before(deadline) {
		if crypto.TOTPStep(time.Now().UTC()) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("TOTP clock did not advance to step %d within 35s", want)
}
