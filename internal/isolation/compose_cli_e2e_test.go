package isolation

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/app"
	"github.com/Hikyo-Org/hikyo/internal/cli"
	"github.com/Hikyo-Org/hikyo/internal/compose"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/keyring"
)

// In-process e2e for the Compose delivery verbs (#63): a real app.Boot server,
// the real CLI, a real workload credential. It proves the wire path end to end
// — the server projects the right values, run merges and execs them, config-only
// is a distinct projection recorded in the audit trail, and compose
// render/doctor agree on the generation. The ids are prefixed UUIDs because the
// HTTP contract validates the path parameters (the short service-layer fixture
// ids do not satisfy it).

const (
	cOrg     = "org_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0100"
	cPrj     = "prj_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0101"
	cEnv     = "env_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0102"
	cKeyURL  = "key_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0103"
	cKeyPw   = "key_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0104"
	cAdmin   = "usr_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0105"
	cKeyWork = "key_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0106"
)

type composeRig struct {
	origin   string
	db       *store.DB
	stateDir string
	credID   string
}

func bootComposeRig(t *testing.T, engine store.Engine) *composeRig {
	t.Helper()
	cfg := retentionAppConfig(t, engine)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := app.Boot(t.Context(), cfg, log)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	origin := "http://" + srv.Addr
	_ = serveRetentionApp(t, srv)
	waitHTTP(t, origin+"/healthz")

	db, err := store.Open(t.Context(), retentionStoreConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// The server's own keyring, so a value this test seals is one the server can
	// open. Register it as the datastore's ONE keyring so valueSvc/revisionSvc
	// seal with it.
	rootKey, err := crypto.ReadRootKey(cfg.RootKeyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	probeKeyringMu.Lock()
	probeKeyrings[db] = kr
	probeKeyringMu.Unlock()

	seedComposeCatalogue(t, db)

	stateDir := t.TempDir()
	writeTrustStore(t, stateDir, origin)
	return &composeRig{origin: origin, db: db, stateDir: stateDir}
}

// seedComposeCatalogue lays down a minimal catalogue with valid prefixed-UUID
// ids: one org/project/env, a config key and a secret key, an administrator
// with edit/publish/definitions-edit/manage-identities, and one published
// revision carrying both values.
func seedComposeCatalogue(t *testing.T, db *store.DB) {
	t.Helper()
	stmts := []string{
		`INSERT INTO orgs (id, name, active, metadata, created_at) VALUES ('` + cOrg + `', 'compose', TRUE, '{}', ` + ts + `)`,
		`INSERT INTO projects (id, org_id, name, created_at) VALUES ('` + cPrj + `', '` + cOrg + `', 'stack', ` + ts + `)`,
		`INSERT INTO project_schema_revisions (org_id, project_id, revision) VALUES ('` + cOrg + `', '` + cPrj + `', 0)`,
		`INSERT INTO environments (id, org_id, project_id, name, note, created_at, display_order) VALUES ('` + cEnv + `', '` + cOrg + `', '` + cPrj + `', 'prod', '', ` + ts + `, 0)`,
		`INSERT INTO keys (id, org_id, project_id, name, folder_path, classification, description, deprecated, deprecation_note, declaration, required_mode, forbidden_mode, group_id, created_at) VALUES ('` + cKeyURL + `', '` + cOrg + `', '` + cPrj + `', 'DATABASE_URL', '', 'config', '', FALSE, '', '{"rule":{"type":"string"}}', 'none', 'none', NULL, ` + ts + `)`,
		`INSERT INTO keys (id, org_id, project_id, name, folder_path, classification, description, deprecated, deprecation_note, declaration, required_mode, forbidden_mode, group_id, created_at) VALUES ('` + cKeyPw + `', '` + cOrg + `', '` + cPrj + `', 'DATABASE_PASSWORD', '', 'secret', '', FALSE, '', '{"rule":{"type":"string"}}', 'none', 'none', NULL, ` + ts + `)`,
		`INSERT INTO keys (id, org_id, project_id, name, folder_path, classification, description, deprecated, deprecation_note, declaration, required_mode, forbidden_mode, group_id, created_at) VALUES ('` + cKeyWork + `', '` + cOrg + `', '` + cPrj + `', 'WORKER_URL', '', 'config', '', FALSE, '', '{"rule":{"type":"string"}}', 'none', 'none', NULL, ` + ts + `)`,
		`INSERT INTO principals (id, kind, created_at) VALUES ('` + cAdmin + `', 'human', ` + ts + `)`,
	}
	for i, cap := range []string{"edit", "publish", "definitions-edit", "manage-identities", "read"} {
		stmts = append(stmts, fmt.Sprintf(
			`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_c_adm_%d', '%s', '%s', '%s', '%s', NULL, %s)`,
			i, cAdmin, cap, cOrg, cPrj, ts))
	}
	for _, s := range stmts {
		execRaw(t, db, s)
	}
	seedOrigins(t, db)
	publishComposeValues(t, db, map[string]string{"DATABASE_URL": "postgres://dev", "DATABASE_PASSWORD": "dev-secret", "WORKER_URL": "http://worker"})
}

func publishComposeValues(t *testing.T, db *store.DB, values map[string]string) {
	t.Helper()
	actor := service.LocalPrincipal(domain.PrincipalID(cAdmin))
	scope := domain.Scope{Org: cOrg, Project: cPrj, Env: cEnv}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	versions := make([]string, 0, len(names))
	for _, name := range names {
		staged, err := valueSvc(t, db).Set(t.Context(), actor, scope, name, values[name])
		if err != nil {
			t.Fatalf("stage %s: %v", name, err)
		}
		versions = append(versions, staged.VersionID)
	}
	if _, err := revisionSvc(t, db).PublishPlanned(t.Context(), actor, scope, service.PublishRequest{VersionIDs: versions}); err != nil {
		t.Fatalf("publish: %v", err)
	}
}

// mintWorkload creates a read-only workload service account and returns its
// principal id and a token-file path holding its credential.
func (r *composeRig) mintWorkload(t *testing.T) (domain.PrincipalID, string) {
	t.Helper()
	ident := identitySvc(r.db)
	actor := service.LocalPrincipal(domain.PrincipalID(cAdmin))
	scope := domain.Scope{Org: cOrg, Project: cPrj}
	sa, err := ident.CreateServiceAccount(t.Context(), actor, scope, "compose-wl", domain.ClassWorkload)
	if err != nil {
		t.Fatalf("create SA: %v", err)
	}
	// Grant read at PROJECT scope (covers the env delivery and the project key
	// catalogue doctor reads), then attach the origin every grant needs.
	execRaw(t, r.db, fmt.Sprintf(
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_c_wl_read', '%s', 'read', '%s', '%s', NULL, %s)`,
		sa.Principal, cOrg, cPrj, ts))
	seedOrigins(t, r.db)
	minted, err := ident.MintCredential(t.Context(), actor, scope, sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatalf("mint credential: %v", err)
	}
	r.credID = minted.Credential.ID
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(minted.Value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return sa.Principal, tokenFile
}

func (r *composeRig) grantReveal(t *testing.T, p domain.PrincipalID) {
	t.Helper()
	execRaw(t, r.db, fmt.Sprintf(
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_c_wl_reveal', '%s', 'reveal', '%s', '%s', '%s', %s)`,
		p, cOrg, cPrj, cEnv, ts))
	seedOrigins(t, r.db)
}

func (r *composeRig) runCLI(t *testing.T, workdir string, capture *[]string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr strings.Builder
	ios := cli.IO{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Workdir: workdir,
		Env: cli.Env{Getenv: func(k string) string {
			if k == "HIKYO_STATE_DIR" {
				return r.stateDir
			}
			return ""
		}},
		Exec: func(_ string, _, env []string) error {
			if capture != nil {
				*capture = env
			}
			return nil
		},
	}
	code := cli.Run(t.Context(), ios, args)
	return code, stdout.String(), stderr.String()
}

func (r *composeRig) runCLIDocker(t *testing.T, workdir, docker string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr strings.Builder
	ios := cli.IO{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Workdir: workdir,
		Env: cli.Env{Getenv: func(k string) string {
			switch k {
			case "HIKYO_STATE_DIR":
				return r.stateDir
			case "HIKYO_COMPOSE_DOCKER":
				return docker
			}
			return ""
		}},
	}
	code := cli.Run(t.Context(), ios, args)
	return code, stdout.String(), stderr.String()
}

func TestComposeCLIDeliverySQLite(t *testing.T) { runComposeCLIDelivery(t, store.EngineSQLite) }

func TestComposeCLIDeliveryPostgres(t *testing.T) { runComposeCLIDelivery(t, store.EnginePostgres) }

func runComposeCLIDelivery(t *testing.T, engine store.Engine) {
	rig := bootComposeRig(t, engine)
	saPrincipal, tokenFile := rig.mintWorkload(t)
	work := t.TempDir()
	target := []string{"run", "--instance", "local", "--org", cOrg, "--project", cPrj, "--env", cEnv, "--token-file", tokenFile}

	// Read-only: the secret cannot be revealed, so all-or-nothing refuses first.
	code, _, stderr := rig.runCLI(t, work, nil, withCmd(target, "true")...)
	if code != cli.ExitRefused {
		t.Fatalf("read-only run exit=%d, want ExitRefused; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "DATABASE_PASSWORD") {
		t.Fatalf("all-or-nothing did not name the secret: %s", stderr)
	}

	// --config-only: a distinct projection with no secret; delivers the config
	// value byte-exact and records config_only in the fetch audit.
	var cfgEnv []string
	code, _, stderr = rig.runCLI(t, work, &cfgEnv, withCmd(append(append([]string{}, target...), "--config-only"), "true")...)
	if code != cli.ExitOK {
		t.Fatalf("config-only run exit=%d, want ExitOK; stderr=%s", code, stderr)
	}
	if !hasKV(cfgEnv, "DATABASE_URL=postgres://dev") {
		t.Fatalf("config-only did not deliver the config value byte-exact: %v", filterKV(cfgEnv, "DATABASE_URL"))
	}
	if len(filterKV(cfgEnv, "DATABASE_PASSWORD=")) != 0 {
		t.Fatalf("config-only leaked a secret: %v", filterKV(cfgEnv, "DATABASE_PASSWORD="))
	}
	if n := queryInt(t, rig.db,
		`SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.delivery_fetched' AND payload LIKE '%"config_only":true%'`); n < 1 {
		t.Fatalf("config-only fetch audit event = %d, want ≥1", n)
	}

	// Grant reveal (store-seeded, mirroring the not-yet-exposed per-project
	// opt-in): both values now deliver byte-exact.
	rig.grantReveal(t, saPrincipal)
	var revealEnv []string
	code, _, stderr = rig.runCLI(t, work, &revealEnv, withCmd(target, "true")...)
	if code != cli.ExitOK {
		t.Fatalf("reveal run exit=%d, want ExitOK; stderr=%s", code, stderr)
	}
	if !hasKV(revealEnv, "DATABASE_URL=postgres://dev") || !hasKV(revealEnv, "DATABASE_PASSWORD=dev-secret") {
		t.Fatalf("reveal run did not deliver both values byte-exact: %v", filterKV(revealEnv, "DATABASE"))
	}

	// 127: a command not on PATH.
	code, _, stderr = rig.runCLI(t, work, nil, withCmd(target, "hikyo-nope-xyzzy")...)
	if code != cli.ExitCommandNotFound {
		t.Fatalf("missing-command exit=%d, want 127; stderr=%s", code, stderr)
	}
}

func TestComposeCLIRenderAndDoctorSQLite(t *testing.T) {
	runComposeCLIRenderAndDoctor(t, store.EngineSQLite)
}

func runComposeCLIRenderAndDoctor(t *testing.T, engine store.Engine) {
	rig := bootComposeRig(t, engine)
	_, tokenFile := rig.mintWorkload(t)

	work := t.TempDir()
	runtimeDir := tmpfsRuntimeDir(t)
	writeRenderConfig(t, work, rig.origin, runtimeDir)

	base := []string{"compose", "render", "--token-file", tokenFile}

	code, _, stderr := rig.runCLI(t, work, nil, base...)
	if code != cli.ExitOK {
		t.Fatalf("first render exit=%d; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "rendered api generation v1-") {
		t.Fatalf("first render did not report a generation: %s", stderr)
	}
	assertRendered(t, runtimeDir)

	// Second render presents the cursor → server answers current → no new gen.
	code, _, stderr = rig.runCLI(t, work, nil, base...)
	if code != cli.ExitOK {
		t.Fatalf("second render exit=%d; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "up to date (generation v1-") {
		t.Fatalf("second render did not present the cursor: %s", stderr)
	}

	// doctor with a REALISTIC fake docker at the floor passes: a service with the
	// right env_file/label, resolving to the managed stamp, satisfies the hardened
	// structural check (finding 4).
	docker230 := fakeDockerRealistic(t, "2.30.0", runtimeDir)
	code, stdout, stderr := rig.runCLIDocker(t, work, docker230, "compose", "doctor", "--token-file", tokenFile, "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("doctor exit=%d; stdout=%s stderr=%s", code, stdout, stderr)
	}

	// doctor with EMPTY services FAILS the structural check with a specific code
	// (finding 4): the required `api` service is missing entirely.
	dockerEmpty := fakeDockerEmptyServices(t, "2.30.0")
	code, stdout, stderr = rig.runCLIDocker(t, work, dockerEmpty, "compose", "doctor", "--token-file", tokenFile, "-o", "json")
	if code != cli.ExitRefused {
		t.Fatalf("doctor with empty services exit=%d, want ExitRefused; stdout=%s", code, stdout)
	}
	// The raw YAML still declares the service, but the RESOLVED config omits it,
	// so the env_file/label resolve to nothing: a structural mismatch (finding 4).
	if !strings.Contains(stdout, "stamp_mismatch") && !strings.Contains(stdout, "label_stamp_mismatch") &&
		!strings.Contains(stdout, "env_file_missing_stamp_var") && !strings.Contains(stdout, "label_absent") {
		t.Fatalf("doctor did not flag the missing service structurally: stdout=%s", stdout)
	}

	// doctor fails CLOSED when `docker compose config` fails: a nil config used to
	// silently disable the service checks (finding 12).
	dockerCfgFail := fakeDockerConfigFails(t, "2.30.0")
	code, stdout, stderr = rig.runCLIDocker(t, work, dockerCfgFail, "compose", "doctor", "--token-file", tokenFile, "-o", "json")
	if code != cli.ExitRefused {
		t.Fatalf("doctor with failing config exit=%d, want ExitRefused; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "docker_config_failed") {
		t.Fatalf("doctor did not fail closed on a config failure: stdout=%s", stdout)
	}

	// doctor below the floor refuses.
	docker229 := fakeDockerRealistic(t, "2.29.7", runtimeDir)
	code, stdout, stderr = rig.runCLIDocker(t, work, docker229, "compose", "doctor", "--token-file", tokenFile)
	if code != cli.ExitRefused {
		t.Fatalf("doctor below floor exit=%d, want ExitRefused; stderr=%s", code, stderr)
	}
	// Findings render to stdout (the doctor report); the refusal to stderr.
	if !strings.Contains(stdout, "compose_version_below_floor") {
		t.Fatalf("doctor did not report the version floor: stdout=%s", stdout)
	}

	// tmpfs-only: no delivered plaintext under the STATE dir (ciphertext snapshot)
	// OR the project dir (.env holds only stamps) — finding 2.
	assertNoPlaintextUnder(t, rig.stateDir, "postgres://dev")
	assertNoPlaintextUnder(t, work, "postgres://dev")
}

func TestComposeCLISyncBlastRadiusSQLite(t *testing.T) {
	rig := bootComposeRig(t, store.EngineSQLite)
	_, tokenFile := rig.mintWorkload(t)
	work := t.TempDir()
	runtimeDir := tmpfsRuntimeDir(t)
	writeRenderConfigTwo(t, work, rig.origin, runtimeDir)

	// First render materializes both targets.
	code, _, stderr := rig.runCLI(t, work, nil, "compose", "render", "--token-file", tokenFile)
	if code != cli.ExitOK {
		t.Fatalf("first render exit=%d; stderr=%s", code, stderr)
	}

	// Publish a change to ONE target's key.
	publishComposeValues(t, rig.db, map[string]string{"DATABASE_URL": "postgres://changed"})

	// sync: doctor, render (only api moves), docker compose up -d. Docker's own
	// stdout must land on hikyo STDERR, keeping sync stdout empty (finding 14).
	docker, dockerLog := fakeDockerRecording(t, runtimeDir)
	code, stdout, stderr := rig.runCLIDocker(t, work, docker, "compose", "sync", "--token-file", tokenFile)
	if code != cli.ExitOK {
		t.Fatalf("sync exit=%d; stderr=%s", code, stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("sync wrote to stdout (must be empty): %q", stdout)
	}
	if !strings.Contains(stderr, "rendered api generation v1-") {
		t.Fatalf("sync did not re-render the changed target: %s", stderr)
	}
	if !strings.Contains(stderr, "unchanged worker generation v1-") {
		t.Fatalf("sync moved a target it should not have (blast radius): %s", stderr)
	}
	if log := readFile(t, dockerLog); !strings.Contains(log, "compose up -d") {
		t.Fatalf("sync did not run `docker compose up -d`: %q", log)
	}

	// A no-change sync recreates nothing.
	docker2, dockerLog2 := fakeDockerRecording(t, runtimeDir)
	code, _, stderr = rig.runCLIDocker(t, work, docker2, "compose", "sync", "--token-file", tokenFile)
	if code != cli.ExitOK {
		t.Fatalf("no-change sync exit=%d; stderr=%s", code, stderr)
	}
	if strings.Contains(readFile(t, dockerLog2), "compose up -d") {
		t.Fatalf("no-change sync ran docker up when nothing moved")
	}
}

// TestComposeCLISyncApplyPendingRetry: a sync whose `docker compose up -d` FAILS
// leaves an apply-pending marker, so the NEXT sync — even with nothing to move —
// retries the apply and, on success, clears the marker (finding 10).
func TestComposeCLISyncApplyPendingRetrySQLite(t *testing.T) {
	rig := bootComposeRig(t, store.EngineSQLite)
	_, tokenFile := rig.mintWorkload(t)
	work := t.TempDir()
	runtimeDir := tmpfsRuntimeDir(t)
	writeRenderConfig(t, work, rig.origin, runtimeDir)

	// Render once so the stack is materialized and the next sync has nothing to
	// move on its own.
	if code, _, stderr := rig.runCLI(t, work, nil, "compose", "render", "--token-file", tokenFile); code != cli.ExitOK {
		t.Fatalf("render exit=%d; stderr=%s", code, stderr)
	}
	sd := filepath.Join(rig.stateDir, "compose", "acme")

	// Publish a change so this sync moves the stamp, then FAIL docker: the marker
	// must remain.
	publishComposeValues(t, rig.db, map[string]string{"DATABASE_URL": "postgres://retry"})
	dockerFail := fakeDockerFailingUp(t, runtimeDir)
	if code, _, _ := rig.runCLIDocker(t, work, dockerFail, "compose", "sync", "--token-file", tokenFile); code != cli.ExitInternal {
		t.Fatalf("failing docker sync exit=%d, want ExitInternal", code)
	}
	if !fileExists(filepath.Join(sd, "apply-pending")) {
		t.Fatalf("failed sync did not leave an apply-pending marker")
	}

	// Next sync: nothing moves (already rendered), but the marker FORCES a retry.
	docker, dockerLog := fakeDockerRecording(t, runtimeDir)
	if code, _, stderr := rig.runCLIDocker(t, work, docker, "compose", "sync", "--token-file", tokenFile); code != cli.ExitOK {
		t.Fatalf("retry sync exit=%d; stderr=%s", code, stderr)
	}
	if log := readFile(t, dockerLog); !strings.Contains(log, "compose up -d") {
		t.Fatalf("retry sync did not re-run docker up: %q", log)
	}
	if fileExists(filepath.Join(sd, "apply-pending")) {
		t.Fatalf("apply-pending marker not cleared after a successful retry")
	}
}

func TestComposeCLIReconcileSQLite(t *testing.T) {
	rig := bootComposeRig(t, store.EngineSQLite)
	_, tokenFile := rig.mintWorkload(t)
	work := t.TempDir()
	runtimeDir := tmpfsRuntimeDir(t)
	writeRenderConfig(t, work, rig.origin, runtimeDir)

	// Buffer an offline-served disclosure record under the stack's state dir.
	sd := filepath.Join(rig.stateDir, "compose", "acme")
	if err := os.MkdirAll(sd, 0o700); err != nil {
		t.Fatal(err)
	}
	rid, err := composeNewRecordID(t)
	if err != nil {
		t.Fatal(err)
	}
	rec := composeOfflineRecord(rid, cKeyURL, "DATABASE_URL", rig.credID)
	if err := appendOffline(sd, rec); err != nil {
		t.Fatal(err)
	}

	// A live render flushes the buffered records before fetching.
	code, _, stderr := rig.runCLI(t, work, nil, "compose", "render", "--token-file", tokenFile)
	if code != cli.ExitOK {
		t.Fatalf("render exit=%d; stderr=%s", code, stderr)
	}
	if n := countOfflineFiles(t, sd); n != 0 {
		t.Fatalf("offline records not flushed: %d files remain", n)
	}
	// The reconcile emits one disclosure per accepted record with origin
	// `offline-reconciled`, plus one envelope event for the batch.
	if n := queryInt(t, rig.db,
		`SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.offline_records_reconciled'`); n < 1 {
		t.Fatalf("no identity.offline_records_reconciled event, got %d", n)
	}
	if n := queryInt(t, rig.db,
		`SELECT COUNT(*) FROM audit_tenant_events WHERE origin = 'offline-reconciled'`); n < 1 {
		t.Fatalf("no audit row with origin offline-reconciled, got %d", n)
	}
}

// ---- helpers ----

func withCmd(base []string, cmd string) []string {
	return append(append(append([]string{}, base...), "--"), cmd)
}

func writeTrustStore(t *testing.T, stateDir, origin string) {
	t.Helper()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	entry := map[string]map[string]string{"local": {"name": "local", "origin": origin}}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "trust.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeRenderConfig(t *testing.T, dir, origin, runtimeDir string) {
	t.Helper()
	content := "version: 1\ninstance: " + origin + "\norg: " + cOrg + "\nproject: " + cPrj + "\nenvironment: " + cEnv + "\n" +
		"slug: acme\nruntime_dir: " + runtimeDir + "\n" +
		"targets:\n  api:\n    keys: [" + cKeyURL + "]\n    services: [api]\n"
	if err := os.WriteFile(filepath.Join(dir, "hikyo-compose.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	compose := "services:\n  api:\n    image: busybox\n    env_file:\n" +
		"      - path: " + runtimeDir + "/${HIKYO_GEN_API:?run 'hikyo compose render' first}/api.env\n" +
		"        format: raw\n    labels:\n      hikyo.stamp: \"${HIKYO_GEN_API:?run 'hikyo compose render' first}\"\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeRenderConfigTwo(t *testing.T, dir, origin, runtimeDir string) {
	t.Helper()
	content := "version: 1\ninstance: " + origin + "\norg: " + cOrg + "\nproject: " + cPrj + "\nenvironment: " + cEnv + "\n" +
		"slug: acme\nruntime_dir: " + runtimeDir + "\n" +
		"targets:\n  api:\n    keys: [" + cKeyURL + "]\n    services: [api]\n" +
		"  worker:\n    keys: [" + cKeyWork + "]\n    services: [worker]\n"
	if err := os.WriteFile(filepath.Join(dir, "hikyo-compose.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	compose := "services:\n" +
		"  api:\n    image: busybox\n    env_file:\n" +
		"      - path: " + runtimeDir + "/${HIKYO_GEN_API:?run first}/api.env\n        format: raw\n" +
		"    labels:\n      hikyo.stamp: \"${HIKYO_GEN_API:?run first}\"\n" +
		"  worker:\n    image: busybox\n    env_file:\n" +
		"      - path: " + runtimeDir + "/${HIKYO_GEN_WORKER:?run first}/worker.env\n        format: raw\n" +
		"    labels:\n      hikyo.stamp: \"${HIKYO_GEN_WORKER:?run first}\"\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fakeDockerRecording is a realistic fake docker that also appends every
// invocation's args to a log file, so a test can assert whether `compose up -d`
// ran. Its `compose config` output is derived from the actual managed .env so it
// AGREES with the hardened doctor's structural check (finding 4).
func fakeDockerRecording(t *testing.T, runtimeDir string) (bin, logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls.log")
	bin = writeFakeDocker(t, dir, "2.30.0", runtimeDir, logPath, false)
	return bin, logPath
}

// fakeDockerRealistic is a fake docker whose `compose config --format json`
// output is computed from the project's managed .env (each HIKYO_GEN_<T>=<stamp>
// becomes a service <t> whose env_file resolves to
// <runtimeDir>/<stamp>/<t>.env with format raw and a matching hikyo.stamp
// label), so a correctly-rendered stack PASSES the structural check (finding 4).
func fakeDockerRealistic(t *testing.T, version, runtimeDir string) string {
	t.Helper()
	return writeFakeDocker(t, t.TempDir(), version, runtimeDir, "", false)
}

// writeFakeDocker generates the sh script. logPath != "" records every call;
// failUp makes `compose up -d` exit non-zero.
func writeFakeDocker(t *testing.T, dir, version, runtimeDir, logPath string, failUp bool) string {
	t.Helper()
	bin := filepath.Join(dir, "docker")
	logLine := ""
	if logPath != "" {
		logLine = "echo \"$@\" >> " + logPath + "\n"
	}
	upLine := ""
	if failUp {
		upLine = "if [ \"$1\" = compose ] && [ \"$2\" = up ]; then echo boom 1>&2; exit 1; fi\n"
	}
	// The config leg reads ./.env (cwd is the project dir), turning each managed
	// stamp variable into a resolved service entry. tr maps HIKYO_GEN_API→api.
	script := "#!/bin/sh\n" + logLine +
		"if [ \"$1\" = compose ] && [ \"$2\" = version ]; then echo " + version + "; exit 0; fi\n" +
		upLine +
		"if [ \"$1\" = compose ] && [ \"$2\" = config ]; then\n" +
		"  printf '{\"services\":{'\n" +
		"  first=1\n" +
		"  while IFS='=' read k v; do\n" +
		"    case \"$k\" in\n" +
		"      HIKYO_GEN_*)\n" +
		"        tsvc=$(printf '%s' \"${k#HIKYO_GEN_}\" | tr 'A-Z_' 'a-z-')\n" +
		"        [ $first -eq 1 ] || printf ','\n" +
		"        first=0\n" +
		"        printf '\"%s\":{\"env_file\":[{\"path\":\"" + runtimeDir + "/%s/%s.env\",\"format\":\"raw\",\"required\":true}],\"labels\":{\"hikyo.stamp\":\"%s\"}}' \"$tsvc\" \"$v\" \"$tsvc\" \"$v\"\n" +
		"        ;;\n" +
		"    esac\n" +
		"  done < .env\n" +
		"  printf '}}\\n'\n" +
		"  exit 0\n" +
		"fi\n" +
		"exit 0\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// fakeDockerFailingUp emits a realistic config (so doctor passes) but exits
// non-zero on `compose up -d`, to drive the apply-pending retry (finding 10).
func fakeDockerFailingUp(t *testing.T, runtimeDir string) string {
	t.Helper()
	return writeFakeDocker(t, t.TempDir(), "2.30.0", runtimeDir, "", true)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// fakeDockerConfigFails answers `compose version` but exits non-zero on
// `compose config`, to exercise doctor's fail-closed docker_config_failed
// (finding 12).
func fakeDockerConfigFails(t *testing.T, version string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "docker")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = compose ] && [ \"$2\" = version ]; then echo " + version + "; exit 0; fi\n" +
		"if [ \"$1\" = compose ] && [ \"$2\" = config ]; then echo 'boom' 1>&2; exit 1; fi\n" +
		"exit 0\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeDockerEmptyServices emits an empty resolved config regardless of .env, so
// a required service is MISSING and the structural check must FAIL (finding 4).
func fakeDockerEmptyServices(t *testing.T, version string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "docker")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = compose ] && [ \"$2\" = version ]; then echo " + version + "; exit 0; fi\n" +
		"if [ \"$1\" = compose ] && [ \"$2\" = config ]; then echo '{\"services\":{}}'; exit 0; fi\n" +
		"exit 0\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// tmpfsRuntimeDir returns a runtime dir that IsTmpfs accepts: on Linux a fresh
// dir under /dev/shm (tmpfs), elsewhere an ordinary temp dir (the non-Linux
// IsTmpfs returns true). The render/doctor checks then do not falsely flag it.
func tmpfsRuntimeDir(t *testing.T) string {
	t.Helper()
	if fi, err := os.Stat("/dev/shm"); err == nil && fi.IsDir() {
		d, err := os.MkdirTemp("/dev/shm", "hikyo-rt-")
		if err == nil {
			t.Cleanup(func() { _ = os.RemoveAll(d) })
			return d
		}
	}
	return filepath.Join(t.TempDir(), "runtime")
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatal(err)
	}
	return string(b)
}

func composeNewRecordID(t *testing.T) (string, error) {
	t.Helper()
	return compose.NewRecordID()
}

func composeOfflineRecord(rid, keyID, name, credID string) compose.OfflineRecord {
	now := "2026-08-19T10:00:00Z"
	return compose.OfflineRecord{
		RecordID: rid, KeyID: keyID, KeyName: name, Classification: "config",
		OccurredAt: now, CredentialID: credID, Generation: "v1-00000000000000000000000000000000", ServedFrom: now,
	}
}

func appendOffline(stateDir string, rec compose.OfflineRecord) error {
	return compose.Append(stateDir, []compose.OfflineRecord{rec})
}

func countOfflineFiles(t *testing.T, stateDir string) int {
	t.Helper()
	_, files, err := compose.Pending(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	return len(files)
}

func assertRendered(t *testing.T, runtimeDir string) {
	t.Helper()
	var found bool
	_ = filepath.WalkDir(runtimeDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, "api.env") {
			found = true
			info, _ := d.Info()
			if info.Mode().Perm() != 0o600 {
				t.Errorf("rendered %s mode = %o, want 0600", p, info.Mode().Perm())
			}
		}
		return nil
	})
	if !found {
		t.Fatalf("no api.env rendered under %s", runtimeDir)
	}
}

func assertNoPlaintextUnder(t *testing.T, dir, plaintext string) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		if strings.Contains(string(b), plaintext) {
			t.Errorf("delivered plaintext found in file %s", p)
		}
		return nil
	})
}

func hasKV(env []string, want string) bool {
	for _, e := range env {
		if e == want {
			return true
		}
	}
	return false
}

func filterKV(env []string, prefix string) []string {
	var out []string
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			out = append(out, e)
		}
	}
	return out
}
