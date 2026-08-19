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
	cOrg    = "org_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0100"
	cPrj    = "prj_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0101"
	cEnv    = "env_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0102"
	cKeyURL = "key_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0103"
	cKeyPw  = "key_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0104"
	cAdmin  = "usr_0193f0b4-1f2a-7c31-8c1e-2a4b6d8e0105"
)

type composeRig struct {
	origin   string
	db       *store.DB
	stateDir string
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
	publishComposeValues(t, db, map[string]string{"DATABASE_URL": "postgres://dev", "DATABASE_PASSWORD": "dev-secret"})
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
	runtimeDir := filepath.Join(t.TempDir(), "runtime")
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

	// doctor with a fake docker at the floor passes.
	docker230 := fakeDocker(t, "2.30.0")
	code, stdout, stderr := rig.runCLIDocker(t, work, docker230, "compose", "doctor", "--token-file", tokenFile, "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("doctor exit=%d; stdout=%s stderr=%s", code, stdout, stderr)
	}

	// doctor below the floor refuses.
	docker229 := fakeDocker(t, "2.29.7")
	code, stdout, stderr = rig.runCLIDocker(t, work, docker229, "compose", "doctor", "--token-file", tokenFile)
	if code != cli.ExitRefused {
		t.Fatalf("doctor below floor exit=%d, want ExitRefused; stderr=%s", code, stderr)
	}
	// Findings render to stdout (the doctor report); the refusal to stderr.
	if !strings.Contains(stdout, "compose_version_below_floor") {
		t.Fatalf("doctor did not report the version floor: stdout=%s", stdout)
	}

	// tmpfs-only: no file under the STATE dir contains a delivered plaintext.
	assertNoPlaintextInState(t, rig.stateDir, "postgres://dev")
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

func fakeDocker(t *testing.T, version string) string {
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

func assertNoPlaintextInState(t *testing.T, stateDir, plaintext string) {
	t.Helper()
	_ = filepath.WalkDir(stateDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		if strings.Contains(string(b), plaintext) {
			t.Errorf("delivered plaintext found in state file %s", p)
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
