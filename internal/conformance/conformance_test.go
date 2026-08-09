// Package conformance runs one scenario corpus against both engines
// (system-architecture ADR § Data layer): canonical cross-engine semantics
// are asserted on sqlite and postgres, not just unit-tested per dialect.
//
// The sqlite leg always runs. The postgres leg needs WENV_TEST_POSTGRES_DSN;
// locally it skips without one, but in CI (CI=true) an unset DSN FAILS —
// "harness green on postgres" must never be vacuously true.
package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/service"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/migrate"
	"github.com/Dunky13/wenv/internal/store/tx"
)

// admin is the corpus's fixture principal: seeded at instance scope with
// instance-config (org create/list/rename/delete) and read (the tenant-class
// org read), which is the pair the real first administrator's template seeds.
// Tenant-scoped scenarios seed their own grants. There is no test-only mint
// hook — every store call in this suite goes through authorize() exactly as
// production does.
const admin = domain.PrincipalID("usr_conformance_admin")

// seed inserts principals and grants with raw SQL: the grant API is #55's,
// and fixtures are the one place allowed to write these tables directly.
func seed(t *testing.T, db *store.DB, statements []string) {
	t.Helper()
	for _, stmt := range statements {
		var err error
		if db.Engine() == store.EnginePostgres {
			_, err = db.PG().Exec(t.Context(), stmt)
		} else {
			_, err = db.SQLiteWrite().ExecContext(t.Context(), stmt)
		}
		if err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
}

func seedAdmin(t *testing.T, db *store.DB) {
	seed(t, db, []string{
		`INSERT INTO principals (id, kind, created_at) VALUES ('usr_conformance_admin', 'human', '2026-01-01T00:00:00Z')`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
		 VALUES ('grt_conformance_admin', 'usr_conformance_admin', 'instance-config', NULL, NULL, NULL, '2026-01-01T00:00:00Z')`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
		 VALUES ('grt_conformance_admin_read', 'usr_conformance_admin', 'read', NULL, NULL, NULL, '2026-01-01T00:00:00Z')`,
	})
}

type scenario struct {
	name string
	fn   func(t *testing.T, db *store.DB)
}

// corpus is the shared scenario list. Every scenario gets a freshly migrated
// database per engine run; scenarios run in order on one database.
var corpus = []scenario{
	{"create_get_roundtrip", scenarioRoundtrip},
	{"list_ordered_by_name", scenarioListOrder},
	{"rollback_leaves_no_row", scenarioRollback},
	{"duplicate_name_refused", scenarioDuplicate},
	{"invalid_metadata_refused", scenarioInvalidMetadata},
	{"missing_org_not_found", scenarioNotFound},
	{"tenant_chain_roundtrip", scenarioTenantChain},
	{"hierarchy_crud_roundtrip", scenarioHierarchyCRUD},
	{"environment_cap_refused", scenarioEnvironmentCap},
	{"order_after_deletion", scenarioOrderAfterDeletion},
	{"non_empty_parent_delete_refused", scenarioDeleteRefusesChildren},
	{"concurrent_writes_all_succeed", scenarioConcurrent},
}

func runCorpus(t *testing.T, db *store.DB) {
	for _, s := range corpus {
		t.Run(s.name, func(t *testing.T) { s.fn(t, db) })
	}
}

func TestConformanceSQLite(t *testing.T) {
	cfg := store.Config{Engine: store.EngineSQLite, Path: filepath.Join(t.TempDir(), "conformance.db")}
	if err := migrate.Run(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	seedAdmin(t, db)
	runCorpus(t, db)
}

// TestSQLiteActiveDomainEnforced proves the CHECK constraint refuses
// non-boolean integers at the engine, sqlite lacking a boolean type. (The
// read-side validation in store is defense-in-depth for databases that
// predate the constraint and cannot be reached through it.)
func TestSQLiteActiveDomainEnforced(t *testing.T) {
	cfg := store.Config{Engine: store.EngineSQLite, Path: filepath.Join(t.TempDir(), "check.db")}
	if err := migrate.Run(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	_, err = db.SQLiteWrite().ExecContext(t.Context(),
		`INSERT INTO orgs (id, name, active, metadata, created_at) VALUES ('org_bad', 'bad', 2, '{}', '2026-01-01T00:00:00Z')`)
	if err == nil {
		t.Fatal("active=2 must be refused by the CHECK constraint")
	}
}

func TestConformancePostgres(t *testing.T) {
	dsn := os.Getenv("WENV_TEST_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI run without WENV_TEST_POSTGRES_DSN: the postgres conformance leg must not silently skip in CI")
		}
		t.Skip("WENV_TEST_POSTGRES_DSN not set")
	}
	cfg := store.Config{Engine: store.EnginePostgres, DSN: dsn}
	resetPostgres(t, cfg)
	if err := migrate.Run(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	seedAdmin(t, db)
	runCorpus(t, db)
}

// resetPostgres drops only the tables this harness owns, so a dedicated test
// database is reusable across runs.
func resetPostgres(t *testing.T, cfg store.Config) {
	t.Helper()
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Children before parents: tier3_keys references master_keys, and the
	// tenant chain is grants -> environments -> projects -> orgs.
	for _, table := range []string{
		// Factor tables (#54, migrations 00006-00008) reference accounts/sessions,
		// so they drop first — a stale one fails the next re-migration's CREATE.
		"webauthn_ceremonies", "webauthn_credentials",
		"oidc_transactions", "external_identities",
		"totp_credentials", "totp_challenges", "recovery_codes", "reauth_windows",
		"credential_authorities", "password_credentials", "sessions",
		// oidc_providers is a PARENT of sessions (sessions.provider_id
		// REFERENCES it ON DELETE CASCADE), so it drops AFTER sessions —
		// postgres refuses DROP while a dependent table exists (SQLSTATE 2BP01).
		"oidc_providers", "accounts",
		"auth_instance_state",
		"grants", "folders", "environments", "projects", "principals",
		"tier3_keys", "master_keys", "key_generations",
		"audit_tenant_events", "audit_instance_events",
		"orgs", "goose_db_version",
	} {
		if _, err := db.PG().Exec(t.Context(), "DROP TABLE IF EXISTS "+table); err != nil {
			t.Fatal(err)
		}
	}
	for _, object := range []string{
		"DROP FUNCTION IF EXISTS assign_audit_tenant_commit_seq()",
		"DROP FUNCTION IF EXISTS assign_audit_instance_commit_seq()",
		"DROP SEQUENCE IF EXISTS audit_tenant_commit_seq",
		"DROP SEQUENCE IF EXISTS audit_instance_commit_seq",
	} {
		if _, err := db.PG().Exec(t.Context(), object); err != nil {
			t.Fatal(err)
		}
	}
}

// --- scenarios (driven through the service layer, so tx and store are both
// under test) ---

func scenarioRoundtrip(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	meta := json.RawMessage(`{"tier":"gold","limits":{"projects":3}}`)
	created, err := orgs.Create(t.Context(), service.LocalPrincipal(admin), "roundtrip", true, meta)
	if err != nil {
		t.Fatal(err)
	}
	got, err := orgs.Get(t.Context(), service.LocalPrincipal(admin), domain.OrgID(created.ID))
	if err != nil {
		t.Fatal(err)
	}
	if !got.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("created_at did not round-trip: stored %v, got %v", created.CreatedAt, got.CreatedAt)
	}
	if got.CreatedAt.Location() != time.UTC {
		t.Errorf("created_at not UTC: %v", got.CreatedAt.Location())
	}
	if !got.Active {
		t.Error("active=true did not round-trip")
	}
	inactive, err := orgs.Create(t.Context(), service.LocalPrincipal(admin), "roundtrip-inactive", false, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	gotInactive, err := orgs.Get(t.Context(), service.LocalPrincipal(admin), domain.OrgID(inactive.ID))
	if err != nil {
		t.Fatal(err)
	}
	if gotInactive.Active {
		t.Error("active=false did not round-trip")
	}
	var m1, m2 any
	if err := json.Unmarshal(created.Metadata, &m1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got.Metadata, &m2); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(m1) != fmt.Sprint(m2) {
		t.Errorf("metadata did not round-trip: %s vs %s", created.Metadata, got.Metadata)
	}
}

func scenarioListOrder(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	for _, name := range []string{"zebra", "alpha", "mango"} {
		if _, err := orgs.Create(t.Context(), service.LocalPrincipal(admin), name, false, json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	list, err := orgs.List(t.Context(), service.LocalPrincipal(admin))
	if err != nil {
		t.Fatal(err)
	}
	var prev string
	for _, o := range list {
		if prev > o.Name {
			t.Fatalf("list not ordered by name: %q before %q", prev, o.Name)
		}
		prev = o.Name
	}
}

func scenarioRollback(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	before, err := orgs.Count(t.Context(), service.LocalPrincipal(admin))
	if err != nil {
		t.Fatal(err)
	}
	sentinel := fmt.Errorf("sentinel")
	err = tx.Write(t.Context(), db, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: admin}, authz.OpOrgCreate, domain.Scope{})
		if err != nil {
			return err
		}
		if err := r.Orgs().Create(ctx, p, store.Org{
			ID: "org_rollback", Name: "rollback-victim",
			Metadata: json.RawMessage(`{}`), CreatedAt: time.Now(),
		}); err != nil {
			return err
		}
		return sentinel
	})
	if err == nil {
		t.Fatal("closure error must surface")
	}
	after, err := orgs.Count(t.Context(), service.LocalPrincipal(admin))
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("rollback leaked a row: count %d -> %d", before, after)
	}
}

func scenarioDuplicate(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	if _, err := orgs.Create(t.Context(), service.LocalPrincipal(admin), "dupe", false, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := orgs.Create(t.Context(), service.LocalPrincipal(admin), "dupe", false, json.RawMessage(`{}`)); err == nil {
		t.Fatal("duplicate org name must be refused by the unique constraint")
	}
}

func scenarioInvalidMetadata(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	if _, err := orgs.Create(t.Context(), service.LocalPrincipal(admin), "badjson", false, json.RawMessage(`{not json`)); err == nil {
		t.Fatal("invalid JSON metadata must be refused at the boundary")
	}
}

func scenarioNotFound(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	_, err := orgs.Get(t.Context(), service.LocalPrincipal(admin), "org_does_not_exist")
	if err != store.ErrNotFound {
		t.Fatalf("want store.ErrNotFound, got %v", err)
	}
}

// scenarioTenantChain drives the tenant-scoped demonstration aggregates
// end-to-end — real grants, real proofs — and asserts the canonical
// cross-engine semantics hold for the new tables too: UTC microsecond
// timestamps round-trip identically, and the written chain columns are the
// proof's resolved chain.
func scenarioTenantChain(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	projects := &service.Projects{DB: db}
	envs := &service.Environments{DB: db}

	org, err := orgs.Create(t.Context(), service.LocalPrincipal(admin), "tenant-chain", true, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	const tenant = domain.PrincipalID("usr_conformance_tenant")
	seed(t, db, []string{
		`INSERT INTO principals (id, kind, created_at) VALUES ('usr_conformance_tenant', 'human', '2026-01-01T00:00:00Z')`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
		 VALUES ('grt_ct_mp', 'usr_conformance_tenant', 'manage-projects', '` + org.ID + `', NULL, NULL, '2026-01-01T00:00:00Z')`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
		 VALUES ('grt_ct_def', 'usr_conformance_tenant', 'definitions-edit', '` + org.ID + `', NULL, NULL, '2026-01-01T00:00:00Z')`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
		 VALUES ('grt_ct_read', 'usr_conformance_tenant', 'read', '` + org.ID + `', NULL, NULL, '2026-01-01T00:00:00Z')`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
		 VALUES ('grt_ct_edit', 'usr_conformance_tenant', 'edit', '` + org.ID + `', NULL, NULL, '2026-01-01T00:00:00Z')`,
	})

	proj, err := projects.Create(t.Context(), service.LocalPrincipal(tenant), domain.OrgID(org.ID), "conformance-project")
	if err != nil {
		t.Fatal(err)
	}
	envScope := domain.Scope{Org: domain.OrgID(org.ID), Project: domain.ProjectID(proj.ID)}
	created, err := envs.Create(t.Context(), service.LocalPrincipal(tenant), envScope, "dev")
	if err != nil {
		t.Fatal(err)
	}
	fullScope := domain.Scope{Org: domain.OrgID(org.ID), Project: domain.ProjectID(proj.ID), Env: domain.EnvID(created.ID)}
	got, err := envs.Get(t.Context(), service.LocalPrincipal(tenant), fullScope)
	if err != nil {
		t.Fatal(err)
	}
	if !got.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("environment created_at did not round-trip: stored %v, got %v", created.CreatedAt, got.CreatedAt)
	}
	if got.CreatedAt.Location() != time.UTC {
		t.Errorf("environment created_at not UTC: %v", got.CreatedAt.Location())
	}
	if got.OrgID != org.ID || got.ProjectID != proj.ID {
		t.Errorf("chain columns did not come from the proof: %+v", got)
	}
	if err := envs.UpdateNote(t.Context(), service.LocalPrincipal(tenant), fullScope, "noted"); err != nil {
		t.Fatal(err)
	}
	got, err = envs.Get(t.Context(), service.LocalPrincipal(tenant), fullScope)
	if err != nil {
		t.Fatal(err)
	}
	if got.Note != "noted" {
		t.Errorf("note update did not round-trip: %q", got.Note)
	}
}

// scenarioConcurrent exercises the tx retry machinery: BEGIN IMMEDIATE
// contention on sqlite, serializable commits on postgres. All writers must
// succeed within the bounded-retry budget.
func scenarioConcurrent(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	before, err := orgs.Count(t.Context(), service.LocalPrincipal(admin))
	if err != nil {
		t.Fatal(err)
	}
	const writers = 8
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := orgs.Create(context.Background(), service.LocalPrincipal(admin), fmt.Sprintf("concurrent-%d", i), true, json.RawMessage(`{}`))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent create failed: %v", err)
		}
	}
	after, err := orgs.Count(t.Context(), service.LocalPrincipal(admin))
	if err != nil {
		t.Fatal(err)
	}
	if after != before+writers {
		t.Fatalf("count %d -> %d, want +%d", before, after, writers)
	}
}

// tenantFixture seeds an org, a project and the grants a hierarchy scenario
// needs, and returns the addressed scopes. Grants are org-scoped so downward
// inheritance carries them to every project and environment beneath, which is
// the lattice the permission ADR fixes.
func tenantFixture(t *testing.T, db *store.DB, label string) (domain.PrincipalID, domain.Scope) {
	t.Helper()
	orgs := &service.Orgs{DB: db}
	projects := &service.Projects{DB: db}
	org, err := orgs.Create(t.Context(), service.LocalPrincipal(admin), label, true, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	principal := domain.PrincipalID("usr_" + label)
	stmts := []string{
		`INSERT INTO principals (id, kind, created_at) VALUES ('` + string(principal) + `', 'human', '2026-01-01T00:00:00Z')`,
	}
	for i, capability := range []string{"manage-projects", "definitions-edit", "read", "edit"} {
		stmts = append(stmts, fmt.Sprintf(
			`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
			 VALUES ('grt_%s_%d', '%s', '%s', '%s', NULL, NULL, '2026-01-01T00:00:00Z')`,
			label, i, principal, capability, org.ID))
	}
	seed(t, db, stmts)
	proj, err := projects.Create(t.Context(), service.LocalPrincipal(principal), domain.OrgID(org.ID), label+"-project")
	if err != nil {
		t.Fatal(err)
	}
	return principal, domain.Scope{Org: domain.OrgID(org.ID), Project: domain.ProjectID(proj.ID)}
}

// scenarioHierarchyCRUD is the acceptance demo as a cross-engine scenario:
// create → list → rename at every level, plus reorder and delete, all through
// the service layer so tx, authorize() and both engines' SQL are under test.
func scenarioHierarchyCRUD(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	projects := &service.Projects{DB: db}
	envs := &service.Environments{DB: db}
	folders := &service.Folders{DB: db}
	who, scope := tenantFixture(t, db, "hierarchy")
	actor := service.LocalPrincipal(who)

	// Project: list, rename, read back.
	list, err := projects.List(t.Context(), actor, scope.Org)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != string(scope.Project) {
		t.Fatalf("project list = %+v, want exactly the created project", list)
	}
	renamedProject, err := projects.Rename(t.Context(), actor, scope, "hierarchy-renamed")
	if err != nil {
		t.Fatal(err)
	}
	if renamedProject.Name != "hierarchy-renamed" {
		t.Fatalf("rename returned %q", renamedProject.Name)
	}
	gotProject, err := projects.Get(t.Context(), actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	if gotProject.Name != "hierarchy-renamed" {
		t.Fatalf("project rename did not persist: %q", gotProject.Name)
	}

	// Environments: created in order, appended at the end.
	var created []service.Environment
	for _, name := range []string{"dev", "staging", "prod"} {
		env, err := envs.Create(t.Context(), actor, scope, name)
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, env)
	}
	ordered, err := envs.List(t.Context(), actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 3 {
		t.Fatalf("environment list = %d rows, want 3", len(ordered))
	}
	for i, env := range ordered {
		if env.Name != []string{"dev", "staging", "prod"}[i] {
			t.Fatalf("creation order not preserved: %+v", ordered)
		}
		if env.DisplayOrder != int64(i) {
			t.Fatalf("environment %q display_order = %d, want %d", env.Name, env.DisplayOrder, i)
		}
	}

	// Reorder: the whole set, reversed. Positions must be dense 0..n-1.
	reversed := []string{created[2].ID, created[1].ID, created[0].ID}
	after, err := envs.Reorder(t.Context(), actor, scope, reversed)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 3 || after[0].ID != created[2].ID {
		t.Fatalf("reorder returned %+v", after)
	}
	ordered, err = envs.List(t.Context(), actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	for i, env := range ordered {
		if env.ID != reversed[i] || env.DisplayOrder != int64(i) {
			t.Fatalf("reorder did not persist densely: %+v", ordered)
		}
	}

	// A reorder that does not name the whole set exactly once is refused, and
	// the stored order is untouched.
	for _, bad := range [][]string{
		{created[0].ID},
		{created[0].ID, created[0].ID, created[1].ID},
		{created[0].ID, created[1].ID, "env_from_nowhere"},
	} {
		if _, err := envs.Reorder(t.Context(), actor, scope, bad); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("reorder %v: err = %v, want ErrInvalid", bad, err)
		}
	}
	stillOrdered, err := envs.List(t.Context(), actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	for i, env := range stillOrdered {
		if env.ID != reversed[i] {
			t.Fatalf("a refused reorder changed the stored order: %+v", stillOrdered)
		}
	}

	// Environment rename, read back through the full chain.
	envScope := scope
	envScope.Env = domain.EnvID(created[0].ID)
	if _, err := envs.Rename(t.Context(), actor, envScope, "development"); err != nil {
		t.Fatal(err)
	}
	gotEnv, err := envs.Get(t.Context(), actor, envScope)
	if err != nil {
		t.Fatal(err)
	}
	if gotEnv.Name != "development" {
		t.Fatalf("environment rename did not persist: %q", gotEnv.Name)
	}

	// A duplicate name among live siblings is a conflict, on both engines.
	if _, err := envs.Create(t.Context(), actor, scope, "prod"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate environment name: err = %v, want ErrConflict", err)
	}

	// Folders: create, list, rename, delete.
	folder, err := folders.Create(t.Context(), actor, scope, "services/api")
	if err != nil {
		t.Fatal(err)
	}
	folderList, err := folders.List(t.Context(), actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(folderList) != 1 || folderList[0].Path != "services/api" {
		t.Fatalf("folder list = %+v", folderList)
	}
	if folderList[0].OrgID != string(scope.Org) || folderList[0].ProjectID != string(scope.Project) {
		t.Fatalf("folder chain columns did not come from the proof: %+v", folderList[0])
	}
	if _, err := folders.Rename(t.Context(), actor, scope, folder.ID, "services/gateway"); err != nil {
		t.Fatal(err)
	}
	gotFolder, err := folders.Get(t.Context(), actor, scope, folder.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotFolder.Path != "services/gateway" {
		t.Fatalf("folder rename did not persist: %q", gotFolder.Path)
	}
	if _, err := folders.Create(t.Context(), actor, scope, "services/gateway"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate folder path: err = %v, want ErrConflict", err)
	}
	if err := folders.Delete(t.Context(), actor, scope, folder.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := folders.Get(t.Context(), actor, scope, folder.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted folder: err = %v, want ErrNotFound", err)
	}

	// Deleting the environments then the project then the org walks the whole
	// hierarchy back down, which also proves no delete cascades silently.
	for _, env := range stillOrdered {
		s := scope
		s.Env = domain.EnvID(env.ID)
		if err := envs.Delete(t.Context(), actor, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := projects.Delete(t.Context(), actor, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := projects.Get(t.Context(), actor, scope); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted project: err = %v, want ErrNotFound", err)
	}
	// The org still holds this principal's grants, so its delete is refused —
	// deletes never cascade. Renaming it still works.
	if _, err := orgs.Rename(t.Context(), service.LocalPrincipal(admin), scope.Org, "hierarchy-renamed-org"); err != nil {
		t.Fatal(err)
	}
	got, err := orgs.Get(t.Context(), service.LocalPrincipal(admin), scope.Org)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "hierarchy-renamed-org" {
		t.Fatalf("org rename did not persist: %q", got.Name)
	}
}

// scenarioEnvironmentCap proves the ops spec's environment-count cap is a real
// refusal on both engines, and that it names the bound rather than failing
// somewhere downstream.
func scenarioEnvironmentCap(t *testing.T, db *store.DB) {
	envs := &service.Environments{DB: db}
	who, scope := tenantFixture(t, db, "envcap")
	actor := service.LocalPrincipal(who)
	for i := range service.MaxEnvironmentsPerProject {
		if _, err := envs.Create(t.Context(), actor, scope, fmt.Sprintf("env-%02d", i)); err != nil {
			t.Fatalf("creating environment %d of the cap: %v", i, err)
		}
	}
	_, err := envs.Create(t.Context(), actor, scope, "one-too-many")
	if !errors.Is(err, domain.ErrLimitExceeded) {
		t.Fatalf("environment %d: err = %v, want ErrLimitExceeded", service.MaxEnvironmentsPerProject+1, err)
	}
	list, err := envs.List(t.Context(), actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != service.MaxEnvironmentsPerProject {
		t.Fatalf("the refused create left %d environments, want %d", len(list), service.MaxEnvironmentsPerProject)
	}
}

// scenarioDeleteRefusesChildren pins the no-cascade rule at the engine: a
// project holding an environment or a folder cannot be deleted, and the refusal
// is a conflict rather than a driver error escaping as a fault.
func scenarioDeleteRefusesChildren(t *testing.T, db *store.DB) {
	projects := &service.Projects{DB: db}
	envs := &service.Environments{DB: db}
	folders := &service.Folders{DB: db}
	who, scope := tenantFixture(t, db, "nocascade")
	actor := service.LocalPrincipal(who)

	env, err := envs.Create(t.Context(), actor, scope, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if err := projects.Delete(t.Context(), actor, scope); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("deleting a project with an environment: err = %v, want ErrConflict", err)
	}
	envScope := scope
	envScope.Env = domain.EnvID(env.ID)
	if err := envs.Delete(t.Context(), actor, envScope); err != nil {
		t.Fatal(err)
	}

	folder, err := folders.Create(t.Context(), actor, scope, "shared")
	if err != nil {
		t.Fatal(err)
	}
	if err := projects.Delete(t.Context(), actor, scope); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("deleting a project with a folder: err = %v, want ErrConflict", err)
	}
	if err := folders.Delete(t.Context(), actor, scope, folder.ID); err != nil {
		t.Fatal(err)
	}
	if err := projects.Delete(t.Context(), actor, scope); err != nil {
		t.Fatalf("deleting the now-empty project: %v", err)
	}
}

// scenarioOrderAfterDeletion is the regression for the append position. Deleting
// an environment leaves its display order behind as a gap on purpose, so the row
// COUNT and the next free position diverge from that moment on: [0,1,2] minus
// the middle is a count of 2 and a next position of 3. A create that used the
// count would hand the new row position 2 — which the last row already holds —
// and the list order would silently depend on the name tiebreak.
func scenarioOrderAfterDeletion(t *testing.T, db *store.DB) {
	envs := &service.Environments{DB: db}
	who, scope := tenantFixture(t, db, "ordergap")
	actor := service.LocalPrincipal(who)

	var created []service.Environment
	for _, name := range []string{"first", "second", "third"} {
		env, err := envs.Create(t.Context(), actor, scope, name)
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, env)
	}
	middle := scope
	middle.Env = domain.EnvID(created[1].ID)
	if err := envs.Delete(t.Context(), actor, middle); err != nil {
		t.Fatal(err)
	}
	appended, err := envs.Create(t.Context(), actor, scope, "fourth")
	if err != nil {
		t.Fatal(err)
	}
	if appended.DisplayOrder != 3 {
		t.Fatalf("appended after a middle deletion at display_order %d, want 3 (max+1, not the row count)", appended.DisplayOrder)
	}
	list, err := envs.List(t.Context(), actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int64]string{}
	for _, e := range list {
		if other, dup := seen[e.DisplayOrder]; dup {
			t.Fatalf("display_order %d held by both %q and %q", e.DisplayOrder, other, e.Name)
		}
		seen[e.DisplayOrder] = e.Name
	}
	if last := list[len(list)-1]; last.Name != "fourth" {
		t.Fatalf("the appended environment is not last: %+v", list)
	}
	// A reorder over the surviving set renumbers it densely from zero, which is
	// how a gap is closed — deliberately, by an operator, never as a side effect.
	ids := []string{list[2].ID, list[0].ID, list[1].ID}
	after, err := envs.Reorder(t.Context(), actor, scope, ids)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range after {
		if e.DisplayOrder != int64(i) {
			t.Fatalf("reorder left a gap: %+v", after)
		}
	}
	// An empty project's whole set is the empty list: a legal no-op, and the
	// contract's minItems agrees (0).
	_, emptyScope := tenantFixture(t, db, "emptyorder")
	if _, err := envs.Reorder(t.Context(), service.LocalPrincipal(domain.PrincipalID("usr_emptyorder")), emptyScope, nil); err != nil {
		t.Fatalf("reordering a project with no environments: %v", err)
	}
}
