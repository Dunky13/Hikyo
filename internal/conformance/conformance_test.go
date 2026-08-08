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

// admin is the corpus's fixture principal: seeded with an instance-scope
// instance-config grant, so it can drive the instance-scoped Org scaffolding
// operations. Tenant-scoped scenarios seed their own grants. There is no
// test-only mint hook — every store call in this suite goes through
// authorize() exactly as production does.
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
		"oidc_transactions", "external_identities", "oidc_providers",
		"totp_credentials", "totp_challenges", "recovery_codes", "reauth_windows",
		"credential_authorities", "password_credentials", "sessions", "accounts",
		"auth_instance_state",
		"grants", "environments", "projects", "principals",
		"tier3_keys", "master_keys", "key_generations",
		"audit_tenant_events", "audit_instance_events",
		"orgs", "goose_db_version",
	} {
		if _, err := db.PG().Exec(t.Context(), "DROP TABLE IF EXISTS "+table); err != nil {
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
	got, err := orgs.Get(t.Context(), service.LocalPrincipal(admin), created.ID)
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
	gotInactive, err := orgs.Get(t.Context(), service.LocalPrincipal(admin), inactive.ID)
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
