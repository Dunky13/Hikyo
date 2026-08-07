// Package isolation is the cross-tenant probe harness and the home of the
// tenant-isolation ADR's 13 CI invariants (#44). Probes run at the service
// layer — the chokepoint under test — on a fixed fixture set: two
// organizations, a human principal in org B probing org A's objects
// (cross-org axis), and a machine principal confined to one project probing
// a sibling project (cross-project axis; org-level probes alone never
// exercise it). Every store call in this harness goes through authorize():
// there is no test-only mint hook.
//
// The suite runs on sqlite always and on postgres via
// WENV_TEST_POSTGRES_DSN, failing loudly in CI when the DSN is unset — the
// postgres leg cannot go vacuously green.
package isolation

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/service"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/migrate"
)

// Fixture principals.
const (
	alice  = domain.PrincipalID("usr_alice")  // human, org A: read/edit/definitions-edit/manage-projects
	bob    = domain.PrincipalID("usr_bob")    // human, org B: same shape — the cross-org prober
	root   = domain.PrincipalID("usr_root")   // human, instance-config at instance scope
	nobody = domain.PrincipalID("usr_nobody") // human, no grants at all
	mchA1  = domain.PrincipalID("mch_a1")     // machine, confined to (org A, project A1) — the cross-project prober
	reader = domain.PrincipalID("usr_reader") // human, org A, exactly `read` — the least-privilege prober
)

// Fixture chain.
const (
	orgA  = domain.OrgID("org_a")
	orgB  = domain.OrgID("org_b")
	prjA1 = domain.ProjectID("prj_a1")
	prjA2 = domain.ProjectID("prj_a2")
	prjB1 = domain.ProjectID("prj_b1")
	envA1 = domain.EnvID("env_a1")
	envA2 = domain.EnvID("env_a2")
	envB1 = domain.EnvID("env_b1")
)

const ts = "'2026-01-01T00:00:00Z'"

var fixtureSQL = []string{
	`INSERT INTO orgs (id, name, active, metadata, created_at) VALUES ('org_a', 'org-a', TRUE, '{}', ` + ts + `)`,
	`INSERT INTO orgs (id, name, active, metadata, created_at) VALUES ('org_b', 'org-b', TRUE, '{}', ` + ts + `)`,
	`INSERT INTO projects (id, org_id, name, created_at) VALUES ('prj_a1', 'org_a', 'a1', ` + ts + `)`,
	`INSERT INTO projects (id, org_id, name, created_at) VALUES ('prj_a2', 'org_a', 'a2', ` + ts + `)`,
	`INSERT INTO projects (id, org_id, name, created_at) VALUES ('prj_b1', 'org_b', 'b1', ` + ts + `)`,
	`INSERT INTO environments (id, org_id, project_id, name, note, created_at) VALUES ('env_a1', 'org_a', 'prj_a1', 'dev', '', ` + ts + `)`,
	`INSERT INTO environments (id, org_id, project_id, name, note, created_at) VALUES ('env_a2', 'org_a', 'prj_a2', 'dev', '', ` + ts + `)`,
	`INSERT INTO environments (id, org_id, project_id, name, note, created_at) VALUES ('env_b1', 'org_b', 'prj_b1', 'dev', '', ` + ts + `)`,
	`INSERT INTO principals (id, kind, created_at) VALUES ('usr_alice', 'human', ` + ts + `)`,
	`INSERT INTO principals (id, kind, created_at) VALUES ('usr_bob', 'human', ` + ts + `)`,
	`INSERT INTO principals (id, kind, created_at) VALUES ('usr_root', 'human', ` + ts + `)`,
	`INSERT INTO principals (id, kind, created_at) VALUES ('usr_nobody', 'human', ` + ts + `)`,
	`INSERT INTO principals (id, kind, created_at) VALUES ('mch_a1', 'machine', ` + ts + `)`,
	`INSERT INTO principals (id, kind, created_at) VALUES ('usr_reader', 'human', ` + ts + `)`,
	// alice: org-scope grants in org A.
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_al_read', 'usr_alice', 'read', 'org_a', NULL, NULL, ` + ts + `)`,
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_al_edit', 'usr_alice', 'edit', 'org_a', NULL, NULL, ` + ts + `)`,
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_al_def', 'usr_alice', 'definitions-edit', 'org_a', NULL, NULL, ` + ts + `)`,
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_al_mp', 'usr_alice', 'manage-projects', 'org_a', NULL, NULL, ` + ts + `)`,
	// bob: the same authority, in org B.
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_bo_read', 'usr_bob', 'read', 'org_b', NULL, NULL, ` + ts + `)`,
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_bo_edit', 'usr_bob', 'edit', 'org_b', NULL, NULL, ` + ts + `)`,
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_bo_def', 'usr_bob', 'definitions-edit', 'org_b', NULL, NULL, ` + ts + `)`,
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_bo_mp', 'usr_bob', 'manage-projects', 'org_b', NULL, NULL, ` + ts + `)`,
	// reader: exactly one capability in org A. Every operation whose formula
	// is not `read` must deny them — that is what stops a formula being
	// silently widened to a capability the fixtures happen to hold.
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_rd_read', 'usr_reader', 'read', 'org_a', NULL, NULL, ` + ts + `)`,
	// root: the instance operator.
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_ro_ic', 'usr_root', 'instance-config', NULL, NULL, NULL, ` + ts + `)`,
	// alice additionally holds audit-read in org A (#45): the tenant-trail
	// positive control. reader/bob/nobody deliberately do NOT hold it — the
	// audit denial probes ride on them.
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_al_ar', 'usr_alice', 'audit-read', 'org_a', NULL, NULL, ` + ts + `)`,
	// root additionally holds instance-scope audit-read (#45): the instance
	// trail is grant-evaluated, never route-implied.
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_ro_ar', 'usr_root', 'audit-read', NULL, NULL, NULL, ` + ts + `)`,
	// mch_a1: machine authority confined to project A1.
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_m1_read', 'mch_a1', 'read', 'org_a', 'prj_a1', NULL, ` + ts + `)`,
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_m1_edit', 'mch_a1', 'edit', 'org_a', 'prj_a1', NULL, ` + ts + `)`,
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_m1_def', 'mch_a1', 'definitions-edit', 'org_a', 'prj_a1', NULL, ` + ts + `)`,
}

func execRaw(t *testing.T, db *store.DB, stmt string) {
	t.Helper()
	var err error
	if db.Engine() == store.EnginePostgres {
		_, err = db.PG().Exec(t.Context(), stmt)
	} else {
		_, err = db.SQLiteWrite().ExecContext(t.Context(), stmt)
	}
	if err != nil {
		t.Fatalf("raw exec %q: %v", stmt, err)
	}
}

func execRawErr(t *testing.T, db *store.DB, stmt string) error {
	t.Helper()
	if db.Engine() == store.EnginePostgres {
		_, err := db.PG().Exec(t.Context(), stmt)
		return err
	}
	_, err := db.SQLiteWrite().ExecContext(t.Context(), stmt)
	return err
}

func queryInt(t *testing.T, db *store.DB, q string) int64 {
	t.Helper()
	var n int64
	var err error
	if db.Engine() == store.EnginePostgres {
		err = db.PG().QueryRow(t.Context(), q).Scan(&n)
	} else {
		err = db.SQLiteRead().QueryRowContext(t.Context(), q).Scan(&n)
	}
	if err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return n
}

var fixtureTables = []string{"orgs", "projects", "environments", "principals", "grants"}

// rowCounts is the row-diff half of the no-side-effect assertion.
func rowCounts(t *testing.T, db *store.DB) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, table := range fixtureTables {
		out[table] = queryInt(t, db, "SELECT COUNT(*) FROM "+table)
	}
	return out
}

func openSQLite(t *testing.T) *store.DB {
	t.Helper()
	cfg := store.Config{Engine: store.EngineSQLite, Path: filepath.Join(t.TempDir(), "isolation.db")}
	if err := migrate.Run(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func openPostgres(t *testing.T) *store.DB {
	t.Helper()
	dsn := os.Getenv("WENV_TEST_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI run without WENV_TEST_POSTGRES_DSN: the postgres isolation leg must not silently skip in CI")
		}
		t.Skip("WENV_TEST_POSTGRES_DSN not set")
	}
	// This harness derives its own database from the configured one:
	// `go test ./...` runs package binaries in parallel, and sharing one
	// database with the conformance harness (same tables, drop + migrate +
	// seed) is a race that flakes CI. Needs CREATE DATABASE rights on the
	// test server — true for the CI service user and any scratch container.
	dsn = derivedDatabase(t, dsn, "_isolation")
	cfg := store.Config{Engine: store.EnginePostgres, DSN: dsn}
	pre, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Children before parents; the keyring tables arrived with #43 and the
	// human-authentication tables with #47 (sessions and accounts reference
	// principals, so they drop first).
	for _, table := range []string{
		"credential_authorities", "password_credentials", "sessions", "accounts",
		"auth_instance_state",
		"grants", "environments", "projects", "principals",
		"tier3_keys", "master_keys", "key_generations",
		"audit_tenant_events", "audit_instance_events",
		"orgs", "goose_db_version",
	} {
		if _, err := pre.PG().Exec(t.Context(), "DROP TABLE IF EXISTS "+table); err != nil {
			pre.Close()
			t.Fatal(err)
		}
	}
	pre.Close()
	if err := migrate.Run(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// derivedDatabase creates (if needed) a sibling database named after the
// configured one plus suffix, and returns the DSN pointing at it.
func derivedDatabase(t *testing.T, dsn, suffix string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse postgres DSN: %v", err)
	}
	base := strings.TrimPrefix(u.Path, "/")
	if base == "" {
		t.Fatal("postgres DSN has no database name")
	}
	derived := base + suffix
	admin, err := store.Open(t.Context(), store.Config{Engine: store.EnginePostgres, DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.PG().Exec(t.Context(), `CREATE DATABASE `+pq(derived)); err != nil {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42P04" { // duplicate_database is fine
			t.Fatalf("create derived database %s: %v", derived, err)
		}
	}
	u.Path = "/" + derived
	return u.String()
}

// pq quotes an identifier defensively; derived names come from the DSN.
func pq(ident string) string { return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"` }

func seededDB(t *testing.T, open func(*testing.T) *store.DB) *store.DB {
	t.Helper()
	db := open(t)
	for _, stmt := range fixtureSQL {
		execRaw(t, db, stmt)
	}
	return db
}

// assertUniformNotFound is the shared uniformity helper (invariant 3): the
// probe outcome must be indistinguishable — same sentinel, same rendered
// message — from a genuinely missing object.
func assertUniformNotFound(t *testing.T, probe, missing error) {
	t.Helper()
	if !errors.Is(probe, domain.ErrNotFound) {
		t.Fatalf("probe outcome = %v, want the uniform nonexistent response", probe)
	}
	if !errors.Is(missing, domain.ErrNotFound) {
		t.Fatalf("genuinely-missing outcome = %v, want domain.ErrNotFound", missing)
	}
	if probe.Error() != missing.Error() {
		t.Fatalf("response shapes differ:\n  probe:   %q\n  missing: %q", probe.Error(), missing.Error())
	}
}

func services(db *store.DB) (*service.Orgs, *service.Projects, *service.Environments) {
	return &service.Orgs{DB: db}, &service.Projects{DB: db}, &service.Environments{DB: db}
}

// ctx shorthand for probes that need a context off the test.
func tctx(t *testing.T) context.Context { return t.Context() }
