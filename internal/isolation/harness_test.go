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
// HIKYO_TEST_POSTGRES_DSN, failing loudly in CI when the DSN is unset — the
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

	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/migrate"
)

// Fixture principals.
const (
	alice  = domain.PrincipalID("usr_alice")  // human, org A: read/edit/definitions-edit/manage-projects
	bob    = domain.PrincipalID("usr_bob")    // human, org B: same shape — the cross-org prober
	root   = domain.PrincipalID("usr_root")   // human, instance-config + read at instance scope
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
	// Key-catalogue fixtures (#49). One key per fixture project, so a key probe
	// addresses a row that genuinely EXISTS and fails only at the boundary —
	// the difference between proving isolation and proving a typo.
	keyA1 = "key_a1"
	keyA2 = "key_a2"
)

// Microsecond width, because the authn resolver's decodeTime parses grant and
// origin timestamps with a fixed-width layout, and RFC3339Nano (which the
// tenant tables use) accepts it too — one literal, both readers.
const ts = "'2026-01-01T00:00:00.000000Z'"

var fixtureSQL = []string{
	`INSERT INTO orgs (id, name, active, metadata, created_at) VALUES ('org_a', 'org-a', TRUE, '{}', ` + ts + `)`,
	`INSERT INTO orgs (id, name, active, metadata, created_at) VALUES ('org_b', 'org-b', TRUE, '{}', ` + ts + `)`,
	`INSERT INTO projects (id, org_id, name, created_at) VALUES ('prj_a1', 'org_a', 'a1', ` + ts + `)`,
	`INSERT INTO projects (id, org_id, name, created_at) VALUES ('prj_a2', 'org_a', 'a2', ` + ts + `)`,
	`INSERT INTO projects (id, org_id, name, created_at) VALUES ('prj_b1', 'org_b', 'b1', ` + ts + `)`,
	// The key-catalogue revision row is born with a project (#49). These
	// projects are seeded with raw SQL rather than through projects.Create, so
	// the row must be seeded too: without it EVERY catalogue mutation here
	// fails on the revision bump, and a probe that passes because the fixture
	// is broken proves nothing about the boundary it names.
	`INSERT INTO project_schema_revisions (org_id, project_id, revision) VALUES ('org_a', 'prj_a1', 0)`,
	`INSERT INTO project_schema_revisions (org_id, project_id, revision) VALUES ('org_a', 'prj_a2', 0)`,
	`INSERT INTO project_schema_revisions (org_id, project_id, revision) VALUES ('org_b', 'prj_b1', 0)`,
	`INSERT INTO environments (id, org_id, project_id, name, note, created_at, display_order) VALUES ('env_a1', 'org_a', 'prj_a1', 'dev', '', ` + ts + `, 0)`,
	`INSERT INTO environments (id, org_id, project_id, name, note, created_at, display_order) VALUES ('env_a2', 'org_a', 'prj_a2', 'dev', '', ` + ts + `, 0)`,
	`INSERT INTO environments (id, org_id, project_id, name, note, created_at, display_order) VALUES ('env_b1', 'org_b', 'prj_b1', 'dev', '', ` + ts + `, 0)`,
	// env_prod is the reauthentication ceremonies' environment. It has to be a
	// REAL row from #55 on: the effective-window seam reads the environment's
	// own protected flag and window, and an environment that does not resolve
	// fails closed at 0 rather than inheriting the instance default — a window
	// opener addressing a nonexistent environment must not be handed the most
	// permissive answer in the system.
	`INSERT INTO environments (id, org_id, project_id, name, note, created_at, display_order) VALUES ('env_prod', 'org_a', 'prj_a1', 'prod', '', ` + ts + `, 1)`,
	// Folders (#48): one per fixture project, so a folder probe addresses a row
	// that genuinely exists and fails only at the boundary.
	`INSERT INTO folders (id, org_id, project_id, path, created_at) VALUES ('fld_a1', 'org_a', 'prj_a1', 'shared', ` + ts + `)`,
	`INSERT INTO folders (id, org_id, project_id, path, created_at) VALUES ('fld_a2', 'org_a', 'prj_a2', 'shared', ` + ts + `)`,
	`INSERT INTO folders (id, org_id, project_id, path, created_at) VALUES ('fld_b1', 'org_b', 'prj_b1', 'shared', ` + ts + `)`,
	// Keys (#49): one per fixture project, config-classified so the reveal gate
	// is not what refuses a cross-tenant probe — the tenant boundary must be,
	// or the probe would prove the wrong thing.
	`INSERT INTO keys (id, org_id, project_id, name, folder_path, classification, description, deprecated, deprecation_note, declaration, required_mode, forbidden_mode, group_id, created_at) VALUES ('key_a1', 'org_a', 'prj_a1', 'SHARED_KEY', '', 'config', '', FALSE, '', '{"rule":{"type":"string"}}', 'none', 'none', NULL, ` + ts + `)`,
	`INSERT INTO keys (id, org_id, project_id, name, folder_path, classification, description, deprecated, deprecation_note, declaration, required_mode, forbidden_mode, group_id, created_at) VALUES ('key_a2', 'org_a', 'prj_a2', 'SHARED_KEY', '', 'config', '', FALSE, '', '{"rule":{"type":"string"}}', 'none', 'none', NULL, ` + ts + `)`,
	`INSERT INTO principals (id, kind, created_at) VALUES ('usr_alice', 'human', ` + ts + `)`,
	`INSERT INTO principals (id, kind, created_at) VALUES ('usr_bob', 'human', ` + ts + `)`,
	`INSERT INTO principals (id, kind, created_at) VALUES ('usr_root', 'human', ` + ts + `)`,
	`INSERT INTO principals (id, kind, created_at) VALUES ('usr_nobody', 'human', ` + ts + `)`,
	// The fixture names its own machine class: migration 00010 deliberately
	// backfills nothing (an unclassified machine fails closed), so a fixture
	// that wants an automation credential has to say so.
	`INSERT INTO principals (id, kind, class, created_at) VALUES ('mch_a1', 'machine', 'automation', ` + ts + `)`,
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
	// root also holds instance-scope `read`, exactly as the bootstrap admin
	// template seeds it (#47): org.get is tenant-class at org depth (#48), so
	// instance-config alone no longer reads an org row.
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_ro_read', 'usr_root', 'read', NULL, NULL, NULL, ` + ts + `)`,
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

	// The permission-model fixtures (#55). Two member managers at different
	// depths, because the grant-authority rule turns on WHERE the grantor
	// holds `manage-members`, not on which depth they address: orgAdmin may
	// hand out capabilities they do not hold, projectAdmin may not.
	`INSERT INTO principals (id, kind, created_at) VALUES ('usr_orgadmin', 'human', ` + ts + `)`,
	`INSERT INTO principals (id, kind, created_at) VALUES ('usr_prjadmin', 'human', ` + ts + `)`,
	`INSERT INTO principals (id, kind, created_at) VALUES ('usr_grantee', 'human', ` + ts + `)`,
	`INSERT INTO principals (id, kind, class, created_at) VALUES ('mch_workload', 'machine', 'workload', ` + ts + `)`,
	`INSERT INTO principals (id, kind, class, created_at) VALUES ('mch_unclassed', 'machine', NULL, ` + ts + `)`,
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_oa_mm', 'usr_orgadmin', 'manage-members', 'org_a', NULL, NULL, ` + ts + `)`,
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_oa_ps', 'usr_orgadmin', 'project-settings', 'org_a', NULL, NULL, ` + ts + `)`,
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_oa_read', 'usr_orgadmin', 'read', 'org_a', NULL, NULL, ` + ts + `)`,
	// projectAdmin manages members inside prj_a1 and holds exactly `read`
	// besides — so `read` is the one capability they may hand out and every
	// other one is the project-scope bound's refusal.
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_pa_mm', 'usr_prjadmin', 'manage-members', 'org_a', 'prj_a1', NULL, ` + ts + `)`,
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_pa_read', 'usr_prjadmin', 'read', 'org_a', 'prj_a1', NULL, ` + ts + `)`,
	// root manages members at instance scope: the operator template's own
	// `manage-members`, and the lockout invariant's instance-scope subject.
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_ro_mm', 'usr_root', 'manage-members', NULL, NULL, NULL, ` + ts + `)`,
	`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_wl_read', 'mch_workload', 'read', 'org_a', 'prj_a1', NULL, ` + ts + `)`,
}

// Permission-model fixture principals (#55).
const (
	orgAdmin = domain.PrincipalID("usr_orgadmin")
	prjAdmin = domain.PrincipalID("usr_prjadmin")
	grantee  = domain.PrincipalID("usr_grantee")
	mchWork  = domain.PrincipalID("mch_workload")
	mchNoCls = domain.PrincipalID("mch_unclassed")
	envProd  = domain.EnvID("env_prod")
)

var orgAScope = domain.Scope{Org: orgA}

// seedOrigins attaches the manual origin every fixture grant needs: a grant
// row with no origin is the state the ADR forbids, and the membership surface
// (an INNER JOIN onto origins) would simply not see it.
func seedOrigins(t *testing.T, db *store.DB) {
	t.Helper()
	execRaw(t, db, `INSERT INTO grant_origins (id, grant_id, kind, subject, created_at) `+
		`SELECT 'gor_' || g.id, g.id, 'manual', g.principal_id, g.created_at FROM grants AS g `+
		`WHERE NOT EXISTS (SELECT 1 FROM grant_origins AS o WHERE o.grant_id = g.id)`)
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

// queryStrings concatenates a single-column text query's rows. It exists for the
// mutation probes' content snapshot: comparing rendered content is what catches
// an unauthorized write that commits and then answers ErrNotFound, which a row
// count cannot see. `||` and ORDER BY behave identically on both engines.
func queryStrings(t *testing.T, db *store.DB, q string) string {
	t.Helper()
	var out strings.Builder
	scan := func(next func() bool, get func(*string) error) {
		for next() {
			var v string
			if err := get(&v); err != nil {
				t.Fatalf("query %q: %v", q, err)
			}
			out.WriteString(v)
		}
	}
	if db.Engine() == store.EnginePostgres {
		rows, err := db.PG().Query(t.Context(), q)
		if err != nil {
			t.Fatalf("query %q: %v", q, err)
		}
		defer rows.Close()
		scan(rows.Next, func(v *string) error { return rows.Scan(v) })
		if err := rows.Err(); err != nil {
			t.Fatalf("query %q: %v", q, err)
		}
		return out.String()
	}
	rows, err := db.SQLiteRead().QueryContext(t.Context(), q)
	if err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	defer rows.Close()
	scan(rows.Next, func(v *string) error { return rows.Scan(v) })
	if err := rows.Err(); err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return out.String()
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

var fixtureTables = []string{
	"orgs", "projects", "environments", "folders", "principals", "grants", "grant_origins",
	// The key catalogue (#49). project_schema_revisions is here too: an
	// unauthorized mutation that rolled its write back but left the revision
	// advanced would be a pinned input moving for nothing.
	"keys", "key_groups", "key_presence_environments", "project_schema_revisions",
}

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
	dsn := os.Getenv("HIKYO_TEST_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI run without HIKYO_TEST_POSTGRES_DSN: the postgres isolation leg must not silently skip in CI")
		}
		t.Skip("HIKYO_TEST_POSTGRES_DSN not set")
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
		// Factor tables (#54, migrations 00006-00008) reference accounts/sessions,
		// so they drop first — a stale one fails the next re-migration's CREATE.
		"webauthn_ceremonies", "webauthn_credentials",
		"saml_transactions", "saml_replay", "saml_sp_keys",
		"oidc_transactions", "external_identities",
		"totp_credentials", "totp_challenges", "recovery_codes", "reauth_windows",
		"credential_authorities", "password_credentials", "sessions",
		// oidc_providers is a PARENT of sessions (sessions.provider_id
		// REFERENCES it ON DELETE CASCADE), so it drops AFTER sessions —
		// postgres refuses DROP while a dependent table exists (SQLSTATE 2BP01).
		"saml_providers", "oidc_providers", "accounts",
		"auth_instance_state",
		// The key catalogue (#49) sits between projects and environments:
		// presence rows reference both keys and environments, keys reference
		// key_groups, and the schema-revision row references projects — so all
		// four drop before the hierarchy they hang from.
		"key_presence_environments", "keys", "key_groups", "project_schema_revisions",
		// grant_origins holds grants under a RESTRICT foreign key (#55), so it
		// goes first of the pair.
		"grant_origins", "grants", "folders", "environments", "projects", "principals",
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
	seedOrigins(t, db)
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

// folderSvc is the fourth hierarchy service; it is separate from services()
// only so the existing three-value call sites stay untouched.
func folderSvc(db *store.DB) *service.Folders { return &service.Folders{DB: db} }

func keySvc(db *store.DB) *service.Keys           { return &service.Keys{DB: db} }
func keyGroupSvc(db *store.DB) *service.KeyGroups { return &service.KeyGroups{DB: db} }

// Fixture scopes, so a probe reads as "who, addressing what" rather than as a
// struct literal repeated forty times.
func scopeProject(org domain.OrgID, project domain.ProjectID) domain.Scope {
	return domain.Scope{Org: org, Project: project}
}

func scopeEnv(org domain.OrgID, project domain.ProjectID, env domain.EnvID) domain.Scope {
	return domain.Scope{Org: org, Project: project, Env: env}
}

// ctx shorthand for probes that need a context off the test.
func tctx(t *testing.T) context.Context { return t.Context() }
