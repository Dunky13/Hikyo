package isolation

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/authn"
	"github.com/Dunky13/wenv/internal/store/pggen"
	"github.com/Dunky13/wenv/internal/store/sqlitegen"
	"github.com/Dunky13/wenv/internal/store/tx"
)

// Query-count instrumentation (acceptance criterion + invariant 3's timing
// half): authorize() issues exactly ONE query when the addressed chain is
// missing — at any level — because chain resolution is a single statement
// and the grant lookup is skipped on a miss. A per-level walk would show 1
// query for a missing org and 3 for a missing environment: a probe-visible
// oracle. Denials against existing objects issue exactly two (chain +
// grants), independent of why the denial happened.

type countingSqliteTx struct {
	tx *sql.Tx
	n  *int
}

func (c countingSqliteTx) ExecContext(ctx context.Context, q string, args ...interface{}) (sql.Result, error) {
	*c.n++
	return c.tx.ExecContext(ctx, q, args...)
}
func (c countingSqliteTx) PrepareContext(ctx context.Context, q string) (*sql.Stmt, error) {
	return c.tx.PrepareContext(ctx, q)
}
func (c countingSqliteTx) QueryContext(ctx context.Context, q string, args ...interface{}) (*sql.Rows, error) {
	*c.n++
	return c.tx.QueryContext(ctx, q, args...)
}
func (c countingSqliteTx) QueryRowContext(ctx context.Context, q string, args ...interface{}) *sql.Row {
	*c.n++
	return c.tx.QueryRowContext(ctx, q, args...)
}

type countingPGTx struct {
	tx pgx.Tx
	n  *int
}

func (c countingPGTx) Exec(ctx context.Context, q string, args ...interface{}) (pgconn.CommandTag, error) {
	*c.n++
	return c.tx.Exec(ctx, q, args...)
}
func (c countingPGTx) Query(ctx context.Context, q string, args ...interface{}) (pgx.Rows, error) {
	*c.n++
	return c.tx.Query(ctx, q, args...)
}
func (c countingPGTx) QueryRow(ctx context.Context, q string, args ...interface{}) pgx.Row {
	*c.n++
	return c.tx.QueryRow(ctx, q, args...)
}

// countedAuthorize runs one Authorize inside a fresh instrumented read
// transaction and returns (queries issued, outcome).
func countedAuthorize(t *testing.T, db *store.DB, principal domain.PrincipalID, scope domain.Scope) (int, error) {
	t.Helper()
	ctx := t.Context()
	count := 0
	tok := authz.NewTxToken()
	defer tok.Invalidate()

	var r *authn.Resolver
	if db.Engine() == store.EnginePostgres {
		pgtx, err := db.PG().BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = pgtx.Rollback(ctx) }()
		var dbtx pggen.DBTX = countingPGTx{tx: pgtx, n: &count}
		r = authn.NewPG(dbtx)
	} else {
		sqtx, err := db.SQLiteRead().BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sqtx.Rollback() }()
		var dbtx sqlitegen.DBTX = countingSqliteTx{tx: sqtx, n: &count}
		r = authn.NewSQLite(dbtx)
	}
	_, err := authz.NewTxAuthorizer(r, tok).Authorize(ctx, authz.Identity{Principal: principal}, authz.OpEnvRead, scope)
	return count, err
}

func runQueryCountChecks(t *testing.T, db *store.DB) {
	misses := []struct {
		name  string
		scope domain.Scope
	}{
		{"missing_org", domain.Scope{Org: "org_missing", Project: prjA1, Env: envA1}},
		{"missing_project", domain.Scope{Org: orgA, Project: "prj_missing", Env: envA1}},
		{"missing_env", domain.Scope{Org: orgA, Project: prjA1, Env: "env_missing"}},
	}
	for _, m := range misses {
		t.Run(m.name, func(t *testing.T) {
			n, err := countedAuthorize(t, db, bob, m.scope)
			if !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("outcome = %v, want ErrNotFound", err)
			}
			if n != 1 {
				t.Fatalf("chain miss at %s issued %d queries, want exactly 1 regardless of failing level", m.name, n)
			}
		})
	}
	t.Run("cross_org_denial_on_existing", func(t *testing.T) {
		n, err := countedAuthorize(t, db, bob, domain.Scope{Org: orgA, Project: prjA1, Env: envA1})
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("outcome = %v, want ErrNotFound", err)
		}
		if n != 2 {
			t.Fatalf("denial on existing object issued %d queries, want 2 (chain + grants)", n)
		}
	})
	t.Run("authorized", func(t *testing.T) {
		n, err := countedAuthorize(t, db, alice, domain.Scope{Org: orgA, Project: prjA1, Env: envA1})
		if err != nil {
			t.Fatalf("outcome = %v, want success", err)
		}
		if n != 2 {
			t.Fatalf("authorized path issued %d queries, want 2 (chain + grants)", n)
		}
	})
}

// runChainConstraintChecks is invariant 10's behavioral half: composite
// ancestry FKs make an inconsistent chain unrepresentable on both engines,
// and the grant CHECK forbids scope gaps. These are raw-SQL attempts —
// below the store — because that is exactly the layer the constraints
// defend.
//
// The display-order pair belongs here for the same reason: a negative position
// sorts ahead of every legitimate one, and an OMITTED position must fail rather
// than silently become zero — which is what having no column default buys, on
// both engines.
func runChainConstraintChecks(t *testing.T, db *store.DB) {
	attempts := []struct {
		name string
		stmt string
	}{
		{"env_chain_crossing_orgs",
			`INSERT INTO environments (id, org_id, project_id, name, note, created_at, display_order) VALUES ('env_evil', 'org_b', 'prj_a1', 'x', '', ` + ts + `, 0)`},
		{"env_parent_project_missing",
			`INSERT INTO environments (id, org_id, project_id, name, note, created_at, display_order) VALUES ('env_evil', 'org_a', 'prj_missing', 'x', '', ` + ts + `, 0)`},
		{"project_parent_org_missing",
			`INSERT INTO projects (id, org_id, name, created_at) VALUES ('prj_evil', 'org_missing', 'x', ` + ts + `)`},
		{"grant_scope_gap",
			`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_evil', 'usr_alice', 'read', NULL, 'prj_a1', NULL, ` + ts + `)`},
		{"negative_display_order",
			`INSERT INTO environments (id, org_id, project_id, name, note, created_at, display_order) VALUES ('env_evil', 'org_a', 'prj_a1', 'x', '', ` + ts + `, -1)`},
		{"missing_display_order",
			`INSERT INTO environments (id, org_id, project_id, name, note, created_at) VALUES ('env_evil', 'org_a', 'prj_a1', 'x', '', ` + ts + `)`},
		{"grant_chain_crossing_orgs",
			`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_evil', 'usr_alice', 'read', 'org_b', 'prj_a1', NULL, ` + ts + `)`},
	}
	for _, a := range attempts {
		t.Run(a.name, func(t *testing.T) {
			if err := execRawErr(t, db, a.stmt); err == nil {
				t.Fatalf("constraint failed to refuse: %s", a.stmt)
			}
		})
	}
}

// runProofLifecycleE2E is invariant 5 at the integration level (the unit
// half lives in internal/authz): a proof captured out of its transaction is
// rejected at the store boundary after commit, and an operation-mismatched
// proof is rejected mid-transaction — before any query, with the whole
// transaction rolled back.
func runProofLifecycleE2E(t *testing.T, db *store.DB) {
	ctx := t.Context()
	scope := domain.Scope{Org: orgA, Project: prjA1, Env: envA1}

	var capturedRepos store.Repos
	var capturedProof authz.Proof
	err := tx.Write(ctx, db, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: alice}, authz.OpEnvRead, scope)
		if err != nil {
			return err
		}
		capturedRepos, capturedProof = r, p
		_, err = r.Environments().Get(ctx, p)
		return err
	})
	if err != nil {
		t.Fatalf("in-transaction read: %v", err)
	}
	_, err = capturedRepos.Environments().Get(ctx, capturedProof)
	if err == nil {
		t.Fatal("a proof outlived its transaction")
	}
	if errors.Is(err, domain.ErrNotFound) || !strings.Contains(err.Error(), "transaction") {
		t.Fatalf("stale proof died with %v, want the loud boundary rejection", err)
	}

	sentinel := errors.New("rollback")
	err = tx.Write(ctx, db, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: alice}, authz.OpEnvRead, scope)
		if err != nil {
			return err
		}
		if err := r.Environments().UpdateNote(ctx, p, "sneak"); err == nil {
			return errors.New("read-formula proof accepted on the mutation path")
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("mismatch transaction: %v", err)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM environments WHERE note = 'sneak'"); n != 0 {
		t.Fatal("mismatched proof's mutation landed")
	}
}
