// Package authn is the authorization package's enumerated resolution surface
// (tenant-isolation ADR § bootstrap carve-out): authorize() cannot run under
// a proof, so the reads it needs to mint one — chain resolution and grant
// lookup — live here, and nowhere else may read chain tables with
// request-supplied identifiers. The import-boundary test allows exactly
// internal/authz and internal/store/tx (which constructs a Resolver per
// transaction) to import this package; its surface is part of the trusted
// set and is the highest-scrutiny diff target in the repo.
//
// Resolver is deliberately a concrete type, not an interface: were it an
// interface, any package could satisfy it structurally (no import needed)
// and hand authorize() a fabricated chain — a proof forgery the boundary
// test would never see. A concrete type can only be built from live
// transaction handles this package's constructors accept.
package authn

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/store/pggen"
	"github.com/Dunky13/hikyo/internal/store/sqlitegen"
)

// Resolver answers the two questions authorize() asks, inside the same
// transaction the eventual store calls run in.
type Resolver struct {
	sq *sqlitegen.Queries
	pg *pggen.Queries
}

// NewSQLite binds a Resolver to an open sqlite transaction (or, for
// read-only authorization, a read-pool connection's transaction).
func NewSQLite(db sqlitegen.DBTX) *Resolver {
	if f := queryObserver.Load(); f != nil {
		db = observedSQLite{db: db, on: *f}
	}
	return &Resolver{sq: sqlitegen.New(db)}
}

// NewPG binds a Resolver to an open postgres transaction.
func NewPG(db pggen.DBTX) *Resolver {
	if f := queryObserver.Load(); f != nil {
		db = observedPG{db: db, on: *f}
	}
	return &Resolver{pg: pggen.New(db)}
}

// The query-observer seam. It exists so the acceptance suite can count the
// queries a REAL SERVICE CALL issues — not only the ones a direct Authorize
// issues — without the isolation harness having to rebuild the transaction
// the service opens for itself.
//
// It lives on the resolution surface for two reasons. This is the package the
// generated queries may be imported into at all (the driver-handle allowlist),
// and on a REFUSED request the resolution surface is the entire query traffic:
// authorization runs before any store call, so a request that does not
// authorize issues nothing else. Counting here therefore counts the whole
// stack for exactly the legs the timing control is about.
//
// Nil in production: the wrapper is installed at Resolver construction, so an
// unset observer costs one atomic load per transaction, never per query.
var queryObserver atomic.Pointer[func()]

// SetQueryObserver installs a test-only per-query callback and returns a
// function that removes it. Not for production code; there is no call site
// outside tests, and the boundary test pins that.
func SetQueryObserver(f func()) func() {
	queryObserver.Store(&f)
	return func() { queryObserver.Store(nil) }
}

type observedSQLite struct {
	db sqlitegen.DBTX
	on func()
}

func (o observedSQLite) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	o.on()
	return o.db.ExecContext(ctx, q, args...)
}

func (o observedSQLite) PrepareContext(ctx context.Context, q string) (*sql.Stmt, error) {
	return o.db.PrepareContext(ctx, q)
}

func (o observedSQLite) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	o.on()
	return o.db.QueryContext(ctx, q, args...)
}

func (o observedSQLite) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	o.on()
	return o.db.QueryRowContext(ctx, q, args...)
}

type observedPG struct {
	db pggen.DBTX
	on func()
}

func (o observedPG) Exec(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
	o.on()
	return o.db.Exec(ctx, q, args...)
}

func (o observedPG) Query(ctx context.Context, q string, args ...any) (pgx.Rows, error) {
	o.on()
	return o.db.Query(ctx, q, args...)
}

func (o observedPG) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	o.on()
	return o.db.QueryRow(ctx, q, args...)
}

// ResolveChain resolves the addressed chain in a single query, one round
// trip, one code path regardless of which level is missing (tenant-isolation
// ADR: the query-count uniformity is the application-layer half of
// unauthorized ≡ nonexistent; engine-internal microtiming is the stated
// residual). Zero rows — whether the org, the project, or the environment is
// the missing link — return domain.ErrNotFound. The denormalized chain
// columns plus the composite ancestry FKs make the addressed row's own chain
// authoritative, so no per-level walk exists to diverge on.
func (r *Resolver) ResolveChain(ctx context.Context, scope domain.Scope) (domain.Scope, error) {
	level, err := scope.Level()
	if err != nil {
		return domain.Scope{}, err
	}
	switch level {
	case domain.LevelOrg:
		return r.resolveOrg(ctx, scope)
	case domain.LevelProject:
		return r.resolveProject(ctx, scope)
	case domain.LevelEnv:
		return r.resolveEnv(ctx, scope)
	default:
		return domain.Scope{}, errors.New("authn: cannot resolve an empty scope")
	}
}

func (r *Resolver) resolveOrg(ctx context.Context, s domain.Scope) (domain.Scope, error) {
	if r.sq != nil {
		id, err := r.sq.ResolveOrgChain(ctx, string(s.Org))
		if err != nil {
			return domain.Scope{}, notFoundOr(err)
		}
		return domain.Scope{Org: domain.OrgID(id)}, nil
	}
	id, err := r.pg.ResolveOrgChain(ctx, string(s.Org))
	if err != nil {
		return domain.Scope{}, notFoundOr(err)
	}
	return domain.Scope{Org: domain.OrgID(id)}, nil
}

func (r *Resolver) resolveProject(ctx context.Context, s domain.Scope) (domain.Scope, error) {
	if r.sq != nil {
		row, err := r.sq.ResolveProjectChain(ctx, sqlitegen.ResolveProjectChainParams{
			OrgID: string(s.Org), ID: string(s.Project),
		})
		if err != nil {
			return domain.Scope{}, notFoundOr(err)
		}
		return domain.Scope{Org: domain.OrgID(row.OrgID), Project: domain.ProjectID(row.ID)}, nil
	}
	row, err := r.pg.ResolveProjectChain(ctx, pggen.ResolveProjectChainParams{
		OrgID: string(s.Org), ID: string(s.Project),
	})
	if err != nil {
		return domain.Scope{}, notFoundOr(err)
	}
	return domain.Scope{Org: domain.OrgID(row.OrgID), Project: domain.ProjectID(row.ID)}, nil
}

func (r *Resolver) resolveEnv(ctx context.Context, s domain.Scope) (domain.Scope, error) {
	if r.sq != nil {
		row, err := r.sq.ResolveEnvChain(ctx, sqlitegen.ResolveEnvChainParams{
			OrgID: string(s.Org), ProjectID: string(s.Project), ID: string(s.Env),
		})
		if err != nil {
			return domain.Scope{}, notFoundOr(err)
		}
		return domain.Scope{
			Org: domain.OrgID(row.OrgID), Project: domain.ProjectID(row.ProjectID), Env: domain.EnvID(row.ID),
		}, nil
	}
	row, err := r.pg.ResolveEnvChain(ctx, pggen.ResolveEnvChainParams{
		OrgID: string(s.Org), ProjectID: string(s.Project), ID: string(s.Env),
	})
	if err != nil {
		return domain.Scope{}, notFoundOr(err)
	}
	return domain.Scope{
		Org: domain.OrgID(row.OrgID), Project: domain.ProjectID(row.ProjectID), Env: domain.EnvID(row.ID),
	}, nil
}

// Grants returns the principal's full grant set for formula evaluation. An
// unknown principal simply has no grants — indistinguishable from a revoked
// one, which is the contract. Current policy is read inside the operation's
// own transaction; there is no authorization cache (permission ADR).
func (r *Resolver) Grants(ctx context.Context, p domain.PrincipalID) ([]domain.Grant, error) {
	if r.sq != nil {
		rows, err := r.sq.ListGrantsForPrincipal(ctx, string(p))
		if err != nil {
			return nil, err
		}
		out := make([]domain.Grant, 0, len(rows))
		for _, row := range rows {
			g, err := grantFrom(row.Capability, row.OrgID.String, row.ProjectID.String, row.EnvID.String)
			if err != nil {
				return nil, err
			}
			out = append(out, g)
		}
		return out, nil
	}
	rows, err := r.pg.ListGrantsForPrincipal(ctx, string(p))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Grant, 0, len(rows))
	for _, row := range rows {
		g, err := grantFrom(row.Capability, row.OrgID.String, row.ProjectID.String, row.EnvID.String)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// grantFrom parses a grant row, re-validating the no-gaps chain rule the
// CHECK constraint already enforces — parse, don't trust.
func grantFrom(capability, org, project, env string) (domain.Grant, error) {
	g := domain.Grant{
		Capability: domain.Capability(capability),
		Scope: domain.Scope{
			Org: domain.OrgID(org), Project: domain.ProjectID(project), Env: domain.EnvID(env),
		},
	}
	if _, err := g.Scope.Level(); err != nil {
		return domain.Grant{}, fmt.Errorf("authn: grant row for capability %q: %w", capability, err)
	}
	return g, nil
}

func notFoundOr(err error) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
