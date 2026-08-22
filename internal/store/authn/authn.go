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
	"sort"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store/pggen"
	"github.com/Hikyo-Org/hikyo/internal/store/sqlitegen"
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
	observer := queryObserver.Load()
	failure := mutationFailureObserver.Load()
	if observer != nil || failure != nil {
		db = observedSQLite{db: db, observer: observer, failure: failure}
	}
	return &Resolver{sq: sqlitegen.New(db)}
}

// NewPG binds a Resolver to an open postgres transaction.
func NewPG(db pggen.DBTX) *Resolver {
	observer := queryObserver.Load()
	failure := mutationFailureObserver.Load()
	if observer != nil || failure != nil {
		db = observedPG{db: db, observer: observer, failure: failure}
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
//
// The callback receives the SQL TEXT, which sqlc prefixes with its own
// `-- name: <Query> :one` header — a stable query IDENTITY. A count alone
// cannot tell two different query SEQUENCES of equal length apart, and the
// cross-org oracle fixtures need exactly that distinction: an attach path and a
// create path that issue different lookups must not cancel out to the same
// number.
var queryObserver atomic.Pointer[func(string)]

// mutationFailureObserver is the failure-injection half of the acceptance
// seam. It runs before generated mutation statements and can return an error,
// letting both real engines prove that every aggregate step rolls back the
// surrounding transaction. Like queryObserver, it is nil in production and
// installed only when a Resolver is constructed for the owning test.
var mutationFailureObserver atomic.Pointer[func(string) error]

// SetQueryObserver installs a test-only per-query callback and returns a
// function that removes it. Not for production code; there is no call site
// outside tests, and the boundary test pins that.
func SetQueryObserver(f func(sql string)) func() {
	queryObserver.Store(&f)
	return func() { queryObserver.Store(nil) }
}

// SetMutationFailureObserver installs a test-only pre-mutation failure hook
// and returns a function that removes it. The hook receives sqlc's statement
// text, including its stable query-name header. Not for production code.
func SetMutationFailureObserver(f func(sql string) error) func() {
	mutationFailureObserver.Store(&f)
	return func() { mutationFailureObserver.Store(nil) }
}

type observedSQLite struct {
	db       sqlitegen.DBTX
	observer *func(string)
	failure  *func(string) error
}

func (o observedSQLite) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if o.observer != nil {
		(*o.observer)(q)
	}
	if o.failure != nil {
		if err := (*o.failure)(q); err != nil {
			return nil, err
		}
	}
	return o.db.ExecContext(ctx, q, args...)
}

func (o observedSQLite) PrepareContext(ctx context.Context, q string) (*sql.Stmt, error) {
	return o.db.PrepareContext(ctx, q)
}

func (o observedSQLite) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	if o.observer != nil {
		(*o.observer)(q)
	}
	return o.db.QueryContext(ctx, q, args...)
}

func (o observedSQLite) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	if o.observer != nil {
		(*o.observer)(q)
	}
	return o.db.QueryRowContext(ctx, q, args...)
}

type observedPG struct {
	db       pggen.DBTX
	observer *func(string)
	failure  *func(string) error
}

func (o observedPG) Exec(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
	if o.observer != nil {
		(*o.observer)(q)
	}
	if o.failure != nil {
		if err := (*o.failure)(q); err != nil {
			return pgconn.CommandTag{}, err
		}
	}
	return o.db.Exec(ctx, q, args...)
}

func (o observedPG) Query(ctx context.Context, q string, args ...any) (pgx.Rows, error) {
	if o.observer != nil {
		(*o.observer)(q)
	}
	return o.db.Query(ctx, q, args...)
}

func (o observedPG) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	if o.observer != nil {
		(*o.observer)(q)
	}
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
// own transaction; there is no authorization cache (permission-model ADR).
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

// OrgIdentity is an organisation as a navigation destination: enough to name
// it and route to it, and nothing else. Metadata and the active flag are
// operator-set state, read through the proof-gated org repository.
type OrgIdentity struct {
	ID   domain.OrgID
	Name string
}

// OrgsForPrincipal projects the principal's own grant rows onto the set of
// organisations those grants name, at org scope or below.
//
// This is the navigation surface, and it deliberately is NOT an enumeration:
// it can only ever return organisations the caller already holds a grant in,
// which is why it needs no capability and authorizes nothing. Two consequences
// follow from the scope lattice and both are correct:
//
//   - a grant at project or environment depth still names its org, so the
//     developer who holds `read` on one environment sees the org that
//     environment lives in — without it the rail would be empty for exactly
//     the persona the permission-model ADR says drives the product;
//   - an INSTANCE-scoped grant names no org, so a principal holding only
//     instance capabilities gets an empty set. Instance scope inherits
//     downward, so expanding it here would silently reproduce the operator's
//     org enumeration — which is MFA-mandatory — on a surface that is not.
//
// The result is ordered by name so the rail is stable between loads.
func (r *Resolver) OrgsForPrincipal(ctx context.Context, p domain.PrincipalID) ([]OrgIdentity, error) {
	grants, err := r.Grants(ctx, p)
	if err != nil {
		return nil, err
	}
	seen := map[domain.OrgID]bool{}
	ids := make([]domain.OrgID, 0, len(grants))
	for _, g := range grants {
		if g.Scope.Org == "" || seen[g.Scope.Org] {
			continue
		}
		seen[g.Scope.Org] = true
		ids = append(ids, g.Scope.Org)
	}
	// ponytail: one read per org. A human belongs to a handful; if machine
	// principals ever need this, batch it with an IN-list query.
	out := make([]OrgIdentity, 0, len(ids))
	for _, id := range ids {
		row, err := r.orgIdentity(ctx, id)
		if errors.Is(err, domain.ErrNotFound) {
			// A grant whose org has been deleted names nothing to navigate to.
			// The grant row is #55's to reap; the rail simply does not show a
			// destination that is not there.
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *Resolver) orgIdentity(ctx context.Context, id domain.OrgID) (OrgIdentity, error) {
	if r.sq != nil {
		row, err := r.sq.GetOrgIdentity(ctx, string(id))
		if err != nil {
			return OrgIdentity{}, notFoundOr(err)
		}
		return OrgIdentity{ID: domain.OrgID(row.ID), Name: row.Name}, nil
	}
	row, err := r.pg.GetOrgIdentity(ctx, string(id))
	if err != nil {
		return OrgIdentity{}, notFoundOr(err)
	}
	return OrgIdentity{ID: domain.OrgID(row.ID), Name: row.Name}, nil
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
