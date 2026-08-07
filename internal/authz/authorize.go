package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store/authn"
)

// TxAuthorizer is the in-transaction face of authorize(). The transaction
// package constructs one per transaction attempt from the resolution surface
// bound to that same transaction; service code receives it inside the
// closure and can only mint proofs through it — the resolver itself is never
// exposed.
type TxAuthorizer struct {
	r   *authn.Resolver
	tok *TxToken
}

// NewTxAuthorizer binds authorize() to one transaction attempt. Called by
// internal/store/tx only; the concrete *authn.Resolver requirement means no
// other package can supply a fabricated resolution surface.
func NewTxAuthorizer(r *authn.Resolver, tok *TxToken) *TxAuthorizer {
	return &TxAuthorizer{r: r, tok: tok}
}

// Authorize evaluates the named operation's formula for the principal
// against the addressed scope, inside the current transaction, and mints the
// proof every store call requires. Outcomes:
//
//   - Tenant-scoped operation, chain missing at any level OR formula denied:
//     domain.ErrNotFound — unauthorized ≡ nonexistent, one error, one code
//     path, and exactly one chain-resolution query either way (the grant
//     lookup is skipped when the chain is missing; a probe cannot count its
//     way to which level failed).
//   - Instance-scoped operation, formula denied: domain.ErrUnauthorized —
//     the grant-refusal contract; there is no tenant object whose
//     nonexistence could be mimicked.
//   - Registry or addressing bugs (unknown operation, scope depth mismatch):
//     loud errors, never uniform responses — these are programming errors,
//     not probe outcomes.
func (a *TxAuthorizer) Authorize(ctx context.Context, principal domain.PrincipalID, op Operation, scope domain.Scope) (Proof, error) {
	spec, ok := operations[op]
	if !ok {
		return nil, fmt.Errorf("authz: operation %q is not in the operation registry", op)
	}
	if principal == "" {
		return nil, errors.New("authz: empty principal")
	}

	switch spec.class {
	case ClassTenant:
		return a.authorizeTenant(ctx, principal, op, spec, scope)
	case ClassInstance:
		if scope != (domain.Scope{}) {
			return nil, fmt.Errorf("authz: instance operation %q addressed with a tenant scope", op)
		}
		return a.authorizeInstance(ctx, principal, op, spec)
	default:
		return nil, fmt.Errorf("authz: operation %q (class %d) does not mint proofs via Authorize", op, spec.class)
	}
}

func (a *TxAuthorizer) authorizeTenant(ctx context.Context, principal domain.PrincipalID, op Operation, spec opSpec, scope domain.Scope) (Proof, error) {
	level, err := scope.Level()
	if err != nil {
		return nil, fmt.Errorf("authz: operation %q: %w", op, err)
	}
	if level != spec.level {
		return nil, fmt.Errorf("authz: operation %q requires a depth-%d scope, got depth %d", op, spec.level, level)
	}

	chain, err := a.r.ResolveChain(ctx, scope)
	if err != nil {
		// domain.ErrNotFound passes through untouched: the uniform
		// nonexistent outcome, before any capability evaluation.
		return nil, err
	}

	grants, err := a.r.Grants(ctx, principal)
	if err != nil {
		return nil, err
	}
	if !evaluate(spec.formula, chain, grants) {
		return nil, domain.ErrNotFound
	}
	return &proof{kind: kindTenant, op: op, chain: chain, tok: a.tok}, nil
}

func (a *TxAuthorizer) authorizeInstance(ctx context.Context, principal domain.PrincipalID, op Operation, spec opSpec) (Proof, error) {
	grants, err := a.r.Grants(ctx, principal)
	if err != nil {
		return nil, err
	}
	if !evaluate(spec.formula, domain.Scope{}, grants) {
		return nil, domain.ErrUnauthorized
	}
	return &proof{kind: kindInstance, op: op, tok: a.tok}, nil
}

// SystemAuthority mints a SystemProof for one of the closed no-principal
// mint sites (boot, migration, recovery-mode reconciliation, break-glass).
// It is not generic store authority: the proof is operation- and
// transaction-bound like every other kind, against the site's closed
// operation set in the system registry — growth of either set fails the
// build until the tenant-isolation ADR is amended (invariant 11).
func SystemAuthority(site SystemSite, tok *TxToken) (Proof, error) {
	if _, ok := systemSites[site]; !ok {
		return nil, fmt.Errorf("authz: %q is not a registered system mint site", site)
	}
	if tok == nil {
		return nil, errors.New("authz: system authority requires a live transaction")
	}
	return &proof{kind: kindSystem, op: Operation("system:" + site), site: site, tok: tok}, nil
}

// evaluate answers the formula: every atom must be covered by at least one
// grant. Grants are purely additive and inherit downward, so a grant covers
// an atom when its capability matches and its scope is an ancestor of (or
// equal to) the resolved chain truncated to the atom's level. No deny rules
// exist, so there is no ordering to reason about.
func evaluate(f Formula, chain domain.Scope, grants []domain.Grant) bool {
	for _, atom := range f {
		target := truncate(chain, atom.At)
		held := false
		for _, g := range grants {
			if g.Capability == atom.Cap && covers(g.Scope, target) {
				held = true
				break
			}
		}
		if !held {
			return false
		}
	}
	return true
}

// truncate cuts a resolved chain to the given level.
func truncate(s domain.Scope, l domain.Level) domain.Scope {
	switch l {
	case domain.LevelOrg:
		return domain.Scope{Org: s.Org}
	case domain.LevelProject:
		return domain.Scope{Org: s.Org, Project: s.Project}
	case domain.LevelEnv:
		return s
	default:
		return domain.Scope{}
	}
}

// covers reports whether grant scope g is an ancestor-or-equal of target.
// The instance scope (zero) covers everything — instance grants inherit
// downward like every other scope (permission ADR). A grant deeper than the
// target never covers it.
func covers(g, target domain.Scope) bool {
	if g.Org == "" {
		return true
	}
	if g.Org != target.Org {
		return false
	}
	if g.Project == "" {
		return true
	}
	if g.Project != target.Project {
		return false
	}
	if g.Env == "" {
		return true
	}
	return g.Env == target.Env
}
