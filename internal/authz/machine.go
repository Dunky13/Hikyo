package authz

import (
	"context"
	"errors"
	"time"

	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/store/authn"
)

// Machine identities at the chokepoint (#61, machine-identities ADR).
//
// The ADR's propagation to the architecture ticket is literal: "MUST resolve
// machine credentials at the same chokepoint as authorize(), in-transaction
// and uncached". So this file adds a resolution leg to the SAME Authenticate
// the human paths already call — not a parallel middleware, not a cached
// principal. Every operation that authorizes a session therefore authorizes a
// machine credential by the same code, and revocation bites at the next
// request because the predicate is read in that request's own transaction.
//
// What it deliberately does NOT share is storage: a machine credential is its
// own artifact type with its own table, lifetime and revocation surface
// (#16's propagation). A machine principal has no session row, no cookie and
// no assurance record, and Identity.SessionID stays empty for one — which is
// also what exempts it from the MFA-mandatory check it could never satisfy.

// Re-exported so the service layer never names the resolution-surface
// package.
type (
	ServiceAccount     = authn.ServiceAccount
	MachineCredential  = authn.MachineCredential
	CredentialPolicy   = authn.CredentialPolicy
	AffectedCredential = authn.AffectedCredential
	NewServiceAccount  = authn.NewServiceAccount
	NewCredential      = authn.NewMachineCredential
)

// authenticateMachine resolves a presented machine bearer value.
//
// It performs the SAME THREE READS in the same order whatever the value turns
// out to be, and evaluates every predicate after all three. Returning as soon
// as one failed would make an unknown credential cost one query and a revoked
// one three — a query-count oracle for which credentials exist.
//
// Equal query counts are necessary and not sufficient, so three things carry
// the property together, and it is worth naming them because two of them are
// easy to remove by accident:
//
//  1. the fixed three reads below, in a fixed order;
//  2. the same per-query ROW WORK on every outcome — the resolver's miss paths
//     decode a decoy row rather than returning early, so an unknown credential
//     costs the same timestamp parses as a revoked one (see machine.go's decoy
//     block in internal/store/authn);
//  3. the constant-time verifier comparison on the resolved row.
//
// What remains is the storage engine's own B-tree probe, which differs between
// a hit and a miss and which no application-level code can equalise. The
// tenant-isolation ADR already records engine-internal microtiming as the
// accepted residual; everything above it is equal.
func (a *TxAuthorizer) authenticateMachine(ctx context.Context, presented string, now time.Time) (Identity, error) {
	cred, credErr := a.r.MachineCredentialByVerifier(ctx, crypto.ArtifactVerifier(presented))
	if credErr != nil && !errors.Is(credErr, domain.ErrNotFound) {
		return Identity{}, credErr
	}

	// A missing credential still resolves a service account, for the empty id
	// — which resolves to nothing, at the same cost.
	sa, saErr := a.r.ServiceAccountByID(ctx, cred.ServiceAccountID)
	if saErr != nil && !errors.Is(saErr, domain.ErrNotFound) {
		return Identity{}, saErr
	}

	epoch, err := a.r.CredentialEpoch(ctx)
	if err != nil {
		return Identity{}, err
	}

	// The constant-time comparison the ADR requires on the resolved row runs
	// inside MachineCredentialByVerifier, like every other bearer artifact in
	// this codebase, and so does the decoy work that keeps a miss costing what
	// a hit costs. A mismatch answers domain.ErrNotFound — what a miss already
	// answered — so the three-read discipline above is untouched.
	//
	// Live() carries the whole predicate — revoked, epoch-superseded, and
	// expired-unless-indefinite — so the listing surface and this one cannot
	// answer differently about the same row.
	if credErr != nil || saErr != nil || !cred.Live(now, epoch) {
		return Identity{}, domain.ErrUnauthenticated
	}
	// A machine principal whose class is not one of the closed service-account
	// kinds fails closed. The row cannot normally hold anything else — the
	// CHECK constraint is the floor — but the class is what the normative
	// allowlists key on, so an unrecognised one authenticates nothing.
	if !domain.IsServiceAccountKind(sa.Kind) {
		return Identity{}, domain.ErrUnauthenticated
	}

	return Identity{
		Principal:    sa.PrincipalID,
		Artifact:     string(cred.Kind),
		Class:        sa.Kind,
		CredentialID: cred.ID,
		CreatedAt:    cred.CreatedAt,
		LastSeenAt:   cred.LastUsedAt,
	}, nil
}

// CreateMachinePrincipal, CreateServiceAccount and the rest are the service
// layer's in-transaction face onto the machine tables. Authorization for them
// happens at the chokepoint first — every caller mints a proof through
// Authorize before reaching here — but the rows are `class=authn`, so the
// reads and writes ride the resolution surface, exactly as grant
// administration does.

func (a *TxAuthorizer) CreateMachinePrincipal(ctx context.Context, id domain.PrincipalID, class domain.PrincipalClass, at time.Time) error {
	return a.r.CreateMachinePrincipal(ctx, id, class, at)
}

func (a *TxAuthorizer) CreateServiceAccount(ctx context.Context, sa NewServiceAccount) error {
	return a.r.CreateServiceAccount(ctx, sa)
}

// ServiceAccountAt resolves one service account within an addressed project;
// an id from another project answers domain.ErrNotFound.
func (a *TxAuthorizer) ServiceAccountAt(ctx context.Context, scope domain.Scope, id string) (ServiceAccount, error) {
	return a.r.ServiceAccountAt(ctx, scope, id)
}

// ServiceAccountByPrincipal resolves the service account a machine principal
// is, for the grant surface's subtree confinement.
func (a *TxAuthorizer) ServiceAccountByPrincipal(ctx context.Context, p domain.PrincipalID) (ServiceAccount, error) {
	return a.r.ServiceAccountByPrincipal(ctx, p)
}

func (a *TxAuthorizer) ServiceAccountsIn(ctx context.Context, scope domain.Scope) ([]ServiceAccount, error) {
	return a.r.ServiceAccountsIn(ctx, scope)
}

func (a *TxAuthorizer) DeleteServiceAccount(ctx context.Context, scope domain.Scope, id string) (int64, error) {
	return a.r.DeleteServiceAccount(ctx, scope, id)
}

func (a *TxAuthorizer) DeleteMachinePrincipal(ctx context.Context, p domain.PrincipalID) error {
	return a.r.DeleteMachinePrincipal(ctx, p)
}

func (a *TxAuthorizer) CreateMachineCredential(ctx context.Context, c NewCredential) error {
	return a.r.CreateMachineCredential(ctx, c)
}

func (a *TxAuthorizer) MachineCredentialsFor(ctx context.Context, serviceAccountID string) ([]MachineCredential, error) {
	return a.r.MachineCredentialsFor(ctx, serviceAccountID)
}

func (a *TxAuthorizer) LiveMachineCredentialCount(ctx context.Context, serviceAccountID string, epoch int64, now time.Time) (int64, error) {
	return a.r.LiveMachineCredentialCount(ctx, serviceAccountID, epoch, now)
}

func (a *TxAuthorizer) LiveMachineCredentialCounts(ctx context.Context, scope domain.Scope, epoch int64, now time.Time) (map[string]int64, error) {
	return a.r.LiveMachineCredentialCounts(ctx, scope, epoch, now)
}

func (a *TxAuthorizer) RevokeMachineCredential(ctx context.Context, serviceAccountID, id string, at time.Time) (bool, error) {
	return a.r.RevokeMachineCredential(ctx, serviceAccountID, id, at)
}

func (a *TxAuthorizer) RevokeAllMachineCredentials(ctx context.Context, serviceAccountID string, at time.Time) (int64, error) {
	return a.r.RevokeAllMachineCredentials(ctx, serviceAccountID, at)
}

func (a *TxAuthorizer) DeleteMachineCredentials(ctx context.Context, serviceAccountID string) error {
	return a.r.DeleteMachineCredentials(ctx, serviceAccountID)
}

func (a *TxAuthorizer) TouchMachineCredential(ctx context.Context, id string, at time.Time) error {
	return a.r.TouchMachineCredential(ctx, id, at)
}

func (a *TxAuthorizer) CredentialsBeyondCeiling(ctx context.Context, ceiling time.Time) ([]AffectedCredential, error) {
	return a.r.CredentialsBeyondCeiling(ctx, ceiling)
}

func (a *TxAuthorizer) IndefiniteCredentials(ctx context.Context) ([]AffectedCredential, error) {
	return a.r.IndefiniteCredentials(ctx)
}

func (a *TxAuthorizer) ClampCredentialExpiry(ctx context.Context, ceiling time.Time) (int64, error) {
	return a.r.ClampCredentialExpiry(ctx, ceiling)
}

func (a *TxAuthorizer) ClampIndefiniteCredentials(ctx context.Context, ceiling time.Time) (int64, error) {
	return a.r.ClampIndefiniteCredentials(ctx, ceiling)
}

// LockCredentialPolicy serializes a mint against a concurrent tightening.
func (a *TxAuthorizer) LockCredentialPolicy(ctx context.Context) error {
	return a.r.LockCredentialPolicy(ctx)
}

// LockMachinePrincipal takes a service account's principal-row lock — THE SAME
// LOCK the grant writers take — so a mint and a grant landing on that
// principal serialize. Without it a grant can widen the account between the
// mint's post-state check and its insert, producing a token whose authority
// never passed the gate.
func (a *TxAuthorizer) LockMachinePrincipal(ctx context.Context, p domain.PrincipalID) error {
	return a.r.LockPrincipalRow(ctx, p)
}

func (a *TxAuthorizer) CredentialPolicy(ctx context.Context) (CredentialPolicy, error) {
	return a.r.CredentialPolicy(ctx)
}

func (a *TxAuthorizer) SetCredentialPolicy(ctx context.Context, p CredentialPolicy, actor domain.PrincipalID, at time.Time) error {
	return a.r.SetCredentialPolicy(ctx, p, actor, at)
}

// EnvironmentsInProject is the universe the mint and widen reachability
// formulas range over.
func (a *TxAuthorizer) EnvironmentsInProject(ctx context.Context, scope domain.Scope) ([]domain.EnvID, error) {
	return a.r.EnvironmentsInProject(ctx, scope)
}

// Reachable is the ADR's reachability computation, and the comment is the
// point of the function: the two authority classes are computed
// INDEPENDENTLY and never collapsed into one "can reach plaintext" boolean.
//
// Collapsing them is a named bypass in the ADR, and a subtle one: a service
// account already holding read(E) ∧ reveal(E) shows an EMPTY delta when
// granted reveal-history(E), so an actor with no historical access at all
// could hand a machine principal the power to read superseded secrets. The
// permission ADR fixed the rule this violates — "reveal-history implies
// nothing about reveal, and vice versa".
type Reachable struct {
	// Current is where read(E) ∧ reveal(E) holds — current plaintext.
	Current map[domain.EnvID]bool
	// Historical is where read(E) ∧ reveal-history(E) holds — superseded
	// plaintext, which may still be live in an external service.
	Historical map[domain.EnvID]bool
}

// ReachableFrom evaluates the two classes over a project's environments for
// one grant set. `grants` is the WHOLE set a principal would hold in the
// state being tested, so the caller computes a pre-state and a post-state and
// diffs them per class.
func ReachableFrom(scope domain.Scope, envs []domain.EnvID, grants []domain.Grant) Reachable {
	out := Reachable{Current: map[domain.EnvID]bool{}, Historical: map[domain.EnvID]bool{}}
	for _, env := range envs {
		at := domain.Scope{Org: scope.Org, Project: scope.Project, Env: env}
		if !coveredBy(grants, domain.CapRead, at) {
			// No read means no delivery at all, so neither disclosure
			// capability reaches plaintext however it is granted.
			continue
		}
		if coveredBy(grants, domain.CapReveal, at) {
			out.Current[env] = true
		}
		if coveredBy(grants, domain.CapRevealHistory, at) {
			out.Historical[env] = true
		}
	}
	return out
}

// coveredBy reuses the chokepoint's own coverage rule, so reachability and
// authorization cannot disagree about what a grant reaches.
func coveredBy(grants []domain.Grant, cap domain.Capability, at domain.Scope) bool {
	for _, g := range grants {
		if g.Capability == cap && covers(g.Scope, at) {
			return true
		}
	}
	return false
}

// GrantsOf returns a principal's full grant set — the pre-state input to the
// reachability diff.
func (a *TxAuthorizer) GrantsOf(ctx context.Context, p domain.PrincipalID) ([]domain.Grant, error) {
	return a.r.Grants(ctx, p)
}
