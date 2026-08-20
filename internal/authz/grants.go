package authz

import (
	"context"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store/authn"
)

// The grant surface's in-transaction face (#55). Service code never sees the
// resolver; it reaches the grant table through these, inside the same
// transaction its chokepoint proof was minted in.

// GrantRow, Origin and GrantLine are re-exported so the service layer never
// names the resolution-surface package.
type (
	GrantRow   = authn.GrantRow
	Origin     = authn.Origin
	GrantLine  = authn.GrantLine
	EnvSetting = authn.EnvironmentSettings
	// GrantOriginRow and LockoutRetention arrive with the SCIM release
	// algorithm (#73 §2.4): the first is one (grant row, origin) pair, the
	// second is a row a retention origin is holding alive.
	GrantOriginRow   = authn.GrantOriginRow
	LockoutRetention = authn.LockoutRetention
	// The SCIM provisioning credential as AUTHENTICATION sees it (#73 §7).
	// Its administration lives on the proof-carrying repository instead.
	SCIMCredential = authn.SCIMCredential
)

// ResolveChain answers "is this (org, project, environment) a real chain" —
// the same single-query resolution authorize() itself performs, exposed for the
// one caller that must ask about a scope it is NOT currently authorizing: a
// SCIM mapping row names a scope at AUTHORING time and expands it at every
// sync, and a row whose environment does not belong to its project would write
// grants against a chain that never existed.
//
// It mints no proof and reveals nothing a caller could not learn by addressing
// the scope: an unresolvable chain answers domain.ErrNotFound uniformly,
// whether the link is missing or foreign.
func (a *TxAuthorizer) ResolveChain(ctx context.Context, scope domain.Scope) (domain.Scope, error) {
	return a.r.ResolveChain(ctx, scope)
}

// GrantRowsForPrincipal lists a principal's grants with their row ids — the
// dedup read every create performs under the principal-row lock.
func (a *TxAuthorizer) GrantRowsForPrincipal(ctx context.Context, p domain.PrincipalID) ([]GrantRow, error) {
	return a.r.GrantRowsForPrincipal(ctx, p)
}

// AddGrantOrigin attaches one origin to a grant row.
func (a *TxAuthorizer) AddGrantOrigin(ctx context.Context, id, grantID string, p domain.PrincipalID, o Origin, at time.Time) error {
	return a.r.AddGrantOrigin(ctx, id, grantID, p, o, at)
}

// ReleaseGrantOrigin releases one origin, reporting whether it held the row.
func (a *TxAuthorizer) ReleaseGrantOrigin(ctx context.Context, grantID string, p domain.PrincipalID, o Origin) (bool, error) {
	return a.r.ReleaseGrantOrigin(ctx, grantID, p, o)
}

// GrantOriginCount reports how many origins still hold a grant row.
func (a *TxAuthorizer) GrantOriginCount(ctx context.Context, grantID string) (int64, error) {
	return a.r.GrantOriginCount(ctx, grantID)
}

// CountGrantsInOrg reports how many grant rows an organization holds — the
// read behind the per-org grant sanity cap.
func (a *TxAuthorizer) CountGrantsInOrg(ctx context.Context, org string) (int64, error) {
	return a.r.CountGrantsInOrg(ctx, org)
}

// DeleteGrantRow removes a grant row whose last origin was released.
func (a *TxAuthorizer) DeleteGrantRow(ctx context.Context, grantID string, p domain.PrincipalID) (bool, error) {
	return a.r.DeleteGrantRow(ctx, grantID, p)
}

// GrantLinesInOrg lists the membership surface for one org.
func (a *TxAuthorizer) GrantLinesInOrg(ctx context.Context, org string) ([]GrantLine, error) {
	return a.r.GrantLinesInOrg(ctx, org)
}

// GrantLinesInProject lists the membership surface for one project.
func (a *TxAuthorizer) GrantLinesInProject(ctx context.Context, org, project string) ([]GrantLine, error) {
	return a.r.GrantLinesInProject(ctx, org, project)
}

// GrantLinesAtInstance lists the instance-scope membership surface.
func (a *TxAuthorizer) GrantLinesAtInstance(ctx context.Context) ([]GrantLine, error) {
	return a.r.GrantLinesAtInstance(ctx)
}

// ManageMembersHolders is the lockout invariant's census at one org, or at
// instance scope when org is empty.
func (a *TxAuthorizer) ManageMembersHolders(ctx context.Context, org string) ([]domain.PrincipalID, error) {
	return a.r.ManageMembersHolders(ctx, org)
}

// EnvironmentReauthSettings reads an environment's protection state and its
// own reauthentication window, if it has one.
func (a *TxAuthorizer) EnvironmentReauthSettings(ctx context.Context, envID string) (EnvSetting, error) {
	return a.r.EnvironmentReauthSettings(ctx, envID)
}

// PrincipalClass resolves a principal's class for the normative machine
// allowlists.
func (a *TxAuthorizer) PrincipalClass(ctx context.Context, p domain.PrincipalID) (domain.PrincipalClass, error) {
	return a.r.PrincipalClass(ctx, p)
}

// GrantOriginsFor lists the origins holding one grant row.
func (a *TxAuthorizer) GrantOriginsFor(ctx context.Context, grantID string) ([]Origin, error) {
	return a.r.GrantOriginsFor(ctx, grantID)
}

// GrantOriginsForPrincipal lists every origin holding every grant row of one
// principal, read at one instant. The SCIM release algorithm (#73 §2.4) decides
// per origin and then counts what remains per row; seeing the two tables at
// different instants would let a row be judged against origins that had already
// moved.
func (a *TxAuthorizer) GrantOriginsForPrincipal(ctx context.Context, p domain.PrincipalID) ([]GrantOriginRow, error) {
	return a.r.GrantOriginsForPrincipal(ctx, p)
}

// LockoutRetentionsInOrg is the org-bounded cure sweep.
func (a *TxAuthorizer) LockoutRetentionsInOrg(ctx context.Context, org domain.OrgID) ([]LockoutRetention, error) {
	return a.r.LockoutRetentionsInOrg(ctx, org)
}

// LockoutRetentions lists every `lockout-retention` origin in the instance,
// which is what the deterministic cure sweep walks (#73 §2.4).
func (a *TxAuthorizer) LockoutRetentions(ctx context.Context) ([]LockoutRetention, error) {
	return a.r.LockoutRetentions(ctx)
}

// ---------------------------------------------------------------------------
// SCIM provisioning credentials (#73 §7)
//
// They sit on the resolution surface for the same reason sessions do: a SCIM
// wire request presents one BEFORE any operation is authorized.
// ---------------------------------------------------------------------------

func (a *TxAuthorizer) SCIMCredentialByVerifier(ctx context.Context, presented []byte) (SCIMCredential, error) {
	return a.r.SCIMCredentialByVerifier(ctx, presented)
}

func (a *TxAuthorizer) TouchSCIMCredential(ctx context.Context, id string, at time.Time) error {
	return a.r.TouchSCIMCredential(ctx, id, at)
}

// The two ends of the provisioning connection's life: created with its binding,
// retired by §6's state machine atomically with the structural grant it held.
// Neither takes a class: the first hardcodes it and the second requires it.
func (a *TxAuthorizer) CreateProvisioningPrincipal(ctx context.Context, id domain.PrincipalID, at time.Time) error {
	return a.r.CreateProvisioningPrincipal(ctx, id, at)
}
