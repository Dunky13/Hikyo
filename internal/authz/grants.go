package authz

import (
	"context"
	"time"

	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/store/authn"
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
)

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
