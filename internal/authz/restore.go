package authz

// The in-transaction restore-reconciliation surface (#76).
//
// It hangs off TxAuthorizer for the same reason the human-authentication
// surface does: the resolution surface stays importable by exactly
// {authz, tx}, and the service layer reaches it only inside a transaction it
// already holds. What is different here is WHY there is no Authorize() call
// in front of it — see SiteRecoveryReconcile, the tenant-isolation ADR's
// enumerated system mint site for exactly this: a restore leaves every
// session dead and every grant inert, so no principal exists who could
// authorize the reconciliation that ends that state. The gate is host access,
// and host access is operator-equivalent under the threat model already.

import (
	"context"
	"time"

	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/store/authn"
)

// RestoreState is the instance's restore posture.
type RestoreState = authn.RestoreState

// PrincipalRef names a principal awaiting reconciliation.
type PrincipalRef = authn.PrincipalRef

// RestoreState reads the instance's restore posture.
func (a *TxAuthorizer) RestoreState(ctx context.Context) (RestoreState, error) {
	return a.r.RestoreState(ctx)
}

// AdvanceRestoreEpoch performs the restore's invalidation.
func (a *TxAuthorizer) AdvanceRestoreEpoch(ctx context.Context, now time.Time) error {
	return a.r.AdvanceRestoreEpoch(ctx, now)
}

// ReconcilePrincipal commits ONE principal's reconciliation. The signature is
// the guarantee: one id in, one answer out. There is no set-taking sibling of
// this method anywhere in the module, and the drill asserts that.
func (a *TxAuthorizer) ReconcilePrincipal(ctx context.Context, p domain.PrincipalID) (bool, error) {
	return a.r.ReconcilePrincipal(ctx, p)
}

// UnreconciledPrincipals lists who is still inert.
func (a *TxAuthorizer) UnreconciledPrincipals(ctx context.Context) ([]PrincipalRef, error) {
	return a.r.UnreconciledPrincipals(ctx)
}
