package authn

// Restore reconciliation storage (#76, ops spec § 11 restore checklist,
// threat model § Compromise assumptions).
//
// It sits on the resolution surface for the sharpest version of the reason
// everything else here does. A restore invalidates every authentication
// artifact in the restored state and leaves every grant inert; at that
// instant NO principal can authorize anything, so a reconciliation that
// itself required authorization could never run. The circularity is not
// awkward, it is total — which is why these four are local-host-authority
// operations reading and writing the same class=authn tables the session
// lifecycle does, and why the two writers are named in the pinned
// enumerated writer list (internal/lint.ResolutionSurfaceWriters).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store/pggen"
	"github.com/Hikyo-Org/hikyo/internal/store/sqlitegen"
)

// RestoreState is the instance's restore posture.
//
// CredentialEpoch and RestoreEpoch are deliberately separate. Any epoch bump
// advances the first; only a restore advances the second. Equal values mean
// the current epoch was reached BY RESTORING and reconciliation is
// outstanding; RestoreEpoch of zero means this instance has never been
// restored at all.
type RestoreState struct {
	CredentialEpoch int64
	RestoreEpoch    int64
	// ReactivatedAt is the instant the restored instance came back, and the
	// zero time when it never was. It anchors the federated-token skew
	// predicate the machine-identities ADR fixes (iat > reactivated_at + 60 s).
	ReactivatedAt time.Time
}

// Restored reports whether reconciliation is outstanding for anybody.
func (s RestoreState) Restored() bool { return s.RestoreEpoch > 0 }

// PrincipalRef names a principal awaiting reconciliation. It carries the kind
// because the operator's decision differs by it: a human is re-established
// through the credential-establishment authority, a machine's bearer
// credentials are never re-activated and must be re-minted.
type PrincipalRef struct {
	ID   domain.PrincipalID
	Kind string
}

// RestoreState reads the instance's restore posture.
func (r *Resolver) RestoreState(ctx context.Context) (RestoreState, error) {
	if r.sq != nil {
		row, err := r.sq.GetRestoreState(ctx)
		if err != nil {
			return RestoreState{}, fmt.Errorf("authn: read restore state: %w", err)
		}
		out := RestoreState{CredentialEpoch: row.CredentialEpoch, RestoreEpoch: row.RestoreEpoch}
		if row.ReactivatedAt.Valid {
			if out.ReactivatedAt, err = decodeTime(row.ReactivatedAt.String); err != nil {
				return RestoreState{}, fmt.Errorf("authn: decode reactivated_at: %w", err)
			}
		}
		return out, nil
	}
	row, err := r.pg.GetRestoreState(ctx)
	if err != nil {
		return RestoreState{}, fmt.Errorf("authn: read restore state: %w", err)
	}
	out := RestoreState{CredentialEpoch: row.CredentialEpoch, RestoreEpoch: row.RestoreEpoch}
	if row.ReactivatedAt.Valid {
		out.ReactivatedAt = canon(row.ReactivatedAt.Time)
	}
	return out, nil
}

// AdvanceRestoreEpoch is the restore's single act of invalidation: one
// increment, and every artifact carrying a different epoch — password
// verifiers, TOTP seeds, recovery-code batches, WebAuthn credentials, browser
// and CLI sessions, machine bearer credentials, OIDC links, and every
// single-use artifact — becomes inert by predicate rather than by a sweep
// somebody could get half-way through.
//
// The new epoch is NOT the archive's counter + 1: it is one past the LARGEST
// epoch stamp found anywhere in the restored state, and every principal's
// reconciliation stamp is stripped. An archive is forgeable by anyone holding
// the PUBLIC recipient, so an epoch or reconciliation stamp inside it is
// attacker-controlled data; trusting either would let a forged archive plant
// a credential stamped one epoch ahead, or a principal stamped
// pre-reconciled, and have the restore itself activate them (K2: restored
// verifiers never trusted).
//
// It runs INSIDE the restore's own transaction (postgres) or against the
// staged database file before it is published (sqlite), so there is no
// instant at which restored rows are reachable under the old epoch.
func (r *Resolver) AdvanceRestoreEpoch(ctx context.Context, now time.Time) error {
	if r.sq != nil {
		maxEpoch, err := r.sq.MaxKnownCredentialEpoch(ctx)
		if err != nil {
			return fmt.Errorf("authn: read max credential epoch: %w", err)
		}
		next, err := nextEpoch(maxEpoch)
		if err != nil {
			return err
		}
		stamp := encodeTime(now)
		if err := r.sq.AdvanceRestoreEpoch(ctx, sqlitegen.AdvanceRestoreEpochParams{
			CredentialEpoch: next,
			RestoreEpoch:    next,
			ReactivatedAt:   sql.NullString{String: stamp, Valid: true},
			UpdatedAt:       stamp,
		}); err != nil {
			return fmt.Errorf("authn: advance restore epoch: %w", err)
		}
		if err := r.sq.MarkAllPrincipalsUnreconciled(ctx); err != nil {
			return fmt.Errorf("authn: mark principals unreconciled: %w", err)
		}
		return nil
	}
	maxEpoch, err := r.pg.MaxKnownCredentialEpoch(ctx)
	if err != nil {
		return fmt.Errorf("authn: read max credential epoch: %w", err)
	}
	next, err := nextEpoch(maxEpoch)
	if err != nil {
		return err
	}
	if err := r.pg.AdvanceRestoreEpoch(ctx, pggen.AdvanceRestoreEpochParams{
		CredentialEpoch: next,
		RestoreEpoch:    next,
		ReactivatedAt:   pgTime(now),
		UpdatedAt:       pgTime(now),
	}); err != nil {
		return fmt.Errorf("authn: advance restore epoch: %w", err)
	}
	if err := r.pg.MarkAllPrincipalsUnreconciled(ctx); err != nil {
		return fmt.Errorf("authn: mark principals unreconciled: %w", err)
	}
	return nil
}

// InvalidateRestoredAdapterCredentials destroys custody of every restored
// outbound provider credential. A PAT is checked by Forgejo, not Hikyo's
// credential epoch, so an epoch bump alone cannot make a restored PAT inert.
func (r *Resolver) InvalidateRestoredAdapterCredentials(ctx context.Context) error {
	if r.sq != nil {
		if err := r.sq.InvalidateRestoredAdapterCredentials(ctx); err != nil {
			return fmt.Errorf("authn: invalidate restored adapter credentials: %w", err)
		}
		return nil
	}
	if err := r.pg.InvalidateRestoredAdapterCredentials(ctx); err != nil {
		return fmt.Errorf("authn: invalidate restored adapter credentials: %w", err)
	}
	return nil
}

// maxSaneEpoch bounds the epoch a restore will accept from restored state.
// The stamps are archive data — attacker-writable — and an int64 stamp at
// MaxInt64 would wrap the +1 to MinInt64, an epoch value an attacker can also
// plant a credential at. One bump per restore never approaches 2^32 in any
// legitimate history, so anything above it is a forged counter and the
// restore refuses it by name instead of wrapping around it.
const maxSaneEpoch = int64(1) << 32

// nextEpoch parses the MAX() aggregate (sqlc types it interface{} because an
// aggregate is nullable) and refuses shapes it does not recognise rather than
// defaulting: a wrong default here is a live pre-restore credential.
func nextEpoch(maxEpoch any) (int64, error) {
	switch v := maxEpoch.(type) {
	case int64:
		if v < 0 || v > maxSaneEpoch {
			return 0, fmt.Errorf("authn: credential epoch %d in restored state is outside the sane range [0, %d] — forged archive bookkeeping refused", v, maxSaneEpoch)
		}
		return v + 1, nil
	default:
		return 0, fmt.Errorf("authn: max credential epoch has unexpected type %T", maxEpoch)
	}
}

// ReconcilePrincipal commits one principal's reconciliation, restoring its
// grants to force. It takes ONE principal id and returns whether that
// principal existed; there is deliberately no variant taking a set, a filter
// or an "all" flag, at any layer above or below this one.
//
// The commit covers `manual` origins ONLY (#73, scim-provisioning ADR section
// 9.1). Every restored `scim` origin this principal holds is dropped in the
// SAME act, and a grant row whose last origin that was is dropped with it — so
// a user the identity provider deprovisioned after the backup was taken is
// never re-authorized, not even for the window between restore and the IdP's
// next cycle. Re-assertion rebuilds SCIM origins from live truth.
//
// The drop lives HERE, at the one statement every reconciliation routes
// through, rather than in the service: a second commit path added later would
// otherwise silently re-activate what this one refuses.
func (r *Resolver) ReconcilePrincipal(ctx context.Context, p domain.PrincipalID) (bool, error) {
	if err := r.dropRestoredSCIMOrigins(ctx, p); err != nil {
		return false, err
	}
	var n int64
	var err error
	if r.sq != nil {
		n, err = r.sq.ReconcilePrincipal(ctx, string(p))
	} else {
		n, err = r.pg.ReconcilePrincipal(ctx, string(p))
	}
	if err != nil {
		return false, fmt.Errorf("authn: reconcile principal: %w", err)
	}
	return n > 0, nil
}

// dropRestoredSCIMOrigins releases this principal's `scim` origins and deletes
// any grant row they were the last hold on.
//
// It runs unconditionally, not only when a restore is outstanding: a
// reconciliation that is not answering a restore reaches a principal holding
// no restored origins, so the statements match nothing and the act is a no-op.
// Gating it on the restore state would add a read whose only effect is to make
// the guarantee conditional on a second fact being right.
func (r *Resolver) dropRestoredSCIMOrigins(ctx context.Context, p domain.PrincipalID) error {
	// The principal-row lock every grant writer takes (#54 B14): the origin
	// arithmetic below is a read-modify-write over this principal's grant rows,
	// and it has to serialize against every other one.
	// An unknown principal is not an error HERE: ReconcilePrincipal's own row
	// count is what answers "did this principal exist", and reporting it twice
	// with two different shapes is how a caller ends up handling one of them.
	switch err := r.LockPrincipalRow(ctx, p); {
	case err == nil:
	case errors.Is(err, domain.ErrNotFound):
		return nil
	default:
		return err
	}
	if r.sq != nil {
		if _, err := r.sq.DropRestoredSCIMOrigins(ctx, string(p)); err != nil {
			return fmt.Errorf("authn: drop restored scim origins: %w", err)
		}
		if _, err := r.sq.DeleteOriginlessGrantsForPrincipal(ctx, string(p)); err != nil {
			return fmt.Errorf("authn: delete originless grants: %w", err)
		}
		return nil
	}
	if _, err := r.pg.DropRestoredSCIMOrigins(ctx, string(p)); err != nil {
		return fmt.Errorf("authn: drop restored scim origins: %w", err)
	}
	if _, err := r.pg.DeleteOriginlessGrantsForPrincipal(ctx, string(p)); err != nil {
		return fmt.Errorf("authn: delete originless grants: %w", err)
	}
	return nil
}

// UnreconciledPrincipals lists who is still inert. Reading the outstanding
// set is not accepting it — the operator needs to know who is waiting in
// order to reconcile them one at a time.
func (r *Resolver) UnreconciledPrincipals(ctx context.Context) ([]PrincipalRef, error) {
	var out []PrincipalRef
	if r.sq != nil {
		rows, err := r.sq.ListUnreconciledPrincipals(ctx)
		if err != nil {
			return nil, fmt.Errorf("authn: list unreconciled principals: %w", err)
		}
		for _, row := range rows {
			out = append(out, PrincipalRef{ID: domain.PrincipalID(row.ID), Kind: row.Kind})
		}
		return out, nil
	}
	rows, err := r.pg.ListUnreconciledPrincipals(ctx)
	if err != nil {
		return nil, fmt.Errorf("authn: list unreconciled principals: %w", err)
	}
	for _, row := range rows {
		out = append(out, PrincipalRef{ID: domain.PrincipalID(row.ID), Kind: row.Kind})
	}
	return out, nil
}
