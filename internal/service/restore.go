package service

// Restore and its reconciliation (#76, ops spec § 11's restore checklist,
// threat model § Compromise assumptions).
//
// The checklist is one mechanism plus one ceremony.
//
// The MECHANISM is the credential epoch, and it was already built (#47/#54/
// #61): every authentication artifact records the epoch it was created under
// and is inert outside it. A restore advances that epoch once, inside the
// transaction that loads the archive, and in that single act every restored
// password verifier, TOTP seed, recovery-code batch, WebAuthn credential,
// browser session, CLI session, machine bearer credential, OIDC link and
// single-use artifact stops authenticating. Nothing is swept, so nothing can
// be half-swept.
//
// The CEREMONY is reconciliation, and it is what this file adds. Restored
// grants are inert until an operator commits them BACK, one principal at a
// time, having looked at what that principal can reach: a restore rewinds the
// authorization state, so it can resurrect a since-revoked role or a since-
// removed member, and the person who knows whether that is right is not the
// software. There is deliberately no bulk-accept: no set-taking method, no
// `--all` flag, and no HTTP route at all — the drill asserts the absence.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// ErrNoRestorePending reports a reconciliation attempted on an instance that
// has not been restored. It is loud rather than a no-op: "reconciled" would
// be a claim about a ceremony that had no subject.
var ErrNoRestorePending = errors.New("this instance has no outstanding restore to reconcile")

// Restore answers the operator's questions after a restore and performs the
// per-principal reconciliation.
type Restore struct {
	DB *store.DB
}

// Status is what `hikyo restore status` prints: the posture plus who is still
// inert. Listing the outstanding set is not accepting it — the operator has
// to know who is waiting in order to reconcile them one at a time.
type Status struct {
	State   authz.RestoreState
	Pending []authz.PrincipalRef
}

// Status reads the instance's restore posture.
func (s *Restore) Status(ctx context.Context) (Status, error) {
	var out Status
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		state, err := az.RestoreState(ctx)
		if err != nil {
			return err
		}
		out.State = state
		if !state.Restored() {
			return nil
		}
		out.Pending, err = az.UnreconciledPrincipals(ctx)
		return err
	})
	if err != nil {
		return Status{}, fmt.Errorf("service: restore status: %w", err)
	}
	return out, nil
}

// Reconcile commits ONE principal's re-activation and records it.
//
// The signature is the guarantee the ADR asks for: one principal id in, one
// answer out. A caller wanting to reconcile twenty principals calls this
// twenty times and leaves twenty audit events behind, which is the intended
// cost — a single "reconcile everything" would turn an informed assertion
// about each identity into a keystroke.
func (s *Restore) Reconcile(ctx context.Context, target domain.PrincipalID) (Status, error) {
	if target == "" {
		return Status{}, errors.New("reconciliation names exactly one principal")
	}
	var out Status
	err := tx.Reconcile(ctx, s.DB, func(ctx context.Context, az *authz.TxAuthorizer) error {
		state, err := az.RestoreState(ctx)
		if err != nil {
			return err
		}
		if !state.Restored() {
			return ErrNoRestorePending
		}
		found, err := az.ReconcilePrincipal(ctx, target)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("%w: %s", ErrUnknownPrincipal, target)
		}
		pending, err := az.UnreconciledPrincipals(ctx)
		if err != nil {
			return err
		}
		out = Status{State: state, Pending: pending}
		e, err := domainEvent(ctx, audit.EventRestorePrincipalReconciled, "",
			audit.Object{Type: "principal", ID: string(target)}, audit.Payload{
				"target_principal":   string(target),
				"restore_epoch":      state.RestoreEpoch,
				"pending_principals": int64(len(pending)),
				"authority":          "local-host",
			})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
	if err != nil {
		return Status{}, err
	}
	return out, nil
}

// CompleteRestore is the closure the restore transaction runs against the
// restored state, before it is committed or published. It advances the
// credential epoch and writes the reconstruction record in that same act.
//
// It is a package-level function rather than a method because it has no
// datastore of its own to hold: the whole point is that it runs on somebody
// else's transaction.
func CompleteRestore(now time.Time, m store.Manifest) tx.RestoreFn {
	return func(ctx context.Context, az *authz.TxAuthorizer) error {
		if err := az.AdvanceRestoreEpoch(ctx, now); err != nil {
			return err
		}
		state, err := az.RestoreState(ctx)
		if err != nil {
			return err
		}
		if !state.Restored() {
			// Unreachable unless the bump silently did nothing, which would
			// mean publishing an instance whose pre-restore credentials still
			// authenticate. Refuse rather than commit that.
			return errors.New("service: restore did not advance the credential epoch — refusing to publish a restored instance with live pre-restore credentials")
		}
		pending, err := az.UnreconciledPrincipals(ctx)
		if err != nil {
			return err
		}
		e, err := domainEvent(ctx, audit.EventRestoreCompleted, "",
			audit.Object{Type: "instance", ID: string(m.Engine)}, audit.Payload{
				"engine":             string(m.Engine),
				"schema_version":     m.SchemaVersion,
				"credential_epoch":   state.CredentialEpoch,
				"restore_epoch":      state.RestoreEpoch,
				"pending_principals": int64(len(pending)),
				"authority":          "local-host",
			})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	}
}
