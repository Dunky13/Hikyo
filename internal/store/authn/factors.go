package authn

import (
	"context"
	"database/sql"
	"time"

	"github.com/Dunky13/wenv/internal/store/pggen"
	"github.com/Dunky13/wenv/internal/store/sqlitegen"
)

// Factor storage (#54, human-auth ADR § Factors). TOTP seeds and recovery-code
// batches are envelope-encrypted by the service before they reach here; this
// layer owns only the enumerated reads and writes, each pinned by the
// sole-writer analyzer like every other member of the resolution surface.

// TOTPCredential is a resolved TOTP factor. Seed is the sealed record; the
// service opens it under the instance DEK.
type TOTPCredential struct {
	ID              string
	AccountID       string
	Seed            []byte
	DEKVersion      int64
	CredentialEpoch int64
	RowVersion      int64
	LastStep        int64
	CreatedStep     int64
	Confirmed       bool
	CreatedAt       time.Time
}

// NewTOTPCredential is the insert carrier for a pending enrolment.
type NewTOTPCredential struct {
	ID              string
	AccountID       string
	Seed            []byte
	DEKVersion      int64
	CredentialEpoch int64
	CreatedStep     int64
	CreatedAt       time.Time
}

// RecoveryBatch is a resolved recovery-code batch: the sealed set of verifiers
// plus the CAS target.
type RecoveryBatch struct {
	AccountID       string
	Batch           []byte
	DEKVersion      int64
	CredentialEpoch int64
	RowVersion      int64
	GeneratedAt     time.Time
}

func sqliteTOTP(row sqlitegen.TotpCredential) (TOTPCredential, error) {
	created, err := decodeTime(row.CreatedAt)
	if err != nil {
		return TOTPCredential{}, err
	}
	return TOTPCredential{
		ID: row.ID, AccountID: row.AccountID, Seed: row.Seed, DEKVersion: row.DekVersion,
		CredentialEpoch: row.CredentialEpoch, RowVersion: row.RowVersion,
		LastStep: row.LastStep, CreatedStep: row.CreatedStep,
		Confirmed: row.ConfirmedAt.Valid, CreatedAt: created,
	}, nil
}

func pgTOTP(row pggen.TotpCredential) TOTPCredential {
	return TOTPCredential{
		ID: row.ID, AccountID: row.AccountID, Seed: row.Seed, DEKVersion: row.DekVersion,
		CredentialEpoch: row.CredentialEpoch, RowVersion: row.RowVersion,
		LastStep: row.LastStep, CreatedStep: row.CreatedStep,
		Confirmed: row.ConfirmedAt.Valid, CreatedAt: row.CreatedAt.Time,
	}
}

// ConfirmedTOTP resolves an account's confirmed TOTP factor, or
// domain.ErrNotFound when none is enrolled. The partial unique index makes
// this at most one row.
func (r *Resolver) ConfirmedTOTP(ctx context.Context, accountID string) (TOTPCredential, error) {
	if r.sq != nil {
		row, err := r.sq.GetConfirmedTOTPForAccount(ctx, accountID)
		if err != nil {
			return TOTPCredential{}, notFoundOr(err)
		}
		return sqliteTOTP(row)
	}
	row, err := r.pg.GetConfirmedTOTPForAccount(ctx, accountID)
	if err != nil {
		return TOTPCredential{}, notFoundOr(err)
	}
	return pgTOTP(row), nil
}

// PendingTOTP resolves an account's in-progress (unconfirmed) enrolment.
func (r *Resolver) PendingTOTP(ctx context.Context, accountID string) (TOTPCredential, error) {
	if r.sq != nil {
		row, err := r.sq.GetPendingTOTPForAccount(ctx, accountID)
		if err != nil {
			return TOTPCredential{}, notFoundOr(err)
		}
		return sqliteTOTP(row)
	}
	row, err := r.pg.GetPendingTOTPForAccount(ctx, accountID)
	if err != nil {
		return TOTPCredential{}, notFoundOr(err)
	}
	return pgTOTP(row), nil
}

// CreateTOTP inserts a pending enrolment. last_step is seeded at created_step
// so a confirming code can never predate the row.
func (r *Resolver) CreateTOTP(ctx context.Context, c NewTOTPCredential) error {
	if r.sq != nil {
		return r.sq.InsertTOTP(ctx, sqlitegen.InsertTOTPParams{
			ID: c.ID, AccountID: c.AccountID, Seed: c.Seed, DekVersion: c.DEKVersion,
			CredentialEpoch: c.CredentialEpoch, LastStep: c.CreatedStep,
			CreatedStep: c.CreatedStep, CreatedAt: encodeTime(c.CreatedAt),
		})
	}
	return r.pg.InsertTOTP(ctx, pggen.InsertTOTPParams{
		ID: c.ID, AccountID: c.AccountID, Seed: c.Seed, DekVersion: c.DEKVersion,
		CredentialEpoch: c.CredentialEpoch, LastStep: c.CreatedStep,
		CreatedStep: c.CreatedStep, CreatedAt: pgTime(c.CreatedAt),
	})
}

// ConfirmTOTP promotes a pending enrolment and consumes the confirming step in
// one CAS. It reports false when the row moved or the step was not beyond the
// last one.
func (r *Resolver) ConfirmTOTP(ctx context.Context, id string, rowVersion, step int64, at time.Time) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.ConfirmTOTP(ctx, sqlitegen.ConfirmTOTPParams{
			ConfirmedAt: sql.NullString{String: encodeTime(at), Valid: true},
			LastStep:    step, ID: id, RowVersion: rowVersion, LastStep_2: step,
		})
		return n == 1, err
	}
	n, err := r.pg.ConfirmTOTP(ctx, pggen.ConfirmTOTPParams{
		ConfirmedAt: pgTime(at), LastStep: step, ID: id, RowVersion: rowVersion, LastStep_2: step,
	})
	return n == 1, err
}

// AdvanceTOTPStep consumes a code's step. It reports false when the step was
// not strictly beyond the last consumed one — the single-use guard.
func (r *Resolver) AdvanceTOTPStep(ctx context.Context, id string, rowVersion, step int64) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.AdvanceTOTPStep(ctx, sqlitegen.AdvanceTOTPStepParams{
			LastStep: step, ID: id, RowVersion: rowVersion, LastStep_2: step,
		})
		return n == 1, err
	}
	n, err := r.pg.AdvanceTOTPStep(ctx, pggen.AdvanceTOTPStepParams{
		LastStep: step, ID: id, RowVersion: rowVersion, LastStep_2: step,
	})
	return n == 1, err
}

// DeleteTOTPForAccount removes every TOTP row of an account (confirmed and
// pending alike) — factor removal, and the cleanup a fresh enrolment does
// first so a stale pending row cannot accumulate.
func (r *Resolver) DeleteTOTPForAccount(ctx context.Context, accountID string) error {
	if r.sq != nil {
		return r.sq.DeleteTOTPForAccount(ctx, accountID)
	}
	return r.pg.DeleteTOTPForAccount(ctx, accountID)
}

// DeletePendingTOTPForAccount clears only in-progress enrolments, leaving a
// confirmed factor standing.
func (r *Resolver) DeletePendingTOTPForAccount(ctx context.Context, accountID string) error {
	if r.sq != nil {
		return r.sq.DeletePendingTOTPForAccount(ctx, accountID)
	}
	return r.pg.DeletePendingTOTPForAccount(ctx, accountID)
}

// RecoveryCodes resolves an account's batch, or domain.ErrNotFound when none.
func (r *Resolver) RecoveryCodes(ctx context.Context, accountID string) (RecoveryBatch, error) {
	if r.sq != nil {
		row, err := r.sq.GetRecoveryCodes(ctx, accountID)
		if err != nil {
			return RecoveryBatch{}, notFoundOr(err)
		}
		gen, err := decodeTime(row.GeneratedAt)
		if err != nil {
			return RecoveryBatch{}, err
		}
		return RecoveryBatch{
			AccountID: row.AccountID, Batch: row.Batch, DEKVersion: row.DekVersion,
			CredentialEpoch: row.CredentialEpoch, RowVersion: row.RowVersion, GeneratedAt: gen,
		}, nil
	}
	row, err := r.pg.GetRecoveryCodes(ctx, accountID)
	if err != nil {
		return RecoveryBatch{}, notFoundOr(err)
	}
	return RecoveryBatch{
		AccountID: row.AccountID, Batch: row.Batch, DEKVersion: row.DekVersion,
		CredentialEpoch: row.CredentialEpoch, RowVersion: row.RowVersion, GeneratedAt: row.GeneratedAt.Time,
	}, nil
}

// CreateRecoveryCodes writes the first batch for an account.
func (r *Resolver) CreateRecoveryCodes(ctx context.Context, b RecoveryBatch, at time.Time) error {
	if r.sq != nil {
		return r.sq.InsertRecoveryCodes(ctx, sqlitegen.InsertRecoveryCodesParams{
			AccountID: b.AccountID, Batch: b.Batch, DekVersion: b.DEKVersion,
			CredentialEpoch: b.CredentialEpoch, GeneratedAt: encodeTime(at),
		})
	}
	return r.pg.InsertRecoveryCodes(ctx, pggen.InsertRecoveryCodesParams{
		AccountID: b.AccountID, Batch: b.Batch, DekVersion: b.DEKVersion,
		CredentialEpoch: b.CredentialEpoch, GeneratedAt: pgTime(at),
	})
}

// UpdateRecoveryCodes compare-and-swaps the batch on RowVersion — regeneration
// and single-code consumption both rewrite it, and a losing CAS fails closed.
func (r *Resolver) UpdateRecoveryCodes(ctx context.Context, b RecoveryBatch, at time.Time) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.UpdateRecoveryCodesCAS(ctx, sqlitegen.UpdateRecoveryCodesCASParams{
			Batch: b.Batch, DekVersion: b.DEKVersion, CredentialEpoch: b.CredentialEpoch,
			GeneratedAt: encodeTime(at), AccountID: b.AccountID, RowVersion: b.RowVersion,
		})
		return n == 1, err
	}
	n, err := r.pg.UpdateRecoveryCodesCAS(ctx, pggen.UpdateRecoveryCodesCASParams{
		Batch: b.Batch, DekVersion: b.DEKVersion, CredentialEpoch: b.CredentialEpoch,
		GeneratedAt: pgTime(at), AccountID: b.AccountID, RowVersion: b.RowVersion,
	})
	return n == 1, err
}

// RotateSessionFactors gives the acting session a new verifier and factor set
// on step-up. The old verifier is gone in the same statement, and the
// authenticated_at / ceremony_id columns are untouched so the original
// authentication's attribution stands.
func (r *Resolver) RotateSessionFactors(ctx context.Context, id string, verifier []byte, factors string) error {
	if r.sq != nil {
		return r.sq.RotateSessionFactors(ctx, sqlitegen.RotateSessionFactorsParams{
			Verifier: verifier, Factors: factors, ID: id,
		})
	}
	return r.pg.RotateSessionFactors(ctx, pggen.RotateSessionFactorsParams{
		Verifier: verifier, Factors: factors, ID: id,
	})
}

// ConsumeOutstandingAuthorities marks every unconsumed establishment authority
// of an account consumed. It runs in the same transaction as a fresh mint or
// consumption, so a second live reset token cannot linger.
func (r *Resolver) ConsumeOutstandingAuthorities(ctx context.Context, accountID string, at time.Time) error {
	if r.sq != nil {
		return r.sq.ConsumeOutstandingAuthoritiesForAccount(ctx, sqlitegen.ConsumeOutstandingAuthoritiesForAccountParams{
			ConsumedAt: sql.NullString{String: encodeTime(at), Valid: true}, AccountID: accountID,
		})
	}
	return r.pg.ConsumeOutstandingAuthoritiesForAccount(ctx, pggen.ConsumeOutstandingAuthoritiesForAccountParams{
		ConsumedAt: pgTime(at), AccountID: accountID,
	})
}
