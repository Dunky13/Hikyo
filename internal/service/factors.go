package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/admission"
	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// Factor service (#54, human-auth ADR § Factors, § Account-security mutations).
//
// Three shapes live here, and the phase discipline is the reason they are not
// one another:
//
//   - Account-security mutations (TOTP enrol/confirm/remove, recovery-code
//     regenerate). Each verifies a pre-existing credential that predates the
//     mutation, then in ONE write tx performs the change, advances the
//     principal's generation, deletes every session, and reissues the acting
//     session SOLELY from the proof ceremony (finding B3). A password proof is
//     an Argon2id derivation, so it runs BETWEEN two transactions exactly like
//     LocalLogin — holding sqlite's single writer for that derivation would be
//     a denial of service.
//   - Step-up. Not an account-security mutation: it elevates the acting session
//     in place, rotating its token and appending a factor class, preserving the
//     original authenticated_at/ceremony (finding A21). No generation advance,
//     no session deletion.
//   - Recovery-code consumption. Pre-auth, session-less: it mints a
//     credential-establishment authority and NOTHING else — no session, no
//     assurance, no window (the A1 mid-reset invariant depends on that
//     artifact being provably session-less). It rides the admission budget and
//     answers uniformly, like LocalLogin.

// RecoveryBatchSize is how many single-use recovery codes a batch holds.
const RecoveryBatchSize = 10

// TOTPIssuer is the label shown in the authenticator app's account list. There
// is no per-instance issuer string in this slice; when instance naming lands it
// supplies this.
// ponytail: fixed issuer label; swap for the instance name once one exists.
const TOTPIssuer = "hikyo"

// Structural factor refusals are loud (400), because the caller is
// authenticated and acting on their OWN account: naming the state helps them
// and reveals nothing to anyone else. A bad code or password stays uniform
// (401, domain.ErrUnauthenticated) so presentation reveals nothing.
var (
	// ErrTOTPAlreadyEnrolled refuses a second confirmed TOTP factor.
	ErrTOTPAlreadyEnrolled = errors.New("service: a confirmed TOTP factor is already enrolled")
	// ErrNoPendingTOTP refuses a confirm with no enrolment in progress.
	ErrNoPendingTOTP = errors.New("service: no TOTP enrolment is in progress")
	// ErrNoTOTPFactor refuses a step-up or removal with no confirmed factor.
	ErrNoTOTPFactor = errors.New("service: no confirmed TOTP factor")
	// ErrNoProofCredential refuses a mutation the account has no pre-existing
	// credential to authorize.
	ErrNoProofCredential = errors.New("service: no pre-existing credential to authorize this change")
	// ErrTOTPCodeAlreadyUsed refuses a code whose (account, time step) was
	// already consumed by an earlier proof — the SAME code presented twice in
	// its 30-second window (human-auth ADR §141 single-use-per-step, §207 the
	// second disclosure waits for the next step). It wraps domain.ErrConflict, a
	// LOUD post-authentication state refusal on the caller's OWN factor that
	// discloses nothing (a stolen session already knows it just spent the code):
	// classify() maps it to 409 and the uniform writer carries its SafeDetail,
	// unlike the uniform 401 a WRONG code returns.
	ErrTOTPCodeAlreadyUsed = fmt.Errorf("%w: this TOTP code's time step was already used", domain.ErrConflict)
)

// totpCodeAlreadyUsedDetail is the caller-safe wire detail for
// ErrTOTPCodeAlreadyUsed: it names the state and the recovery (wait for the next
// code) without disclosing anything the caller could not already see.
const totpCodeAlreadyUsedDetail = "this authenticator code was already used for its time step; wait for the next code"

// totpStepAlreadyUsed builds the already-used refusal carrying its safe detail,
// following the ProtectedDestinationRefusal pattern (a domain sentinel wrapped
// with a SafeDetail the uniform writer honours for conflict).
func totpStepAlreadyUsed() error {
	return &detailErr{detail: totpCodeAlreadyUsedDetail, err: ErrTOTPCodeAlreadyUsed}
}

// totpStepConsumed reports whether a failed step CAS (ConfirmTOTP/AdvanceTOTPStep
// returning false) was caused by the presented step already being spent, rather
// than by the row moving underneath the CAS. It re-reads the account's confirmed
// factor inside the same transaction: the SAME row id with last_step at or beyond
// the presented step means this exact code was already used for its window. A row
// that moved (a concurrent replace, finding HIGH-5) reads as a different id or is
// gone and stays the uniform refusal — never the loud already-used sentinel.
func (s *Auth) totpStepConsumed(ctx context.Context, az *authz.TxAuthorizer, accountID, rowID string, step int64) bool {
	cur, err := az.ConfirmedTOTP(ctx, accountID)
	return err == nil && cur.ID == rowID && cur.LastStep >= step
}

// totpSeedAAD binds a sealed seed to the row that owns it.
func totpSeedAAD(totpRowID string) crypto.InstanceFieldAAD {
	return crypto.InstanceFieldAAD{OwnerTable: "totp_credentials", OwnerRowID: totpRowID, FieldTag: "seed"}
}

// recoveryBatchAAD binds a sealed recovery batch to its account.
func recoveryBatchAAD(accountID string) crypto.InstanceFieldAAD {
	return crypto.InstanceFieldAAD{OwnerTable: "recovery_codes", OwnerRowID: accountID, FieldTag: "batch"}
}

// verifyPassword opens an account's sealed verifier and checks a candidate,
// outside any transaction. A verifier that will not open is a fault, logged and
// answered as the uniform refusal — never a 500 while a wrong password is a 401,
// which would be an existence oracle.
func (s *Auth) verifyPassword(ctx context.Context, accountID string, cred authz.PasswordCredential, password string) bool {
	plain, err := s.Keyring.ForInstance().OpenField(verifierAAD(accountID), cred.Verifier)
	if err != nil {
		s.logFault(ctx, "opening a password verifier failed", err, accountID)
		crypto.BurnDummyVerification([]byte(password), s.KDF)
		return false
	}
	ok := crypto.VerifyPassword([]byte(password), plain, crypto.PasswordParams(cred.KDF))
	crypto.Zero(plain)
	return ok
}

// enterFactorBudget applies LocalLogin's admission discipline to a
// proof/validation ceremony on an already-authenticated account. The
// per-account backoff is checked BEFORE the expensive-work semaphore, so a
// backed-off account never occupies a slot while it sleeps; the key is the
// canonical account id, never the session, because an attacker holding a stolen
// session can open many and keying on the session would be bypassable. Both a
// wrong password (Argon2, 64 MiB) and a wrong TOTP code go through here — the
// first to bound resource exhaustion, the second to bound online brute force of
// a six-digit code whose skew window admits roughly three valid values.
func (s *Auth) enterFactorBudget(ctx context.Context, accountID string) (func(), error) {
	if delay := s.Admission.AccountDelay(accountID); delay > 0 {
		return nil, admission.ErrOverloaded
	}
	return s.Admission.Enter(ctx, audit.FromContext(ctx).SourceIP)
}

// recordFactorFailure feeds a failed proof into the per-account backoff and, on
// a threshold crossing, emits the throttle event. Per-attempt failures are NOT
// individually audited: a durable write per attempt is the audit amplification
// the threat model forbids under a flood, so — exactly as LocalLogin does — the
// aggregated threshold crossing is the visibility, and the backoff is the
// defence.
func (s *Auth) recordFactorFailure(ctx context.Context, principal domain.PrincipalID, accountID string) {
	if crossed := s.Admission.RecordFailure(accountID); crossed {
		s.recordFactorThrottleCrossing(ctx, principal, accountID)
	}
}

// recordFactorThrottleCrossing emits the throttle event for an authenticated
// account whose backoff threshold was crossed. Best-effort for the caller — the
// request is already refused — but never silent: a swallowed error would hide a
// crossing nobody sees.
func (s *Auth) recordFactorThrottleCrossing(ctx context.Context, principal domain.PrincipalID, accountID string) {
	err := tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		e, err := newAuditEvent(ctx, audit.EventAuthThrottleCrossed, principal,
			audit.Object{Type: "account", ID: accountID}, audit.OutcomeFailure, "",
			audit.Payload{"scope": "account", "subject_resolved": true, "account_id": accountID})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
	if err != nil {
		s.logFault(ctx, "recording a factor throttle threshold crossing failed", err, accountID)
	}
}

// reissueSession is the write-phase half of every account-security mutation:
// advance the generation, delete every session, and mint a fresh acting session
// built SOLELY from the proof ceremony (finding B3) — one factor class, a fresh
// authenticated_at, this instant's generation and epoch. The generation is read
// AFTER the advance so the new session is born live rather than one generation
// behind and dead on arrival.
//
// The TOTP/recovery mutations reissue a CLI/local-password session; the WebAuthn
// mutations run on a browser session, so the acting artifact and the proof's
// method/class are threaded in rather than assumed (a browser reissue also mints
// a fresh CSRF verifier). The assurance is built solely from the proof (B3).
func (s *Auth) reissueSession(ctx context.Context, az *authz.TxAuthorizer, account authz.Account, factorClass, method string, artifact Artifact, now time.Time) (LoginResult, error) {
	if err := az.AdvanceGeneration(ctx, account.PrincipalID); err != nil {
		return LoginResult{}, err
	}
	if err := az.RevokeAllSessionsFor(ctx, account.PrincipalID); err != nil {
		return LoginResult{}, err
	}
	generation, err := az.PrincipalGeneration(ctx, account.PrincipalID)
	if err != nil {
		return LoginResult{}, err
	}
	epoch, err := az.CredentialEpoch(ctx)
	if err != nil {
		return LoginResult{}, err
	}
	value, verifier, err := crypto.NewArtifact(artifact.bearerKind())
	if err != nil {
		return LoginResult{}, err
	}
	var csrfValue string
	var csrfVerifier []byte
	if artifact == ArtifactBrowser {
		csrfValue, csrfVerifier, err = crypto.NewArtifact(crypto.ArtifactCSRF)
		if err != nil {
			return LoginResult{}, err
		}
	}
	id, err := newID("ses")
	if err != nil {
		return LoginResult{}, err
	}
	factors, err := json.Marshal([]string{factorClass})
	if err != nil {
		return LoginResult{}, err
	}
	wire := audit.FromContext(ctx)
	sess := authz.NewSession{
		ID: id, PrincipalID: account.PrincipalID, Verifier: verifier,
		Artifact: artifact.String(), SessionGeneration: generation, CredentialEpoch: epoch,
		AuthMethod: method, Factors: string(factors),
		AuthenticatedAt: now, CreatedAt: now,
		IdleExpiresAt: now.Add(artifact.idle()), AbsoluteExpiresAt: now.Add(artifact.absolute()),
		SourceIP: wire.SourceIP, UserAgent: wire.UserAgent,
		CSRFVerifier: csrfVerifier,
	}
	if err := az.MintSession(ctx, sess); err != nil {
		return LoginResult{}, err
	}
	assuranceLabel := "single-factor"
	if factorClass == "webauthn" {
		assuranceLabel = "multi-factor"
	}
	e, err := newAuditEvent(ctx, audit.EventAuthSessionCreated, account.PrincipalID,
		audit.Object{Type: "session", ID: id}, audit.OutcomeSuccess, "",
		audit.Payload{
			"session_id": id, "artifact": artifact.String(),
			"method": method, "assurance": assuranceLabel,
		})
	if err != nil {
		return LoginResult{}, err
	}
	if err := az.RecordAuthEvent(ctx, e); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		SessionToken: value, SessionID: id, Artifact: artifact,
		CreatedAt: now, IdleExpires: sess.IdleExpiresAt, AbsExpires: sess.AbsoluteExpiresAt,
		Principal: account.PrincipalID, AccountID: account.ID, DisplayName: account.DisplayName,
		Assurance: Assurance{Method: method, Factors: []string{factorClass}, AuthenticatedAt: now},
		CSRFToken: csrfValue,
	}, nil
}

// TOTPStatusResult is the caller's own authenticator state: whether a confirmed
// factor stands and whether an enrolment is staged but unconfirmed.
type TOTPStatusResult struct {
	Confirmed bool
	Pending   bool
}

// TOTPStatus reads the caller's OWN authenticator state. It is a pure read that
// mutates nothing and advances no generation. It reveals only what a caller
// could already learn by attempting an enrolment — a second start is refused by
// name — so the account surface can state the fact instead of disclaiming it.
func (s *Auth) TOTPStatus(ctx context.Context, presented string) (TOTPStatusResult, error) {
	var status TOTPStatusResult
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		id, err := az.Authenticate(ctx, presented, s.now())
		if err != nil {
			return err
		}
		account, err := az.AccountByPrincipal(ctx, id.Principal)
		if err != nil {
			return err
		}
		if _, err := az.ConfirmedTOTP(ctx, account.ID); err == nil {
			status.Confirmed = true
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		// A pending row is only "pending" while it is still finishable. Confirm
		// binds the seed to its start ceremony by the same window (a stale or
		// future-stamped row is refused there), so reporting an expired one as
		// pending would promise a completion the server would reject.
		if p, err := az.PendingTOTP(ctx, account.ID); err == nil {
			age := s.now().Sub(p.CreatedAt)
			status.Pending = age >= 0 && age <= AuthorityLifetime
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		return nil
	})
	if err != nil {
		return TOTPStatusResult{}, err
	}
	return status, nil
}

// EnrolTOTPStart verifies the account-security proof (the pre-existing password,
// since no possession factor stands yet), stages a fresh sealed seed as a
// pending enrolment, and returns the otpauth URI ONCE. It performs no
// account-security mutation — the pending row is inert and proves nothing until
// EnrolTOTPConfirm completes it — so it advances no generation and reissues no
// session (finding B2).
func (s *Auth) EnrolTOTPStart(ctx context.Context, presented, password string) (string, error) {
	// Phase 1 — read.
	var (
		account authz.Account
		cred    authz.PasswordCredential
	)
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		id, err := az.Authenticate(ctx, presented, s.now())
		if err != nil {
			return err
		}
		account, err = az.AccountByPrincipal(ctx, id.Principal)
		if err != nil {
			return err
		}
		if _, err := az.ConfirmedTOTP(ctx, account.ID); err == nil {
			return ErrTOTPAlreadyEnrolled
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		cred, err = az.PasswordCredentialFor(ctx, account.ID)
		if errors.Is(err, domain.ErrNotFound) {
			return ErrNoProofCredential
		}
		return err
	})
	if err != nil {
		return "", err
	}

	// Admission: a stolen session must not be an unthrottled Argon2 oracle or a
	// lever to exhaust the expensive-work budget.
	release, err := s.enterFactorBudget(ctx, account.ID)
	if err != nil {
		return "", err
	}
	defer release()

	// Phase 2 — verify the password proof, outside any transaction.
	if !s.verifyPassword(ctx, account.ID, cred, password) {
		s.recordFactorFailure(ctx, account.PrincipalID, account.ID)
		return "", domain.ErrUnauthenticated
	}
	s.Admission.RecordSuccess(account.ID)

	// Seal the seed under the row it will own, so the id is minted first.
	rawSeed, err := crypto.NewTOTPSeed()
	if err != nil {
		return "", err
	}
	defer crypto.Zero(rawSeed)
	totpID, err := newID("totp")
	if err != nil {
		return "", err
	}
	sealer := s.Keyring.ForInstance()
	sealed, err := sealer.SealField(totpSeedAAD(totpID), rawSeed)
	if err != nil {
		return "", err
	}

	// Phase 3 — write. Re-read the proof credential: it must not have moved
	// while we derived, and the epoch must still be live.
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		now := s.now()
		current, err := az.PasswordCredentialFor(ctx, account.ID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return domain.ErrUnauthenticated
			}
			return err
		}
		liveEpoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		if current.RowVersion != cred.RowVersion || current.CredentialEpoch != liveEpoch {
			return domain.ErrUnauthenticated
		}
		if _, err := az.ConfirmedTOTP(ctx, account.ID); err == nil {
			return ErrTOTPAlreadyEnrolled
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		// A prior abandoned enrolment must not accumulate.
		if err := az.ClearPendingTOTP(ctx, account.ID); err != nil {
			return err
		}
		// Writer fence (invariant 7): refuse if a rotate-dek --instance retired
		// the version the seed was sealed under. This INSERT has no row_version
		// CAS, so the fence is the only guard against stranding it.
		if err := az.AssertActiveInstanceDEKVersion(ctx, int64(sealer.Version())); err != nil {
			return err
		}
		return az.CreateTOTP(ctx, authz.NewTOTPCredential{
			ID: totpID, AccountID: account.ID, Seed: sealed,
			DEKVersion: int64(sealer.Version()), CredentialEpoch: liveEpoch,
			CreatedStep: crypto.TOTPStep(now), CreatedAt: now,
		})
	})
	if err != nil {
		return "", err
	}
	return crypto.TOTPProvisioningURI(TOTPIssuer, account.Username, rawSeed), nil
}

// EnrolTOTPConfirm consumes a valid code against the pending seed and completes
// the enrolment as an account-security mutation: the pending row is promoted
// (CAS on its step, so the confirming code is single-use like every other),
// then the generation advances, every session is deleted, and the acting
// session is reissued carrying ONLY the proof class (password) — NOT totp. The
// user steps up separately to present the factor they just enrolled (B2/B3).
func (s *Auth) EnrolTOTPConfirm(ctx context.Context, presented, code string) (LoginResult, error) {
	// Phase 1 — read.
	var (
		account authz.Account
		pending authz.TOTPCredential
	)
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		id, err := az.Authenticate(ctx, presented, s.now())
		if err != nil {
			return err
		}
		account, err = az.AccountByPrincipal(ctx, id.Principal)
		if err != nil {
			return err
		}
		pending, err = az.PendingTOTP(ctx, account.ID)
		if errors.Is(err, domain.ErrNotFound) {
			return ErrNoPendingTOTP
		}
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}

	// A pending enrolment is bound to its start ceremony by a short expiry: an
	// old seed cannot be completed indefinitely by a later session (finding
	// HIGH-4). A password change between start and confirm additionally kills
	// the session, which the write-phase re-authentication below catches.
	if s.now().Sub(pending.CreatedAt) > AuthorityLifetime {
		return LoginResult{}, ErrNoPendingTOTP
	}

	// Admission: bound online brute force of the confirming code.
	release, err := s.enterFactorBudget(ctx, account.ID)
	if err != nil {
		return LoginResult{}, err
	}
	defer release()

	// Phase 2 — verify the code against the sealed seed.
	seed, err := s.Keyring.ForInstance().OpenField(totpSeedAAD(pending.ID), pending.Seed)
	if err != nil {
		s.logFault(ctx, "opening a TOTP seed failed", err, account.ID)
		return LoginResult{}, domain.ErrUnauthenticated
	}
	step, ok := crypto.ValidateTOTP(seed, code, s.now(), crypto.TOTPSkewSteps)
	crypto.Zero(seed)
	if !ok {
		s.recordFactorFailure(ctx, account.PrincipalID, account.ID)
		return LoginResult{}, domain.ErrUnauthenticated
	}
	s.Admission.RecordSuccess(account.ID)

	// Phase 3 — write: promote (single-use CAS), then reissue.
	var result LoginResult
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		now := s.now()
		// Re-authenticate inside the write tx: a session revoked between the
		// phases (a concurrent recovery or password change) must not be able to
		// complete the enrolment and reissue itself (finding HIGH-3).
		live, err := az.Authenticate(ctx, presented, now)
		if err != nil {
			return err
		}
		if live.Principal != account.PrincipalID {
			return domain.ErrUnauthenticated
		}
		// Re-check the enrolment's expiry against the write-tx clock (finding
		// R2 R1-4): the earlier check raced the write-lock wait, so a request
		// delayed past the window could otherwise still promote. A pending row
		// stamped in the future (clock moved backward) is refused rather than
		// granted extended life.
		age := now.Sub(pending.CreatedAt)
		if age < 0 || age > AuthorityLifetime {
			return domain.ErrUnauthenticated
		}
		// CAS on the row whose seed was VERIFIED, not a freshly read one: a
		// concurrent start that cleared and re-inserted the pending row must not
		// have its replacement promoted by a code proved against the old seed
		// (finding HIGH-5). A mismatch fails the CAS and refuses.
		promoted, err := az.ConfirmTOTP(ctx, pending.ID, pending.RowVersion, step, now)
		if err != nil {
			return err
		}
		if !promoted {
			// The row moved or the step was already consumed: single-use holds. A
			// step already spent on the SAME row is named for the caller; a moved
			// row (a concurrent replace) stays the uniform refusal.
			if s.totpStepConsumed(ctx, az, account.ID, pending.ID, step) {
				return totpStepAlreadyUsed()
			}
			return domain.ErrUnauthenticated
		}
		result, err = s.reissueSession(ctx, az, account, "password", MethodLocalPassword, Artifact(live.Artifact), now)
		if err != nil {
			return err
		}
		e, err := newAuditEvent(ctx, audit.EventAuthFactorEnrolled, account.PrincipalID,
			audit.Object{Type: "account", ID: account.ID}, audit.OutcomeSuccess, "",
			audit.Payload{"factor": "totp", "account_id": account.ID, "authorizing_credential": "password"})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
	if err != nil {
		return LoginResult{}, err
	}
	return result, nil
}

// RemoveTOTP removes the confirmed factor. The mutated credential is excluded
// from the proof set (finding B7), so with no OTHER possession factor the proof
// is the password — a stolen phone alone cannot drop the very factor it is
// (never accept the factor being removed to authorize its own removal). It
// reissues the acting session carrying only the password class.
func (s *Auth) RemoveTOTP(ctx context.Context, presented, password string) (LoginResult, error) {
	// Phase 1 — read.
	var (
		account authz.Account
		cred    authz.PasswordCredential
	)
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		id, err := az.Authenticate(ctx, presented, s.now())
		if err != nil {
			return err
		}
		account, err = az.AccountByPrincipal(ctx, id.Principal)
		if err != nil {
			return err
		}
		if _, err := az.ConfirmedTOTP(ctx, account.ID); errors.Is(err, domain.ErrNotFound) {
			return ErrNoTOTPFactor
		} else if err != nil {
			return err
		}
		cred, err = az.PasswordCredentialFor(ctx, account.ID)
		if errors.Is(err, domain.ErrNotFound) {
			return ErrNoProofCredential
		}
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}

	// Admission: a stolen session must not be an unthrottled Argon2 oracle.
	release, err := s.enterFactorBudget(ctx, account.ID)
	if err != nil {
		return LoginResult{}, err
	}
	defer release()

	// Phase 2 — verify the password proof, outside any transaction.
	if !s.verifyPassword(ctx, account.ID, cred, password) {
		s.recordFactorFailure(ctx, account.PrincipalID, account.ID)
		return LoginResult{}, domain.ErrUnauthenticated
	}
	s.Admission.RecordSuccess(account.ID)

	// Phase 3 — write.
	var result LoginResult
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		now := s.now()
		// Re-authenticate inside the write tx: a session revoked between the
		// phases must not remove a factor and reissue itself (finding HIGH-3).
		live, err := az.Authenticate(ctx, presented, now)
		if err != nil {
			return err
		}
		if live.Principal != account.PrincipalID {
			return domain.ErrUnauthenticated
		}
		current, err := az.PasswordCredentialFor(ctx, account.ID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return domain.ErrUnauthenticated
			}
			return err
		}
		liveEpoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		if current.RowVersion != cred.RowVersion || current.CredentialEpoch != liveEpoch {
			return domain.ErrUnauthenticated
		}
		if err := az.RemoveTOTPForAccount(ctx, account.ID); err != nil {
			return err
		}
		result, err = s.reissueSession(ctx, az, account, "password", MethodLocalPassword, Artifact(live.Artifact), now)
		if err != nil {
			return err
		}
		e, err := newAuditEvent(ctx, audit.EventAuthFactorRemoved, account.PrincipalID,
			audit.Object{Type: "account", ID: account.ID}, audit.OutcomeSuccess, "",
			audit.Payload{"factor": "totp", "account_id": account.ID, "authorizing_credential": "password"})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
	if err != nil {
		return LoginResult{}, err
	}
	return result, nil
}

// StepUpTOTP elevates the acting session in place: a valid code consumes its
// step (single-use CAS), then the session's factor set gains `totp` and its
// token rotates. It is NOT an account-security mutation — no generation
// advance, no session deletion — and it preserves the original
// authenticated_at/ceremony so repeated step-ups cannot reset absolute age
// (finding A21). Returns the rotated token.
func (s *Auth) StepUpTOTP(ctx context.Context, presented, code string) (LoginResult, error) {
	// Phase 1 — read the acting session and the confirmed factor.
	var (
		acting    authz.Identity
		account   authz.Account
		confirmed authz.TOTPCredential
	)
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		id, err := az.Authenticate(ctx, presented, s.now())
		if err != nil {
			return err
		}
		acting = id
		account, err = az.AccountByPrincipal(ctx, id.Principal)
		if err != nil {
			return err
		}
		confirmed, err = az.ConfirmedTOTP(ctx, account.ID)
		if errors.Is(err, domain.ErrNotFound) {
			return ErrNoTOTPFactor
		}
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}

	// Admission: bound online brute force of the six-digit code by an attacker
	// holding a stolen session.
	release, err := s.enterFactorBudget(ctx, account.ID)
	if err != nil {
		return LoginResult{}, err
	}
	defer release()

	// Phase 2 — verify the code.
	seed, err := s.Keyring.ForInstance().OpenField(totpSeedAAD(confirmed.ID), confirmed.Seed)
	if err != nil {
		s.logFault(ctx, "opening a TOTP seed failed", err, account.ID)
		return LoginResult{}, domain.ErrUnauthenticated
	}
	step, ok := crypto.ValidateTOTP(seed, code, s.now(), crypto.TOTPSkewSteps)
	crypto.Zero(seed)
	if !ok {
		s.recordFactorFailure(ctx, account.PrincipalID, account.ID)
		return LoginResult{}, domain.ErrUnauthenticated
	}
	s.Admission.RecordSuccess(account.ID)

	// Phase 3 — consume the step and rotate the acting session.
	//
	// The replacement token must be the SAME artifact kind the acting session
	// is: a browser session handed a `cli` token would have that token echoed
	// into a script-readable body (the cookie leg omits it), and the cookie
	// it still holds would point at a rotated verifier — an instant logout
	// plus a long-lived credential in the DOM. `RotateSessionFactors` leaves
	// `csrf_verifier` alone, so the synchronizer token stays valid and only
	// the session cookie needs re-delivery.
	actingArtifact := Artifact(acting.Artifact)
	value, verifier, err := crypto.NewArtifact(actingArtifact.bearerKind())
	if err != nil {
		return LoginResult{}, err
	}
	factors := stepUpFactors(acting.Assurance.Factors, "totp")
	factorsJSON, err := json.Marshal(factors)
	if err != nil {
		return LoginResult{}, err
	}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		// Re-authenticate inside the write tx: rotating a revoked session would
		// hand out a token for a row that is gone.
		live, err := az.Authenticate(ctx, presented, s.now())
		if err != nil {
			return err
		}
		if _, err := az.ConfirmedTOTP(ctx, account.ID); errors.Is(err, domain.ErrNotFound) {
			return ErrNoTOTPFactor
		} else if err != nil {
			return err
		}
		// CAS on the row whose seed was VERIFIED in phase 1, not a freshly read
		// one, so a code proved against a since-removed-and-replaced factor
		// cannot be applied to its successor (finding HIGH-5). A replacement row
		// has a different id and fails the CAS.
		consumed, err := az.AdvanceTOTPStep(ctx, confirmed.ID, confirmed.RowVersion, step)
		if err != nil {
			return err
		}
		if !consumed {
			// The step was already spent or the row moved: single-use holds. A code
			// re-presented in the SAME step it already elevated with is named; a
			// moved row stays the uniform refusal.
			if s.totpStepConsumed(ctx, az, account.ID, confirmed.ID, step) {
				return totpStepAlreadyUsed()
			}
			return domain.ErrUnauthenticated
		}
		if err := az.RotateSessionFactors(ctx, live.SessionID, verifier, string(factorsJSON)); err != nil {
			return err
		}
		e, err := newAuditEvent(ctx, audit.EventAuthReauthenticated, account.PrincipalID,
			audit.Object{Type: "session", ID: live.SessionID}, audit.OutcomeSuccess, "",
			audit.Payload{"session_id": live.SessionID, "factor": "totp"})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		SessionToken: value, SessionID: acting.SessionID, Artifact: actingArtifact,
		CreatedAt: acting.CreatedAt, IdleExpires: acting.IdleExpiresAt, AbsExpires: acting.AbsoluteExpiresAt,
		Principal: account.PrincipalID, AccountID: account.ID, DisplayName: account.DisplayName,
		Assurance: Assurance{
			Method: acting.Assurance.Method, Factors: factors,
			AuthenticatedAt: acting.Assurance.AuthenticatedAt, CeremonyID: acting.Assurance.CeremonyID,
		},
	}, nil
}

// stepUpFactors adds a class to a session's factor set without duplicating it.
func stepUpFactors(existing []string, add string) []string {
	out := make([]string, 0, len(existing)+1)
	seen := map[string]bool{}
	for _, f := range existing {
		if !seen[f] {
			out = append(out, f)
			seen[f] = true
		}
	}
	if !seen[add] {
		out = append(out, add)
	}
	return out
}

// GenerateRecoveryCodes replaces the account's recovery batch as an
// account-security mutation and returns the plaintext codes ONCE. The proof is
// the confirmed TOTP code where one stands, else the password (finding B7);
// recovery codes never authorize their own regeneration. The batch is a sealed
// JSON array of the codes' verifiers; only the verifiers persist.
func (s *Auth) GenerateRecoveryCodes(ctx context.Context, presented, proof string) ([]string, LoginResult, error) {
	// Phase 1 — read. Determine the proof class over the pre-existing set.
	var (
		account   authz.Account
		cred      authz.PasswordCredential
		confirmed authz.TOTPCredential
		existing  authz.RecoveryBatch
		hasTOTP   bool
		hasBatch  bool
	)
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		id, err := az.Authenticate(ctx, presented, s.now())
		if err != nil {
			return err
		}
		account, err = az.AccountByPrincipal(ctx, id.Principal)
		if err != nil {
			return err
		}
		confirmed, err = az.ConfirmedTOTP(ctx, account.ID)
		switch {
		case err == nil:
			hasTOTP = true
		case errors.Is(err, domain.ErrNotFound):
			cred, err = az.PasswordCredentialFor(ctx, account.ID)
			if errors.Is(err, domain.ErrNotFound) {
				return ErrNoProofCredential
			}
			if err != nil {
				return err
			}
		default:
			return err
		}
		existing, err = az.RecoveryCodesFor(ctx, account.ID)
		switch {
		case err == nil:
			hasBatch = true
		case errors.Is(err, domain.ErrNotFound):
		default:
			return err
		}
		return nil
	})
	if err != nil {
		return nil, LoginResult{}, err
	}

	// Admission: whether the proof is a password (Argon2) or a TOTP code, a
	// stolen session must not make regeneration an unthrottled oracle — a bad
	// proof here yields a fresh recovery batch, so it is a takeover primitive.
	release, err := s.enterFactorBudget(ctx, account.ID)
	if err != nil {
		return nil, LoginResult{}, err
	}
	defer release()

	// Phase 2 — verify the proof (Argon2 outside any tx for a password).
	var proofClass string
	var totpStep int64
	if hasTOTP {
		proofClass = "totp"
		seed, oerr := s.Keyring.ForInstance().OpenField(totpSeedAAD(confirmed.ID), confirmed.Seed)
		if oerr != nil {
			s.logFault(ctx, "opening a TOTP seed failed", oerr, account.ID)
			return nil, LoginResult{}, domain.ErrUnauthenticated
		}
		var ok bool
		totpStep, ok = crypto.ValidateTOTP(seed, proof, s.now(), crypto.TOTPSkewSteps)
		crypto.Zero(seed)
		if !ok {
			s.recordFactorFailure(ctx, account.PrincipalID, account.ID)
			return nil, LoginResult{}, domain.ErrUnauthenticated
		}
	} else {
		proofClass = "password"
		if !s.verifyPassword(ctx, account.ID, cred, proof) {
			s.recordFactorFailure(ctx, account.PrincipalID, account.ID)
			return nil, LoginResult{}, domain.ErrUnauthenticated
		}
	}
	s.Admission.RecordSuccess(account.ID)

	// Mint the batch and seal its verifiers.
	codes, verifiers, err := crypto.GenerateRecoveryBatch(RecoveryBatchSize)
	if err != nil {
		return nil, LoginResult{}, err
	}
	sealer := s.Keyring.ForInstance()
	batchJSON, err := json.Marshal(verifiers)
	if err != nil {
		return nil, LoginResult{}, err
	}
	sealed, err := sealer.SealField(recoveryBatchAAD(account.ID), batchJSON)
	crypto.Zero(batchJSON)
	zeroVerifiers(verifiers)
	if err != nil {
		return nil, LoginResult{}, err
	}

	// Phase 3 — write.
	var result LoginResult
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		now := s.now()
		// Re-authenticate inside the write tx: a session revoked between the
		// phases must not replace the owner's recovery batch and reissue itself
		// (finding HIGH-3).
		liveID, err := az.Authenticate(ctx, presented, now)
		if err != nil {
			return err
		}
		if liveID.Principal != account.PrincipalID {
			return domain.ErrUnauthenticated
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		if hasTOTP {
			if _, err := az.ConfirmedTOTP(ctx, account.ID); err != nil {
				if errors.Is(err, domain.ErrNotFound) {
					return domain.ErrUnauthenticated
				}
				return err
			}
			// CAS on the row VERIFIED in phase 1 (finding HIGH-5): a code proved
			// against a since-replaced factor must not consume its successor.
			consumed, err := az.AdvanceTOTPStep(ctx, confirmed.ID, confirmed.RowVersion, totpStep)
			if err != nil {
				return err
			}
			if !consumed {
				// A step already spent on the same row is named; a moved row
				// (a concurrent replace) stays the uniform refusal.
				if s.totpStepConsumed(ctx, az, account.ID, confirmed.ID, totpStep) {
					return totpStepAlreadyUsed()
				}
				return domain.ErrUnauthenticated
			}
		} else {
			current, err := az.PasswordCredentialFor(ctx, account.ID)
			if err != nil {
				if errors.Is(err, domain.ErrNotFound) {
					return domain.ErrUnauthenticated
				}
				return err
			}
			if current.RowVersion != cred.RowVersion || current.CredentialEpoch != epoch {
				return domain.ErrUnauthenticated
			}
		}
		batch := authz.RecoveryBatch{
			AccountID: account.ID, Batch: sealed,
			DEKVersion: int64(sealer.Version()), CredentialEpoch: epoch,
		}
		// Writer fence (invariant 7): refuse if a rotate-dek --instance retired
		// the version the batch was sealed under. The first-batch WriteRecoveryCodes
		// is a bare INSERT with no row_version CAS, so the fence is its only guard.
		if err := az.AssertActiveInstanceDEKVersion(ctx, int64(sealer.Version())); err != nil {
			return err
		}
		if hasBatch {
			batch.RowVersion = existing.RowVersion
			swapped, err := az.ReplaceRecoveryCodes(ctx, batch, now)
			if err != nil {
				return err
			}
			if !swapped {
				return ErrCredentialRace
			}
		} else {
			if err := az.WriteRecoveryCodes(ctx, batch, now); err != nil {
				return err
			}
		}
		result, err = s.reissueSession(ctx, az, account, proofClass, MethodLocalPassword, Artifact(liveID.Artifact), now)
		if err != nil {
			return err
		}
		e, err := newAuditEvent(ctx, audit.EventAuthRecoveryCodesGenerated, account.PrincipalID,
			audit.Object{Type: "account", ID: account.ID}, audit.OutcomeSuccess, "",
			audit.Payload{"account_id": account.ID, "count": RecoveryBatchSize, "authorizing_credential": proofClass})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
	if err != nil {
		return nil, LoginResult{}, err
	}
	return codes, result, nil
}

// RecoveryResult is a session-less credential-establishment authority minted by
// consuming a recovery code. It creates NO session, NO assurance and NO window:
// the holder establishes a new password with it and then logs in like anyone.
type RecoveryResult struct {
	Authority string
	ExpiresAt time.Time
}

// ConsumeRecoveryCode is the pre-auth break-in-glass path. It rides the
// admission budget and answers uniformly: an unknown username, an absent batch,
// a stale epoch and a non-matching code all cost a set scan and refuse
// identically. On a match it removes that code (CAS on the batch), sweeps the
// account's outstanding authorities (finding B12), mints a recovery-issued
// credential-establishment authority (which may only ever establish a password,
// enforced by the DB CHECK), advances the generation and deletes every session
// — all in one transaction. A losing CAS discards the authority (finding B22).
func (s *Auth) ConsumeRecoveryCode(ctx context.Context, username, code string) (RecoveryResult, error) {
	if delay := s.Admission.AccountDelay(username); delay > 0 {
		return RecoveryResult{}, admission.ErrOverloaded
	}
	release, err := s.Admission.Enter(ctx, audit.FromContext(ctx).SourceIP)
	if err != nil {
		return RecoveryResult{}, err
	}
	defer release()

	out, err := s.attemptRecovery(ctx, username, code)
	switch {
	case err == nil:
		s.Admission.RecordSuccess(username)
		return out, nil
	case errors.Is(err, domain.ErrUnauthenticated):
		if crossed := s.Admission.RecordFailure(username); crossed {
			s.recordThrottleCrossing(ctx, username)
		}
		return RecoveryResult{}, err
	default:
		return RecoveryResult{}, err
	}
}

func (s *Auth) attemptRecovery(ctx context.Context, username, code string) (RecoveryResult, error) {
	// Phase 1 — read.
	var (
		account  authz.Account
		batch    authz.RecoveryBatch
		epoch    int64
		resolved bool
		haveBtch bool
	)
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		var err error
		if epoch, err = az.CredentialEpoch(ctx); err != nil {
			return err
		}
		account, err = az.AccountByUsername(ctx, username)
		switch {
		case errors.Is(err, domain.ErrNotFound):
			// Equalise the read shape: an unknown subject still issues the batch
			// lookup (against a fixed dummy id that resolves to nothing) so the
			// query count does not distinguish it from a known one.
			_, _ = az.RecoveryCodesFor(ctx, dummyRecoveryAccount)
			return nil
		case err != nil:
			return err
		}
		resolved = true
		batch, err = az.RecoveryCodesFor(ctx, account.ID)
		switch {
		case errors.Is(err, domain.ErrNotFound):
			return nil
		case err != nil:
			return err
		}
		haveBtch = true
		return nil
	})
	if err != nil {
		return RecoveryResult{}, err
	}

	// Phase 2 — match. Every non-matching path scans a set of the same size so
	// timing does not distinguish an unknown subject from a wrong code.
	cause := ""
	matchIdx := -1
	switch {
	case !resolved:
		s.burnRecoveryMatch(ctx, code)
		cause = "unknown-subject"
	case !haveBtch:
		s.burnRecoveryMatch(ctx, code)
		cause = "no-batch"
	case batch.CredentialEpoch != epoch:
		s.burnRecoveryMatch(ctx, code)
		cause = "epoch-superseded"
	default:
		verifiers, oerr := s.openRecoveryBatch(ctx, account.ID, batch.Batch)
		if oerr != nil {
			// The real open already paid the envelope-decrypt cost (a GCM tag
			// mismatch decrypts fully before failing), so only the scan is
			// added here — a second dummy open would make this path observably
			// heavier than the other misses (finding R2 R1-6).
			dummy := dummyRecoveryVerifiers()
			crypto.MatchRecoveryCode(code, dummy)
			zeroVerifiers(dummy)
			cause = "batch-unreadable"
			break
		}
		matchIdx = crypto.MatchRecoveryCode(code, verifiers)
		zeroVerifiers(verifiers)
		if matchIdx < 0 {
			cause = "no-match"
		}
	}

	// Phase 3 — write.
	value, verifier, err := crypto.NewArtifact(crypto.ArtifactBootstrap)
	if err != nil {
		return RecoveryResult{}, err
	}
	authorityID, err := newID("cea")
	if err != nil {
		return RecoveryResult{}, err
	}
	var (
		out     RecoveryResult
		refused error
	)
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		refused = nil
		now := s.now()
		if cause != "" {
			if ferr := s.failRecovery(ctx, az, now, accountIDOf(resolved, account), resolved, cause); ferr != nil {
				return ferr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		// Re-read the batch and re-match under the write tx: a concurrent
		// regenerate may have replaced it since phase 2.
		live, err := az.RecoveryCodesFor(ctx, account.ID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				if ferr := s.failRecovery(ctx, az, now, account.ID, true, "no-batch"); ferr != nil {
					return ferr
				}
				refused = domain.ErrUnauthenticated
				return nil
			}
			return err
		}
		liveEpoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		if live.CredentialEpoch != liveEpoch {
			if ferr := s.failRecovery(ctx, az, now, account.ID, true, "epoch-superseded"); ferr != nil {
				return ferr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		verifiers, oerr := s.openRecoveryBatch(ctx, account.ID, live.Batch)
		if oerr != nil {
			return oerr
		}
		idx := crypto.MatchRecoveryCode(code, verifiers)
		if idx < 0 {
			zeroVerifiers(verifiers)
			if ferr := s.failRecovery(ctx, az, now, account.ID, true, "no-match"); ferr != nil {
				return ferr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		// Remove the consumed verifier and re-seal the remainder. The CAS is
		// the single-use claim: a losing swap discards this authority (B22).
		crypto.Zero(verifiers[idx])
		remaining := append(verifiers[:idx:idx], verifiers[idx+1:]...)
		// Fail-closed passkey-only floor (A1): consuming the FINAL recovery code on
		// a passwordless (passkey-only) account would strand it below the floor —
		// no password and no current recovery batch. Refuse. The rollback is
		// non-destructive: the code is NOT burned, no authority minted, no sessions
		// revoked, so the reserve code stays usable. A passwordless account that has
		// also lost its passkeys recovers through the break-glass vertical (#7), not
		// by spending its last code into a bricked floor.
		if len(remaining) == 0 {
			if _, perr := az.PasswordCredentialFor(ctx, account.ID); errors.Is(perr, domain.ErrNotFound) {
				zeroVerifiers(remaining)
				// Refuse with an audit event, never an eventless refusal (the
				// failRecovery contract): nothing destructive has run yet — no batch
				// swap, no authority, no generation advance, no session revocation —
				// so committing ONLY the event keeps the reserve code usable while
				// the refusal stays visible to audit.
				if ferr := s.failRecovery(ctx, az, now, account.ID, true, "passkey-only-floor"); ferr != nil {
					return ferr
				}
				refused = ErrPasskeyOnlyViolation
				return nil
			} else if perr != nil {
				zeroVerifiers(remaining)
				return perr
			}
		}
		batchJSON, err := json.Marshal(remaining)
		if err != nil {
			return err
		}
		sealer := s.Keyring.ForInstance()
		sealed, err := sealer.SealField(recoveryBatchAAD(account.ID), batchJSON)
		crypto.Zero(batchJSON)
		zeroVerifiers(remaining)
		if err != nil {
			return err
		}
		// Writer fence (invariant 7): refuse if a rotate-dek --instance retired
		// the version the pruned batch was sealed under.
		if err := az.AssertActiveInstanceDEKVersion(ctx, int64(sealer.Version())); err != nil {
			return err
		}
		swapped, err := az.ReplaceRecoveryCodes(ctx, authz.RecoveryBatch{
			AccountID: account.ID, Batch: sealed, DEKVersion: int64(sealer.Version()),
			CredentialEpoch: liveEpoch, RowVersion: live.RowVersion,
		}, now)
		if err != nil {
			return err
		}
		if !swapped {
			if ferr := s.failRecovery(ctx, az, now, account.ID, true, "race"); ferr != nil {
				return ferr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		// Minting an authority sweeps every outstanding one for this account.
		if err := az.ConsumeOutstandingAuthorities(ctx, account.ID, now); err != nil {
			return err
		}
		expires := now.Add(AuthorityLifetime)
		if err := az.MintAuthority(ctx, authz.NewCredentialAuthority{
			ID: authorityID, Verifier: verifier, AccountID: account.ID,
			Purpose: "establish-credential", IssuedBy: "recovery",
			CredentialEpoch: liveEpoch, ExpiresAt: expires, CreatedAt: now,
		}); err != nil {
			return err
		}
		if err := az.AdvanceGeneration(ctx, account.PrincipalID); err != nil {
			return err
		}
		if err := az.RevokeAllSessionsFor(ctx, account.PrincipalID); err != nil {
			return err
		}
		// The authority coming into existence is its own audit record, in the
		// same transaction as the mint (finding MEDIUM-7): audit consumers that
		// watch authority issuance must see the recovery-issued password-reset
		// capability, delivered in the API response.
		minted, err := newAuditEvent(ctx, audit.EventAuthAuthorityMinted, account.PrincipalID,
			audit.Object{Type: "authority", ID: authorityID}, audit.OutcomeSuccess, "",
			audit.Payload{"authority_id": authorityID, "account_id": account.ID, "issued_by": "recovery", "delivery": "response"})
		if err != nil {
			return err
		}
		if err := az.RecordAuthEvent(ctx, minted); err != nil {
			return err
		}
		e, err := newAuditEvent(ctx, audit.EventAuthRecoveryCodeConsumed, account.PrincipalID,
			audit.Object{Type: "account", ID: account.ID}, audit.OutcomeSuccess, "",
			audit.Payload{"subject_resolved": true, "account_id": account.ID, "authority_id": authorityID})
		if err != nil {
			return err
		}
		if err := az.RecordAuthEvent(ctx, e); err != nil {
			return err
		}
		out = RecoveryResult{Authority: value, ExpiresAt: expires}
		return nil
	})
	if err != nil {
		return RecoveryResult{}, err
	}
	if refused != nil {
		return RecoveryResult{}, refused
	}
	return out, nil
}

// openRecoveryBatch unseals a batch into its verifier set.
func (s *Auth) openRecoveryBatch(ctx context.Context, accountID string, sealed []byte) ([][]byte, error) {
	plain, err := s.Keyring.ForInstance().OpenField(recoveryBatchAAD(accountID), sealed)
	if err != nil {
		s.logFault(ctx, "opening a recovery batch failed", err, accountID)
		return nil, err
	}
	var verifiers [][]byte
	err = json.Unmarshal(plain, &verifiers)
	crypto.Zero(plain)
	if err != nil {
		s.logFault(ctx, "recovery batch is unparseable", err, accountID)
		return nil, err
	}
	return verifiers, nil
}

// failRecovery stages the failure event on the same fail-closed contract as
// failLogin: a nil return means the record is staged and the caller may refuse;
// a non-nil return must be propagated loudly rather than committing an eventless
// refusal.
func (s *Auth) failRecovery(ctx context.Context, az *authz.TxAuthorizer, now time.Time, accountID string, resolved bool, cause string) error {
	payload := audit.Payload{"subject_resolved": resolved, "cause": cause}
	if accountID != "" {
		payload["account_id"] = accountID
	}
	e, err := newAuditEvent(ctx, audit.EventAuthRecoveryCodeConsumed, "",
		audit.Object{Type: "account", ID: accountID}, audit.OutcomeFailure, "", payload)
	if err != nil {
		return err
	}
	e.OccurredAt = now
	return az.RecordAuthEvent(ctx, e)
}

// dummyRecoveryAccount is the owner id the dummy batch is sealed under. Its
// AAD must be stable so the cached blob opens on every call.
const dummyRecoveryAccount = "dummy-recovery-account"

// dummyRecoveryVerifiers is a set the size of a real batch, the fallback scan
// when the cached dummy envelope is unavailable.
func dummyRecoveryVerifiers() [][]byte {
	out := make([][]byte, RecoveryBatchSize)
	for i := range out {
		out[i] = make([]byte, 32)
	}
	return out
}

// zeroVerifiers wipes a verifier set's backing bytes.
func zeroVerifiers(vs [][]byte) {
	for _, v := range vs {
		crypto.Zero(v)
	}
}

// burnRecoveryMatch performs the SAME envelope decrypt + JSON decode + set scan
// a matching path performs, on a cached dummy batch, so a non-matching path
// (unknown subject, absent batch, stale epoch, unreadable batch, wrong code) is
// not distinguishable from a match by the dominant crypto cost (finding
// MEDIUM-6). The batch is sealed once; if that ever fails the scan still runs
// against an in-memory dummy so the path never becomes observably cheaper.
//
// fence:exempt — the sealed dummy batch is held in memory for timing only and
// is NEVER written to any table, so no writer fence applies (there is no row to
// strand under a rotated DEK version).
func (s *Auth) burnRecoveryMatch(ctx context.Context, code string) {
	s.dummyRecoveryOnce.Do(func() {
		_, verifiers, err := crypto.GenerateRecoveryBatch(RecoveryBatchSize)
		if err != nil {
			return
		}
		j, err := json.Marshal(verifiers)
		if err != nil {
			return
		}
		sealed, serr := s.Keyring.ForInstance().SealField(recoveryBatchAAD(dummyRecoveryAccount), j)
		crypto.Zero(j)
		zeroVerifiers(verifiers)
		if serr != nil {
			s.logFault(ctx, "sealing the dummy recovery batch failed", serr, "")
			return
		}
		s.dummyRecoverySealed = sealed
	})
	if s.dummyRecoverySealed == nil {
		fallback := dummyRecoveryVerifiers()
		crypto.MatchRecoveryCode(code, fallback)
		zeroVerifiers(fallback)
		return
	}
	plain, err := s.Keyring.ForInstance().OpenField(recoveryBatchAAD(dummyRecoveryAccount), s.dummyRecoverySealed)
	if err != nil {
		fallback := dummyRecoveryVerifiers()
		crypto.MatchRecoveryCode(code, fallback)
		zeroVerifiers(fallback)
		return
	}
	var verifiers [][]byte
	if json.Unmarshal(plain, &verifiers) != nil {
		verifiers = dummyRecoveryVerifiers()
	}
	crypto.Zero(plain)
	crypto.MatchRecoveryCode(code, verifiers)
	zeroVerifiers(verifiers)
}
