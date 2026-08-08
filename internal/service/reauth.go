package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/crypto"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/tx"
)

// Reauthentication-window CONSUMPTION at disclosure, the effective-window
// transition, and TOTP reauth (#54, human-auth ADR - Reauthentication). The
// OIDC and WebAuthn verticals already OPEN windows; this file adds the
// disclosure-time consumption and the window-lowering ceremony.
//
// There is no `reveal` operation to call ConsumeReauthWindow yet (it lands with
// #50/#58) and no `project-settings` knob to call LowerEffectiveWindow yet (it
// lands with #55). Both ship here as the library those verticals consume, wired
// against fixtures that exercise them directly rather than a live endpoint.

var (
	// ErrNoReauthWindow refuses a disclosure with no live window for (session,
	// environment). Fail-closed: at a 0 effective window with no WebAuthn ceremony
	// there is no window at all, which is the default state (B18).
	ErrNoReauthWindow = errors.New("service: no live reauthentication window for this disclosure")
	// ErrReauthWindowExpired refuses a disclosure whose window has lapsed (idle or
	// hard cap) or whose credential epoch is inert.
	ErrReauthWindowExpired = errors.New("service: the reauthentication window has expired")
	// ErrReauthUnitMismatch refuses a single-decision window presented for a
	// different enumerated unit than its ceremony bound (B11).
	ErrReauthUnitMismatch = errors.New("service: this reauthentication authorized a different disclosure")
	// ErrReauthWindowSpent refuses a single-decision window already consumed (B11
	// double-spend).
	ErrReauthWindowSpent = errors.New("service: this reauthentication has already been spent")
)

// ConsumeReauthWindow is the disclosure-time half of the reauthentication gate.
// It runs inside the disclosure's own transaction; the future reveal path calls
// it before disclosing the enumerated keys in one environment.
//
// A disclosure on environment E requires a live window for (session, E):
// now < hard_expires_at AND now < window_expires_at, at the current credential
// epoch. A single_decision window — opened by a 0-window WebAuthn ceremony bound
// to an enumerated unit — authorizes exactly the unit its ceremony pinned and is
// consumed by exactly one decision through the consumed_at NULL guard. A sliding
// window slides window_expires_at forward per disclosure, never past the hard cap.
func (s *Auth) ConsumeReauthWindow(ctx context.Context, az *authz.TxAuthorizer, sessionID, environmentID string, keyIDs []string, now time.Time) error {
	w, err := az.ReauthWindowFor(ctx, sessionID, environmentID)
	if errors.Is(err, domain.ErrNotFound) {
		return ErrNoReauthWindow
	}
	if err != nil {
		return err
	}
	epoch, err := az.CredentialEpoch(ctx)
	if err != nil {
		return err
	}
	// Fail closed on lapsed clocks or an inert epoch: an artifact from an earlier
	// epoch cannot authenticate or be reauthenticated against (ADR - Restore).
	if w.CredentialEpoch != epoch || !now.Before(w.HardExpiresAt) || !now.Before(w.WindowExpiresAt) {
		return ErrReauthWindowExpired
	}
	if w.SingleDecision {
		// The unit is fixed before the ceremony and cannot grow after it: the
		// ceremony's pinned binding is matched byte-exact against this unit.
		ceremony, err := az.WebAuthnCeremonyByID(ctx, w.CeremonyID)
		if err != nil {
			return err
		}
		want, err := operationBinding(environmentID, keyIDs)
		if err != nil {
			return err
		}
		if ceremony.OperationBinding != want {
			return ErrReauthUnitMismatch
		}
		claimed, err := az.ConsumeSingleDecisionWindow(ctx, w.ID, now)
		if err != nil {
			return err
		}
		if !claimed {
			return ErrReauthWindowSpent
		}
		return nil
	}
	// Sliding window: refresh the idle clock, capped at the hard cap. The liveness
	// check above already authorized this decision; a losing CAS (row moved) means
	// no refresh, never a refused disclosure.
	windowExpires := now.Add(s.ReauthWindow)
	if windowExpires.After(w.HardExpiresAt) {
		windowExpires = w.HardExpiresAt
	}
	if _, err := az.SlideReauthWindow(ctx, w.ID, windowExpires); err != nil {
		return err
	}
	return nil
}

// LowerEffectiveWindow performs, in one transaction, the five ADR items on an
// environment's effective-window transition to newValue (human-auth ADR -
// Reauthentication; finding B6). It is the library #55's project-settings knob
// calls; this vertical ships it plus a fixture, with #55 named as the caller.
//
// The five items: (1) invalidate every open window on the environment; (2)
// RETAIN grants — a settings change never revokes a capability; (3) enumerate
// the principals a 0 effective window strands (reveal/reveal-history there
// without an enrolled WebAuthn authenticator) and return them so the caller can
// surface them before commit; (4) disclosure fails closed for them until they
// enrol — a consequence of the invalidation plus the 0-window rule, not a
// separate write; (5) factor enrolment stays reachable — it is an
// account-security mutation, never gated by the reveal window, so nothing to do.
// The audit event carries the stranded list.
//
// Stranded principals are computed only when newValue <= 0: at a smaller
// non-zero window TOTP still opens a window, so no reveal holder is locked out.
func (s *Auth) LowerEffectiveWindow(ctx context.Context, az *authz.TxAuthorizer, envID string, newValue time.Duration, now time.Time) ([]domain.PrincipalID, int, error) {
	invalidated, err := az.InvalidateReauthWindowsForEnvironment(ctx, envID)
	if err != nil {
		return nil, 0, err
	}
	var stranded []domain.PrincipalID
	if newValue <= 0 {
		chain, err := az.EnvironmentChainByID(ctx, envID)
		if err != nil {
			return nil, 0, err
		}
		stranded, err = az.StrandedRevealPrincipals(ctx, chain.Org, chain.Project, chain.Env)
		if err != nil {
			return nil, 0, err
		}
	}
	ids := make([]string, 0, len(stranded))
	for _, p := range stranded {
		ids = append(ids, string(p))
	}
	// The actor is the settings mutation #55 wraps this in; that operation carries
	// its own actor-attributed settings-change event. This event records the
	// security-relevant transition itself, with the surfaced stranded list.
	e, err := newAuditEvent(ctx, audit.EventAuthEffectiveWindowLowered, "",
		audit.Object{Type: "environment", ID: envID}, audit.OutcomeSuccess, "",
		audit.Payload{
			"environment_id":      envID,
			"new_window_seconds":  int(newValue / time.Second),
			"windows_invalidated": int(invalidated),
			"stranded_count":      len(ids),
			"stranded_principals": strings.Join(ids, ","),
		})
	if err != nil {
		return nil, 0, err
	}
	if err := az.RecordAuthEvent(ctx, e); err != nil {
		return nil, 0, err
	}
	return stranded, int(invalidated), nil
}

// ReauthTOTP opens a reauthentication window over one environment by presenting
// a TOTP code, the possession-factor analog of OIDC reauth. Like OIDC, TOTP
// cannot bind the challenge to the enumerated unit, so it opens a window only
// where the effective window is > 0 and refuses at a 0 window naming the remedy
// (a WebAuthn ceremony); only WebAuthn opens a single-decision 0-window gate.
//
// It ships as a service method exercised by fixtures: the HTTP endpoint the
// design lists (POST /auth/reauth/totp) waits on the reveal surface (#50/#58),
// since there is no disclosure yet for a TOTP window to gate.
func (s *Auth) ReauthTOTP(ctx context.Context, presented, environmentID, code string) (ReauthResult, error) {
	if environmentID == "" {
		return ReauthResult{}, ErrNoReauthWindow
	}
	// Phase 1 - read the acting session and confirmed factor.
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
		return ReauthResult{}, err
	}

	// Refuse at a 0 effective window BEFORE consuming any code: TOTP cannot supply
	// a per-operation gate, so a 0 window has no TOTP path (ADR - Reauthentication).
	if s.ReauthWindow <= 0 {
		return ReauthResult{}, ErrReauthWindowClosed
	}

	release, err := s.enterFactorBudget(ctx, account.ID)
	if err != nil {
		return ReauthResult{}, err
	}
	defer release()

	// Phase 2 - verify the code.
	seed, err := s.Keyring.ForInstance().OpenField(totpSeedAAD(confirmed.ID), confirmed.Seed)
	if err != nil {
		s.logFault(ctx, "opening a TOTP seed failed", err, account.ID)
		return ReauthResult{}, domain.ErrUnauthenticated
	}
	step, ok := crypto.ValidateTOTP(seed, code, s.now(), crypto.TOTPSkewSteps)
	crypto.Zero(seed)
	if !ok {
		s.recordFactorFailure(ctx, account.PrincipalID, account.ID)
		return ReauthResult{}, domain.ErrUnauthenticated
	}
	s.Admission.RecordSuccess(account.ID)

	// Phase 3 - consume the step, rotate the acting session (every reauth rotates)
	// and open the window over the environment.
	value, verifier, err := s.newSessionArtifact(acting.Artifact)
	if err != nil {
		return ReauthResult{}, err
	}
	windowID, err := newID("raw")
	if err != nil {
		return ReauthResult{}, err
	}
	now := s.now()
	hardCap := s.ReauthHardCap
	if hardCap <= 0 {
		hardCap = s.ReauthWindow
	}
	windowExpires := now.Add(s.ReauthWindow)
	var out ReauthResult
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		// Re-authenticate inside the write tx: a revoked session may not open a
		// window (mirrors StepUpTOTP's HIGH-2 fix).
		live, err := az.Authenticate(ctx, presented, now)
		if err != nil {
			return err
		}
		if _, err := az.ConfirmedTOTP(ctx, account.ID); errors.Is(err, domain.ErrNotFound) {
			return ErrNoTOTPFactor
		} else if err != nil {
			return err
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		// CAS on the row whose seed was verified in phase 1, so a code proved
		// against a since-replaced factor cannot apply to its successor.
		consumed, err := az.AdvanceTOTPStep(ctx, confirmed.ID, confirmed.RowVersion, step)
		if err != nil {
			return err
		}
		if !consumed {
			return domain.ErrUnauthenticated
		}
		factorsJSON, err := json.Marshal(live.Assurance.Factors)
		if err != nil {
			return err
		}
		if err := az.RotateSessionFactors(ctx, live.SessionID, verifier, string(factorsJSON)); err != nil {
			return err
		}
		if err := az.OpenReauthWindow(ctx, authz.NewReauthWindow{
			// CeremonyID carries the confirmed TOTP credential id (TOTP has no
			// challenge row of its own; totp_challenges is dormant, see B8): it is
			// provenance only. A TOTP window is never single_decision, so
			// ConsumeReauthWindow never resolves it as a ceremony for unit matching.
			ID: windowID, SessionID: live.SessionID, EnvironmentID: environmentID,
			CeremonyID: confirmed.ID, FactorClass: "totp", SingleDecision: false,
			AuthenticatedAt: now, WindowExpiresAt: windowExpires, HardExpiresAt: now.Add(hardCap),
			CredentialEpoch: epoch, CreatedAt: now,
		}); err != nil {
			return err
		}
		e, err := newAuditEvent(ctx, audit.EventAuthReauthenticated, account.PrincipalID,
			audit.Object{Type: "session", ID: live.SessionID}, audit.OutcomeSuccess, "",
			audit.Payload{"session_id": live.SessionID, "factor": "totp"})
		if err != nil {
			return err
		}
		out = ReauthResult{
			SessionToken: value, SessionID: live.SessionID, EnvironmentID: environmentID,
			SingleDecision: false, WindowExpires: windowExpires,
		}
		return az.RecordAuthEvent(ctx, e)
	})
	if err != nil {
		return ReauthResult{}, err
	}
	return out, nil
}
