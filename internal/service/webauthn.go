package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
	"github.com/Hikyo-Org/hikyo/internal/webauthnrp"
)

// WebAuthn service (#54, human-auth ADR § WebAuthn relying-party policy, §
// Passkey login, § Account-security mutations).
//
// The shapes mirror the TOTP vertical's phase discipline. Enrolment and removal
// are account-security mutations: a pre-existing credential proves the change,
// then in ONE write tx the credential inventory changes, the generation
// advances, every session dies, and the acting session is reissued SOLELY from
// the proof (B1/B3). Passkey login is a pre-auth discoverable ceremony that
// mints a browser session carrying webauthn assurance in one gesture. Step-up
// elevates the acting session in place; reauth opens a window (its consumption
// at disclosure is #7). The passkey-only precondition is a POST-STATE invariant
// (B4/B13) run in every tx that touches the credential inventory.

// WebAuthnCeremonyLifetime bounds a challenge's life. A ceremony not finished
// inside it is inert, exactly as an expired OIDC transaction is.
const WebAuthnCeremonyLifetime = 5 * time.Minute

// Structural refusals are loud (400) — the caller owns the account, so naming
// the state helps them and reveals nothing. A bad assertion stays uniform (401)
// so presentation reveals nothing.
var (
	// ErrWebAuthnUnavailable is returned when the relying party was not
	// configured at boot, so no WebAuthn route can serve.
	ErrWebAuthnUnavailable = errors.New("service: webauthn is not configured on this instance")
	// ErrNoWebAuthnCeremony refuses a finish with no live matching ceremony.
	ErrNoWebAuthnCeremony = errors.New("service: no matching webauthn ceremony")
	// ErrNoPasskey refuses a step-up, reauth or removal with no usable passkey.
	ErrNoPasskey = errors.New("service: no usable passkey")
	// ErrPasskeyOnlyViolation refuses a mutation that would leave a passwordless
	// account without >=2 discoverable authenticators and a current recovery
	// batch, in either direction (B4/B13).
	ErrPasskeyOnlyViolation = errors.New("service: a passwordless account needs at least two discoverable passkeys and a current recovery-code batch")
)

// PasskeyView is the transport's view of an enrolled credential.
type PasskeyView struct {
	ID           string
	Label        string
	Discoverable bool
	Disabled     bool
	CreatedAt    time.Time
	LastUsedAt   time.Time
}

// ReauthResult reports a reauthentication that opened (or single-decision-armed)
// a window, plus the rotated session token.
type ReauthResult struct {
	SessionToken string
	// CSRFToken is the rotated synchronizer token that travels with a rotated
	// browser session. Without it the caller's next state-changing request
	// would present a stale token against a freshly minted verifier and be
	// refused (#56).
	CSRFToken      string
	SessionID      string
	EnvironmentID  string
	SingleDecision bool
	WindowExpires  time.Time
}

func challengeVerifier(challenge string) []byte { return crypto.ArtifactVerifier(challenge) }

// rpUser builds the relying-party ceremony subject from an account and its
// stored credentials.
func rpUser(handle []byte, account authz.Account, creds []authz.WebAuthnCredential) webauthnrp.User {
	return webauthnrp.User{
		Handle: handle, Name: account.Username, DisplayName: account.DisplayName,
		Credentials: rpCredentials(creds),
	}
}

func rpCredentials(creds []authz.WebAuthnCredential) []webauthnrp.Credential {
	out := make([]webauthnrp.Credential, 0, len(creds))
	for _, c := range creds {
		if c.Disabled {
			continue // a disabled (cloned) credential cannot answer any ceremony
		}
		out = append(out, webauthnrp.Credential{
			ID: c.CredentialID, PublicKey: c.PublicKey, AAGUID: c.AAGUID,
			SignCount: uint32(c.SignCount), Transports: splitTransports(c.Transports),
			BackupEligible: c.BackupEligible, BackupState: c.BackupState,
		})
	}
	return out
}

func splitTransports(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	if json.Unmarshal([]byte(s), &out) == nil {
		return out
	}
	return nil
}

func joinTransports(ts []string) string {
	b, err := json.Marshal(ts)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// requireRP fails closed when the relying party was not configured at boot.
func (s *Auth) requireRP() error {
	if s.WebAuthn == nil {
		return ErrWebAuthnUnavailable
	}
	return nil
}

// ConfigureWebAuthnRP builds the relying party from ExternalOrigin (RP ID = host,
// expected origin = the origin verbatim) and installs it. Boot and tests call it
// so the RP config has exactly one derivation; an origin that yields no valid RP
// is an error the caller refuses on.
func (s *Auth) ConfigureWebAuthnRP() error {
	rp, err := webauthnrp.FromExternalOrigin(s.ExternalOrigin)
	if err != nil {
		return err
	}
	s.WebAuthn = rp
	return nil
}

// EnrolPasskeyStart verifies the account-security proof (the pre-existing
// password or confirmed TOTP code — never the passkey being added, B7/B1) and
// stages an enrolment ceremony bound to the acting session, recording the proof
// class so the finish can reissue the session solely from it (B3). It returns
// the credential-creation options once.
func (s *Auth) EnrolPasskeyStart(ctx context.Context, presented, password, code string) ([]byte, error) {
	if err := s.requireRP(); err != nil {
		return nil, err
	}
	account, cred, confirmed, hasTOTP, proofClass, err := s.readAccountSecurityProof(ctx, presented, password, code)
	if err != nil {
		return nil, err
	}

	release, err := s.enterFactorBudget(ctx, account.ID)
	if err != nil {
		return nil, err
	}
	defer release()

	if !s.verifyProof(ctx, account, cred, confirmed, hasTOTP, proofClass, password, code) {
		s.recordFactorFailure(ctx, account.PrincipalID, account.ID)
		return nil, domain.ErrUnauthenticated
	}
	s.Admission.RecordSuccess(account.ID)

	var options []byte
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		now := s.now()
		live, err := az.Authenticate(ctx, presented, now)
		if err != nil {
			return err
		}
		if live.Principal != account.PrincipalID {
			return domain.ErrUnauthenticated
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		handle, err := s.ensureUserHandle(ctx, az, account.ID)
		if err != nil {
			return err
		}
		existing, err := az.WebAuthnCredentialsForAccount(ctx, account.ID)
		if err != nil {
			return err
		}
		opts, sessionData, challenge, err := s.WebAuthn.BeginEnrol(rpUser(handle, account, existing))
		if err != nil {
			return err
		}
		ceremonyID, err := newID("wac")
		if err != nil {
			return err
		}
		if err := az.CreateWebAuthnCeremony(ctx, authz.NewWebAuthnCeremony{
			ID: ceremonyID, ChallengeVerifier: challengeVerifier(challenge), SessionData: sessionData,
			AccountID: account.ID, SessionID: live.SessionID, Purpose: "enrol",
			OperationBinding: proofClass, CredentialEpoch: epoch,
			ExpiresAt: now.Add(WebAuthnCeremonyLifetime), CreatedAt: now,
		}); err != nil {
			return err
		}
		options = opts
		return nil
	})
	if err != nil {
		return nil, err
	}
	return options, nil
}

// EnrolPasskeyFinish validates the registration response, records residency from
// credProps (absent credProps => non-discoverable, fail-closed on the login
// capability, B13), and completes the account-security mutation: it creates the
// credential and reissues the acting session from the proof ceremony (never the
// new passkey, B1/B3), asserting the passkey-only invariant in the same tx.
func (s *Auth) EnrolPasskeyFinish(ctx context.Context, presented string, responseJSON []byte) (LoginResult, error) {
	if err := s.requireRP(); err != nil {
		return LoginResult{}, err
	}
	challenge, err := webauthnrp.ChallengeFromAttestation(responseJSON)
	if err != nil {
		return LoginResult{}, domain.ErrUnauthenticated
	}

	var (
		account  authz.Account
		ceremony authz.WebAuthnCeremony
		acting   authz.Identity
	)
	err = tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		id, err := az.Authenticate(ctx, presented, s.now())
		if err != nil {
			return err
		}
		acting = id
		account, err = az.AccountByPrincipal(ctx, id.Principal)
		if err != nil {
			return err
		}
		ceremony, err = az.WebAuthnCeremonyByChallenge(ctx, challengeVerifier(challenge))
		if errors.Is(err, domain.ErrNotFound) {
			return ErrNoWebAuthnCeremony
		}
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}
	if !validCeremony(ceremony, "enrol", account.ID, acting.SessionID, "", s.now()) {
		return LoginResult{}, ErrNoWebAuthnCeremony
	}

	existing, credsErr := s.credentialsForAccount(ctx, account.ID)
	if credsErr != nil {
		return LoginResult{}, credsErr
	}
	handle, hErr := s.userHandle(ctx, account.ID)
	if hErr != nil {
		return LoginResult{}, hErr
	}
	reg, err := s.WebAuthn.FinishEnrol(rpUser(handle, account, existing), ceremony.SessionData, responseJSON)
	if err != nil {
		return LoginResult{}, domain.ErrUnauthenticated
	}
	discoverable := credPropsDiscoverable(reg.CredProps)

	credID, err := newID("wacred")
	if err != nil {
		return LoginResult{}, err
	}
	result, err := writeCommittedLoginResult(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer, result *LoginResult) error {
		now := s.now()
		live, err := az.Authenticate(ctx, presented, now)
		if err != nil {
			return err
		}
		if live.Principal != account.PrincipalID {
			return domain.ErrUnauthenticated
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		fresh, err := az.WebAuthnCeremonyByChallenge(ctx, challengeVerifier(challenge))
		if err != nil {
			return err
		}
		// Re-check the ceremony against the write-tx clock (R2 R1-4): a request
		// delayed past the window must not still complete, and a ceremony from a
		// superseded epoch is inert.
		if !validCeremony(fresh, "enrol", account.ID, acting.SessionID, "", now) || fresh.CredentialEpoch != epoch {
			return ErrNoWebAuthnCeremony
		}
		consumed, err := az.ConsumeWebAuthnCeremony(ctx, fresh.ID, credID, now)
		if err != nil {
			return err
		}
		if !consumed {
			return ErrNoWebAuthnCeremony
		}
		if err := az.CreateWebAuthnCredential(ctx, authz.NewWebAuthnCredential{
			ID: credID, AccountID: account.ID, CredentialID: reg.CredentialID, PublicKey: reg.PublicKey,
			AAGUID: reg.AAGUID, SignCount: int64(reg.SignCount), Transports: joinTransports(reg.Transports),
			Discoverable: discoverable, BackupEligible: reg.BackupEligible, BackupState: reg.BackupState,
			Label: "passkey", CredentialEpoch: epoch, CreatedAt: now,
		}); err != nil {
			return err
		}
		// Adding a credential never breaks the invariant, but the assertion is
		// run in every credential-touching tx as the post-state discipline (B4).
		if err := s.assertPasskeyOnlyInvariant(ctx, az, account.ID); err != nil {
			return err
		}
		*result, err = s.reissueSession(ctx, az, account, ceremony.OperationBinding, MethodLocalPassword, Artifact(acting.Artifact), now)
		if err != nil {
			return err
		}
		e, err := newAuditEvent(ctx, audit.EventAuthPasskeyAdded, account.PrincipalID,
			audit.Object{Type: "account", ID: account.ID}, audit.OutcomeSuccess, "",
			audit.Payload{"account_id": account.ID, "credential_id": credID,
				"authorizing_credential": ceremony.OperationBinding, "discoverable": discoverable})
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

// PasskeyLoginStart opens a discoverable-credential login ceremony. It is
// pre-auth: no account is named (the authenticator selects the credential), so
// the ceremony carries no account or session.
func (s *Auth) PasskeyLoginStart(ctx context.Context) ([]byte, error) {
	if err := s.requireRP(); err != nil {
		return nil, err
	}
	release, err := s.Admission.Enter(ctx, audit.FromContext(ctx).SourceIP)
	if err != nil {
		return nil, err
	}
	defer release()

	opts, sessionData, challenge, err := s.WebAuthn.BeginDiscoverableLogin()
	if err != nil {
		return nil, err
	}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		now := s.now()
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		ceremonyID, err := newID("wac")
		if err != nil {
			return err
		}
		return az.CreateWebAuthnCeremony(ctx, authz.NewWebAuthnCeremony{
			ID: ceremonyID, ChallengeVerifier: challengeVerifier(challenge), SessionData: sessionData,
			Purpose: "login", CredentialEpoch: epoch,
			ExpiresAt: now.Add(WebAuthnCeremonyLifetime), CreatedAt: now,
		})
	})
	if err != nil {
		return nil, err
	}
	return opts, nil
}

// PasskeyLoginFinish validates a discoverable assertion, applies the B9
// sign-count rule (a real clone disables the credential and sweeps its sessions
// before refusing), and mints a browser session carrying webauthn assurance in
// one gesture (method local-passkey, factors [webauthn]).
func (s *Auth) PasskeyLoginFinish(ctx context.Context, responseJSON []byte) (LoginResult, error) {
	if err := s.requireRP(); err != nil {
		return LoginResult{}, err
	}
	release, err := s.Admission.Enter(ctx, audit.FromContext(ctx).SourceIP)
	if err != nil {
		return LoginResult{}, err
	}
	defer release()

	out, err := s.attemptPasskeyLogin(ctx, responseJSON)
	if errors.Is(err, domain.ErrUnauthenticated) {
		return LoginResult{}, err
	}
	return out, err
}

func (s *Auth) attemptPasskeyLogin(ctx context.Context, responseJSON []byte) (LoginResult, error) {
	challenge, err := webauthnrp.ChallengeFromAssertion(responseJSON)
	if err != nil {
		return LoginResult{}, domain.ErrUnauthenticated
	}
	var ceremony authz.WebAuthnCeremony
	err = tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		ceremony, err = az.WebAuthnCeremonyByChallenge(ctx, challengeVerifier(challenge))
		if errors.Is(err, domain.ErrNotFound) {
			return ErrNoWebAuthnCeremony
		}
		return err
	})
	if err != nil {
		if errors.Is(err, ErrNoWebAuthnCeremony) {
			return LoginResult{}, domain.ErrUnauthenticated
		}
		return LoginResult{}, err
	}
	if !validCeremony(ceremony, "login", "", "", "", s.now()) {
		return LoginResult{}, domain.ErrUnauthenticated
	}

	// Resolve + verify the assertion. The lookup resolves the account from the
	// assertion's CREDENTIAL id (rawID) — the cryptographically-meaningful
	// identifier — and requires the assertion's user handle to match that
	// credential's account handle, so a bare user-handle claim can neither select
	// the account nor charge it (A2). The pre-auth login path touches NO
	// per-account admission state: brute force is bounded by the per-IP + global
	// Admission budget entered in PasskeyLoginFinish, and per-account backoff
	// lives only on the authenticated step-up/reauth/factor paths — an
	// unauthenticated, client-claimed account must not be holdable in backoff.
	lookup := func(rawID, userHandle []byte) (webauthnrp.User, error) {
		var u webauthnrp.User
		lerr := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
			cred, err := az.WebAuthnCredentialByCredentialID(ctx, rawID)
			if err != nil {
				return err
			}
			acc, err := az.AccountByID(ctx, cred.AccountID)
			if err != nil {
				return err
			}
			handle, err := az.WebAuthnUserHandle(ctx, acc.ID)
			if err != nil {
				return err
			}
			// The assertion's user handle must name the account the resolved
			// credential belongs to; the account is chosen by the credential id,
			// never by the client-supplied handle.
			if len(userHandle) == 0 || !bytes.Equal(handle, userHandle) {
				return domain.ErrUnauthenticated
			}
			creds, err := az.WebAuthnCredentialsForAccount(ctx, acc.ID)
			if err != nil {
				return err
			}
			u = rpUser(handle, acc, creds)
			return nil
		})
		if lerr != nil {
			return webauthnrp.User{}, lerr
		}
		return u, nil
	}
	assertion, err := s.WebAuthn.FinishDiscoverableLogin(ceremony.SessionData, responseJSON, lookup)
	if err != nil {
		return LoginResult{}, domain.ErrUnauthenticated
	}

	// Resolve the stored credential and apply the sign-count rule + mint the
	// session, atomically.
	attempt, err := writeCommittedSessionAttempt(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer, attempt *sessionCompletionAttempt) error {
		now := s.now()
		// Reload the ceremony inside the write tx and re-validate against the tx
		// clock/epoch (A3): a ceremony accepted just before expiry must not
		// complete after it, and one from a superseded epoch is inert.
		fresh, err := az.WebAuthnCeremonyByChallenge(ctx, challengeVerifier(challenge))
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				attempt.refused = sessionRefusedUnauthenticated
				return nil
			}
			return err
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		if !validCeremony(fresh, "login", "", "", "", now) || fresh.CredentialEpoch != epoch {
			attempt.refused = sessionRefusedUnauthenticated
			return nil
		}
		stored, err := az.WebAuthnCredentialByCredentialID(ctx, assertion.CredentialID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				attempt.refused = sessionRefusedUnauthenticated
				return nil
			}
			return err
		}
		if stored.Disabled || stored.CredentialEpoch != epoch || !stored.Discoverable {
			attempt.refused = sessionRefusedUnauthenticated
			return nil
		}
		account, err := az.AccountByID(ctx, stored.AccountID)
		if err != nil {
			return err
		}
		// Re-consume the ceremony under the write lock: a replayed assertion
		// cannot win the phase gap.
		consumed, err := az.ConsumeWebAuthnCeremony(ctx, fresh.ID, stored.ID, now)
		if err != nil {
			return err
		}
		if !consumed {
			attempt.refused = sessionRefusedUnauthenticated
			return nil
		}
		if s.isClone(stored, assertion.SignCount) {
			if err := s.respondToClone(ctx, az, account, stored, now); err != nil {
				return err
			}
			attempt.refused = sessionRefusedUnauthenticated
			return nil
		}
		advanced, err := az.AdvanceWebAuthnSignCount(ctx, stored.ID, stored.RowVersion, int64(assertion.SignCount), now)
		if err != nil {
			return err
		}
		if !advanced {
			// The row moved under a concurrent assertion — the single-writer
			// guarantee row_version exists for. Refuse rather than mint on a stale
			// counter.
			attempt.refused = sessionRefusedUnauthenticated
			return nil
		}
		// Mint against the RELOADED ceremony row (A3): its id is what was consumed
		// above, so the minted session's ceremony_id traces the credential that
		// authored it even if the pre-tx row were ever superseded.
		attempt.result, err = s.mintPasskeySession(ctx, az, account, fresh.ID, now)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	if refused := attempt.refused.err(); refused != nil {
		return LoginResult{}, refused
	}
	return attempt.result, nil
}

// isClone applies B9: skip the counter comparison for a backup-eligible
// (synced) credential or when both counters are 0; otherwise a presented
// counter that does not strictly advance is a clone.
func (s *Auth) isClone(stored authz.WebAuthnCredential, presented uint32) bool {
	if stored.BackupEligible || (stored.SignCount == 0 && presented == 0) {
		return false
	}
	return int64(presented) <= stored.SignCount
}

// respondToClone disables the credential, sweeps every session it minted,
// advances the account's generation and audits — all in the caller's tx (B9).
func (s *Auth) respondToClone(ctx context.Context, az *authz.TxAuthorizer, account authz.Account, stored authz.WebAuthnCredential, now time.Time) error {
	disabled, err := az.DisableWebAuthnCredential(ctx, stored.ID, stored.RowVersion, now)
	if err != nil {
		return err
	}
	if !disabled {
		// The row moved under a concurrent writer; roll the tx back rather than
		// audit a disable that did not happen. The refusal still stands, and a
		// retry re-detects the clone against the advanced counter.
		return ErrCredentialRace
	}
	swept, err := az.SweepSessionsForWebAuthnCredential(ctx, stored.ID)
	if err != nil {
		return err
	}
	if err := az.AdvanceGeneration(ctx, account.PrincipalID); err != nil {
		return err
	}
	e, err := newAuditEvent(ctx, audit.EventAuthPasskeyCloned, account.PrincipalID,
		audit.Object{Type: "account", ID: account.ID}, audit.OutcomeFailure, "",
		audit.Payload{"account_id": account.ID, "credential_id": stored.ID, "sessions_swept": int(swept)})
	if err != nil {
		return err
	}
	return az.RecordAuthEvent(ctx, e)
}

// mintPasskeySession mints a browser session for a discoverable login. Its
// ceremony_id is the login ceremony, whose credential_id is the passkey that
// authored it — the link the clone sweep traces.
func (s *Auth) mintPasskeySession(ctx context.Context, az *authz.TxAuthorizer, account authz.Account, ceremonyID string, now time.Time) (LoginResult, error) {
	result, err := s.completeSession(ctx, az, CreateSession{
		account: account, artifact: ArtifactBrowser,
		assurance: Assurance{
			Method: MethodLocalPasskey, Factors: []string{"webauthn"},
			AuthenticatedAt: now, CeremonyID: ceremonyID,
		},
		csrf: sessionWithCSRF,
	}, now)
	if err != nil {
		return LoginResult{}, err
	}
	for _, ev := range []struct {
		typ     audit.EventType
		payload audit.Payload
	}{
		{audit.EventAuthLogin, audit.Payload{
			"method": MethodLocalPasskey, "artifact": ArtifactBrowser.String(),
			"subject_resolved": true, "account_id": account.ID, "assurance": "multi-factor",
		}},
		{audit.EventAuthSessionCreated, audit.Payload{
			"session_id": result.SessionID, "artifact": ArtifactBrowser.String(),
			"method": MethodLocalPasskey, "assurance": "multi-factor",
		}},
	} {
		e, err := newAuditEvent(ctx, ev.typ, account.PrincipalID,
			audit.Object{Type: "session", ID: result.SessionID}, audit.OutcomeSuccess, "", ev.payload)
		if err != nil {
			return LoginResult{}, err
		}
		if err := az.RecordAuthEvent(ctx, e); err != nil {
			return LoginResult{}, err
		}
	}
	return result, nil
}

// StepUpPasskeyStart opens a non-discoverable ceremony scoped to the acting
// account's credentials, to elevate the session in place.
func (s *Auth) StepUpPasskeyStart(ctx context.Context, presented string) ([]byte, error) {
	return s.beginAccountCeremony(ctx, presented, "step-up", "", "", nil)
}

// StepUpPasskeyFinish validates the assertion, applies the sign-count rule, and
// appends webauthn to the acting session's factor set, rotating its token and
// preserving the original authenticated_at/ceremony (A21). Not an
// account-security mutation.
func (s *Auth) StepUpPasskeyFinish(ctx context.Context, presented string, responseJSON []byte) (LoginResult, error) {
	return s.finishAssertionElevation(ctx, presented, responseJSON, "step-up", nil)
}

// ReauthPasskeyStart opens a reauth ceremony bound to the enumerated unit
// (purpose + environment + sorted key ids), so the challenge authorizes exactly
// that decision and no other with the same shape.
func (s *Auth) ReauthPasskeyStart(ctx context.Context, presented string, intent ReauthIntent) ([]byte, error) {
	unbound, err := intent.isUnbound()
	if err != nil {
		return nil, err
	}
	if unbound {
		return nil, ErrReauthUnitMismatch
	}
	binding, err := intent.bindingFor(intent.environmentID)
	if err != nil {
		return nil, err
	}
	return s.beginAccountCeremony(ctx, presented, "reauth", binding.challengeBinding,
		binding.environmentID, intent.EnvironmentIDs())
}

// ReauthPasskeyFinish validates the assertion and opens a reauthentication
// window over the bound environment. Where the effective window is 0 the window
// is single-decision (B11); otherwise it slides by the configured window.
func (s *Auth) ReauthPasskeyFinish(ctx context.Context, presented string, responseJSON []byte) (ReauthResult, error) {
	var out ReauthResult
	rotated, err := s.finishAssertionElevation(ctx, presented, responseJSON, "reauth", func(ctx context.Context, az *authz.TxAuthorizer, account authz.Account, ceremony authz.WebAuthnCeremony, now time.Time) error {
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		windowID, err := newID("raw")
		if err != nil {
			return err
		}
		// The environment's effective window is resolved through the one seam, not
		// the global s.ReauthWindow (A2): once #55 persists per-environment
		// overrides, an env lowered to 0 opens the mandated single-decision gate
		// here — never a sliding window — exactly as the TOTP/OIDC openers honour it.
		effWin, err := s.effectiveReauthWindow(ctx, az, ceremony.EnvironmentID)
		if err != nil {
			return err
		}
		single := effWin <= 0
		hardCap := s.hardCap()
		hardExpires := now.Add(hardCap)
		// A sliding window must never exceed the hard cap, even on open — clamp it
		// exactly as the TOTP/OIDC openers do (A2). A single-decision 0-window still
		// needs a bounded life; the flag, not the clock, limits it to one decision
		// (#7 consumes it), so it too lives to the hard cap.
		windowExpires := now.Add(effWin)
		if single || windowExpires.After(hardExpires) {
			windowExpires = hardExpires
		}
		window := authz.NewReauthWindow{
			ID: windowID, SessionID: ceremony.SessionID, EnvironmentID: ceremony.EnvironmentID,
			CeremonyID: ceremony.ID, FactorClass: "webauthn", SingleDecision: single,
			AuthenticatedAt: now, WindowExpiresAt: windowExpires, HardExpiresAt: hardExpires,
			CredentialEpoch: epoch, CreatedAt: now,
		}
		if binding, ok, err := parseAdapterOperationBinding(ceremony.OperationBinding); err != nil {
			return err
		} else if ok {
			intent, err := NewAdapterReauthIntent(binding.Operation, binding.EnvironmentIDs)
			if err != nil {
				return ErrReauthUnitMismatch
			}
			target, err := intent.ForEnvironment(binding.EnvironmentID)
			if err != nil {
				return ErrReauthUnitMismatch
			}
			derived, err := target.bindingFor(binding.EnvironmentID)
			if err != nil || binding.EnvironmentID != ceremony.EnvironmentID || derived.challengeBinding != ceremony.OperationBinding {
				return ErrReauthUnitMismatch
			}
			window.BoundPurpose = string(derived.purpose)
			window.BoundOperation = string(derived.operation)
			window.BoundEnvironmentSet = derived.environmentSet
		}
		if err := az.OpenReauthWindow(ctx, window); err != nil {
			return err
		}
		out = ReauthResult{
			EnvironmentID: ceremony.EnvironmentID, SingleDecision: single, WindowExpires: windowExpires,
		}
		return nil
	})
	if err != nil {
		return ReauthResult{}, err
	}
	// The reauth rotates the acting session token (every reauth rotates); carry
	// the new token and session id back beside the window it opened.
	out.SessionToken = rotated.SessionToken
	out.CSRFToken = rotated.CSRFToken
	out.SessionID = rotated.SessionID
	return out, nil
}

// beginAccountCeremony is the shared start for step-up and reauth: a
// non-discoverable ceremony scoped to the acting account's credentials.
func (s *Auth) beginAccountCeremony(ctx context.Context, presented, purpose, operationBinding, environmentID string, environmentIDs []string) ([]byte, error) {
	if err := s.requireRP(); err != nil {
		return nil, err
	}
	var options []byte
	err := tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		now := s.now()
		id, err := az.Authenticate(ctx, presented, now)
		if err != nil {
			return err
		}
		// AUTHORIZE THE ENVIRONMENT BEFORE ANYTHING ELSE TOUCHES IT.
		//
		// A reauth ceremony names an environment, and `finish` derives the
		// window's shape from that environment's policy — so without this the
		// route is the same oracle the TOTP one was: an authenticated
		// principal could tell an environment they cannot reach from one that
		// is missing, and a protected one from an open one, by starting
		// ceremonies and reading the refusals. Resolving the chain and
		// requiring `read(E)` first collapses all of those into the
		// chokepoint's own uniform nonexistent outcome.
		//
		// An empty environment id is the ACCOUNT ceremonies (enrol, step-up):
		// they address no environment, so there is nothing to authorize.
		for _, authorizedEnvironmentID := range environmentIDs {
			if err := authorizeEnvironmentRead(ctx, az, id, authorizedEnvironmentID); err != nil {
				return err
			}
		}
		account, err := az.AccountByPrincipal(ctx, id.Principal)
		if err != nil {
			return err
		}
		creds, err := az.WebAuthnCredentialsForAccount(ctx, account.ID)
		if err != nil {
			return err
		}
		handle, err := az.WebAuthnUserHandle(ctx, account.ID)
		if err != nil {
			return err
		}
		user := rpUser(handle, account, creds)
		if len(user.Credentials) == 0 {
			return ErrNoPasskey
		}
		opts, sessionData, challenge, err := s.WebAuthn.BeginLogin(user)
		if err != nil {
			return err
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		ceremonyID, err := newID("wac")
		if err != nil {
			return err
		}
		if err := az.CreateWebAuthnCeremony(ctx, authz.NewWebAuthnCeremony{
			ID: ceremonyID, ChallengeVerifier: challengeVerifier(challenge), SessionData: sessionData,
			AccountID: account.ID, SessionID: id.SessionID, Purpose: purpose,
			OperationBinding: operationBinding, EnvironmentID: environmentID, CredentialEpoch: epoch,
			ExpiresAt: now.Add(WebAuthnCeremonyLifetime), CreatedAt: now,
		}); err != nil {
			return err
		}
		options = opts
		return nil
	})
	if err != nil {
		return nil, err
	}
	return options, nil
}

// finishAssertionElevation is the shared finish for step-up and reauth: validate
// the assertion against the acting account, apply the sign-count rule, consume
// the ceremony, then run the purpose-specific effect (append a factor / open a
// window). The session token rotates either way.
func (s *Auth) finishAssertionElevation(ctx context.Context, presented string, responseJSON []byte, purpose string, effect func(ctx context.Context, az *authz.TxAuthorizer, account authz.Account, ceremony authz.WebAuthnCeremony, now time.Time) error) (LoginResult, error) {
	if err := s.requireRP(); err != nil {
		return LoginResult{}, err
	}
	challenge, err := webauthnrp.ChallengeFromAssertion(responseJSON)
	if err != nil {
		return LoginResult{}, domain.ErrUnauthenticated
	}
	var (
		account  authz.Account
		ceremony authz.WebAuthnCeremony
		acting   authz.Identity
		creds    []authz.WebAuthnCredential
		handle   []byte
	)
	err = tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		id, err := az.Authenticate(ctx, presented, s.now())
		if err != nil {
			return err
		}
		acting = id
		account, err = az.AccountByPrincipal(ctx, id.Principal)
		if err != nil {
			return err
		}
		ceremony, err = az.WebAuthnCeremonyByChallenge(ctx, challengeVerifier(challenge))
		if errors.Is(err, domain.ErrNotFound) {
			return ErrNoWebAuthnCeremony
		}
		if err != nil {
			return err
		}
		creds, err = az.WebAuthnCredentialsForAccount(ctx, account.ID)
		if err != nil {
			return err
		}
		handle, err = az.WebAuthnUserHandle(ctx, account.ID)
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}
	// The expected reauth binding is the read-phase ceremony's own enumerated unit
	// (the operation this reauth is for); step-up/enrol carry none. validCeremony
	// enforces its presence + environment consistency here, and re-affirms the
	// reloaded row still binds the same unit inside the write tx (A3).
	if !validCeremony(ceremony, purpose, account.ID, acting.SessionID, ceremony.OperationBinding, s.now()) {
		return LoginResult{}, ErrNoWebAuthnCeremony
	}
	expectedBinding := ceremony.OperationBinding

	// Per-account admission (A2): the account is known up front for step-up and
	// reauth, so check AccountDelay + Enter the expensive-work budget before the
	// signature verification, exactly as the factor proof paths do. Held across
	// the verification and the write tx; a bad assertion advances the backoff.
	release, err := s.enterFactorBudget(ctx, account.ID)
	if err != nil {
		return LoginResult{}, err
	}
	defer release()

	assertion, err := s.WebAuthn.FinishLogin(rpUser(handle, account, creds), ceremony.SessionData, responseJSON)
	if err != nil {
		s.recordFactorFailure(ctx, account.PrincipalID, account.ID)
		return LoginResult{}, domain.ErrUnauthenticated
	}

	factors := stepUpFactors(acting.Assurance.Factors, "webauthn")

	attempt, err := writeCommittedSessionAttempt(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer, attempt *sessionCompletionAttempt) error {
		now := s.now()
		live, err := az.Authenticate(ctx, presented, now)
		if err != nil {
			return err
		}
		if live.Principal != account.PrincipalID {
			return domain.ErrUnauthenticated
		}
		// Reload + re-validate the ceremony against the tx clock/epoch (A3): a
		// ceremony accepted just before expiry must not complete after it, and one
		// from a superseded epoch is inert. The reloaded row is what is consumed.
		fresh, err := az.WebAuthnCeremonyByChallenge(ctx, challengeVerifier(challenge))
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				attempt.refused = sessionRefusedUnauthenticated
				return nil
			}
			return err
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		if !validCeremony(fresh, purpose, account.ID, acting.SessionID, expectedBinding, now) || fresh.CredentialEpoch != epoch {
			attempt.refused = sessionRefusedUnauthenticated
			return nil
		}
		stored, err := az.WebAuthnCredentialByCredentialID(ctx, assertion.CredentialID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				attempt.refused = sessionRefusedUnauthenticated
				return nil
			}
			return err
		}
		if stored.AccountID != account.ID || stored.Disabled || stored.CredentialEpoch != epoch {
			attempt.refused = sessionRefusedUnauthenticated
			return nil
		}
		consumed, err := az.ConsumeWebAuthnCeremony(ctx, fresh.ID, stored.ID, now)
		if err != nil {
			return err
		}
		if !consumed {
			attempt.refused = sessionRefusedUnauthenticated
			return nil
		}
		if s.isClone(stored, assertion.SignCount) {
			if err := s.respondToClone(ctx, az, account, stored, now); err != nil {
				return err
			}
			s.Admission.RecordFailure(account.ID)
			attempt.refused = sessionRefusedUnauthenticated
			return nil
		}
		advanced, err := az.AdvanceWebAuthnSignCount(ctx, stored.ID, stored.RowVersion, int64(assertion.SignCount), now)
		if err != nil {
			return err
		}
		if !advanced {
			attempt.refused = sessionRefusedUnauthenticated
			return nil
		}
		// Rotate the acting session token (every step-up/reauth rotates),
		// preserving authenticated_at/ceremony (A21). Step-up also appends the
		// factor class; reauth keeps the factor set and opens a window.
		newFactors := live.Assurance.Factors
		if purpose == "step-up" {
			newFactors = factors
		}
		completion, err := s.completeSession(ctx, az, RotateSession{
			session: live, account: account, factors: newFactors,
		}, now)
		if err != nil {
			return err
		}
		if effect != nil {
			if err := effect(ctx, az, account, fresh, now); err != nil {
				return err
			}
		}
		e, err := newAuditEvent(ctx, audit.EventAuthReauthenticated, account.PrincipalID,
			audit.Object{Type: "session", ID: live.SessionID}, audit.OutcomeSuccess, "",
			audit.Payload{"session_id": live.SessionID, "factor": "webauthn"})
		if err != nil {
			return err
		}
		if err := az.RecordAuthEvent(ctx, e); err != nil {
			return err
		}
		attempt.result = completion
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	if refused := attempt.refused.err(); refused != nil {
		return LoginResult{}, refused
	}
	s.Admission.RecordSuccess(account.ID)
	return attempt.result, nil
}

// RemovePasskey removes a credential as an account-security mutation. The
// passkey-only invariant is checked on the POST-removal state first, so an
// impossible removal (the second-to-last discoverable authenticator of a
// passwordless account) is refused structurally before any proof is asked for.
// A valid removal is then proven by the pre-existing password or TOTP code
// (never the credential being removed, B7) and reissues the acting session.
func (s *Auth) RemovePasskey(ctx context.Context, presented, credentialID, password, code string) (LoginResult, error) {
	if err := s.requireRP(); err != nil {
		return LoginResult{}, err
	}
	// Phase 1 — read the target, the inventory and the available proof.
	var (
		account    authz.Account
		target     authz.WebAuthnCredential
		cred       authz.PasswordCredential
		confirmed  authz.TOTPCredential
		hasTOTP    bool
		proofClass string
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
		target, err = az.WebAuthnCredentialByID(ctx, credentialID)
		if errors.Is(err, domain.ErrNotFound) || (err == nil && target.AccountID != account.ID) {
			return ErrNoPasskey
		}
		if err != nil {
			return err
		}
		// Post-state structural check: would removing this credential leave a
		// passwordless account below the passkey-only floor? Refuse before proof.
		if serr := s.assertRemovalKeepsInvariant(ctx, az, account.ID, target); serr != nil {
			return serr
		}
		cred, confirmed, hasTOTP, proofClass, err = s.proofSelection(ctx, az, account.ID, password, code)
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}

	release, err := s.enterFactorBudget(ctx, account.ID)
	if err != nil {
		return LoginResult{}, err
	}
	defer release()

	if !s.verifyProof(ctx, account, cred, confirmed, hasTOTP, proofClass, password, code) {
		s.recordFactorFailure(ctx, account.PrincipalID, account.ID)
		return LoginResult{}, domain.ErrUnauthenticated
	}
	s.Admission.RecordSuccess(account.ID)

	result, err := writeCommittedLoginResult(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer, result *LoginResult) error {
		now := s.now()
		live, err := az.Authenticate(ctx, presented, now)
		if err != nil {
			return err
		}
		if live.Principal != account.PrincipalID {
			return domain.ErrUnauthenticated
		}
		current, err := az.WebAuthnCredentialByID(ctx, credentialID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return ErrNoPasskey
			}
			return err
		}
		if current.AccountID != account.ID {
			return ErrNoPasskey
		}
		// The account_id predicate is defence in depth behind the ownership check
		// above: zero rows deleted (a regressed check, or a concurrent delete)
		// refuses on the same ErrNoPasskey disposition an unowned credential does,
		// so the fail-closed path stays indistinguishable from "not yours".
		deleted, err := az.DeleteWebAuthnCredential(ctx, credentialID, account.ID)
		if err != nil {
			return err
		}
		if !deleted {
			return ErrNoPasskey
		}
		// Post-state invariant, re-evaluated against the committed inventory (B4).
		if err := s.assertPasskeyOnlyInvariant(ctx, az, account.ID); err != nil {
			return err
		}
		*result, err = s.reissueSession(ctx, az, account, proofClass, MethodLocalPassword, Artifact(live.Artifact), now)
		if err != nil {
			return err
		}
		e, err := newAuditEvent(ctx, audit.EventAuthPasskeyRemoved, account.PrincipalID,
			audit.Object{Type: "account", ID: account.ID}, audit.OutcomeSuccess, "",
			audit.Payload{"account_id": account.ID, "credential_id": credentialID, "authorizing_credential": proofClass})
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

// ListPasskeys lists the acting account's enrolled credentials.
func (s *Auth) ListPasskeys(ctx context.Context, presented string) ([]PasskeyView, error) {
	var out []PasskeyView
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		id, err := az.Authenticate(ctx, presented, s.now())
		if err != nil {
			return err
		}
		account, err := az.AccountByPrincipal(ctx, id.Principal)
		if err != nil {
			return err
		}
		creds, err := az.WebAuthnCredentialsForAccount(ctx, account.ID)
		if err != nil {
			return err
		}
		out = make([]PasskeyView, 0, len(creds))
		for _, c := range creds {
			out = append(out, PasskeyView{
				ID: c.ID, Label: c.Label, Discoverable: c.Discoverable,
				Disabled: c.Disabled, CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// --- account-security proof helpers ---

// readAccountSecurityProof loads the account and the proof material for an enrol
// mutation: the password where the account has one, else the confirmed TOTP
// factor. A passwordless account with no TOTP has only passkeys, which cannot
// prove their own enrolment here (documented limitation of this vertical).
func (s *Auth) readAccountSecurityProof(ctx context.Context, presented, password, code string) (authz.Account, authz.PasswordCredential, authz.TOTPCredential, bool, string, error) {
	var (
		account    authz.Account
		cred       authz.PasswordCredential
		confirmed  authz.TOTPCredential
		hasTOTP    bool
		proofClass string
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
		cred, confirmed, hasTOTP, proofClass, err = s.proofSelection(ctx, az, account.ID, password, code)
		return err
	})
	return account, cred, confirmed, hasTOTP, proofClass, err
}

// proofSelection picks the proof class for an account-security mutation over the
// pre-existing credentials: the password where the account has one, else the
// confirmed TOTP factor (B7 excludes the credential being mutated, which for a
// passkey mutation is never a password/TOTP).
func (s *Auth) proofSelection(ctx context.Context, az *authz.TxAuthorizer, accountID, password, code string) (authz.PasswordCredential, authz.TOTPCredential, bool, string, error) {
	cred, err := az.PasswordCredentialFor(ctx, accountID)
	switch {
	case err == nil:
		return cred, authz.TOTPCredential{}, false, "password", nil
	case !errors.Is(err, domain.ErrNotFound):
		return authz.PasswordCredential{}, authz.TOTPCredential{}, false, "", err
	}
	confirmed, err := az.ConfirmedTOTP(ctx, accountID)
	if err == nil {
		return authz.PasswordCredential{}, confirmed, true, "totp", nil
	}
	if errors.Is(err, domain.ErrNotFound) {
		return authz.PasswordCredential{}, authz.TOTPCredential{}, false, "", ErrNoProofCredential
	}
	return authz.PasswordCredential{}, authz.TOTPCredential{}, false, "", err
}

// verifyProof checks the selected proof outside any transaction (Argon2 for a
// password), returning whether it holds.
func (s *Auth) verifyProof(ctx context.Context, account authz.Account, cred authz.PasswordCredential, confirmed authz.TOTPCredential, hasTOTP bool, proofClass, password, code string) bool {
	if hasTOTP {
		seed, err := s.Keyring.ForInstance().OpenField(totpSeedAAD(confirmed.ID), confirmed.Seed)
		if err != nil {
			s.logFault(ctx, "opening a TOTP seed failed", err, account.ID)
			return false
		}
		_, ok := crypto.ValidateTOTP(seed, code, s.now(), crypto.TOTPSkewSteps)
		crypto.Zero(seed)
		return ok
	}
	return s.verifyPassword(ctx, account.ID, cred, password)
}

// --- passkey-only invariant (B4/B13) ---

// assertPasskeyOnlyInvariant is the POST-STATE predicate run in every tx that
// touches the credential inventory: a passwordless account is admissible only
// with >=2 discoverable, enabled authenticators AND a current recovery batch (a
// live-epoch row with >=1 unconsumed hash). An account holding a password is
// unconstrained here.
func (s *Auth) assertPasskeyOnlyInvariant(ctx context.Context, az *authz.TxAuthorizer, accountID string) error {
	if _, err := az.PasswordCredentialFor(ctx, accountID); err == nil {
		return nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	creds, err := az.WebAuthnCredentialsForAccount(ctx, accountID)
	if err != nil {
		return err
	}
	if discoverableCount(creds) < 2 {
		return ErrPasskeyOnlyViolation
	}
	ok, err := s.hasCurrentRecoveryBatch(ctx, az, accountID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrPasskeyOnlyViolation
	}
	return nil
}

// assertRemovalKeepsInvariant is the structural pre-check: it evaluates the
// invariant against the state that WOULD result from removing target, so an
// impossible removal is refused before any proof is required.
func (s *Auth) assertRemovalKeepsInvariant(ctx context.Context, az *authz.TxAuthorizer, accountID string, target authz.WebAuthnCredential) error {
	if _, err := az.PasswordCredentialFor(ctx, accountID); err == nil {
		return nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	creds, err := az.WebAuthnCredentialsForAccount(ctx, accountID)
	if err != nil {
		return err
	}
	remaining := 0
	for _, c := range creds {
		if c.ID == target.ID {
			continue
		}
		if c.Discoverable && !c.Disabled {
			remaining++
		}
	}
	if remaining < 2 {
		return ErrPasskeyOnlyViolation
	}
	ok, err := s.hasCurrentRecoveryBatch(ctx, az, accountID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrPasskeyOnlyViolation
	}
	return nil
}

func discoverableCount(creds []authz.WebAuthnCredential) int {
	n := 0
	for _, c := range creds {
		if c.Discoverable && !c.Disabled {
			n++
		}
	}
	return n
}

// hasCurrentRecoveryBatch reports whether the account holds a live-epoch recovery
// batch with at least one unconsumed code. It opens the sealed batch to count
// the remaining verifiers (an exhausted batch is an empty array, B4).
func (s *Auth) hasCurrentRecoveryBatch(ctx context.Context, az *authz.TxAuthorizer, accountID string) (bool, error) {
	batch, err := az.RecoveryCodesFor(ctx, accountID)
	if errors.Is(err, domain.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	epoch, err := az.CredentialEpoch(ctx)
	if err != nil {
		return false, err
	}
	if batch.CredentialEpoch != epoch {
		return false, nil
	}
	verifiers, err := s.openRecoveryBatch(ctx, accountID, batch.Batch)
	if err != nil {
		return false, err
	}
	n := len(verifiers)
	zeroVerifiers(verifiers)
	return n >= 1, nil
}

// --- small helpers ---

// ensureUserHandle resolves the account's opaque handle, minting and storing one
// on first enrolment. The handle is opaque random bytes, never a username, email
// or id.
func (s *Auth) ensureUserHandle(ctx context.Context, az *authz.TxAuthorizer, accountID string) ([]byte, error) {
	handle, err := az.WebAuthnUserHandle(ctx, accountID)
	if err != nil {
		return nil, err
	}
	if len(handle) > 0 {
		return handle, nil
	}
	fresh, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	ok, err := az.SetWebAuthnUserHandle(ctx, accountID, fresh)
	if err != nil {
		return nil, err
	}
	if ok {
		return fresh, nil
	}
	// A concurrent enrolment set it first; read it back.
	return az.WebAuthnUserHandle(ctx, accountID)
}

func (s *Auth) userHandle(ctx context.Context, accountID string) ([]byte, error) {
	var handle []byte
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		var err error
		handle, err = az.WebAuthnUserHandle(ctx, accountID)
		return err
	})
	return handle, err
}

func (s *Auth) credentialsForAccount(ctx context.Context, accountID string) ([]authz.WebAuthnCredential, error) {
	var creds []authz.WebAuthnCredential
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		var err error
		creds, err = az.WebAuthnCredentialsForAccount(ctx, accountID)
		return err
	})
	return creds, err
}

// validCeremony checks a ceremony is the expected purpose, unconsumed, unexpired
// and carries the binding its purpose REQUIRES. A login ceremony carries none
// (account, session and binding all expected ""). Every other purpose is
// account+session bound (the schema CHECK pins account-security; enrol, step-up
// and reauth are opened bound the same way), and reauth additionally binds the
// enumerated operation unit to its environment. An empty EXPECTED value where the
// purpose requires one is a MISMATCH (refuse), never a skip — a caller that omits
// the account, session or reauth binding cannot slip past the equality check.
func validCeremony(c authz.WebAuthnCeremony, purpose, accountID, sessionID, binding string, now time.Time) bool {
	if c.Purpose != purpose || c.Consumed || !now.Before(c.ExpiresAt) {
		return false
	}
	if purpose == "login" {
		return true
	}
	if accountID == "" || c.AccountID != accountID {
		return false
	}
	if sessionID == "" || c.SessionID != sessionID {
		return false
	}
	if purpose == "reauth" {
		// The reauth ceremony must carry its enumerated operation binding (schema:
		// operation_binding NOT NULL for reauth), that binding must equal the
		// expected unit, and it must name the ceremony's own environment — the
		// internal consistency the schema cannot express. Threaded through the
		// write tx, this re-affirms the reloaded row still binds the same unit.
		if binding == "" || c.OperationBinding != binding || c.EnvironmentID == "" {
			return false
		}
		if !bindingNamesEnvironment(c.OperationBinding, c.EnvironmentID) {
			return false
		}
	}
	return true
}

// bindingNamesEnvironment reports whether a reauth operation binding's canonical
// JSON names environmentID. Unparseable binding => false (fail closed).
func bindingNamesEnvironment(binding, environmentID string) bool {
	var b struct {
		EnvironmentID string `json:"environment_id"`
	}
	if json.Unmarshal([]byte(binding), &b) != nil {
		return false
	}
	return b.EnvironmentID == environmentID
}

// credPropsDiscoverable reads residency from the credProps extension. Absent or
// false means non-discoverable — fail-closed on the login capability (B13).
func credPropsDiscoverable(props map[string]any) bool {
	if props == nil {
		return false
	}
	rk, ok := props["rk"].(bool)
	return ok && rk
}

// operationBinding is the reauth enumerated-unit binding: canonical JSON of the
// OPERATION, the environment and the sorted key ids, so the ceremony commits to
// exactly the decision the challenge authorizes.
//
// The operation is in here because "purpose-bound" has to mean something the
// SIGNATURE covers, not something the modal says. Without it, an assertion the
// human gave to "reveal · production" would be spendable on "publish into ·
// production" over the same keys — the same unit, a different decision, and
// the human agreed to only one of them.
func operationBinding(op ReauthPurpose, environmentID string, keyIDs []string) (string, error) {
	if !op.Valid() {
		return "", fmt.Errorf("%w: unknown reauthentication purpose %q", domain.ErrInvalid, op)
	}
	sorted := append([]string(nil), keyIDs...)
	sort.Strings(sorted)
	b, err := json.Marshal(struct {
		Operation     string   `json:"operation"`
		EnvironmentID string   `json:"environment_id"`
		KeyIDs        []string `json:"key_ids"`
	}{Operation: string(op), EnvironmentID: environmentID, KeyIDs: sorted})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

type adapterReauthBinding struct {
	Purpose        string   `json:"purpose"`
	Operation      string   `json:"operation"`
	EnvironmentID  string   `json:"environment_id"`
	EnvironmentIDs []string `json:"environment_ids"`
}

func adapterOperationBinding(operation authz.Operation, environmentID string, environmentIDs []string) (string, error) {
	if !adapterReauthOperation(operation) || environmentID == "" {
		return "", ErrReauthUnitMismatch
	}
	environmentIDs = adapterEnvironmentSet(environmentIDs)
	if !slices.Contains(environmentIDs, environmentID) {
		return "", ErrReauthUnitMismatch
	}
	b, err := json.Marshal(adapterReauthBinding{
		Purpose: string(PurposeAdapter), Operation: string(operation),
		EnvironmentID: environmentID, EnvironmentIDs: environmentIDs,
	})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseAdapterOperationBinding(raw string) (adapterReauthBinding, bool, error) {
	var binding adapterReauthBinding
	if err := json.Unmarshal([]byte(raw), &binding); err != nil {
		return adapterReauthBinding{}, false, err
	}
	if binding.Purpose == "" {
		return adapterReauthBinding{}, false, nil
	}
	if binding.Purpose != string(PurposeAdapter) || !adapterReauthOperation(authz.Operation(binding.Operation)) ||
		binding.EnvironmentID == "" || !slices.Contains(binding.EnvironmentIDs, binding.EnvironmentID) ||
		CanonicalEnvironmentSet(binding.EnvironmentIDs) == "" {
		return adapterReauthBinding{}, false, ErrReauthUnitMismatch
	}
	return binding, true, nil
}
