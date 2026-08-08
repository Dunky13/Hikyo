package service

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/crypto"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/tx"
	"github.com/Dunky13/wenv/internal/webauthnrp"
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
	SessionToken   string
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
	if !validCeremony(ceremony, "enrol", account.ID, acting.SessionID, s.now()) {
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
	var result LoginResult
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
		fresh, err := az.WebAuthnCeremonyByChallenge(ctx, challengeVerifier(challenge))
		if err != nil {
			return err
		}
		// Re-check the ceremony against the write-tx clock (R2 R1-4): a request
		// delayed past the window must not still complete, and a ceremony from a
		// superseded epoch is inert.
		if !validCeremony(fresh, "enrol", account.ID, acting.SessionID, now) || fresh.CredentialEpoch != epoch {
			return ErrNoWebAuthnCeremony
		}
		consumed, err := az.ConsumeWebAuthnCeremony(ctx, ceremony.ID, credID, now)
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
		result, err = s.reissueSession(ctx, az, account, ceremony.OperationBinding, MethodLocalPassword, acting.Artifact, now)
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
	if !validCeremony(ceremony, "login", "", "", s.now()) {
		return LoginResult{}, domain.ErrUnauthenticated
	}

	// Resolve + verify the assertion. The lookup loads the account the user
	// handle names and its non-disabled credentials so go-webauthn can verify
	// the signature; a disabled (cloned) credential is not offered.
	lookup := func(rawID, userHandle []byte) (webauthnrp.User, error) {
		var u webauthnrp.User
		lerr := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
			acc, err := az.AccountByWebAuthnUserHandle(ctx, userHandle)
			if err != nil {
				return err
			}
			creds, err := az.WebAuthnCredentialsForAccount(ctx, acc.ID)
			if err != nil {
				return err
			}
			u = rpUser(userHandle, acc, creds)
			return nil
		})
		return u, lerr
	}
	assertion, err := s.WebAuthn.FinishDiscoverableLogin(ceremony.SessionData, responseJSON, lookup)
	if err != nil {
		return LoginResult{}, domain.ErrUnauthenticated
	}

	// Resolve the stored credential and apply the sign-count rule + mint the
	// session, atomically.
	var result LoginResult
	var refused error
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		refused = nil
		now := s.now()
		stored, err := az.WebAuthnCredentialByCredentialID(ctx, assertion.CredentialID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				refused = domain.ErrUnauthenticated
				return nil
			}
			return err
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		if stored.Disabled || stored.CredentialEpoch != epoch || !stored.Discoverable || ceremony.CredentialEpoch != epoch {
			refused = domain.ErrUnauthenticated
			return nil
		}
		account, err := az.AccountByID(ctx, stored.AccountID)
		if err != nil {
			return err
		}
		// Re-consume the ceremony under the write lock: a replayed assertion
		// cannot win the phase gap.
		consumed, err := az.ConsumeWebAuthnCeremony(ctx, ceremony.ID, stored.ID, now)
		if err != nil {
			return err
		}
		if !consumed {
			refused = domain.ErrUnauthenticated
			return nil
		}
		if s.isClone(stored, assertion.SignCount) {
			if err := s.respondToClone(ctx, az, account, stored, now); err != nil {
				return err
			}
			s.Admission.RecordFailure(account.ID)
			refused = domain.ErrUnauthenticated
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
			refused = domain.ErrUnauthenticated
			return nil
		}
		result, err = s.mintPasskeySession(ctx, az, account, ceremony.ID, now)
		if err != nil {
			return err
		}
		s.Admission.RecordSuccess(account.ID)
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	if refused != nil {
		return LoginResult{}, refused
	}
	return result, nil
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
	generation, err := az.PrincipalGeneration(ctx, account.PrincipalID)
	if err != nil {
		return LoginResult{}, err
	}
	epoch, err := az.CredentialEpoch(ctx)
	if err != nil {
		return LoginResult{}, err
	}
	value, verifier, err := crypto.NewArtifact(crypto.ArtifactBrowserSession)
	if err != nil {
		return LoginResult{}, err
	}
	csrfValue, csrfVerifier, err := crypto.NewArtifact(crypto.ArtifactCSRF)
	if err != nil {
		return LoginResult{}, err
	}
	sessionID, err := newID("ses")
	if err != nil {
		return LoginResult{}, err
	}
	factors, err := json.Marshal([]string{"webauthn"})
	if err != nil {
		return LoginResult{}, err
	}
	wire := audit.FromContext(ctx)
	sess := authz.NewSession{
		ID: sessionID, PrincipalID: account.PrincipalID, Verifier: verifier,
		Artifact: ArtifactBrowser, SessionGeneration: generation, CredentialEpoch: epoch,
		AuthMethod: MethodLocalPasskey, Factors: string(factors),
		AuthenticatedAt: now, CeremonyID: ceremonyID, CreatedAt: now,
		IdleExpiresAt: now.Add(BrowserSessionIdle), AbsoluteExpiresAt: now.Add(BrowserSessionAbsolute),
		SourceIP: wire.SourceIP, UserAgent: wire.UserAgent, CSRFVerifier: csrfVerifier,
	}
	if err := az.MintSession(ctx, sess); err != nil {
		return LoginResult{}, err
	}
	for _, ev := range []struct {
		typ     audit.EventType
		payload audit.Payload
	}{
		{audit.EventAuthLogin, audit.Payload{
			"method": MethodLocalPasskey, "artifact": ArtifactBrowser,
			"subject_resolved": true, "account_id": account.ID, "assurance": "multi-factor",
		}},
		{audit.EventAuthSessionCreated, audit.Payload{
			"session_id": sessionID, "artifact": ArtifactBrowser,
			"method": MethodLocalPasskey, "assurance": "multi-factor",
		}},
	} {
		e, err := newAuditEvent(ctx, ev.typ, account.PrincipalID,
			audit.Object{Type: "session", ID: sessionID}, audit.OutcomeSuccess, "", ev.payload)
		if err != nil {
			return LoginResult{}, err
		}
		if err := az.RecordAuthEvent(ctx, e); err != nil {
			return LoginResult{}, err
		}
	}
	return LoginResult{
		SessionToken: value, SessionID: sessionID, Artifact: ArtifactBrowser,
		CreatedAt: now, IdleExpires: sess.IdleExpiresAt, AbsExpires: sess.AbsoluteExpiresAt,
		Principal: account.PrincipalID, AccountID: account.ID, DisplayName: account.DisplayName,
		Assurance: Assurance{Method: MethodLocalPasskey, Factors: []string{"webauthn"}, AuthenticatedAt: now},
		CSRFToken: csrfValue,
	}, nil
}

// StepUpPasskeyStart opens a non-discoverable ceremony scoped to the acting
// account's credentials, to elevate the session in place.
func (s *Auth) StepUpPasskeyStart(ctx context.Context, presented string) ([]byte, error) {
	return s.beginAccountCeremony(ctx, presented, "step-up", "", "")
}

// StepUpPasskeyFinish validates the assertion, applies the sign-count rule, and
// appends webauthn to the acting session's factor set, rotating its token and
// preserving the original authenticated_at/ceremony (A21). Not an
// account-security mutation.
func (s *Auth) StepUpPasskeyFinish(ctx context.Context, presented string, responseJSON []byte) (LoginResult, error) {
	return s.finishAssertionElevation(ctx, presented, responseJSON, "step-up", "", nil)
}

// ReauthPasskeyStart opens a reauth ceremony bound to the enumerated unit
// (environment + sorted key ids), so the challenge authorizes exactly that unit
// (the 0-window per-operation gate). The window's consumption at disclosure is
// #7; this vertical opens it.
func (s *Auth) ReauthPasskeyStart(ctx context.Context, presented, environmentID string, keyIDs []string) ([]byte, error) {
	if environmentID == "" {
		return nil, ErrNoWebAuthnCeremony
	}
	binding, err := operationBinding(environmentID, keyIDs)
	if err != nil {
		return nil, err
	}
	return s.beginAccountCeremony(ctx, presented, "reauth", binding, environmentID)
}

// ReauthPasskeyFinish validates the assertion and opens a reauthentication
// window over the bound environment. Where the effective window is 0 the window
// is single-decision (B11); otherwise it slides by the configured window.
func (s *Auth) ReauthPasskeyFinish(ctx context.Context, presented string, responseJSON []byte) (ReauthResult, error) {
	var out ReauthResult
	rotated, err := s.finishAssertionElevation(ctx, presented, responseJSON, "reauth", "", func(ctx context.Context, az *authz.TxAuthorizer, account authz.Account, ceremony authz.WebAuthnCeremony, now time.Time) error {
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		windowID, err := newID("raw")
		if err != nil {
			return err
		}
		single := s.ReauthWindow <= 0
		hardCap := s.ReauthHardCap
		if hardCap <= 0 {
			hardCap = s.ReauthWindow
		}
		windowExpires := now.Add(s.ReauthWindow)
		if single {
			// A single-decision 0-window still needs a bounded life; the flag,
			// not the clock, is what limits it to one decision (#7 consumes it).
			windowExpires = now.Add(hardCap)
		}
		if err := az.OpenReauthWindow(ctx, authz.NewReauthWindow{
			ID: windowID, SessionID: ceremony.SessionID, EnvironmentID: ceremony.EnvironmentID,
			CeremonyID: ceremony.ID, FactorClass: "webauthn", SingleDecision: single,
			AuthenticatedAt: now, WindowExpiresAt: windowExpires, HardExpiresAt: now.Add(hardCap),
			CredentialEpoch: epoch, CreatedAt: now,
		}); err != nil {
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
	out.SessionID = rotated.SessionID
	return out, nil
}

// beginAccountCeremony is the shared start for step-up and reauth: a
// non-discoverable ceremony scoped to the acting account's credentials.
func (s *Auth) beginAccountCeremony(ctx context.Context, presented, purpose, operationBinding, environmentID string) ([]byte, error) {
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
func (s *Auth) finishAssertionElevation(ctx context.Context, presented string, responseJSON []byte, purpose, _ string, effect func(ctx context.Context, az *authz.TxAuthorizer, account authz.Account, ceremony authz.WebAuthnCeremony, now time.Time) error) (LoginResult, error) {
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
	if !validCeremony(ceremony, purpose, account.ID, acting.SessionID, s.now()) {
		return LoginResult{}, ErrNoWebAuthnCeremony
	}
	assertion, err := s.WebAuthn.FinishLogin(rpUser(handle, account, creds), ceremony.SessionData, responseJSON)
	if err != nil {
		return LoginResult{}, domain.ErrUnauthenticated
	}

	factors := stepUpFactors(acting.Assurance.Factors, "webauthn")
	value, verifier, err := s.newSessionArtifact(acting.Artifact)
	if err != nil {
		return LoginResult{}, err
	}

	var result LoginResult
	var refused error
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		refused = nil
		now := s.now()
		live, err := az.Authenticate(ctx, presented, now)
		if err != nil {
			return err
		}
		if live.Principal != account.PrincipalID {
			return domain.ErrUnauthenticated
		}
		stored, err := az.WebAuthnCredentialByCredentialID(ctx, assertion.CredentialID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				refused = domain.ErrUnauthenticated
				return nil
			}
			return err
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		if stored.AccountID != account.ID || stored.Disabled || stored.CredentialEpoch != epoch || ceremony.CredentialEpoch != epoch {
			refused = domain.ErrUnauthenticated
			return nil
		}
		consumed, err := az.ConsumeWebAuthnCeremony(ctx, ceremony.ID, stored.ID, now)
		if err != nil {
			return err
		}
		if !consumed {
			refused = domain.ErrUnauthenticated
			return nil
		}
		if s.isClone(stored, assertion.SignCount) {
			if err := s.respondToClone(ctx, az, account, stored, now); err != nil {
				return err
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		advanced, err := az.AdvanceWebAuthnSignCount(ctx, stored.ID, stored.RowVersion, int64(assertion.SignCount), now)
		if err != nil {
			return err
		}
		if !advanced {
			refused = domain.ErrUnauthenticated
			return nil
		}
		// Rotate the acting session token (every step-up/reauth rotates),
		// preserving authenticated_at/ceremony (A21). Step-up also appends the
		// factor class; reauth keeps the factor set and opens a window.
		newFactors := live.Assurance.Factors
		if purpose == "step-up" {
			newFactors = factors
		}
		nf, err := json.Marshal(newFactors)
		if err != nil {
			return err
		}
		if err := az.RotateSessionFactors(ctx, live.SessionID, verifier, string(nf)); err != nil {
			return err
		}
		if effect != nil {
			if err := effect(ctx, az, account, ceremony, now); err != nil {
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
		result = LoginResult{
			SessionToken: value, SessionID: acting.SessionID, Artifact: acting.Artifact,
			CreatedAt: acting.CreatedAt, IdleExpires: acting.IdleExpiresAt, AbsExpires: acting.AbsoluteExpiresAt,
			Principal: account.PrincipalID, AccountID: account.ID, DisplayName: account.DisplayName,
			Assurance: Assurance{
				Method: acting.Assurance.Method, Factors: newFactors,
				AuthenticatedAt: acting.Assurance.AuthenticatedAt, CeremonyID: acting.Assurance.CeremonyID,
			},
		}
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	if refused != nil {
		return LoginResult{}, refused
	}
	return result, nil
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

	var result LoginResult
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
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
		if err := az.DeleteWebAuthnCredential(ctx, credentialID); err != nil {
			return err
		}
		// Post-state invariant, re-evaluated against the committed inventory (B4).
		if err := s.assertPasskeyOnlyInvariant(ctx, az, account.ID); err != nil {
			return err
		}
		result, err = s.reissueSession(ctx, az, account, proofClass, MethodLocalPassword, live.Artifact, now)
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
// and — for account-bound purposes — bound to this account and session. A login
// ceremony carries neither (account "" and session "").
func validCeremony(c authz.WebAuthnCeremony, purpose, accountID, sessionID string, now time.Time) bool {
	if c.Purpose != purpose || c.Consumed || !now.Before(c.ExpiresAt) {
		return false
	}
	if accountID != "" && c.AccountID != accountID {
		return false
	}
	if sessionID != "" && c.SessionID != sessionID {
		return false
	}
	return true
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
// environment and the sorted key ids, so the ceremony commits to exactly the
// unit the challenge authorizes.
func operationBinding(environmentID string, keyIDs []string) (string, error) {
	sorted := append([]string(nil), keyIDs...)
	sort.Strings(sorted)
	b, err := json.Marshal(struct {
		EnvironmentID string   `json:"environment_id"`
		KeyIDs        []string `json:"key_ids"`
	}{EnvironmentID: environmentID, KeyIDs: sorted})
	if err != nil {
		return "", err
	}
	return string(b), nil
}
