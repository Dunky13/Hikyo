package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Dunky13/hikyo/internal/admission"
	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/oidcrp"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/tx"
)

// ErrBadPurpose refuses an unknown OIDC transaction purpose loudly: it is a
// caller programming error, not a probe outcome.
var ErrBadPurpose = errors.New("service: OIDC purpose must be login, link or reauth")

// ErrAlreadyLinked refuses linking an identity that is already bound.
var ErrAlreadyLinked = errors.New("service: that identity is already linked")

// ErrReauthNoPolicy refuses starting a reauth against a provider with no
// assurance policy (A5): an unconstrained provider cannot open a window.
var ErrReauthNoPolicy = errors.New("service: provider has no assurance policy; OIDC reauthentication is refused")

// ErrReauthNoEnvironment refuses a reauth with no environment scope.
var ErrReauthNoEnvironment = errors.New("service: OIDC reauthentication requires an environment_id")

// OIDCStartResult is the authorization URL plus the artifacts the transport
// carries: the state value (used to derive the per-transaction binding-cookie
// name, A16) and, for an anonymous login, the browser-binding cookie value the
// callback must present (A2).
type OIDCStartResult struct {
	AuthURL       string
	State         string
	BindingCookie string // "ob" artifact for an anonymous login; empty for a session-bound tx
	Purpose       string
}

// OIDCStart creates a single-use transaction and returns the IdP authorization
// URL. login is anonymous and browser-cookie-bound; link and reauth require an
// authenticated session and are session-bound, and link additionally verifies
// the account-security proof (the pre-existing password) up front, binding it to
// the transaction ceremony (A6). PKCE S256 is always used.
func (s *Auth) OIDCStart(ctx context.Context, slug, purpose, environmentID, presented, proof string) (OIDCStartResult, error) {
	// Admission is entered FIRST, uniformly for every purpose and BEFORE the
	// provider is resolved or the purpose/environment validated. An unknown
	// slug, a bad purpose, a missing environment and a fully resolved provider
	// then take one path with one per-IP admission cost, so a pre-auth prober
	// cannot enumerate provider config by the status, body or timing of the
	// refusal. link/reauth additionally ride the per-account backoff below; the
	// per-IP slot taken here already throttles their Argon2 proof.
	release, err := s.Admission.Enter(ctx, audit.FromContext(ctx).SourceIP)
	if err != nil {
		return OIDCStartResult{}, err
	}
	defer release()

	switch purpose {
	case purposeLogin, purposeLink, purposeReauth:
	default:
		return OIDCStartResult{}, ErrBadPurpose
	}
	// reauth scopes a window to one environment; without it the transaction
	// CHECK would reject the row as a raw fault. Refuse loudly up front.
	if purpose == purposeReauth && environmentID == "" {
		return OIDCStartResult{}, ErrReauthNoEnvironment
	}

	// Phase 1 - resolve the provider and, for a session-bound purpose, the
	// acting session and account. Both run INSIDE the admission budget, and
	// link/reauth authenticate BEFORE the provider is resolved so an
	// unauthenticated caller refuses identically (uniform 401) whether the slug
	// is known or not: provider existence is never what a prober learns first.
	var (
		provider  authz.OIDCProvider
		epoch     int64
		account   authz.Account
		sessionID string
	)
	err = tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		var e error
		if purpose != purposeLogin {
			id, e := az.Authenticate(ctx, presented, s.now())
			if e != nil {
				return e
			}
			account, e = az.AccountByPrincipal(ctx, id.Principal)
			if e != nil {
				return e
			}
			sessionID = id.SessionID
		}
		provider, e = az.EnabledProviderBySlug(ctx, slug)
		if errors.Is(e, domain.ErrNotFound) {
			return ErrProviderNotFound
		}
		if e != nil {
			return e
		}
		if epoch, e = az.CredentialEpoch(ctx); e != nil {
			return e
		}
		return nil
	})
	if err != nil {
		return OIDCStartResult{}, err
	}
	if purpose == purposeReauth && provider.AssurancePolicy == nil {
		return OIDCStartResult{}, ErrReauthNoPolicy // A5, fail fast (also enforced at callback)
	}

	// link/reauth ride the per-account backoff so a stolen session cannot be an
	// unthrottled Argon2 oracle; the per-IP admission slot is already held, so
	// this adds only the account-scoped delay, never a second slot.
	if purpose != purposeLogin {
		if s.Admission.AccountDelay(account.ID) > 0 {
			return OIDCStartResult{}, admission.ErrOverloaded
		}
	}

	// Link: verify the account-security proof (the pre-existing password, since
	// the credential being added never authorizes its own addition).
	if purpose == purposeLink {
		var cred authz.PasswordCredential
		perr := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
			var e error
			cred, e = az.PasswordCredentialFor(ctx, account.ID)
			if errors.Is(e, domain.ErrNotFound) {
				return ErrNoProofCredential
			}
			return e
		})
		if perr != nil {
			return OIDCStartResult{}, perr
		}
		if !s.verifyPassword(ctx, account.ID, cred, proof) {
			s.recordFactorFailure(ctx, account.PrincipalID, account.ID)
			return OIDCStartResult{}, domain.ErrUnauthenticated
		}
		s.Admission.RecordSuccess(account.ID)
	}

	// Discovery reconstructs the provider (A20), then the authorization URL.
	rp, err := s.discover(ctx, provider.Issuer)
	if err != nil {
		return OIDCStartResult{}, ErrProviderDiscovery
	}
	state, stateVerifier, err := crypto.NewArtifact(crypto.ArtifactOIDCState)
	if err != nil {
		return OIDCStartResult{}, err
	}
	nonce, err := randToken()
	if err != nil {
		return OIDCStartResult{}, err
	}
	pkce, err := randToken()
	if err != nil {
		return OIDCStartResult{}, err
	}
	var extra map[string]string
	if purpose == purposeReauth {
		// prompt=login and max_age=0 force a fresh authentication; alone they
		// prove neither freshness nor multi-factor, which is why the callback
		// checks auth_time and acr/amr against policy.
		extra = map[string]string{"prompt": "login", "max_age": "0"}
	}
	authURL := rp.AuthCodeURL(provider.ClientID, provider.RedirectURI, provider.Scopes, state, nonce, pkce, extra)

	txID, err := newID("oidctx")
	if err != nil {
		return OIDCStartResult{}, err
	}
	newTx := authz.NewOIDCTransaction{
		ID: txID, StateVerifier: stateVerifier, Nonce: crypto.ArtifactVerifier(nonce), PKCEVerifier: pkce,
		ProviderID: provider.ID, Issuer: provider.Issuer, RedirectURI: provider.RedirectURI,
		Purpose: purpose, EnvironmentID: environmentID, CredentialEpoch: epoch,
	}
	var bindingCookie string
	if purpose == purposeLogin {
		obVal, obVerifier, aerr := crypto.NewArtifact(crypto.ArtifactOIDCBinding)
		if aerr != nil {
			return OIDCStartResult{}, aerr
		}
		newTx.BindingKind = bindingBrowserCookie
		newTx.BrowserBindingVerifier = obVerifier
		bindingCookie = obVal
	} else {
		newTx.BindingKind = bindingSession
		newTx.InitiatingSessionID = sessionID
		newTx.AccountID = account.ID
	}
	if purpose == purposeLink {
		ceremonyID, cerr := newID("cer")
		if cerr != nil {
			return OIDCStartResult{}, cerr
		}
		newTx.CeremonyID = ceremonyID
	}

	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		now := s.now()
		newTx.CreatedAt = now
		newTx.ExpiresAt = now.Add(oidcTxLifetime)
		return az.CreateOIDCTransaction(ctx, newTx)
	})
	if err != nil {
		return OIDCStartResult{}, err
	}
	return OIDCStartResult{AuthURL: authURL, State: state, BindingCookie: bindingCookie, Purpose: purpose}, nil
}

// OIDCCallbackResult carries the freshly minted or rotated session on success.
type OIDCCallbackResult struct {
	Login   LoginResult
	Purpose string
}

// OIDCCallback processes an IdP redirect against its own transaction. Mix-up is
// refused BEFORE any token is fetched (A1): the callback's provider slug must
// equal the transaction's provider, and the RFC 9207 iss (when present) must
// equal the pinned issuer. The transaction is consumed single-use; the exchange
// runs only at the recorded provider; the ID token is validated completely; and
// the purpose wall is structural - the branch is the transaction's purpose.
func (s *Auth) OIDCCallback(ctx context.Context, slug, code, stateValue, issParam, idpError, bindingCookie, presented string) (OIDCCallbackResult, error) {
	release, err := s.Admission.Enter(ctx, audit.FromContext(ctx).SourceIP)
	if err != nil {
		return OIDCCallbackResult{}, err
	}
	defer release()

	// An unparseable state cannot match any transaction; refuse uniformly.
	if crypto.ParseArtifact(stateValue, crypto.ArtifactOIDCState) != nil {
		return OIDCCallbackResult{}, s.refuseOIDC(ctx, causeState, "", stateValue)
	}
	stateVerifier := crypto.ArtifactVerifier(stateValue)

	// Phase A - resolve, validate, consume. No network here.
	var (
		txn     authz.OIDCTransaction
		prov    authz.OIDCProvider
		refused error
	)
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		refused = nil
		now := s.now()
		epoch, e := az.CredentialEpoch(ctx)
		if e != nil {
			return e
		}
		t, e := az.OIDCTransactionByState(ctx, stateVerifier)
		if errors.Is(e, domain.ErrNotFound) {
			if aerr := s.stageOIDCRefuse(ctx, az, causeState, ""); aerr != nil {
				return aerr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		if e != nil {
			return e
		}
		cause := ""
		switch {
		case t.Consumed:
			cause = causeState
		case !now.Before(t.ExpiresAt):
			cause = causeExpired
		}
		var provider authz.OIDCProvider
		if cause == "" {
			provider, e = az.ProviderForCallback(ctx, t.ProviderID)
			switch {
			case errors.Is(e, domain.ErrNotFound):
				cause = causeMixup
			case e != nil:
				return e
			case provider.Slug != slug: // mix-up leg 1, BEFORE any token
				cause = causeMixup
			case issParam != "" && issParam != t.Issuer: // RFC 9207 leg 2
				cause = causeMixup
			case provider.Issuer != t.Issuer: // A11
				cause = causeIssuer
			case !provider.Enabled:
				cause = causeReconciliation
			case t.CredentialEpoch != epoch:
				cause = causeEpoch
			}
		}
		if cause == "" && idpError != "" { // A18
			cause = causeIDPError
		}
		if cause == "" {
			cause = s.checkBinding(ctx, az, t, bindingCookie, presented, now)
		}
		// A resolved transaction is spent by this callback, whatever the outcome:
		// single-use, no replay.
		claimed, e := az.ConsumeOIDCTransaction(ctx, t.ID, now)
		if e != nil {
			return e
		}
		if !claimed && cause == "" {
			cause = causeState
		}
		if cause != "" {
			if aerr := s.stageOIDCRefuse(ctx, az, cause, t.ProviderID); aerr != nil {
				return aerr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		txn = t
		prov = provider
		return nil
	})
	if err != nil {
		return OIDCCallbackResult{}, err
	}
	if refused != nil {
		return OIDCCallbackResult{}, refused
	}

	// Phase B - exchange and validate, outside any transaction.
	claims, cause := s.exchangeAndVerify(ctx, prov, txn, code)
	if cause != "" {
		return OIDCCallbackResult{}, s.refuseOIDC(ctx, cause, prov.ID, "")
	}

	// Phase C - purpose dispatch. The branch IS the transaction's purpose, so a
	// response obtained for one purpose cannot complete another.
	switch txn.Purpose {
	case purposeLogin:
		return s.completeLogin(ctx, prov, txn, claims)
	case purposeLink:
		return s.completeLink(ctx, prov, txn, claims)
	case purposeReauth:
		return s.completeReauth(ctx, prov, txn, claims, presented)
	default:
		return OIDCCallbackResult{}, ErrBadPurpose
	}
}

// checkBinding enforces the transaction binding (A2). A browser-cookie tx
// requires the ob cookie whose hash was recorded; a session tx requires the
// presented session to still be the initiating one. No default branch trusts an
// unknown binding.
func (s *Auth) checkBinding(ctx context.Context, az *authz.TxAuthorizer, t authz.OIDCTransaction, bindingCookie, presented string, now time.Time) string {
	switch t.BindingKind {
	case bindingBrowserCookie:
		if bindingCookie == "" || !bytes.Equal(crypto.ArtifactVerifier(bindingCookie), t.BrowserBindingVerifier) {
			return causeBinding
		}
		return ""
	case bindingSession:
		id, err := az.Authenticate(ctx, presented, now)
		if err != nil || id.SessionID != t.InitiatingSessionID {
			return causeBinding
		}
		return ""
	default:
		return causeBinding
	}
}

// exchangeAndVerify opens the client secret, exchanges the code at the recorded
// provider only, validates the ID token completely, and compares the nonce hash
// (A19). It returns a closed refusal cause on any failure, never a downgrade.
func (s *Auth) exchangeAndVerify(ctx context.Context, prov authz.OIDCProvider, txn authz.OIDCTransaction, code string) (oidcrp.Claims, string) {
	plainSecret, err := s.Keyring.ForInstance().OpenField(providerSecretAAD(prov.ID), prov.ClientSecret)
	if err != nil {
		s.logFault(ctx, "opening an OIDC client secret failed", err, prov.ID)
		return oidcrp.Claims{}, causeSignature
	}
	defer crypto.Zero(plainSecret)

	rp, err := s.discover(ctx, txn.Issuer)
	if err != nil {
		return oidcrp.Claims{}, causeIDPError
	}
	rawIDToken, err := rp.Exchange(ctx, prov.ClientID, plainSecret, txn.RedirectURI, prov.Scopes, code, txn.PKCEVerifier)
	if err != nil {
		return oidcrp.Claims{}, causeIDPError
	}
	claims, err := rp.Verify(ctx, prov.ClientID, rawIDToken, s.now)
	if err != nil {
		switch {
		case errors.Is(err, oidcrp.ErrIssuer):
			return oidcrp.Claims{}, causeIssuer
		case errors.Is(err, oidcrp.ErrAudience):
			return oidcrp.Claims{}, causeAudience
		default:
			return oidcrp.Claims{}, causeSignature
		}
	}
	if !bytes.Equal(crypto.ArtifactVerifier(claims.Nonce), txn.Nonce) {
		return oidcrp.Claims{}, causeNonce
	}
	return claims, ""
}

// revalidateProvider locks the pinned provider row inside a Phase-C write tx
// and returns a refusal cause if it moved since the Phase-A snapshot. The
// snapshot was taken before the network exchange, so a concurrent reconfigure
// could have swept sessions and narrowed policy while the exchange was in
// flight. A plain re-read is not enough under postgres READ COMMITTED: the
// callback could read a stale snapshot and mint after the sweep committed. The
// guard is a no-op CAS UPDATE on the provider row (row_version + enabled +
// issuer against the snapshot), so it deterministically CONFLICTS with a
// concurrent provider-change UPDATE on the same row — whichever commits first,
// the other refuses. 0 rows means the provider was disabled, deleted, re-issued
// or reconfigured (every reconfigure bumps row_version), so the sweep always
// wins (A4): a stale evaluation cannot mint an account, identity, session or
// window. On sqlite the single writer already serializes; the guard keeps one
// code path across engines.
//
// ponytail: every phase-C mint now takes the provider row lock, so concurrent
// logins through one provider serialize at phase C. Acceptable — the locked
// window is a small local write tx (no network, which was phase B), and login
// is not a hot enough path here to want per-provider lock striping.
func (s *Auth) revalidateProvider(ctx context.Context, az *authz.TxAuthorizer, snapshot authz.OIDCProvider) (string, error) {
	ok, err := az.GuardProviderForMint(ctx, snapshot.ID, snapshot.RowVersion, snapshot.Issuer)
	if err != nil {
		return "", err
	}
	if !ok {
		return causeReconciliation, nil
	}
	return "", nil
}

// completeLogin resolves the identity three ways (live / epoch-inert / unknown,
// A8) and mints a browser session, provisions via JIT policy, or refuses
// uniformly. An epoch-inert identity is terminal and never a JIT input.
func (s *Auth) completeLogin(ctx context.Context, prov authz.OIDCProvider, txn authz.OIDCTransaction, claims oidcrp.Claims) (OIDCCallbackResult, error) {
	var (
		result  LoginResult
		refused error
	)
	err := tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		refused = nil
		now := s.now()
		if cause, e := s.revalidateProvider(ctx, az, prov); e != nil {
			return e
		} else if cause != "" {
			if aerr := s.stageOIDCRefuse(ctx, az, cause, prov.ID); aerr != nil {
				return aerr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		epoch, e := az.CredentialEpoch(ctx)
		if e != nil {
			return e
		}
		var account authz.Account
		identity, e := az.ExternalIdentityByKey(ctx, OIDCKind, txn.Issuer, claims.Subject)
		switch {
		case errors.Is(e, domain.ErrNotFound):
			// Unknown: JIT or uniform refusal.
			acc, cause, jerr := s.jitProvision(ctx, az, prov, claims, now)
			if jerr != nil {
				return jerr
			}
			if cause != "" {
				if aerr := s.stageOIDCRefuse(ctx, az, cause, prov.ID); aerr != nil {
					return aerr
				}
				refused = domain.ErrUnauthenticated
				return nil
			}
			account = acc
		case e != nil:
			return e
		default:
			// A8: epoch-inert is terminal, never JIT.
			if identity.CredentialEpoch != epoch {
				if aerr := s.stageOIDCRefuse(ctx, az, causeEpoch, prov.ID); aerr != nil {
					return aerr
				}
				refused = domain.ErrUnauthenticated
				return nil
			}
			// A3: the recorded provider must be the currently enabled one for
			// this issuer (which is prov, since we exchanged there and it is
			// enabled). A mismatch is a restored/superseded link: refuse to
			// operator reconciliation.
			if identity.ProviderID != prov.ID {
				if aerr := s.stageOIDCRefuse(ctx, az, causeReconciliation, prov.ID); aerr != nil {
					return aerr
				}
				refused = domain.ErrUnauthenticated
				return nil
			}
			account, e = az.AccountByID(ctx, identity.AccountID)
			if e != nil {
				return e
			}
		}
		mfa, e := evaluateAssurance(prov.AssurancePolicy, claims.ACR, claims.AMR)
		if e != nil {
			return e
		}
		result, e = s.mintOIDCSession(ctx, az, account, prov, txn.Issuer, purposeLogin, claims, mfa, now)
		return e
	})
	if err != nil {
		return OIDCCallbackResult{}, err
	}
	if refused != nil {
		return OIDCCallbackResult{}, refused
	}
	return OIDCCallbackResult{Login: result, Purpose: purposeLogin}, nil
}

// jitProvision creates a zero-grant account for an unknown identity when the
// provider's JIT policy admits it, naming the verified claim. It returns a
// refusal cause when the policy is absent or the claim does not match; the
// created account can authenticate and see nothing until granted.
func (s *Auth) jitProvision(ctx context.Context, az *authz.TxAuthorizer, prov authz.OIDCProvider, claims oidcrp.Claims, now time.Time) (authz.Account, string, error) {
	if prov.JITPolicy == nil {
		return authz.Account{}, causeUnknownIdentity, nil
	}
	var policy jitPolicy
	if err := json.Unmarshal([]byte(*prov.JITPolicy), &policy); err != nil {
		return authz.Account{}, "", err
	}
	if policy.Claim == "" {
		return authz.Account{}, causeJITRefused, nil
	}
	raw, ok := claims.Raw[policy.Claim]
	if !ok {
		return authz.Account{}, causeJITRefused, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return authz.Account{}, causeJITRefused, nil
	}
	matched := false
	for _, v := range policy.Values {
		if value == v {
			matched = true
			break
		}
	}
	if !matched {
		return authz.Account{}, causeJITRefused, nil
	}

	epoch, err := az.CredentialEpoch(ctx)
	if err != nil {
		return authz.Account{}, "", err
	}
	principalID, err := newID("usr")
	if err != nil {
		return authz.Account{}, "", err
	}
	accountID, err := newID("acc")
	if err != nil {
		return authz.Account{}, "", err
	}
	identityID, err := newID("eid")
	if err != nil {
		return authz.Account{}, "", err
	}
	// A generated handle, never the email or a provider-supplied username, so a
	// JIT account cannot collide with or impersonate a local handle.
	username := "oidc-" + accountID
	if err := az.CreateHumanPrincipal(ctx, domain.PrincipalID(principalID), now); err != nil {
		return authz.Account{}, "", err
	}
	account := authz.Account{ID: accountID, PrincipalID: domain.PrincipalID(principalID), Username: username, DisplayName: username, CreatedAt: now}
	if err := az.CreateAccount(ctx, account); err != nil {
		return authz.Account{}, "", err
	}
	if err := az.CreateExternalIdentity(ctx, authz.NewExternalIdentity{
		ID: identityID, AccountID: accountID, Kind: OIDCKind, Issuer: prov.Issuer,
		Subject: claims.Subject, ProviderID: prov.ID, CredentialEpoch: epoch, CreatedAt: now,
	}); err != nil {
		return authz.Account{}, "", err
	}
	e, err := newAuditEvent(ctx, audit.EventJITProvisioned, domain.PrincipalID(principalID),
		audit.Object{Type: "account", ID: accountID}, audit.OutcomeSuccess, "",
		audit.Payload{"account_id": accountID, "provider_id": prov.ID, "claim": policy.Claim})
	if err != nil {
		return authz.Account{}, "", err
	}
	if err := az.RecordAuthEvent(ctx, e); err != nil {
		return authz.Account{}, "", err
	}
	return account, "", nil
}

// completeLink binds a new identity to the transaction's account as an
// account-security mutation: the proof ceremony was consumed with the
// transaction (A6), so here the mutation reissues the acting session from that
// proof, deleting every prior session.
func (s *Auth) completeLink(ctx context.Context, prov authz.OIDCProvider, txn authz.OIDCTransaction, claims oidcrp.Claims) (OIDCCallbackResult, error) {
	var (
		result  LoginResult
		refused error
	)
	err := tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		refused = nil
		now := s.now()
		if cause, e := s.revalidateProvider(ctx, az, prov); e != nil {
			return e
		} else if cause != "" {
			if aerr := s.stageOIDCRefuse(ctx, az, cause, prov.ID); aerr != nil {
				return aerr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		epoch, e := az.CredentialEpoch(ctx)
		if e != nil {
			return e
		}
		account, e := az.AccountByID(ctx, txn.AccountID)
		if e != nil {
			return e
		}
		if _, e := az.ExternalIdentityByKey(ctx, OIDCKind, txn.Issuer, claims.Subject); e == nil {
			return ErrAlreadyLinked
		} else if !errors.Is(e, domain.ErrNotFound) {
			return e
		}
		identityID, e := newID("eid")
		if e != nil {
			return e
		}
		if e := az.CreateExternalIdentity(ctx, authz.NewExternalIdentity{
			ID: identityID, AccountID: account.ID, Kind: OIDCKind, Issuer: txn.Issuer,
			Subject: claims.Subject, ProviderID: prov.ID, CredentialEpoch: epoch, CreatedAt: now,
		}); e != nil {
			return e
		}
		result, e = s.reissueSession(ctx, az, account, "password", MethodLocalPassword, ArtifactCLI, now)
		if e != nil {
			return e
		}
		ev, e := newAuditEvent(ctx, audit.EventIdentityLinked, account.PrincipalID,
			audit.Object{Type: "external_identity", ID: identityID}, audit.OutcomeSuccess, "",
			audit.Payload{"kind": OIDCKind, "account_id": account.ID, "identity_id": identityID, "provider_id": prov.ID, "authorizing_credential": "password"})
		if e != nil {
			return e
		}
		return az.RecordAuthEvent(ctx, ev)
	})
	if err != nil {
		return OIDCCallbackResult{}, err
	}
	if refused != nil {
		return OIDCCallbackResult{}, refused
	}
	return OIDCCallbackResult{Login: result, Purpose: purposeLink}, nil
}

// completeReauth validates a fresh federated authentication and opens a
// reauthentication window over the transaction's environment. It is at least as
// strict as completeLogin: it refuses when the pinned provider moved during the
// exchange (A4 TOCTOU), when the provider has no assurance policy (A5), when
// auth_time is absent or stale (A7), when the returned identity is not the
// account's (B15), when the identity is epoch-inert (B2) or recorded against a
// superseded provider (A3), when the policy is unsatisfied or the amr carries no
// recognized possession factor (A5/B5), when the evidence is weaker than the
// session it re-authorizes (a downgrade), or when the effective window is 0
// (only WebAuthn opens a 0-window gate). On success the acting session rotates.
func (s *Auth) completeReauth(ctx context.Context, prov authz.OIDCProvider, txn authz.OIDCTransaction, claims oidcrp.Claims, presented string) (OIDCCallbackResult, error) {
	var (
		result  LoginResult
		refused error
	)
	err := tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		refused = nil
		now := s.now()
		reject := func(cause string) error {
			if aerr := s.stageOIDCRefuse(ctx, az, cause, prov.ID); aerr != nil {
				return aerr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		if cause, e := s.revalidateProvider(ctx, az, prov); e != nil {
			return e
		} else if cause != "" {
			return reject(cause)
		}
		if prov.AssurancePolicy == nil {
			return reject(causeNoPolicy)
		}
		if !claims.HasAuthTime {
			return reject(causeNoAuthTime)
		}
		if now.Sub(claims.AuthTime) > oidcAuthTimeBound || claims.AuthTime.After(now.Add(time.Minute)) {
			return reject(causeNoAuthTime)
		}
		identity, e := az.ExternalIdentityByKey(ctx, OIDCKind, txn.Issuer, claims.Subject)
		if errors.Is(e, domain.ErrNotFound) || (e == nil && identity.AccountID != txn.AccountID) {
			return reject(causeUnknownIdentity) // B15: not the identity the session used
		}
		if e != nil && !errors.Is(e, domain.ErrNotFound) {
			return e
		}
		epoch, e := az.CredentialEpoch(ctx)
		if e != nil {
			return e
		}
		// B2: an epoch-inert (restored) identity is terminal, exactly as
		// completeLogin refuses it — never opens a window.
		if identity.CredentialEpoch != epoch {
			return reject(causeEpoch)
		}
		// A3: the identity must be recorded against the currently enabled
		// provider for this issuer (which is prov). A mismatch is a
		// restored/superseded link after a provider replacement.
		if identity.ProviderID != prov.ID {
			return reject(causeReconciliation)
		}
		mfa, e := evaluateAssurance(prov.AssurancePolicy, claims.ACR, claims.AMR)
		if e != nil {
			return e
		}
		if !mfa {
			return reject(causeNoPolicy) // policy not satisfied
		}
		// Possession is checked INDEPENDENTLY of policy satisfaction (A5/B5): an
		// acr match or a knowledge-only amr set can satisfy a policy without any
		// possession factor, and a reveal reauth demands one.
		if !hasPossessionAMR(claims.AMR) {
			return reject(causeNoPossession)
		}

		// Authenticate the initiating session inside this tx and refuse a
		// downgrade: a reauth may not re-authorize a session established with a
		// stronger (phishing-resistant) credential than this federated evidence.
		id, e := az.Authenticate(ctx, presented, now)
		if e != nil || id.SessionID != txn.InitiatingSessionID {
			return reject(causeBinding)
		}
		evidence := authz.Assurance{Factors: oidcFactors(mfa)}
		if authz.AssuranceRank(id.Assurance) > authz.AssuranceRank(evidence) {
			return reject(causeDowngrade)
		}
		// The environment's effective window is resolved through the one seam,
		// never the global s.ReauthWindow directly (A2), so a lowered environment
		// is honoured on the OIDC path exactly as on the TOTP path.
		effWin, e := s.effectiveReauthWindow(ctx, az, txn.EnvironmentID)
		if e != nil {
			return e
		}
		if effWin <= 0 {
			// A 0-window gate requires WebAuthn: OIDC cannot bind the enumerated
			// unit, so it opens nothing here (B18). Refuse naming the remedy.
			refused = ErrReauthWindowClosed
			if aerr := s.stageOIDCRefuse(ctx, az, causeWindowClosed, prov.ID); aerr != nil {
				return aerr
			}
			return nil
		}

		// Rotate the acting session token (every reauth rotates) preserving its
		// factor set, and open the window over the recorded environment.
		factors, e := json.Marshal(id.Assurance.Factors)
		if e != nil {
			return e
		}
		value, verifier, e := s.newSessionArtifact(id.Artifact)
		if e != nil {
			return e
		}
		if e := az.RotateSessionFactors(ctx, id.SessionID, verifier, string(factors)); e != nil {
			return e
		}
		windowID, e := newID("raw")
		if e != nil {
			return e
		}
		hardCap := s.hardCap()
		hardExpires := now.Add(hardCap)
		windowExpires := now.Add(effWin)
		if windowExpires.After(hardExpires) {
			windowExpires = hardExpires
		}
		if e := az.OpenReauthWindow(ctx, authz.NewReauthWindow{
			ID: windowID, SessionID: id.SessionID, EnvironmentID: txn.EnvironmentID, CeremonyID: txn.ID,
			FactorClass: "oidc", AuthenticatedAt: now, WindowExpiresAt: windowExpires,
			HardExpiresAt: hardExpires, CredentialEpoch: epoch, CreatedAt: now,
		}); e != nil {
			return e
		}
		for _, ev := range []struct {
			typ     audit.EventType
			payload audit.Payload
		}{
			{audit.EventAuthReauthenticated, audit.Payload{"session_id": id.SessionID, "factor": "oidc"}},
			{audit.EventOIDCLogin, audit.Payload{
				"method": oidcMethod(txn.Issuer), "purpose": purposeReauth, "account_id": txn.AccountID,
				"assurance": "multi-factor", "provider_id": prov.ID, "acr": claims.ACR,
				"amr": joinAMR(claims.AMR), "provider_row_version": int(prov.RowVersion),
			}},
		} {
			e, aerr := newAuditEvent(ctx, ev.typ, id.Principal, audit.Object{Type: "session", ID: id.SessionID}, audit.OutcomeSuccess, "", ev.payload)
			if aerr != nil {
				return aerr
			}
			if aerr := az.RecordAuthEvent(ctx, e); aerr != nil {
				return aerr
			}
		}
		result = LoginResult{
			SessionToken: value, SessionID: id.SessionID, Artifact: id.Artifact,
			CreatedAt: id.CreatedAt, IdleExpires: id.IdleExpiresAt, AbsExpires: id.AbsoluteExpiresAt,
			Principal: id.Principal,
		}
		return nil
	})
	if err != nil {
		return OIDCCallbackResult{}, err
	}
	if refused != nil {
		return OIDCCallbackResult{}, refused
	}
	return OIDCCallbackResult{Login: result, Purpose: purposeReauth}, nil
}

// newSessionArtifact mints a fresh value+verifier of the same artifact type as
// the session being rotated.
func (s *Auth) newSessionArtifact(artifact string) (string, []byte, error) {
	if artifact == ArtifactBrowser {
		return crypto.NewArtifact(crypto.ArtifactBrowserSession)
	}
	return crypto.NewArtifact(crypto.ArtifactCLISession)
}

// mintOIDCSession mints a browser session for a federated login, recording the
// assurance the provider policy yielded. The raw acr/amr and the provider
// row_version are recorded in the audit event, read in this same mint tx (A12);
// the provider-change sweep by provider_id keeps a stale evaluation from
// lingering (A4).
func (s *Auth) mintOIDCSession(ctx context.Context, az *authz.TxAuthorizer, account authz.Account, prov authz.OIDCProvider, issuer, purpose string, claims oidcrp.Claims, mfa bool, now time.Time) (LoginResult, error) {
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
	factorClasses := oidcFactors(mfa)
	factors, err := json.Marshal(factorClasses)
	if err != nil {
		return LoginResult{}, err
	}
	assuranceLabel := "single-factor"
	if mfa {
		assuranceLabel = "multi-factor"
	}
	wire := audit.FromContext(ctx)
	sess := authz.NewSession{
		ID: sessionID, PrincipalID: account.PrincipalID, Verifier: verifier,
		Artifact: ArtifactBrowser, SessionGeneration: generation, CredentialEpoch: epoch,
		AuthMethod: oidcMethod(issuer), Factors: string(factors),
		AuthenticatedAt: now, CreatedAt: now,
		IdleExpiresAt: now.Add(BrowserSessionIdle), AbsoluteExpiresAt: now.Add(BrowserSessionAbsolute),
		SourceIP: wire.SourceIP, UserAgent: wire.UserAgent,
		ProviderID: prov.ID, CSRFVerifier: csrfVerifier,
	}
	if err := az.MintSession(ctx, sess); err != nil {
		return LoginResult{}, err
	}
	for _, ev := range []struct {
		typ     audit.EventType
		payload audit.Payload
	}{
		{audit.EventOIDCLogin, audit.Payload{
			"method": oidcMethod(issuer), "purpose": purpose, "account_id": account.ID,
			"assurance": assuranceLabel, "provider_id": prov.ID, "acr": claims.ACR,
			"amr": joinAMR(claims.AMR), "provider_row_version": int(prov.RowVersion),
		}},
		{audit.EventAuthSessionCreated, audit.Payload{
			"session_id": sessionID, "artifact": ArtifactBrowser,
			"method": oidcMethod(issuer), "assurance": assuranceLabel,
		}},
	} {
		e, err := newAuditEvent(ctx, ev.typ, account.PrincipalID, audit.Object{Type: "session", ID: sessionID}, audit.OutcomeSuccess, "", ev.payload)
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
		Assurance: Assurance{Method: oidcMethod(issuer), Factors: factorClasses, AuthenticatedAt: now},
		CSRFToken: csrfValue,
	}, nil
}

// refuseOIDC records an oidc_refused event with its cause and answers the
// uniform refusal. The event is committed with the refusal (fail-closed): a
// denial without its durable record is exactly what the discipline forbids.
func (s *Auth) refuseOIDC(ctx context.Context, cause, providerID, backoffKey string) error {
	if backoffKey != "" {
		s.Admission.RecordFailure(backoffKey)
	}
	if err := tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		return s.stageOIDCRefuse(ctx, az, cause, providerID)
	}); err != nil {
		return err
	}
	if cause == causeWindowClosed {
		return ErrReauthWindowClosed
	}
	return domain.ErrUnauthenticated
}

// stageOIDCRefuse stages the refusal event in the caller's transaction and
// returns only the audit-write error, on the same fail-closed contract as
// failLogin.
func (s *Auth) stageOIDCRefuse(ctx context.Context, az *authz.TxAuthorizer, cause, providerID string) error {
	payload := audit.Payload{"cause": cause}
	if providerID != "" {
		payload["provider_id"] = providerID
	}
	e, err := newAuditEvent(ctx, audit.EventOIDCRefused, "",
		audit.Object{Type: "oidc_transaction"}, audit.OutcomeFailure, "", payload)
	if err != nil {
		return err
	}
	return az.RecordAuthEvent(ctx, e)
}

func joinAMR(amr []string) string {
	out := ""
	for i, m := range amr {
		if i > 0 {
			out += ","
		}
		out += m
	}
	return out
}

// AuthMethodProvider is one enabled provider for the public methods list.
type AuthMethodProvider struct {
	Slug        string
	DisplayName string
	Kind        string
}

// AuthMethods returns the enabled OIDC providers and whether local login is on.
// Public discovery: proof-free, instance-level, never per-account.
func (s *Auth) AuthMethods(ctx context.Context) ([]AuthMethodProvider, bool, error) {
	var out []AuthMethodProvider
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		rows, e := az.ListProviders(ctx)
		if e != nil {
			return e
		}
		for _, p := range rows {
			if p.Enabled {
				out = append(out, AuthMethodProvider{Slug: p.Slug, DisplayName: p.DisplayName, Kind: OIDCKind})
			}
		}
		samlProviders, e := az.ListSAMLProviders(ctx)
		if e != nil {
			return e
		}
		for _, p := range samlProviders {
			if p.Enabled {
				out = append(out, AuthMethodProvider{Slug: p.Slug, DisplayName: p.DisplayName, Kind: SAMLKind})
			}
		}
		return nil
	})
	return out, true, err
}

// ExternalIdentityView is the transport-facing shape of a linked identity, so
// internal/server needs no authz import.
type ExternalIdentityView struct {
	ID         string
	Kind       string
	Issuer     string
	Subject    string
	ProviderID string
	CreatedAt  time.Time
}

// ListIdentities returns an account's linked external identities.
func (s *Auth) ListIdentities(ctx context.Context, presented string) ([]ExternalIdentityView, error) {
	var out []ExternalIdentityView
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		id, e := az.Authenticate(ctx, presented, s.now())
		if e != nil {
			return e
		}
		account, e := az.AccountByPrincipal(ctx, id.Principal)
		if e != nil {
			return e
		}
		rows, e := az.ExternalIdentitiesForAccount(ctx, account.ID)
		if e != nil {
			return e
		}
		for _, r := range rows {
			out = append(out, ExternalIdentityView{
				ID: r.ID, Kind: r.Kind, Issuer: r.Issuer, Subject: r.Subject, ProviderID: r.ProviderID, CreatedAt: r.CreatedAt,
			})
		}
		return nil
	})
	return out, err
}

// UnlinkIdentity removes a linked identity as an account-security mutation. It
// refuses removing the last remaining credential (in the lockout-invariant
// shape), verifies the pre-existing password, and reissues the acting session.
func (s *Auth) UnlinkIdentity(ctx context.Context, presented, identityID, proof string) (LoginResult, error) {
	var (
		account      authz.Account
		cred         authz.PasswordCredential
		identityKind string
	)
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		id, e := az.Authenticate(ctx, presented, s.now())
		if e != nil {
			return e
		}
		account, e = az.AccountByPrincipal(ctx, id.Principal)
		if e != nil {
			return e
		}
		identity, e := az.ExternalIdentityByID(ctx, identityID)
		if errors.Is(e, domain.ErrNotFound) || (e == nil && identity.AccountID != account.ID) {
			return ErrIdentityNotFound
		}
		if e != nil {
			return e
		}
		identityKind = identity.Kind
		cred, e = az.PasswordCredentialFor(ctx, account.ID)
		if errors.Is(e, domain.ErrNotFound) {
			return ErrNoProofCredential
		}
		return e
	})
	if err != nil {
		return LoginResult{}, err
	}

	release, err := s.enterFactorBudget(ctx, account.ID)
	if err != nil {
		return LoginResult{}, err
	}
	defer release()
	if !s.verifyPassword(ctx, account.ID, cred, proof) {
		s.recordFactorFailure(ctx, account.PrincipalID, account.ID)
		return LoginResult{}, domain.ErrUnauthenticated
	}
	s.Admission.RecordSuccess(account.ID)

	var result LoginResult
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		now := s.now()
		live, e := az.Authenticate(ctx, presented, now)
		if e != nil {
			return e
		}
		if live.Principal != account.PrincipalID {
			return domain.ErrUnauthenticated
		}
		// Last-credential refusal: unlinking must not strand the account. A
		// password stands here (the proof), so an identity unlink is always
		// safe while a password exists; the check is kept for the passwordless
		// future and stays in the lockout-invariant shape.
		identities, e := az.ExternalIdentitiesForAccount(ctx, account.ID)
		if e != nil {
			return e
		}
		if _, e := az.PasswordCredentialFor(ctx, account.ID); errors.Is(e, domain.ErrNotFound) && len(identities) <= 1 {
			return ErrLastCredential
		} else if e != nil && !errors.Is(e, domain.ErrNotFound) {
			return e
		}
		if e := az.RemoveExternalIdentity(ctx, identityID); e != nil {
			return e
		}
		result, e = s.reissueSession(ctx, az, account, "password", MethodLocalPassword, ArtifactCLI, now)
		if e != nil {
			return e
		}
		ev, e := newAuditEvent(ctx, audit.EventIdentityUnlinked, account.PrincipalID,
			audit.Object{Type: "external_identity", ID: identityID}, audit.OutcomeSuccess, "",
			audit.Payload{"kind": identityKind, "account_id": account.ID, "identity_id": identityID, "authorizing_credential": "password"})
		if e != nil {
			return e
		}
		return az.RecordAuthEvent(ctx, ev)
	})
	if err != nil {
		return LoginResult{}, err
	}
	return result, nil
}
