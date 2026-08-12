package service

import (
	"context"
	stdcrypto "crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Dunky13/hikyo/internal/admission"
	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/authz"
	wencrypto "github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/samlsp"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/tx"
)

const (
	SAMLKind = "saml"

	samlNameIDPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	samlNameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	samlNameIDTransient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	samlNameIDEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

	samlTransactionLifetime = 10 * time.Minute
	samlReauthFreshness     = 5 * time.Minute
	samlClockSkew           = time.Minute
)

var (
	ErrSAMLTransientNameID     = errors.New("service: transient SAML NameID is unsupported")
	ErrSAMLEmailNameIDDisabled = errors.New("service: emailAddress SAML NameID requires provider opt-in")
	ErrSAMLNameIDFormat        = errors.New("service: unsupported SAML NameID format")
	ErrSAMLProviderNotFound    = errors.New("service: no such SAML provider")
	ErrSAMLMetadataExpired     = errors.New("service: SAML provider metadata has expired")
	ErrSAMLResponse            = errors.New("service: SAML response refused")
	ErrSAMLRelayState          = errors.New("service: invalid SAML RelayState")
	ErrSAMLSigningKey          = errors.New("service: SAML request signing key is unavailable")
	ErrSAMLReauthNoPolicy      = errors.New("service: SAML provider has no assurance policy; reauthentication is refused")
	ErrSAMLReauthNoEnvironment = errors.New("service: SAML reauthentication requires an environment_id")
)

type samlAssurancePolicy struct {
	AuthnContextClassRefs []string `json:"authn_context_class_refs"`
}

func evaluateSAMLAssurance(policy *string, contextClassRef *string) (bool, error) {
	if policy == nil || contextClassRef == nil {
		return false, nil
	}
	var parsed samlAssurancePolicy
	if err := json.Unmarshal([]byte(*policy), &parsed); err != nil {
		var refs []string
		if listErr := json.Unmarshal([]byte(*policy), &refs); listErr != nil {
			return false, fmt.Errorf("service: parsing a SAML assurance policy: %w", err)
		}
		parsed.AuthnContextClassRefs = refs
	}
	for _, accepted := range parsed.AuthnContextClassRefs {
		if accepted == *contextClassRef {
			return true, nil
		}
	}
	return false, nil
}

// samlSubject enforces the provider's NameID-format policy, then turns the
// ADR's arbitrary-byte injective encoding into an equally injective text key.
// Base64 is representation only: it performs no normalization and is safe for
// PostgreSQL TEXT (which cannot store the encoding's NUL presence bytes).
func samlSubject(nameID samlsp.NameID, allowEmail bool) (string, error) {
	// SAML Core 2.2.2 treats an omitted Format as unspecified. Accept it under
	// that policy while retaining nil in the injective encoding: the ADR's
	// byte-exact identity rule still distinguishes omitted from explicitly set.
	if nameID.Format != nil {
		switch *nameID.Format {
		case samlNameIDPersistent, samlNameIDUnspecified:
		case samlNameIDTransient:
			return "", ErrSAMLTransientNameID
		case samlNameIDEmail:
			if !allowEmail {
				return "", ErrSAMLEmailNameIDDisabled
			}
		default:
			return "", ErrSAMLNameIDFormat
		}
	}
	encoded, err := samlsp.EncodeNameID(nameID)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(encoded), nil
}

func samlMethod(entityID string) string { return "saml:" + entityID }

func samlFactors(mfa bool) []string {
	if mfa {
		return []string{"saml", "saml-mfa"}
	}
	return []string{"saml"}
}

func samlSPEntityID(origin string) string {
	return strings.TrimRight(origin, "/") + "/api/v1/auth/saml"
}

func samlSPKeyAAD(id string) wencrypto.InstanceFieldAAD {
	return wencrypto.InstanceFieldAAD{OwnerTable: "saml_sp_keys", OwnerRowID: id, FieldTag: "private_key"}
}

// SAMLStartResult carries the redirect and the anonymous-login binding value.
// Transport returns only RedirectURL in JSON and sets InitiatorCookie as the
// path-scoped Secure/HttpOnly/SameSite=None cookie the ACS must present.
type SAMLStartResult struct {
	RedirectURL     string
	InitiatorCookie string
	Purpose         string
}

// SAMLStart creates the SP-initiated request and its durable purpose binding.
func (s *Auth) SAMLStart(ctx context.Context, slug, purpose, environmentID, presented, proof string) (SAMLStartResult, error) {
	release, err := s.Admission.Enter(ctx, audit.FromContext(ctx).SourceIP)
	if err != nil {
		return SAMLStartResult{}, err
	}
	defer release()

	switch purpose {
	case purposeLogin, purposeLink, purposeReauth:
	default:
		return SAMLStartResult{}, ErrBadPurpose
	}
	if purpose == purposeReauth && environmentID == "" {
		return SAMLStartResult{}, ErrSAMLReauthNoEnvironment
	}

	var (
		provider  authz.SAMLProvider
		account   authz.Account
		sessionID string
		epoch     int64
	)
	err = tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		var readErr error
		if purpose != purposeLogin {
			identity, authErr := az.Authenticate(ctx, presented, s.now())
			if authErr != nil {
				return authErr
			}
			account, readErr = az.AccountByPrincipal(ctx, identity.Principal)
			if readErr != nil {
				return readErr
			}
			sessionID = identity.SessionID
		}
		provider, readErr = az.SAMLProviderBySlug(ctx, slug)
		if errors.Is(readErr, domain.ErrNotFound) || (readErr == nil && !provider.Enabled) {
			return ErrSAMLProviderNotFound
		}
		if readErr != nil {
			return readErr
		}
		if provider.MetadataValidUntil != nil && !s.now().Before(*provider.MetadataValidUntil) {
			return ErrSAMLMetadataExpired
		}
		epoch, readErr = az.CredentialEpoch(ctx)
		return readErr
	})
	if err != nil {
		return SAMLStartResult{}, err
	}
	if purpose == purposeReauth && provider.AssurancePolicy == nil {
		return SAMLStartResult{}, ErrSAMLReauthNoPolicy
	}
	if purpose != purposeLogin && s.Admission.AccountDelay(account.ID) > 0 {
		return SAMLStartResult{}, admission.ErrOverloaded
	}
	if purpose == purposeLink {
		var credential authz.PasswordCredential
		err = tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
			var readErr error
			credential, readErr = az.PasswordCredentialFor(ctx, account.ID)
			if errors.Is(readErr, domain.ErrNotFound) {
				return ErrNoProofCredential
			}
			return readErr
		})
		if err != nil {
			return SAMLStartResult{}, err
		}
		if !s.verifyPassword(ctx, account.ID, credential, proof) {
			s.recordFactorFailure(ctx, account.PrincipalID, account.ID)
			return SAMLStartResult{}, domain.ErrUnauthenticated
		}
		s.Admission.RecordSuccess(account.ID)
	}

	relayState, err := randToken()
	if err != nil {
		return SAMLStartResult{}, err
	}
	initiator, err := randToken()
	if err != nil {
		return SAMLStartResult{}, err
	}
	config := samlsp.AuthnRequestConfig{
		IDPSSOURL: provider.SSORedirectURL, SPEntityID: samlSPEntityID(s.ExternalOrigin),
		ACSURL: provider.ACSURL, RelayState: relayState, ForceAuthn: purpose == purposeReauth,
		Sign: provider.ForceSignRequests || provider.MetadataWantAuthnRequestsSigned, Now: s.now(),
	}
	if config.Sign {
		config.Signer, config.Certificate, err = s.samlSigningMaterial(ctx)
		if err != nil {
			return SAMLStartResult{}, err
		}
	}
	request, err := samlsp.BuildAuthnRequest(config)
	if err != nil {
		return SAMLStartResult{}, err
	}
	transactionID, err := newID("samltx")
	if err != nil {
		return SAMLStartResult{}, err
	}
	transaction := newSAMLTransaction(transactionID, request.RequestID, relayState, initiator,
		provider, purpose, sessionID, account.ID, environmentID, epoch)
	if purpose == purposeLink {
		transaction.CeremonyID, err = newID("cer")
		if err != nil {
			return SAMLStartResult{}, err
		}
	}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		now := s.now()
		transaction.CreatedAt = now
		transaction.ExpiresAt = now.Add(samlTransactionLifetime)
		return az.CreateSAMLTransaction(ctx, transaction)
	})
	if err != nil {
		return SAMLStartResult{}, err
	}
	return SAMLStartResult{RedirectURL: request.URL, InitiatorCookie: initiator, Purpose: purpose}, nil
}

func newSAMLTransaction(id, requestID, relayState, initiator string, provider authz.SAMLProvider,
	purpose, sessionID, accountID, environmentID string, epoch int64,
) authz.NewSAMLTransaction {
	return authz.NewSAMLTransaction{
		ID: id, RequestID: requestID,
		RelayStateVerifier: wencrypto.ArtifactVerifier(relayState),
		InitiatorVerifier:  wencrypto.ArtifactVerifier(initiator),
		ProviderID:         provider.ID, EntityID: provider.EntityID, ACSURL: provider.ACSURL,
		Purpose: purpose, InitiatingSessionID: sessionID, AccountID: accountID,
		EnvironmentID: environmentID, CredentialEpoch: epoch,
	}
}

func (s *Auth) samlSigningMaterial(ctx context.Context) (stdcrypto.Signer, []byte, error) {
	var key authz.SAMLSPKey
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		var readErr error
		key, readErr = az.ActiveSAMLSPKey(ctx)
		return readErr
	})
	if err != nil {
		return nil, nil, ErrSAMLSigningKey
	}
	plain, err := s.Keyring.ForInstance().OpenField(samlSPKeyAAD(key.ID), key.EncryptedPrivateKey)
	if err != nil {
		return nil, nil, ErrSAMLSigningKey
	}
	defer wencrypto.Zero(plain)
	parsed, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		return nil, nil, ErrSAMLSigningKey
	}
	signer, ok := parsed.(stdcrypto.Signer)
	if !ok {
		return nil, nil, ErrSAMLSigningKey
	}
	return signer, key.CertificateDER, nil
}

// SAMLACS validates one HTTP-POST response and completes the transaction's
// recorded purpose. Transaction consumption, replay insertion and the session
// or reauth write commit together; a concurrent replay can win only once.
func (s *Auth) SAMLACS(ctx context.Context, slug, encodedResponse, relayState, initiatorCookie string) (LoginResult, error) {
	release, err := s.Admission.Enter(ctx, audit.FromContext(ctx).SourceIP)
	if err != nil {
		return LoginResult{}, err
	}
	defer release()
	if !validSAMLHandle(relayState) {
		return LoginResult{}, s.refuseSAML(ctx, "relay-state", "", "", "", "")
	}
	raw, responseDecodeErr := base64.StdEncoding.DecodeString(encodedResponse)

	var (
		result  LoginResult
		refused error
	)
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		now := s.now()
		transaction, lookupErr := az.SAMLTransactionByRelayState(ctx, wencrypto.ArtifactVerifier(relayState))
		if errors.Is(lookupErr, domain.ErrNotFound) {
			if auditErr := s.stageSAML(ctx, az, audit.OutcomeFailure, "relay-state", "", "", "", "", nil); auditErr != nil {
				return auditErr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		if lookupErr != nil {
			return lookupErr
		}
		provider, providerErr := az.SAMLProviderForCallback(ctx, transaction.ProviderID)
		cause := ""
		switch {
		case transaction.Consumed:
			cause = "consumed-transaction"
		case !now.Before(transaction.ExpiresAt):
			cause = "expired-transaction"
		case errors.Is(providerErr, domain.ErrNotFound):
			cause = "provider-mixup"
		case providerErr != nil:
			return providerErr
		case provider.Slug != slug || provider.ID != transaction.ProviderID:
			cause = "provider-mixup"
		case !provider.Enabled || provider.EntityID != transaction.EntityID || provider.ACSURL != transaction.ACSURL:
			cause = "provider-reconciliation"
		case provider.MetadataValidUntil != nil && !now.Before(*provider.MetadataValidUntil):
			cause = "metadata-expired"
		}
		epoch, epochErr := az.CredentialEpoch(ctx)
		if epochErr != nil {
			return epochErr
		}
		if cause == "" && transaction.CredentialEpoch != epoch {
			cause = "epoch"
		}

		var initiating authz.Identity
		if cause == "" && (initiatorCookie == "" || !equalVerifier(transaction.InitiatorVerifier, initiatorCookie)) {
			cause = "initiator-mismatch"
		}
		if cause == "" {
			switch transaction.Purpose {
			case purposeLogin:
			case purposeLink, purposeReauth:
				initiating, lookupErr = az.AuthenticateSessionByID(ctx, transaction.InitiatingSessionID, now)
				if lookupErr != nil {
					cause = "initiator-mismatch"
				}
			default:
				cause = "purpose-mismatch"
			}
		}

		claimed, consumeErr := az.ConsumeSAMLTransaction(ctx, transaction.ID, now)
		if consumeErr != nil {
			return consumeErr
		}
		if !claimed && cause == "" {
			cause = "consumed-transaction"
		}
		if cause == "" && responseDecodeErr != nil {
			cause = "malformed"
		}
		if cause != "" {
			if auditErr := s.stageSAML(ctx, az, audit.OutcomeFailure, cause, provider.ID, transaction.EntityID, transaction.Purpose, transaction.ID, nil); auditErr != nil {
				return auditErr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}

		certificates, certErr := parseSAMLCertificates(provider.SigningCertificates)
		if certErr != nil {
			return certErr
		}
		claims, validationErr := samlsp.ValidateResponse(raw, certificates, samlsp.ValidationExpectations{
			ProviderEntityID: transaction.EntityID, SPEntityID: samlSPEntityID(s.ExternalOrigin),
			ACSURL: transaction.ACSURL, RequestID: transaction.RequestID, Now: now,
			ClockSkew: samlClockSkew, MaxIssueAge: samlReauthFreshness,
		})
		if validationErr != nil {
			if auditErr := s.stageSAML(ctx, az, audit.OutcomeFailure, samlValidationCause(validationErr), provider.ID, transaction.EntityID, transaction.Purpose, transaction.ID, nil); auditErr != nil {
				return auditErr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		subject, subjectErr := samlSubject(claims.NameID, provider.AllowEmailNameID)
		if subjectErr != nil {
			if auditErr := s.stageSAML(ctx, az, audit.OutcomeFailure, samlValidationCause(subjectErr), provider.ID, transaction.EntityID, transaction.Purpose, transaction.ID, &claims); auditErr != nil {
				return auditErr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		if _, gcErr := az.DeleteExpiredSAMLReplay(ctx, now); gcErr != nil {
			return gcErr
		}
		replayClaimed, replayErr := az.ClaimSAMLReplay(ctx, authz.NewSAMLReplay{
			Issuer: transaction.EntityID, AssertionID: claims.AssertionID,
			ExpiresAt: claims.Conditions.NotOnOrAfter.Add(samlClockSkew), CreatedAt: now,
		})
		if replayErr != nil {
			return replayErr
		}
		if !replayClaimed {
			if auditErr := s.stageSAML(ctx, az, audit.OutcomeFailure, "replayed-assertion", provider.ID, transaction.EntityID, transaction.Purpose, transaction.ID, &claims); auditErr != nil {
				return auditErr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		guarded, guardErr := az.GuardSAMLProviderForMint(ctx, provider.ID, provider.RowVersion, provider.EntityID)
		if guardErr != nil {
			return guardErr
		}
		if !guarded {
			if auditErr := s.stageSAML(ctx, az, audit.OutcomeFailure, "provider-reconciliation", provider.ID, transaction.EntityID, transaction.Purpose, transaction.ID, &claims); auditErr != nil {
				return auditErr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}

		var completeErr error
		switch transaction.Purpose {
		case purposeLogin:
			result, completeErr = s.completeSAMLLogin(ctx, az, provider, transaction, claims, subject, epoch, now)
		case purposeLink:
			result, completeErr = s.completeSAMLLink(ctx, az, provider, transaction, claims, subject, initiating, epoch, now)
		case purposeReauth:
			result, completeErr = s.completeSAMLReauth(ctx, az, provider, transaction, claims, subject, initiating, epoch, now)
		}
		if errors.Is(completeErr, domain.ErrUnauthenticated) || errors.Is(completeErr, ErrReauthWindowClosed) {
			refused = completeErr
			return nil
		}
		if errors.Is(completeErr, ErrAlreadyLinked) {
			refused = completeErr
			return nil
		}
		return completeErr
	})
	if err != nil {
		return LoginResult{}, err
	}
	if refused != nil {
		return LoginResult{}, refused
	}
	return result, nil
}

func validSAMLHandle(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func equalVerifier(want []byte, value string) bool {
	return len(want) != 0 && subtle.ConstantTimeCompare(want, wencrypto.ArtifactVerifier(value)) == 1
}

func parseSAMLCertificates(encoded []byte) ([]*x509.Certificate, error) {
	var ders [][]byte
	if err := json.Unmarshal(encoded, &ders); err != nil {
		return nil, fmt.Errorf("service: parsing SAML certificate set: %w", err)
	}
	if len(ders) == 0 {
		return nil, errors.New("service: SAML certificate set is empty")
	}
	certificates := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("service: parsing pinned SAML certificate: %w", err)
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

func (s *Auth) completeSAMLLogin(ctx context.Context, az *authz.TxAuthorizer, provider authz.SAMLProvider, transaction authz.SAMLTransaction, claims samlsp.Claims, subject string, epoch int64, now time.Time) (LoginResult, error) {
	identity, err := az.ExternalIdentityByKey(ctx, SAMLKind, transaction.EntityID, subject)
	if errors.Is(err, domain.ErrNotFound) {
		if auditErr := s.stageSAML(ctx, az, audit.OutcomeFailure, "unknown-identity", provider.ID, transaction.EntityID, transaction.Purpose, transaction.ID, &claims); auditErr != nil {
			return LoginResult{}, auditErr
		}
		return LoginResult{}, domain.ErrUnauthenticated
	}
	if err != nil {
		return LoginResult{}, err
	}
	if identity.CredentialEpoch != epoch {
		if auditErr := s.stageSAML(ctx, az, audit.OutcomeFailure, "provider-reconciliation", provider.ID, transaction.EntityID, transaction.Purpose, transaction.ID, &claims); auditErr != nil {
			return LoginResult{}, auditErr
		}
		return LoginResult{}, domain.ErrUnauthenticated
	}
	if identity.ProviderID != provider.ID {
		rebound, rebindErr := az.RebindSAMLExternalIdentityProvider(ctx, identity.ID, identity.ProviderID, provider.ID)
		if rebindErr != nil {
			return LoginResult{}, rebindErr
		}
		if !rebound {
			if auditErr := s.stageSAML(ctx, az, audit.OutcomeFailure, "provider-reconciliation", provider.ID, transaction.EntityID, transaction.Purpose, transaction.ID, &claims); auditErr != nil {
				return LoginResult{}, auditErr
			}
			return LoginResult{}, domain.ErrUnauthenticated
		}
	}
	account, err := az.AccountByID(ctx, identity.AccountID)
	if err != nil {
		return LoginResult{}, err
	}
	mfa, err := evaluateSAMLAssurance(provider.AssurancePolicy, claims.Authn.ContextClassRef)
	if err != nil {
		return LoginResult{}, err
	}
	return s.mintSAMLSession(ctx, az, account, provider, transaction, claims, mfa, now)
}

func (s *Auth) completeSAMLLink(ctx context.Context, az *authz.TxAuthorizer, provider authz.SAMLProvider, transaction authz.SAMLTransaction, claims samlsp.Claims, subject string, initiating authz.Identity, epoch int64, now time.Time) (LoginResult, error) {
	if _, err := az.ExternalIdentityByKey(ctx, SAMLKind, transaction.EntityID, subject); err == nil {
		if auditErr := s.stageSAML(ctx, az, audit.OutcomeFailure, "already-linked", provider.ID, transaction.EntityID, transaction.Purpose, transaction.ID, &claims); auditErr != nil {
			return LoginResult{}, auditErr
		}
		return LoginResult{}, ErrAlreadyLinked
	} else if !errors.Is(err, domain.ErrNotFound) {
		return LoginResult{}, err
	}
	account, err := az.AccountByID(ctx, transaction.AccountID)
	if err != nil || initiating.Principal != account.PrincipalID {
		if err != nil {
			return LoginResult{}, err
		}
		if auditErr := s.stageSAML(ctx, az, audit.OutcomeFailure, "initiator-mismatch", provider.ID, transaction.EntityID, transaction.Purpose, transaction.ID, &claims); auditErr != nil {
			return LoginResult{}, auditErr
		}
		return LoginResult{}, domain.ErrUnauthenticated
	}
	identityID, err := newID("eid")
	if err != nil {
		return LoginResult{}, err
	}
	if err := az.CreateExternalIdentity(ctx, authz.NewExternalIdentity{
		ID: identityID, AccountID: account.ID, Kind: SAMLKind, Issuer: transaction.EntityID,
		Subject: subject, ProviderID: provider.ID, CredentialEpoch: epoch, CreatedAt: now,
	}); err != nil {
		return LoginResult{}, err
	}
	result, err := s.reissueSession(ctx, az, account, "password", MethodLocalPassword, initiating.Artifact, now)
	if err != nil {
		return LoginResult{}, err
	}
	event, err := newAuditEvent(ctx, audit.EventIdentityLinked, account.PrincipalID,
		audit.Object{Type: "external_identity", ID: identityID}, audit.OutcomeSuccess, "",
		audit.Payload{"kind": SAMLKind, "account_id": account.ID, "identity_id": identityID, "provider_id": provider.ID, "authorizing_credential": "password"})
	if err != nil {
		return LoginResult{}, err
	}
	if err := az.RecordAuthEvent(ctx, event); err != nil {
		return LoginResult{}, err
	}
	if err := s.stageSAMLActor(ctx, az, account.PrincipalID, audit.OutcomeSuccess, "", provider.ID, transaction.EntityID, transaction.Purpose, transaction.ID, &claims); err != nil {
		return LoginResult{}, err
	}
	return result, nil
}

func (s *Auth) completeSAMLReauth(ctx context.Context, az *authz.TxAuthorizer, provider authz.SAMLProvider, transaction authz.SAMLTransaction, claims samlsp.Claims, subject string, initiating authz.Identity, epoch int64, now time.Time) (LoginResult, error) {
	reject := func(cause string) (LoginResult, error) {
		if err := s.stageSAML(ctx, az, audit.OutcomeFailure, cause, provider.ID, transaction.EntityID, transaction.Purpose, transaction.ID, &claims); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, domain.ErrUnauthenticated
	}
	if provider.AssurancePolicy == nil || claims.Authn.ContextClassRef == nil {
		return reject("no-assurance-policy")
	}
	if claims.Authn.Instant.After(now.Add(samlClockSkew)) || now.Sub(claims.Authn.Instant) > samlReauthFreshness+samlClockSkew {
		return reject("stale-authn-instant")
	}
	mfa, err := evaluateSAMLAssurance(provider.AssurancePolicy, claims.Authn.ContextClassRef)
	if err != nil {
		return LoginResult{}, err
	}
	if !mfa {
		return reject("no-assurance-policy")
	}
	identity, err := az.ExternalIdentityByKey(ctx, SAMLKind, transaction.EntityID, subject)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && identity.AccountID != transaction.AccountID) {
		return reject("unknown-identity")
	}
	if err != nil {
		return LoginResult{}, err
	}
	if identity.CredentialEpoch != epoch {
		return reject("provider-reconciliation")
	}
	if identity.ProviderID != provider.ID {
		rebound, rebindErr := az.RebindSAMLExternalIdentityProvider(ctx, identity.ID, identity.ProviderID, provider.ID)
		if rebindErr != nil {
			return LoginResult{}, rebindErr
		}
		if !rebound {
			return reject("provider-reconciliation")
		}
	}
	if initiating.SessionID != transaction.InitiatingSessionID {
		return reject("initiator-mismatch")
	}
	evidence := authz.Assurance{Factors: samlFactors(true)}
	if authz.AssuranceRank(initiating.Assurance) > authz.AssuranceRank(evidence) {
		return reject("downgrade")
	}
	effectiveWindow, err := s.effectiveReauthWindow(ctx, az, transaction.EnvironmentID)
	if err != nil {
		return LoginResult{}, err
	}
	if effectiveWindow <= 0 {
		if err := s.stageSAML(ctx, az, audit.OutcomeFailure, "window-zero", provider.ID, transaction.EntityID, transaction.Purpose, transaction.ID, &claims); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, ErrReauthWindowClosed
	}
	factorsJSON, err := json.Marshal(initiating.Assurance.Factors)
	if err != nil {
		return LoginResult{}, err
	}
	value, verifier, err := s.newSessionArtifact(initiating.Artifact)
	if err != nil {
		return LoginResult{}, err
	}
	if err := az.RotateSessionFactors(ctx, initiating.SessionID, verifier, string(factorsJSON)); err != nil {
		return LoginResult{}, err
	}
	windowID, err := newID("raw")
	if err != nil {
		return LoginResult{}, err
	}
	hardCap := s.ReauthHardCap
	if hardCap <= 0 {
		hardCap = effectiveWindow
	}
	hardExpires := now.Add(hardCap)
	windowExpires := now.Add(effectiveWindow)
	if windowExpires.After(hardExpires) {
		windowExpires = hardExpires
	}
	if err := az.OpenReauthWindow(ctx, authz.NewReauthWindow{
		ID: windowID, SessionID: initiating.SessionID, EnvironmentID: transaction.EnvironmentID,
		CeremonyID: transaction.ID, FactorClass: SAMLKind, AuthenticatedAt: claims.Authn.Instant,
		WindowExpiresAt: windowExpires, HardExpiresAt: hardExpires, CredentialEpoch: epoch, CreatedAt: now,
	}); err != nil {
		return LoginResult{}, err
	}
	event, err := newAuditEvent(ctx, audit.EventAuthReauthenticated, initiating.Principal,
		audit.Object{Type: "session", ID: initiating.SessionID}, audit.OutcomeSuccess, "",
		audit.Payload{"session_id": initiating.SessionID, "factor": SAMLKind})
	if err != nil {
		return LoginResult{}, err
	}
	if err := az.RecordAuthEvent(ctx, event); err != nil {
		return LoginResult{}, err
	}
	if err := s.stageSAMLActor(ctx, az, initiating.Principal, audit.OutcomeSuccess, "", provider.ID, transaction.EntityID, transaction.Purpose, transaction.ID, &claims); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		SessionToken: value, SessionID: initiating.SessionID, Artifact: initiating.Artifact,
		CreatedAt: initiating.CreatedAt, IdleExpires: initiating.IdleExpiresAt,
		AbsExpires: initiating.AbsoluteExpiresAt, Principal: initiating.Principal,
	}, nil
}

func (s *Auth) mintSAMLSession(ctx context.Context, az *authz.TxAuthorizer, account authz.Account, provider authz.SAMLProvider, transaction authz.SAMLTransaction, claims samlsp.Claims, mfa bool, now time.Time) (LoginResult, error) {
	generation, err := az.PrincipalGeneration(ctx, account.PrincipalID)
	if err != nil {
		return LoginResult{}, err
	}
	epoch, err := az.CredentialEpoch(ctx)
	if err != nil {
		return LoginResult{}, err
	}
	value, verifier, err := wencrypto.NewArtifact(wencrypto.ArtifactBrowserSession)
	if err != nil {
		return LoginResult{}, err
	}
	csrfValue, csrfVerifier, err := wencrypto.NewArtifact(wencrypto.ArtifactCSRF)
	if err != nil {
		return LoginResult{}, err
	}
	sessionID, err := newID("ses")
	if err != nil {
		return LoginResult{}, err
	}
	factorClasses := samlFactors(mfa)
	factorsJSON, err := json.Marshal(factorClasses)
	if err != nil {
		return LoginResult{}, err
	}
	wire := audit.FromContext(ctx)
	session := authz.NewSession{
		ID: sessionID, PrincipalID: account.PrincipalID, Verifier: verifier,
		Artifact: ArtifactBrowser, SessionGeneration: generation, CredentialEpoch: epoch,
		AuthMethod: samlMethod(transaction.EntityID), Factors: string(factorsJSON),
		AuthenticatedAt: claims.Authn.Instant, CeremonyID: transaction.ID, CreatedAt: now,
		IdleExpiresAt: now.Add(BrowserSessionIdle), AbsoluteExpiresAt: now.Add(BrowserSessionAbsolute),
		SourceIP: wire.SourceIP, UserAgent: wire.UserAgent, CSRFVerifier: csrfVerifier,
	}
	if err := az.MintSession(ctx, session); err != nil {
		return LoginResult{}, err
	}
	bound, err := az.BindSessionToSAMLProvider(ctx, sessionID, provider.ID)
	if err != nil {
		return LoginResult{}, err
	}
	if !bound {
		return LoginResult{}, errors.New("service: failed to bind SAML session provider")
	}
	assuranceLabel := "single-factor"
	if mfa {
		assuranceLabel = "multi-factor"
	}
	if err := s.stageSAMLActor(ctx, az, account.PrincipalID, audit.OutcomeSuccess, "", provider.ID, transaction.EntityID, transaction.Purpose, transaction.ID, &claims); err != nil {
		return LoginResult{}, err
	}
	event, err := newAuditEvent(ctx, audit.EventAuthSessionCreated, account.PrincipalID,
		audit.Object{Type: "session", ID: sessionID}, audit.OutcomeSuccess, "",
		audit.Payload{"session_id": sessionID, "artifact": ArtifactBrowser, "method": samlMethod(transaction.EntityID), "assurance": assuranceLabel})
	if err != nil {
		return LoginResult{}, err
	}
	if err := az.RecordAuthEvent(ctx, event); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		SessionToken: value, SessionID: sessionID, Artifact: ArtifactBrowser,
		CreatedAt: now, IdleExpires: session.IdleExpiresAt, AbsExpires: session.AbsoluteExpiresAt,
		Principal: account.PrincipalID, AccountID: account.ID, DisplayName: account.DisplayName,
		Assurance: Assurance{Method: samlMethod(transaction.EntityID), Factors: factorClasses, AuthenticatedAt: claims.Authn.Instant, CeremonyID: transaction.ID},
		CSRFToken: csrfValue,
	}, nil
}

func (s *Auth) stageSAML(ctx context.Context, az *authz.TxAuthorizer, outcome audit.Outcome, cause, providerID, entityID, purpose, transactionID string, claims *samlsp.Claims) error {
	return s.stageSAMLActor(ctx, az, "", outcome, cause, providerID, entityID, purpose, transactionID, claims)
}

func (s *Auth) stageSAMLActor(ctx context.Context, az *authz.TxAuthorizer, principal domain.PrincipalID, outcome audit.Outcome, cause, providerID, entityID, purpose, transactionID string, claims *samlsp.Claims) error {
	eventType := audit.EventSAMLLogin
	if purpose == purposeReauth {
		eventType = audit.EventSAMLReauth
	}
	payload := samlCeremonyPayload(outcome, cause, providerID, entityID, purpose, transactionID, claims)
	event, err := newAuditEvent(ctx, eventType, principal, audit.Object{Type: "saml_transaction", ID: transactionID}, outcome, "", payload)
	if err != nil {
		return err
	}
	return az.RecordAuthEvent(ctx, event)
}

func samlCeremonyPayload(outcome audit.Outcome, cause, providerID, entityID, purpose, transactionID string, claims *samlsp.Claims) audit.Payload {
	payload := audit.Payload{
		"provider_id": providerID, "entity_id": entityID, "purpose": purpose,
		"transaction_id": transactionID,
	}
	if outcome == audit.OutcomeFailure {
		payload["cause"] = cause
	}
	if claims != nil {
		if claims.ExpiredPinnedCertificate {
			payload["pinned_certificate_expired"] = true
		}
		if claims.NameID.Format != nil {
			payload["name_id_format"] = *claims.NameID.Format
		}
		if claims.Authn.ContextClassRef != nil {
			payload["authn_context_class_ref"] = *claims.Authn.ContextClassRef
		}
	}
	return payload
}

func (s *Auth) refuseSAML(ctx context.Context, cause, providerID, entityID, purpose, transactionID string) error {
	if err := tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		return s.stageSAML(ctx, az, audit.OutcomeFailure, cause, providerID, entityID, purpose, transactionID, nil)
	}); err != nil {
		return err
	}
	return domain.ErrUnauthenticated
}

func samlValidationCause(err error) string {
	switch {
	case errors.Is(err, samlsp.ErrDuplicateID):
		return "duplicate-id"
	case errors.Is(err, samlsp.ErrEmptyID):
		return "empty-id"
	case errors.Is(err, samlsp.ErrAssertionCardinality):
		return "assertion-cardinality"
	case errors.Is(err, samlsp.ErrAssertionPosition):
		return "assertion-position"
	case errors.Is(err, samlsp.ErrEncryptedAssertion):
		return "encrypted-assertion"
	case errors.Is(err, samlsp.ErrSignatureAlgorithm):
		return "signature-algorithm"
	case errors.Is(err, samlsp.ErrDigestAlgorithm):
		return "digest-algorithm"
	case errors.Is(err, samlsp.ErrCanonicalizationAlgorithm):
		return "canonicalization-algorithm"
	case errors.Is(err, samlsp.ErrTransformAlgorithm):
		return "transform-algorithm"
	case errors.Is(err, samlsp.ErrNoPinnedCertificate):
		return "unknown-certificate"
	case errors.Is(err, samlsp.ErrAssertionSignature):
		return "assertion-signature"
	case errors.Is(err, samlsp.ErrResponseSignature):
		return "response-signature"
	case errors.Is(err, samlsp.ErrSignatureReference):
		return "signature-reference"
	case errors.Is(err, samlsp.ErrSignatureStructure):
		return "signature-structure"
	case errors.Is(err, samlsp.ErrResponseStatus):
		return "response-status"
	case errors.Is(err, samlsp.ErrResponseIssuer):
		return "response-issuer-mismatch"
	case errors.Is(err, samlsp.ErrAssertionIssuer):
		return "assertion-issuer-mismatch"
	case errors.Is(err, samlsp.ErrInResponseTo):
		return "request-mismatch"
	case errors.Is(err, samlsp.ErrDestination):
		return "destination-mismatch"
	case errors.Is(err, samlsp.ErrAudienceMissing):
		return "audience-missing"
	case errors.Is(err, samlsp.ErrAudienceMismatch):
		return "audience-mismatch"
	case errors.Is(err, samlsp.ErrAudience):
		return "audience-structure"
	case errors.Is(err, samlsp.ErrSubjectConfirmationMissing):
		return "subject-confirmation-missing"
	case errors.Is(err, samlsp.ErrSubjectConfirmationMethod):
		return "confirmation-method"
	case errors.Is(err, samlsp.ErrSubjectConfirmationRecipient):
		return "confirmation-recipient"
	case errors.Is(err, samlsp.ErrSubjectConfirmationInResponseTo):
		return "confirmation-request-mismatch"
	case errors.Is(err, samlsp.ErrSubjectConfirmationExpiryMissing):
		return "confirmation-expiry-missing"
	case errors.Is(err, samlsp.ErrSubjectConfirmationExpired):
		return "confirmation-expired"
	case errors.Is(err, samlsp.ErrSubjectConfirmation):
		return "subject-confirmation-structure"
	case errors.Is(err, samlsp.ErrConditionsMissing):
		return "conditions-missing"
	case errors.Is(err, samlsp.ErrConditionsNotBefore):
		return "conditions-too-early"
	case errors.Is(err, samlsp.ErrConditionsExpiryMissing):
		return "conditions-expiry-missing"
	case errors.Is(err, samlsp.ErrConditionsExpired):
		return "conditions-expired"
	case errors.Is(err, samlsp.ErrConditions):
		return "conditions-structure"
	case errors.Is(err, samlsp.ErrResponseIssueInstant):
		return "response-issue-instant"
	case errors.Is(err, samlsp.ErrAssertionIssueInstant):
		return "assertion-issue-instant"
	case errors.Is(err, samlsp.ErrIssueInstant):
		return "issue-instant"
	case errors.Is(err, samlsp.ErrAuthnStatementCardinality), errors.Is(err, samlsp.ErrAuthnContextCardinality):
		if errors.Is(err, samlsp.ErrAuthnContextCardinality) {
			return "authn-context-cardinality"
		}
		return "authn-statement-cardinality"
	case errors.Is(err, samlsp.ErrInvalidAuthnInstant):
		return "authn-instant"
	case errors.Is(err, samlsp.ErrDTD):
		return "dtd"
	case errors.Is(err, samlsp.ErrDocumentTooLarge):
		return "document-size"
	case errors.Is(err, samlsp.ErrDocumentTooDeep):
		return "document-depth"
	case errors.Is(err, samlsp.ErrTooManyTokens):
		return "document-token-count"
	case errors.Is(err, samlsp.ErrRoundTrip):
		return "xml-roundtrip"
	case errors.Is(err, samlsp.ErrResponseRoot):
		return "response-root"
	case errors.Is(err, ErrSAMLTransientNameID):
		return "transient-nameid"
	case errors.Is(err, ErrSAMLEmailNameIDDisabled):
		return "email-nameid-disabled"
	case errors.Is(err, ErrSAMLNameIDFormat), errors.Is(err, samlsp.ErrEmptyNameID), errors.Is(err, samlsp.ErrNameIDCardinality):
		return "nameid"
	default:
		return "malformed"
	}
}
