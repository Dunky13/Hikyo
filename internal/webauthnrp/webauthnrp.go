// Package webauthnrp is the WebAuthn relying-party wrapper: ceremony
// construction and response validation, all behind go-webauthn/webauthn. It
// exists so the protocol library is used in exactly one place under one policy —
// the human-auth ADR's "library selection is not policy selection": choosing
// go-webauthn does not choose the RP ID, the expected origins or the
// user-verification requirement. The boundary test pins who may import it
// (internal/service, its tests, and the wiring layer only).
//
// It owns wire mechanics, never product policy: the passkey-only precondition,
// the sign-count clone rule, the account-security proof discipline, ceremony
// single-use bookkeeping and assurance all live in internal/service, because
// they are decisions a library does not make. What lives here is the one policy
// a library forces the RP to state — RP ID, exact origins, UV required — plus a
// belt that re-asserts the UP and UV bits server-side on every response.
package webauthnrp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Sentinel refusals the service maps to closed audit causes. Every one is a
// refusal, never a downgrade.
var (
	// ErrConfig is an invalid immutable RP configuration (empty RP ID or no
	// expected origin) — the server refuses to enable any WebAuthn route.
	ErrConfig = errors.New("webauthnrp: invalid relying-party configuration")
	// ErrCeremony is a malformed begin request (no user handle, say).
	ErrCeremony = errors.New("webauthnrp: cannot begin the ceremony")
	// ErrResponse is an unparseable or invalid attestation/assertion response.
	ErrResponse = errors.New("webauthnrp: response validation failed")
	// ErrUserPresence is a response whose UP or UV bit is not set. UV is required
	// on every ceremony and both bits are re-asserted server-side here.
	ErrUserPresence = errors.New("webauthnrp: user presence or verification not asserted")
)

// RP is a relying party pinned to an immutable RP ID and expected-origin set.
type RP struct {
	wa *webauthn.WebAuthn
}

// Credential is a stored public-key record the service persists and rehydrates
// for a ceremony (the private key never leaves the authenticator).
type Credential struct {
	ID             []byte
	PublicKey      []byte
	AAGUID         []byte
	SignCount      uint32
	Transports     []string
	BackupEligible bool
	BackupState    bool
}

// User is a ceremony subject: the opaque handle and the credentials it owns.
type User struct {
	Handle      []byte
	Name        string
	DisplayName string
	Credentials []Credential
}

// LookupUser resolves the account a discoverable assertion names, by its raw
// credential id and user handle. The service implements it against the store.
type LookupUser func(rawID, userHandle []byte) (User, error)

// Registration is what a finished enrolment yields for the service to persist.
// Discoverable is read from the credProps extension by the caller (absent
// credProps means non-discoverable, fail-closed on the login capability — B13),
// so it is NOT decided here.
type Registration struct {
	CredentialID   []byte
	PublicKey      []byte
	AAGUID         []byte
	SignCount      uint32
	Transports     []string
	BackupEligible bool
	BackupState    bool
	CredProps      map[string]any
}

// Assertion is what a finished login/step-up/reauth yields. SignCount is the
// counter the authenticator presented; the caller applies the B9 clone rule.
type Assertion struct {
	CredentialID   []byte
	UserHandle     []byte
	SignCount      uint32
	BackupEligible bool
	BackupState    bool
}

// New builds a relying party from immutable instance configuration. rpID is the
// origin's host with no scheme or port; origins are the exact permitted origins
// (no wildcard). UV is required on every ceremony and resident keys are required
// so an enrolled passkey can serve discoverable login.
func New(rpID string, origins []string) (*RP, error) {
	if rpID == "" || len(origins) == 0 {
		return nil, ErrConfig
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  rpID,
		RPDisplayName:         "hikyo",
		RPOrigins:             origins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	return &RP{wa: wa}, nil
}

// FromExternalOrigin builds a relying party from the instance's public origin:
// the RP ID is the origin's host (no scheme, no port) and the single expected
// origin is the origin verbatim. This is the immutable instance config the ADR
// requires — derived from configuration, never from a request Host or forwarded
// header. An origin that does not parse, or carries no host, refuses.
func FromExternalOrigin(externalOrigin string) (*RP, error) {
	u, err := url.Parse(externalOrigin)
	if err != nil || u.Hostname() == "" {
		return nil, ErrConfig
	}
	return New(u.Hostname(), []string{externalOrigin})
}

// waUser adapts a User to go-webauthn's interface.
type waUser struct {
	u User
}

func (w waUser) WebAuthnID() []byte          { return w.u.Handle }
func (w waUser) WebAuthnName() string        { return w.u.Name }
func (w waUser) WebAuthnDisplayName() string { return w.u.DisplayName }
func (w waUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(w.u.Credentials))
	for _, c := range w.u.Credentials {
		transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
		for _, t := range c.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
		out = append(out, webauthn.Credential{
			ID: c.ID, PublicKey: c.PublicKey, Transport: transports,
			Flags:         webauthn.CredentialFlags{BackupEligible: c.BackupEligible, BackupState: c.BackupState},
			Authenticator: webauthn.Authenticator{AAGUID: c.AAGUID, SignCount: c.SignCount},
		})
	}
	return out
}

// BeginEnrol starts a registration ceremony. It returns the options JSON for the
// client, the opaque session blob the service stores on the ceremony row, and
// the base64url challenge the service hashes into the row's lookup key.
func (rp *RP) BeginEnrol(u User) (options, session []byte, challenge string, err error) {
	if len(u.Handle) == 0 {
		return nil, nil, "", ErrCeremony
	}
	creation, sess, err := rp.wa.BeginRegistration(waUser{u})
	if err != nil {
		return nil, nil, "", fmt.Errorf("%w: %v", ErrCeremony, err)
	}
	return marshalCeremony(creation, sess)
}

// BeginLogin starts a non-discoverable ceremony scoped to one known user's
// credentials (step-up / reauth, where the account is already established).
func (rp *RP) BeginLogin(u User) (options, session []byte, challenge string, err error) {
	if len(u.Credentials) == 0 {
		return nil, nil, "", ErrCeremony
	}
	assertion, sess, err := rp.wa.BeginLogin(waUser{u})
	if err != nil {
		return nil, nil, "", fmt.Errorf("%w: %v", ErrCeremony, err)
	}
	return marshalCeremony(assertion, sess)
}

// BeginDiscoverableLogin starts a resident-credential ceremony (passkey login):
// no user is named, the authenticator selects the credential.
func (rp *RP) BeginDiscoverableLogin() (options, session []byte, challenge string, err error) {
	assertion, sess, err := rp.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, nil, "", fmt.Errorf("%w: %v", ErrCeremony, err)
	}
	return marshalCeremony(assertion, sess)
}

func marshalCeremony(options any, sess *webauthn.SessionData) ([]byte, []byte, string, error) {
	optJSON, err := json.Marshal(options)
	if err != nil {
		return nil, nil, "", fmt.Errorf("%w: %v", ErrCeremony, err)
	}
	sessJSON, err := json.Marshal(sess)
	if err != nil {
		return nil, nil, "", fmt.Errorf("%w: %v", ErrCeremony, err)
	}
	return optJSON, sessJSON, sess.Challenge, nil
}

// ChallengeFromAttestation extracts the base64url challenge from a registration
// response so the service can resolve the ceremony row before validating.
func ChallengeFromAttestation(responseJSON []byte) (string, error) {
	pcc, err := protocol.ParseCredentialCreationResponseBytes(responseJSON)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrResponse, err)
	}
	return pcc.Response.CollectedClientData.Challenge, nil
}

// ChallengeFromAssertion extracts the base64url challenge from an assertion
// response.
func ChallengeFromAssertion(responseJSON []byte) (string, error) {
	pca, err := protocol.ParseCredentialRequestResponseBytes(responseJSON)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrResponse, err)
	}
	return pca.Response.CollectedClientData.Challenge, nil
}

// FinishEnrol validates a registration response against the stored session and
// the enrolling user (whose existing credentials exclude a re-registration). It
// re-asserts UP and UV server-side and returns the record to persist plus the
// raw credProps extension for the caller's residency decision.
func (rp *RP) FinishEnrol(u User, session, responseJSON []byte) (Registration, error) {
	var sess webauthn.SessionData
	if err := json.Unmarshal(session, &sess); err != nil {
		return Registration{}, fmt.Errorf("%w: %v", ErrResponse, err)
	}
	pcc, err := protocol.ParseCredentialCreationResponseBytes(responseJSON)
	if err != nil {
		return Registration{}, fmt.Errorf("%w: %v", ErrResponse, err)
	}
	cred, err := rp.wa.CreateCredential(waUser{u}, sess, pcc)
	if err != nil {
		return Registration{}, fmt.Errorf("%w: %v", ErrResponse, err)
	}
	if !cred.Flags.UserPresent || !cred.Flags.UserVerified {
		return Registration{}, ErrUserPresence
	}
	return Registration{
		CredentialID: cred.ID, PublicKey: cred.PublicKey, AAGUID: cred.Authenticator.AAGUID,
		SignCount: cred.Authenticator.SignCount, Transports: transportStrings(cred.Transport),
		BackupEligible: cred.Flags.BackupEligible, BackupState: cred.Flags.BackupState,
		CredProps: credProps(pcc.ClientExtensionResults),
	}, nil
}

// FinishDiscoverableLogin validates a passkey assertion, resolving the account
// through lookup. It re-asserts UP and UV server-side.
func (rp *RP) FinishDiscoverableLogin(session, responseJSON []byte, lookup LookupUser) (Assertion, error) {
	var sess webauthn.SessionData
	if err := json.Unmarshal(session, &sess); err != nil {
		return Assertion{}, fmt.Errorf("%w: %v", ErrResponse, err)
	}
	pca, err := protocol.ParseCredentialRequestResponseBytes(responseJSON)
	if err != nil {
		return Assertion{}, fmt.Errorf("%w: %v", ErrResponse, err)
	}
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		u, err := lookup(rawID, userHandle)
		if err != nil {
			return nil, err
		}
		return waUser{u}, nil
	}
	cred, err := rp.wa.ValidateDiscoverableLogin(handler, sess, pca)
	if err != nil {
		return Assertion{}, fmt.Errorf("%w: %v", ErrResponse, err)
	}
	if err := assertPresence(pca); err != nil {
		return Assertion{}, err
	}
	return assertionOf(cred, pca), nil
}

// FinishLogin validates a non-discoverable assertion against a known user
// (step-up / reauth). It re-asserts UP and UV server-side.
func (rp *RP) FinishLogin(u User, session, responseJSON []byte) (Assertion, error) {
	var sess webauthn.SessionData
	if err := json.Unmarshal(session, &sess); err != nil {
		return Assertion{}, fmt.Errorf("%w: %v", ErrResponse, err)
	}
	pca, err := protocol.ParseCredentialRequestResponseBytes(responseJSON)
	if err != nil {
		return Assertion{}, fmt.Errorf("%w: %v", ErrResponse, err)
	}
	cred, err := rp.wa.ValidateLogin(waUser{u}, sess, pca)
	if err != nil {
		return Assertion{}, fmt.Errorf("%w: %v", ErrResponse, err)
	}
	if err := assertPresence(pca); err != nil {
		return Assertion{}, err
	}
	return assertionOf(cred, pca), nil
}

// assertPresence re-checks the UP and UV bits directly from the authenticator
// data, independent of the library's own checks — the server's own guarantee
// that both were asserted, surviving a library behaviour change.
func assertPresence(pca *protocol.ParsedCredentialAssertionData) error {
	flags := pca.Response.AuthenticatorData.Flags
	if !flags.HasUserPresent() || !flags.HasUserVerified() {
		return ErrUserPresence
	}
	return nil
}

func assertionOf(cred *webauthn.Credential, pca *protocol.ParsedCredentialAssertionData) Assertion {
	return Assertion{
		CredentialID: cred.ID, UserHandle: pca.Response.UserHandle,
		SignCount:      pca.Response.AuthenticatorData.Counter,
		BackupEligible: cred.Flags.BackupEligible, BackupState: cred.Flags.BackupState,
	}
}

func transportStrings(ts []protocol.AuthenticatorTransport) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, string(t))
	}
	return out
}

func credProps(ext protocol.AuthenticationExtensionsClientOutputs) map[string]any {
	if ext == nil {
		return nil
	}
	raw, ok := ext["credProps"]
	if !ok {
		return nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	return m
}
