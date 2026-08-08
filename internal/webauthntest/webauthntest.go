// Package webauthntest is a test-only software authenticator built on
// descope/virtualwebauthn. It plays the browser + authenticator half of a
// WebAuthn ceremony so the #54 fixtures run against the real go-webauthn
// validation path. It ships in no production binary; the import boundary pins
// it to tests.
package webauthntest

import (
	vw "github.com/descope/virtualwebauthn"
)

// Device is one software authenticator holding a single credential. Two enrolled
// passkeys on one account are two Devices sharing the account's opaque user
// handle (each Enrol reads the handle the server put in the options), exactly as
// two physical security keys would.
type Device struct {
	rp   vw.RelyingParty
	opts vw.AuthenticatorOptions
	auth vw.Authenticator
	cred vw.Credential

	enrolled bool
}

// New builds a Device for the given RP id and origin (matching the server's
// immutable RP config). By default it verifies the user, is not backup-eligible,
// and emits credProps.rk=true so the enrolled credential is discoverable — the
// realistic default a platform authenticator produces.
func New(rpID, origin string) *Device {
	return &Device{
		rp: vw.RelyingParty{Name: "wenv", ID: rpID, Origin: origin},
		opts: vw.AuthenticatorOptions{
			ClientExtensionResults: map[string]any{"credProps": map[string]any{"rk": true}},
		},
	}
}

// SetUserVerified controls the UV bit the authenticator asserts. Setting it
// false drives the "UV not asserted is refused" fixture.
func (d *Device) SetUserVerified(v bool) { d.opts.UserNotVerified = !v }

// SetBackupEligible marks the credential as a synced (backup-eligible) passkey,
// which suppresses the sign-count clone check (B9).
func (d *Device) SetBackupEligible(v bool) {
	d.opts.BackupEligible = v
	d.opts.BackupState = v
}

// SuppressCredProps drops the credProps extension, so the server records the
// credential as non-discoverable (fail-closed on the login capability, B13).
func (d *Device) SuppressCredProps() { d.opts.ClientExtensionResults = nil }

// SetCounter sets the authenticator sign counter the next assertion presents.
// Enrolment records the counter as it stands at Enrol.
func (d *Device) SetCounter(c uint32) { d.cred.Counter = c }

// Counter reports the current sign counter.
func (d *Device) Counter() uint32 { return d.cred.Counter }

// CredentialID is the authenticator-chosen credential id (base64url is the
// server's, this is the raw bytes).
func (d *Device) CredentialID() []byte { return d.cred.ID }

// Enrol turns registration options from the server into an attestation response.
// It reads the account's user handle from the options so a second Device for the
// same account shares it.
func (d *Device) Enrol(optionsJSON []byte) ([]byte, error) {
	att, err := vw.ParseAttestationOptions(string(optionsJSON))
	if err != nil {
		return nil, err
	}
	d.opts.UserHandle = []byte(att.UserID)
	d.auth = vw.NewAuthenticatorWithOptions(d.opts)
	d.cred = vw.NewCredential(vw.KeyTypeEC2)
	d.auth.AddCredential(d.cred)
	d.enrolled = true
	return []byte(vw.CreateAttestationResponse(d.rp, d.auth, d.cred, *att)), nil
}

// Assert turns assertion options (discoverable login, step-up or reauth) into an
// assertion response signed by this Device's credential.
func (d *Device) Assert(optionsJSON []byte) ([]byte, error) {
	as, err := vw.ParseAssertionOptions(string(optionsJSON))
	if err != nil {
		return nil, err
	}
	// Refresh the authenticator so a counter set since enrolment is reflected.
	d.auth = vw.NewAuthenticatorWithOptions(d.opts)
	d.auth.AddCredential(d.cred)
	return []byte(vw.CreateAssertionResponse(d.rp, d.auth, d.cred, *as)), nil
}
