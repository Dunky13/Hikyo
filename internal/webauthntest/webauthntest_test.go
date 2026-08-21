package webauthntest

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
)

const (
	testRPID   = "hikyo.example"
	testOrigin = "https://hikyo.example"
)

// b64 encodes bytes the way a WebAuthn server encodes challenge and user id
// fields in its options JSON.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// attestationOptionsJSON builds the registration options a server sends. The
// user id is the account's opaque handle: two Devices enrolled from the same
// handle are two passkeys on one account.
func attestationOptionsJSON(userHandle string) []byte {
	return []byte(`{
		"challenge": "` + b64([]byte("enrol-challenge")) + `",
		"rp": {"id": "` + testRPID + `", "name": "hikyo"},
		"user": {"id": "` + b64([]byte(userHandle)) + `", "name": "u", "displayName": "u"}
	}`)
}

// assertionOptionsJSON builds the login options a server sends.
func assertionOptionsJSON() []byte {
	return []byte(`{
		"challenge": "` + b64([]byte("login-challenge")) + `",
		"rpId": "` + testRPID + `"
	}`)
}

// assertionResponse is the subset of the ceremony response this test reads back.
type assertionResponse struct {
	Response struct {
		AuthenticatorData string `json:"authenticatorData"`
		UserHandle        string `json:"userHandle"`
	} `json:"response"`
}

func parseAssertion(t *testing.T, resp []byte) assertionResponse {
	t.Helper()
	var out assertionResponse
	if err := json.Unmarshal(resp, &out); err != nil {
		t.Fatalf("parse assertion response: %v", err)
	}
	return out
}

// signCount reads the big-endian sign counter from the authenticator data, which
// sits after the 32-byte RP id hash and the 1-byte flags.
func signCount(t *testing.T, authData string) uint32 {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(authData)
	if err != nil {
		t.Fatalf("decode authenticator data: %v", err)
	}
	if len(raw) < 37 {
		t.Fatalf("authenticator data too short: %d bytes", len(raw))
	}
	return binary.BigEndian.Uint32(raw[33:37])
}

// enrolled returns a Device that has completed registration.
func enrolled(t *testing.T, userHandle string) *Device {
	t.Helper()
	d := New(testRPID, testOrigin)
	if _, err := d.Enrol(attestationOptionsJSON(userHandle)); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	return d
}

// A Device that never enrolled must fail its assertion with the fixture error,
// so a ceremony never runs against the zero credential. A test that means to
// prove the server refuses a bad ceremony then sees this fixture sentinel when
// it forgets to enrol, told apart from a real server refusal, so the refusal
// test never passes for the wrong reason.
func TestAssertBeforeEnrol(t *testing.T) {
	d := New(testRPID, testOrigin)
	resp, err := d.Assert(assertionOptionsJSON())
	if !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("assert before enrol: got %v, want ErrNotEnrolled", err)
	}
	if resp != nil {
		t.Fatalf("assert before enrol returned a response: %q", resp)
	}
}

// The credential accessors touch the zero credential before enrolment, so they
// must panic with the fixture error rather than report zero-value state.
func TestCredentialAccessorsPanicBeforeEnrol(t *testing.T) {
	cases := map[string]func(*Device){
		"SetCounter":   func(d *Device) { d.SetCounter(1) },
		"Counter":      func(d *Device) { _ = d.Counter() },
		"CredentialID": func(d *Device) { _ = d.CredentialID() },
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				r := recover()
				if err, ok := r.(error); !ok || !errors.Is(err, ErrNotEnrolled) {
					t.Fatalf("%s before enrol: recovered %v, want ErrNotEnrolled", name, r)
				}
			}()
			call(New(testRPID, testOrigin))
		})
	}
}

// Two Devices enrolled from one account's options are two passkeys on that
// account: distinct credential ids, one shared user handle.
func TestMultiCredentialSharesUserHandle(t *testing.T) {
	const handle = "account-handle"
	a := enrolled(t, handle)
	b := enrolled(t, handle)

	if string(a.CredentialID()) == string(b.CredentialID()) {
		t.Fatal("two passkeys must have distinct credential ids")
	}

	ra := parseAssertion(t, mustAssert(t, a))
	rb := parseAssertion(t, mustAssert(t, b))
	if ra.Response.UserHandle != rb.Response.UserHandle {
		t.Fatalf("passkeys on one account must share the user handle: %q vs %q",
			ra.Response.UserHandle, rb.Response.UserHandle)
	}
	if want := b64([]byte(handle)); ra.Response.UserHandle != want {
		t.Fatalf("user handle = %q, want %q", ra.Response.UserHandle, want)
	}
}

// A counter set after enrolment reaches the next assertion.
func TestCounterMutation(t *testing.T) {
	d := enrolled(t, "account-handle")
	if got := d.Counter(); got != 0 {
		t.Fatalf("fresh counter = %d, want 0", got)
	}

	d.SetCounter(7)
	if got := d.Counter(); got != 7 {
		t.Fatalf("counter after SetCounter = %d, want 7", got)
	}
	if got := signCount(t, parseAssertion(t, mustAssert(t, d)).Response.AuthenticatorData); got != 7 {
		t.Fatalf("assertion sign count = %d, want 7", got)
	}
}

func mustAssert(t *testing.T, d *Device) []byte {
	t.Helper()
	resp, err := d.Assert(assertionOptionsJSON())
	if err != nil {
		t.Fatalf("assert: %v", err)
	}
	return resp
}
