package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"net/url"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTP (human-auth ADR § Factors). The primitive is pquerna/otp — nothing here
// is hand-rolled. This wrapper lives in internal/crypto beside the other key
// material so seed generation, the constant-time code comparison and the
// envelope-sealed seed all sit behind one boundary.
//
// Parameters are the interoperable TOTP defaults: 30-second period, 6 digits,
// SHA-1 (the algorithm every authenticator app implements). The seed is 160
// bits, the RFC 4226 recommendation.

const (
	// totpSeedBytes is 160 bits, the HOTP/TOTP recommended shared-secret size.
	totpSeedBytes = 20
	// totpPeriod is the time step in seconds.
	totpPeriod = 30
	// totpDigits is the code length.
	totpDigits = 6
	// TOTPSkewSteps is how many steps on either side of now a code is accepted
	// for, absorbing clock drift between the server and the authenticator. One
	// step (±30s) is the common choice; single-use consumption per step means
	// a captured code cannot be replayed within the window.
	TOTPSkewSteps = 1
)

// totpEncoding is unpadded base32, the encoding authenticator apps expect in
// an otpauth URI.
var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSeed draws a fresh random seed. The raw bytes are what gets
// envelope-encrypted; the base32 form is only ever handed to the user's app
// inside the provisioning URI.
func NewTOTPSeed() ([]byte, error) {
	seed := make([]byte, totpSeedBytes)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("crypto: totp seed: %w", err)
	}
	return seed, nil
}

// TOTPProvisioningURI renders the otpauth:// URI an authenticator app scans.
// The label carries the instance issuer and the account handle; the secret is
// the base32 seed. It is returned once, at enrolment, and never stored.
func TOTPProvisioningURI(issuer, account string, seed []byte) string {
	secret := totpEncoding.EncodeToString(seed)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprintf("%d", totpDigits))
	v.Set("period", fmt.Sprintf("%d", totpPeriod))
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// TOTPStep is the time-step index of an instant: the single-use consumption
// unit. A code is accepted at most once per (account, step).
func TOTPStep(t time.Time) int64 {
	return t.Unix() / totpPeriod
}

// ValidateTOTP checks a presented code against the seed within the skew
// window and returns the exact step it matched. The whole window is scanned
// (no early return) so the number of HMAC evaluations does not depend on which
// step matched, and the comparison is constant-time. ok is false for a code
// that matches no step in the window.
func ValidateTOTP(seed []byte, code string, now time.Time, skew int) (step int64, ok bool) {
	secret := totpEncoding.EncodeToString(seed)
	matched := int64(0)
	found := false
	for d := -skew; d <= skew; d++ {
		at := now.Add(time.Duration(d) * totpPeriod * time.Second)
		want, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{
			Period: totpPeriod, Digits: totpDigits, Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			matched = TOTPStep(at)
			found = true
		}
	}
	return matched, found
}
