package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Password verifiers (human-auth ADR § Credential storage).
//
// This lives in internal/crypto because the boundary test confines
// golang.org/x/crypto/* to this package — and because the confinement is the
// point: one place derives key material, one place compares it in constant
// time, and no auth package grows a second opinion about either.
//
// What Wenv owns here is parameter policy and the boot floor. The KDF itself
// is x/crypto's; nothing about it is hand-rolled.

// SaltSize is 16 random bytes per verifier, as the ADR fixes.
const SaltSize = 16

// verifierSize is the Argon2id output length.
const verifierSize = 32

// PasswordParams are the Argon2id cost parameters recorded per verifier, so
// the floor can be raised later without invalidating existing credentials —
// a verifier is re-derived on the next successful login under the
// compare-and-swap rule.
type PasswordParams struct {
	MemoryKiB   uint32
	Time        uint32
	Parallelism uint8
}

// PasswordFloor is the hard floor the human-auth ADR fixes: m=64 MiB, t=3,
// p=2. Parameters are tunable UPWARD for stronger hardware and explicitly
// NOT downward: the server refuses to start below this rather than degrading
// quietly, because a silently weakened KDF is indistinguishable from a strong
// one until the database leaks.
var PasswordFloor = PasswordParams{MemoryKiB: 64 * 1024, Time: 3, Parallelism: 2}

// ErrBelowFloor is the boot refusal. It is a distinct error so the startup
// path can name the exact parameter that is short.
var ErrBelowFloor = errors.New("crypto: Argon2id parameters below the boot-verified floor")

// CheckFloor is the boot check. Fail fast, fail loud: an installation
// configured below the floor does not start.
func (p PasswordParams) CheckFloor() error {
	switch {
	case p.MemoryKiB < PasswordFloor.MemoryKiB:
		return fmt.Errorf("%w: memory %d KiB < %d KiB", ErrBelowFloor, p.MemoryKiB, PasswordFloor.MemoryKiB)
	case p.Time < PasswordFloor.Time:
		return fmt.Errorf("%w: time %d < %d", ErrBelowFloor, p.Time, PasswordFloor.Time)
	case p.Parallelism < PasswordFloor.Parallelism:
		return fmt.Errorf("%w: parallelism %d < %d", ErrBelowFloor, p.Parallelism, PasswordFloor.Parallelism)
	}
	return nil
}

// NewSalt draws a fresh per-verifier salt. An RNG failure aborts — the same
// rule every seal in this package follows.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("crypto: salt: %w", err)
	}
	return salt, nil
}

// DeriveVerifier returns salt ‖ Argon2id(password, salt). The salt travels
// with the digest because the whole blob is then envelope-encrypted under the
// instance DEK: the hash stays a hash — a root-key holder still cannot
// reverse it — and the encryption is an outer layer that denies an attacker
// holding the database without the root key the ability to mount the offline
// guessing attack at all, rather than merely mounting it slowly.
func DeriveVerifier(password, salt []byte, p PasswordParams) ([]byte, error) {
	if err := p.CheckFloor(); err != nil {
		return nil, err
	}
	return derive(password, salt, p)
}

// derive is DeriveVerifier without the floor check. Unexported precisely so
// no production caller can reach it: the only legitimate sub-floor
// derivations are this package's own tests, which would otherwise spend
// minutes proving properties that have nothing to do with cost.
func derive(password, salt []byte, p PasswordParams) ([]byte, error) {
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("crypto: salt must be %d bytes, got %d", SaltSize, len(salt))
	}
	digest := argon2.IDKey(password, salt, p.Time, p.MemoryKiB, p.Parallelism, verifierSize)
	out := make([]byte, 0, SaltSize+verifierSize)
	out = append(out, salt...)
	out = append(out, digest...)
	Zero(digest)
	return out, nil
}

// VerifyPassword re-derives under the verifier's own recorded parameters and
// compares in constant time. A malformed verifier answers false rather than
// erroring: at the login path a stored-value defect and a wrong password must
// look identical from outside.
func VerifyPassword(password, verifier []byte, p PasswordParams) bool {
	if len(verifier) != SaltSize+verifierSize {
		return false
	}
	// The floor is deliberately NOT enforced here. A verifier written under
	// older parameters must still authenticate — the upgrade happens on the
	// next successful login — and refusing it would lock out every account the
	// moment the floor is raised.
	digest := argon2.IDKey(password, verifier[:SaltSize], p.Time, p.MemoryKiB, p.Parallelism, verifierSize)
	defer Zero(digest)
	return subtle.ConstantTimeCompare(digest, verifier[SaltSize:]) == 1
}

// dummyVerifier is a fixed, valid-shaped verifier for the unknown-account
// path. An unknown account traverses a bounded dummy-verifier derivation with
// the same parameters so timing is comparable and no pre-authentication path
// distinguishes an existing account from a missing one.
var dummyVerifier = make([]byte, SaltSize+verifierSize)

// BurnDummyVerification performs the work a real verification would, and
// discards it. It exists so the caller cannot accidentally skip the work by
// returning early on a missing account — the expensive step is the
// observable one, so it has to happen either way.
func BurnDummyVerification(password []byte, p PasswordParams) {
	VerifyPassword(password, dummyVerifier, p)
}
