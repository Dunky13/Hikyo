// Package crypto is the envelope package — the sole crypto chokepoint fixed
// by the encryption-model ADR and placed here by the system-architecture ADR. It
// owns the keyring (root → master → tier-3 keys), the per-kind AAD schemas
// with their injective length-prefixed encoding, the versioned ciphertext
// envelope over XChaCha20-Poly1305, the DEK cache, root-key bootstrap, and
// process hardening. No cryptographic primitive is imported anywhere else in
// the module (enforced by internal/boundary).
//
// The package is a leaf: it imports nothing under internal/, and persists
// wrapped key material through the narrow KeyStore interface that
// internal/store/keyring implements.
package crypto

import "errors"

// KeySize is the size of every key in the hierarchy: 256-bit, per the
// encryption-model ADR.
const KeySize = 32

// Kind is the envelope kind byte. It selects the AAD schema, so identifiers
// from different tables can never collide into the same context.
type Kind byte

const (
	KindValue           Kind = 1
	KindWrappedDEK      Kind = 2
	KindWrappedMaster   Kind = 3
	KindWrappedTokenKey Kind = 4
	KindProjectField    Kind = 5
	KindInstanceField   Kind = 6
)

const (
	// formatV1 is the only ciphertext format version this build writes or
	// reads. A record at any other version is refused, never guessed at.
	formatV1 byte = 1
	// algXChaCha20Poly1305 is the only algorithm id in format v1.
	algXChaCha20Poly1305 byte = 1
)

// ErrUnknownFormat marks a ciphertext whose format version this build does
// not know — startup refusal 5 of the encryption-model ADR ("abort rather than
// guess") depends on it being distinguishable.
var ErrUnknownFormat = errors.New("crypto: unknown ciphertext format version")

// ErrDecrypt is the uniform decrypt failure. It deliberately carries no
// detail: which byte failed is not the caller's business, and error strings
// reach logs.
var ErrDecrypt = errors.New("crypto: decryption failed")

// Zero overwrites b. Best effort only — Go's GC gives no wipe guarantee, and
// the encryption-model ADR makes no memory-secrecy claim.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
