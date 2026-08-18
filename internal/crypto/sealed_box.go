package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// CredentialFingerprint creates a non-reversible in-process coordination key.
// Callers can share provider budgets without retaining another credential copy.
func CredentialFingerprint(credential []byte) [32]byte {
	return sha256.Sum256(credential)
}

// SealAnonymousBox confines the GitHub Actions sealed-box primitive to the
// repository's crypto chokepoint. The provider adapter receives ciphertext
// only and never imports cryptographic primitives directly.
func SealAnonymousBox(value []byte, publicKey [32]byte) ([]byte, error) {
	sealed, err := box.SealAnonymous(nil, value, &publicKey, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: seal anonymous box: %w", err)
	}
	return sealed, nil
}
