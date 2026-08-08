package oidctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
)

// signRS256 signs the JWT signing input with RSASSA-PKCS1-v1_5 / SHA-256.
func signRS256(key *rsa.PrivateKey, signingInput string) (string, error) {
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifierMatchesS256 reports whether the PKCE verifier hashes to the
// recorded S256 challenge — the check a real token endpoint performs.
func VerifierMatchesS256(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}
