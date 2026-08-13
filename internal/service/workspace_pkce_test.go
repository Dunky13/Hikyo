package service

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestWorkspacePKCESyntax(t *testing.T) {
	seed := sha256.Sum256([]byte("workspace PKCE verifier"))
	verifier := base64.RawURLEncoding.EncodeToString(seed[:])
	challenge := pkceS256(verifier)
	if !validPKCEVerifier(verifier) {
		t.Fatal("a canonical 32-byte base64url verifier was refused")
	}
	if !validPKCEChallenge(challenge) {
		t.Fatal("its S256 challenge was refused")
	}

	for _, invalid := range []string{
		"short",
		verifier + "=",
		strings.Repeat("a", 42) + ".",
		strings.Repeat("a", 129),
	} {
		if validPKCEVerifier(invalid) {
			t.Errorf("invalid verifier %q was accepted", invalid)
		}
	}
	if validPKCEChallenge(challenge[:42]) || validPKCEChallenge(challenge+"=") {
		t.Fatal("a malformed S256 challenge was accepted")
	}
}
