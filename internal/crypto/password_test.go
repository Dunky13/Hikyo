package crypto

import (
	"bytes"
	"strings"
	"testing"
)

// Cheap parameters: the floor is 64 MiB per derivation, which would make this
// file take minutes. VerifyPassword deliberately does not enforce the floor
// (an old verifier must still authenticate), so these exercise the real code
// path with the cost dialled down. The floor itself is tested directly.
var cheap = PasswordParams{MemoryKiB: 64, Time: 1, Parallelism: 1}

func mustSalt(t *testing.T) []byte {
	t.Helper()
	s, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerifierRoundTrip(t *testing.T) {
	salt := mustSalt(t)
	v, err := derive([]byte("correct horse battery staple"), salt, cheap)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword([]byte("correct horse battery staple"), v, cheap) {
		t.Fatal("the right password did not verify")
	}
	if VerifyPassword([]byte("correct horse battery stapl"), v, cheap) {
		t.Fatal("a wrong password verified")
	}
	if !bytes.Equal(v[:SaltSize], salt) {
		t.Fatal("the salt is not carried in the verifier")
	}
}

func TestDistinctSaltsGiveDistinctVerifiers(t *testing.T) {
	a, err := derive([]byte("same password"), mustSalt(t), cheap)
	if err != nil {
		t.Fatal(err)
	}
	b, err := derive([]byte("same password"), mustSalt(t), cheap)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two verifiers for one password are identical — the per-verifier salt is not doing its job")
	}
}

func TestMalformedVerifierIsAWrongPasswordNotAnError(t *testing.T) {
	// At the login path a stored-value defect and a wrong password must look
	// identical from outside.
	for name, v := range map[string][]byte{
		"empty":     {},
		"truncated": make([]byte, SaltSize),
		"oversized": make([]byte, SaltSize+64),
	} {
		t.Run(name, func(t *testing.T) {
			if VerifyPassword([]byte("anything"), v, cheap) {
				t.Fatal("a malformed verifier accepted a password")
			}
		})
	}
}

func TestBootFloorRefusesEachShortParameter(t *testing.T) {
	if err := PasswordFloor.CheckFloor(); err != nil {
		t.Fatalf("the floor itself does not satisfy the floor: %v", err)
	}
	cases := map[string]PasswordParams{
		"memory":      {MemoryKiB: PasswordFloor.MemoryKiB - 1, Time: 3, Parallelism: 2},
		"time":        {MemoryKiB: PasswordFloor.MemoryKiB, Time: 2, Parallelism: 2},
		"parallelism": {MemoryKiB: PasswordFloor.MemoryKiB, Time: 3, Parallelism: 1},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			err := p.CheckFloor()
			if err == nil {
				t.Fatal("parameters below the floor accepted — the server would start with a quietly weakened KDF")
			}
			if !strings.Contains(err.Error(), name) {
				t.Fatalf("refusal does not name the short parameter: %v", err)
			}
		})
	}
	// Raising is always allowed; only lowering is refused.
	stronger := PasswordParams{MemoryKiB: 128 * 1024, Time: 4, Parallelism: 4}
	if err := stronger.CheckFloor(); err != nil {
		t.Fatalf("stronger-than-floor parameters refused: %v", err)
	}
}

func TestDeriveRefusesBelowFloor(t *testing.T) {
	if _, err := DeriveVerifier([]byte("pw"), make([]byte, SaltSize), PasswordParams{MemoryKiB: 8, Time: 1, Parallelism: 1}); err == nil {
		t.Fatal("a new verifier was written below the floor")
	}
}

func TestVerifyStillAcceptsAnOlderParameterSet(t *testing.T) {
	// Raising the floor must not lock out every existing account: the upgrade
	// happens on the next successful login, under the CAS rule.
	old := PasswordParams{MemoryKiB: 32, Time: 1, Parallelism: 1}
	v, err := derive([]byte("pw"), mustSalt(t), old)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword([]byte("pw"), v, old) {
		t.Fatal("a verifier written under older parameters no longer authenticates")
	}
}

func TestArtifactGrammarAndChecksum(t *testing.T) {
	value, verifier, err := NewArtifact(ArtifactCLISession)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(value, "ew_1_cli_") {
		t.Fatalf("artifact does not follow the locked grammar: %q", value)
	}
	if err := ParseArtifact(value, ArtifactCLISession); err != nil {
		t.Fatalf("freshly minted artifact fails its own parser: %v", err)
	}
	if err := ParseArtifact(value, ArtifactBootstrap); err == nil {
		t.Fatal("an artifact of one type parsed as another")
	}
	if !bytes.Equal(verifier, ArtifactVerifier(value)) {
		t.Fatal("the returned verifier is not the verifier of the returned value")
	}
	if len(verifier) != 32 {
		t.Fatalf("verifier is %d bytes, want a SHA-256 digest", len(verifier))
	}
}

func TestArtifactChecksumRejectsCorruptionLocally(t *testing.T) {
	value, _, err := NewArtifact(ArtifactCLISession)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]string{
		"truncated":      value[:len(value)-1],
		"flipped body":   flip(value, len("ew_1_cli_")),
		"flipped suffix": flip(value, len(value)-1),
		"no prefix":      strings.TrimPrefix(value, "ew_"),
		"empty":          "",
	}
	for name, bad := range mutations {
		t.Run(name, func(t *testing.T) {
			if err := ParseArtifact(bad, ArtifactCLISession); err == nil {
				t.Fatal("a corrupt artifact passed the local check and would have reached the admission budget")
			}
		})
	}
}

func TestArtifactsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 64 {
		v, _, err := NewArtifact(ArtifactBootstrap)
		if err != nil {
			t.Fatal(err)
		}
		if seen[v] {
			t.Fatal("two mints produced the same artifact")
		}
		seen[v] = true
	}
}

func flip(s string, i int) string {
	b := []byte(s)
	if b[i] == 'a' {
		b[i] = 'b'
	} else {
		b[i] = 'a'
	}
	return string(b)
}
