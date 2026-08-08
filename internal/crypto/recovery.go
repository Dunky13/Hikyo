package crypto

import "crypto/subtle"

// Recovery codes (human-auth ADR § Factors). Single-use, each carrying the
// bearer artifact grammar's >=256 bits of entropy — comfortably above the
// ADR's >=128-bit floor — so the stored form is an unsalted SHA-256 verifier
// like any other high-entropy artifact, and the audit redaction filter covers
// the plaintext for free. The batch of hashes is envelope-encrypted as a whole
// by the caller; this package owns only generation and the constant-time
// match.

// GenerateRecoveryBatch mints n fresh recovery codes and their verifiers. The
// plaintext codes are returned once, to display exactly once; only the
// verifiers are persisted.
func GenerateRecoveryBatch(n int) (codes []string, verifiers [][]byte, err error) {
	codes = make([]string, 0, n)
	verifiers = make([][]byte, 0, n)
	for range n {
		value, verifier, err := NewArtifact(ArtifactRecoveryCode)
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, value)
		verifiers = append(verifiers, verifier)
	}
	return codes, verifiers, nil
}

// MatchRecoveryCode returns the index of the verifier the presented code
// matches, or -1 for no match. The whole set is scanned in constant time per
// entry so neither the presence of a match nor its position leaks through
// timing; a grammatically invalid code still scans the set rather than
// returning early.
func MatchRecoveryCode(presented string, verifiers [][]byte) int {
	valid := ParseArtifact(presented, ArtifactRecoveryCode) == nil
	want := ArtifactVerifier(presented)
	match := -1
	for i, v := range verifiers {
		if subtle.ConstantTimeCompare(want, v) == 1 && valid {
			match = i
		}
	}
	return match
}
