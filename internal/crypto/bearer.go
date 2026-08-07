package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"strings"
)

// Bearer artifacts (machine-identity ADR § The bearer token, adopted for
// human artifacts too).
//
//	ew_<version>_<type>_<body><checksum>
//
// The type list that ADR fixes already names the human artifacts this slice
// mints — `cli` for a CLI session and `bs` for a bootstrap authority — so
// there is one grammar, one scanner rule, and the audit package's existing
// `ew_` redaction filter covers these values for free. Minting a second,
// unfiltered grammar for human artifacts would have been strictly worse.
//
// Normative, restated because it is the part that is easy to lose: the
// server trusts NOTHING inside the value. Kind, principal, expiry and
// credential epoch are read from the row the verifier resolves to. The prefix
// is a hint for humans and for secret scanners; the checksum lets a CLI or a
// leak scanner reject a truncated or mistyped value with zero server calls.

// ArtifactType is the `type` field of the token grammar.
type ArtifactType string

const (
	// ArtifactCLISession is a human CLI session — a distinct artifact type
	// with its own storage, lifetime, audit identity and revocation surface.
	ArtifactCLISession ArtifactType = "cli"
	// ArtifactBootstrap is a credential-establishment authority.
	ArtifactBootstrap ArtifactType = "bs"
)

// artifactFormatVersion is the grammar's `version` field. It exists so a
// format change is not a flag day.
const artifactFormatVersion = "1"

// bodyBytes is 256 bits of CSPRNG output — the entropy that makes an
// unsalted SHA-256 verifier safe and brute force infeasible.
const bodyBytes = 32

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// checksumChars is the fixed width of the base62 CRC-32 suffix.
const checksumChars = 6

// ErrMalformedArtifact is returned by ParseArtifact for anything that is not
// a well-formed value of the expected type. It is deliberately one error for
// every malformation: a caller must not be able to learn which part was
// wrong, and the server answers all of them identically anyway.
var ErrMalformedArtifact = errors.New("crypto: malformed bearer artifact")

// NewArtifact mints a bearer value of the given type and returns it with its
// verifier. The plaintext is returned exactly once, to exactly one caller;
// only the verifier is ever persisted.
func NewArtifact(t ArtifactType) (value string, verifier []byte, err error) {
	raw := make([]byte, bodyBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("crypto: artifact body: %w", err)
	}
	body := base62(raw)
	Zero(raw)
	value = "ew_" + artifactFormatVersion + "_" + string(t) + "_" + body + checksum(body)
	return value, ArtifactVerifier(value), nil
}

// ArtifactVerifier is the stored form: an unsalted SHA-256 of the whole
// presented value. Fast hashing is correct here, not a shortcut — the
// artifact carries >=256 bits of entropy, so brute force is infeasible and
// authentication stays a single indexed read. A salt would buy nothing and
// cost the index.
func ArtifactVerifier(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

// ParseArtifact checks the grammar and the checksum locally, so a truncated
// or mistyped value is refused with zero server calls and never reaches the
// admission budget. It returns the value unchanged on success — the caller
// still resolves it against the database, because the server trusts nothing
// inside it.
func ParseArtifact(value string, want ArtifactType) error {
	parts := strings.Split(value, "_")
	if len(parts) != 4 || parts[0] != "ew" {
		return ErrMalformedArtifact
	}
	if parts[1] != artifactFormatVersion || parts[2] != string(want) {
		return ErrMalformedArtifact
	}
	payload := parts[3]
	if len(payload) <= checksumChars {
		return ErrMalformedArtifact
	}
	body, sum := payload[:len(payload)-checksumChars], payload[len(payload)-checksumChars:]

	// The accepted grammar must be EXACTLY what NewArtifact can produce, and a
	// character-count bound is not exact: leading zero bytes shorten the body,
	// so a fixed [min,max] window both admits lengths no mint emits and
	// rejects the rare short body a real mint does. Decode instead — the body
	// must be the canonical base62 of exactly bodyBytes — which makes the
	// accepted set the emittable set with nothing on either side.
	raw, ok := decodeBase62(body)
	if !ok || len(raw) != bodyBytes || base62(raw) != body {
		return ErrMalformedArtifact
	}
	for i := range checksumChars {
		if !isBase62(sum[i]) {
			return ErrMalformedArtifact
		}
	}
	if checksum(body) != sum {
		return ErrMalformedArtifact
	}
	return nil
}

func isBase62(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// decodeBase62 is the exact inverse of base62: leading '0' characters become
// leading zero bytes, the remainder decodes as a big-endian integer. It
// reports false on any non-alphabet character. Canonicality — that the input
// is the ONLY encoding of its bytes — is checked by the caller re-encoding
// the result, so a non-minimal encoding is caught there rather than guessed
// at here.
func decodeBase62(sv string) ([]byte, bool) {
	leadingZeros := 0
	for leadingZeros < len(sv) && sv[leadingZeros] == '0' {
		leadingZeros++
	}
	n := new(big.Int)
	radix := big.NewInt(62)
	for i := 0; i < len(sv); i++ {
		idx := strings.IndexByte(base62Alphabet, sv[i])
		if idx < 0 {
			return nil, false
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(idx)))
	}
	rest := n.Bytes()
	out := make([]byte, leadingZeros+len(rest))
	copy(out[leadingZeros:], rest)
	return out, true
}

// checksum is a CRC-32 over the body, base62-encoded to a fixed width. It is
// an integrity hint, never a security property — the ADR says so and this
// comment repeats it because a checksum sitting beside a secret invites the
// opposite reading.
func checksum(body string) string {
	sum := crc32.ChecksumIEEE([]byte(body))
	out := make([]byte, checksumChars)
	for i := checksumChars - 1; i >= 0; i-- {
		out[i] = base62Alphabet[sum%62]
		sum /= 62
	}
	return string(out)
}

// base62 renders bytes as base62, preserving leading zero bytes as leading
// zero digits so the encoding stays injective.
func base62(b []byte) string {
	var leading int
	for leading < len(b) && b[leading] == 0 {
		leading++
	}
	n := new(big.Int).SetBytes(b)
	radix := big.NewInt(62)
	mod := new(big.Int)
	var digits []byte
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		digits = append(digits, base62Alphabet[mod.Int64()])
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return strings.Repeat("0", leading) + string(digits)
}
