package crypto

import "testing"

// The accepted grammar must be EXACTLY the emittable one: every mint round-
// trips, and a body one byte too long or too short is refused. This is the
// property the char-count bound could not hold — leading zero bytes shorten
// the body, so a fixed window admitted lengths no mint emits and rejected the
// rare short body a real mint does.
func TestParseArtifactAcceptsOnlyEmittableBodies(t *testing.T) {
	// Every mint parses, across enough draws to hit occasional leading-zero
	// (hence shorter) bodies.
	for range 2000 {
		v, _, err := NewArtifact(ArtifactCLISession)
		if err != nil {
			t.Fatal(err)
		}
		if err := ParseArtifact(v, ArtifactCLISession); err != nil {
			t.Fatalf("a freshly minted artifact was refused: %q -> %v", v, err)
		}
	}

	// A body that decodes to the wrong number of bytes is refused, even with a
	// correct checksum: 33 bytes and 31 bytes both bracket the 32 a mint emits.
	for _, raw := range [][]byte{make([]byte, bodyBytes+1), make([]byte, bodyBytes-1)} {
		for i := range raw {
			raw[i] = byte(i + 1)
		}
		body := base62(raw)
		v := "hik_" + artifactFormatVersion + "_" + string(ArtifactCLISession) + "_" + body + checksum(body)
		if err := ParseArtifact(v, ArtifactCLISession); err == nil {
			t.Fatalf("a %d-byte body was accepted, only %d is emittable", len(raw), bodyBytes)
		}
	}

	// A non-canonical encoding (an extra leading zero) is refused even though
	// it decodes to the right bytes.
	v, _, _ := NewArtifact(ArtifactBootstrap)
	// Splice an extra '0' into the body: same value, longer string.
	prefix := "hik_" + artifactFormatVersion + "_" + string(ArtifactBootstrap) + "_"
	payload := v[len(prefix):]
	body, sum := payload[:len(payload)-checksumChars], payload[len(payload)-checksumChars:]
	nonCanonical := prefix + "0" + body + sum
	if err := ParseArtifact(nonCanonical, ArtifactBootstrap); err == nil {
		t.Fatal("a non-canonical encoding was accepted")
	}
}
