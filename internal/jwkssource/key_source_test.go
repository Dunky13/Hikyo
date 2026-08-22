package jwkssource

import (
	"errors"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/domain"
)

const testEd25519JWKX = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestParseKeySourceRejectsImpossibleCombinations(t *testing.T) {
	valid := `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + testEd25519JWKX + `","kid":"test","use":"sig"}]}`
	empty := ""
	for _, tc := range []struct {
		name     string
		mode     domain.JWKSMode
		document *string
	}{
		{name: "unknown mode", mode: domain.JWKSMode("other")},
		{name: "discovery with document", mode: domain.JWKSDiscovery, document: &valid},
		{name: "discovery with empty document", mode: domain.JWKSDiscovery, document: &empty},
		{name: "static without document", mode: domain.JWKSStatic},
		{name: "static with empty document", mode: domain.JWKSStatic, document: &empty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseKeySource(tc.mode, tc.document); !errors.Is(err, ErrKeySource) {
				t.Fatalf("ParseKeySource() error = %v, want ErrKeySource", err)
			}
		})
	}
}

func TestStaticKeySourceCanonicalizesBeforeUse(t *testing.T) {
	rawA := "{\n  \"keys\": [ { \"use\": \"sig\", \"x\": \"" + testEd25519JWKX + "\", \"kid\": \"test\", \"crv\": \"Ed25519\", \"kty\": \"OKP\" } ]\n}"
	rawB := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"test","x":"` + testEd25519JWKX + `","use":"sig"}]}`

	sourceA, err := ParseKeySource(domain.JWKSStatic, &rawA)
	if err != nil {
		t.Fatal(err)
	}
	sourceB, err := ParseKeySource(domain.JWKSStatic, &rawB)
	if err != nil {
		t.Fatal(err)
	}
	documentA, ok := sourceA.CanonicalJWKS()
	if !ok {
		t.Fatal("static source reported no canonical JWKS")
	}
	documentB, ok := sourceB.CanonicalJWKS()
	if !ok {
		t.Fatal("static source reported no canonical JWKS")
	}
	if documentA != documentB {
		t.Fatalf("equivalent JWKS documents canonicalized differently:\n%s\n%s", documentA, documentB)
	}
	if strings.ContainsAny(documentA, "\n\t") || strings.Contains(documentA, "  ") {
		t.Fatalf("canonical JWKS still contains formatting whitespace: %q", documentA)
	}
	if sourceA.Mode() != domain.JWKSStatic {
		t.Fatalf("static source mode = %q", sourceA.Mode())
	}
	if _, ok := RemoteDiscovery().CanonicalJWKS(); ok {
		t.Fatal("remote discovery carried a static JWKS")
	}
}

func TestStaticKeySourcePreservesJWKSAdmissionPolicy(t *testing.T) {
	noSigningKeys := `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + testEd25519JWKX + `","use":"enc"}]}`
	if _, err := ParseKeySource(domain.JWKSStatic, &noSigningKeys); !errors.Is(err, ErrKeySource) {
		t.Fatalf("non-signing JWKS error = %v, want ErrKeySource", err)
	}

	tooLarge := `{"keys":[]}` + strings.Repeat(" ", MaxJWKSBytes)
	if _, err := ParseKeySource(domain.JWKSStatic, &tooLarge); !errors.Is(err, ErrKeySource) {
		t.Fatalf("oversize JWKS error = %v, want ErrKeySource", err)
	}
}
