// Package jwkssource owns the closed representation and parsing policy for a
// federation issuer's signing-key source. It is a leaf shared by the wire,
// store facade, and verifier; it performs no fetches and imports no service or
// persistence package.
package jwkssource

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/Hikyo-Org/hikyo/internal/domain"
)

// MaxJWKSBytes is the shared admission cap for static and remote JWKS
// documents. Both sources must carry the same bounded key policy.
const MaxJWKSBytes = 1 << 20

// ErrKeySource reports a wire or stored representation that is not exactly one
// of remote discovery or a validated static JWKS document.
var ErrKeySource = errors.New("jwkssource: invalid issuer key source")

// KeySource is the closed value RemoteDiscovery | Static{CanonicalJWKS}.
//
// Its zero value is remote discovery. The static arm is private and can only be
// created by ParseKeySource, which validates and canonicalizes the document.
// That makes the former mode/static pair's impossible combinations
// unrepresentable everywhere after the wire or storage boundary.
type KeySource struct {
	static *canonicalJWKS
}

type canonicalJWKS struct {
	document string
}

// RemoteDiscovery returns the remote-discovery variant.
func RemoteDiscovery() KeySource { return KeySource{} }

// ParseKeySource converts the compatible wire representation into its closed
// value. Presence matters: discovery with even an empty static_jwks property is
// not the remote variant, and static without the property is not the static
// variant.
func ParseKeySource(mode domain.JWKSMode, staticJWKS *string) (KeySource, error) {
	switch mode {
	case domain.JWKSDiscovery:
		if staticJWKS != nil {
			return KeySource{}, fmt.Errorf("%w: discovery cannot carry static JWKS", ErrKeySource)
		}
		return RemoteDiscovery(), nil
	case domain.JWKSStatic:
		if staticJWKS == nil || *staticJWKS == "" {
			return KeySource{}, fmt.Errorf("%w: static source needs a JWKS document", ErrKeySource)
		}
		canonical, err := canonicalizeJWKS([]byte(*staticJWKS))
		if err != nil {
			return KeySource{}, fmt.Errorf("%w: %v", ErrKeySource, err)
		}
		return KeySource{static: &canonicalJWKS{document: canonical}}, nil
	default:
		return KeySource{}, fmt.Errorf("%w: unknown mode %q", ErrKeySource, mode)
	}
}

// ParseStoredKeySource converts the existing two database columns into their
// closed value. Stored rows are validated on read so corruption fails loud
// instead of selecting a source by accident. Valid legacy static documents are
// canonicalized in memory without requiring a migration.
func ParseStoredKeySource(mode domain.JWKSMode, staticJWKS string, present bool) (KeySource, error) {
	if !present {
		return ParseKeySource(mode, nil)
	}
	return ParseKeySource(mode, &staticJWKS)
}

// Mode returns the compatibility value used by the API and existing columns.
func (s KeySource) Mode() domain.JWKSMode {
	if s.static != nil {
		return domain.JWKSStatic
	}
	return domain.JWKSDiscovery
}

// CanonicalJWKS returns the canonical document only for the static variant.
func (s KeySource) CanonicalJWKS() (string, bool) {
	if s.static == nil {
		return "", false
	}
	return s.static.document, true
}

// StorageColumns maps the closed value to the existing compatible columns.
func (s KeySource) StorageColumns() (domain.JWKSMode, string) {
	if s.static == nil {
		return domain.JWKSDiscovery, ""
	}
	return domain.JWKSStatic, s.static.document
}

// Equal reports whether two sources select the same variant and, for static
// sources, the same canonical key document.
func (s KeySource) Equal(other KeySource) bool {
	left, leftStatic := s.CanonicalJWKS()
	right, rightStatic := other.CanonicalJWKS()
	return leftStatic == rightStatic && left == right
}

func canonicalizeJWKS(body []byte) (string, error) {
	if len(body) > MaxJWKSBytes {
		return "", fmt.Errorf("jwks document exceeds %d bytes", MaxJWKSBytes)
	}
	set, _, _, err := decodeJWKS(body)
	if err != nil {
		return "", err
	}
	document, err := json.Marshal(set)
	if err != nil {
		return "", fmt.Errorf("jwks canonicalize: %w", err)
	}
	return string(document), nil
}

// ParseJWKS turns a document into fresh public keys through go-jose. This is
// key parsing, not verification: go-oidc performs the signature check against
// the returned keys. A rotation publishes old and new keys together, so both
// enter the set and tokens signed by either continue to verify.
func ParseJWKS(body []byte) ([]crypto.PublicKey, map[string]bool, error) {
	_, keys, kids, err := decodeJWKS(body)
	return keys, kids, err
}

func decodeJWKS(body []byte) (jose.JSONWebKeySet, []crypto.PublicKey, map[string]bool, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return jose.JSONWebKeySet{}, nil, nil, fmt.Errorf("jwks parse: %w", err)
	}
	keys := make([]crypto.PublicKey, 0, len(set.Keys))
	kids := map[string]bool{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub := k.Public()
		if pub.Key == nil {
			continue
		}
		keys = append(keys, pub.Key)
		if k.KeyID != "" {
			kids[k.KeyID] = true
		}
	}
	if len(keys) == 0 {
		return jose.JSONWebKeySet{}, nil, nil, errors.New("jwks document carries no usable signing keys")
	}
	return set, keys, kids, nil
}
