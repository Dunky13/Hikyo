package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// tokenInfoLabel domain-separates change-token derivation from any future
// per-purpose derivation.
const tokenInfoLabel = "wenv/change-token/v1"

// ScopedTokenKey derives the per-scope change-token key from the root token
// key (encryption ADR § Key hierarchy):
//
//	scopedTokenKey = HKDF-SHA256(rootTokenKey, info = LP(label, org_id, project_id, env_id))
//
// The info encoding is the same length-prefixed canonical encoding as the
// AADs — load-bearing: raw concatenation would let ("a","bc") and ("ab","c")
// derive the identical key, resurrecting the cross-scope equality oracle the
// revision ADR keyed the token to eliminate. Derived per use, never cached
// or stored.
func (k *Keyring) ScopedTokenKey(orgID, projectID, envID string) ([]byte, error) {
	info := appendLP(nil, []byte(tokenInfoLabel))
	info = appendLP(info, []byte(orgID))
	info = appendLP(info, []byte(projectID))
	info = appendLP(info, []byte(envID))
	key, err := hkdf.Key(sha256.New, k.token.key, nil, string(info), KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive scoped token key: %w", err)
	}
	return key, nil
}
