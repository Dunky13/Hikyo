package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// tokenInfoLabel domain-separates change-token derivation from any future
// per-purpose derivation. The legacy product name is immutable cryptographic
// protocol data; changing it would derive different keys for existing values.
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

// occurrenceInfoLabel domain-separates the import occurrence key from the
// change-token and cursor keys. Same reasoning as the cursor's own label: three
// values that travel differently get three keys, which removes the question
// "could a holder of one forge another?" rather than answering it.
const occurrenceInfoLabel = "hikyo/import-occurrence/v1"

// OccurrenceToken is HMAC-SHA256(scopedOccurrenceKey, encoding), base64url,
// prefixed — the server-minted opaque token an import's phase 1 records per
// (key, environment) and phase 2 verifies inside its own authorized
// transaction.
//
// Keyed rather than a bare digest, and SCOPED per (org, project, environment),
// for the reason the change token is: a global key would make tokens comparable
// across scopes, so an attacker who can write values in their own project could
// construct a candidate state, read its token, and test it against a target
// environment's manifest. Scoped and keyed, an edited or fabricated manifest
// cannot phrase a question about someone else's state that the server will
// answer — an unrecognized token recomputes to a mismatch exactly like a stale
// one, which is what makes the two indistinguishable to a caller.
//
// The caller owns the encoding (internal/delivery.EncodeOccurrence); this
// package receives bytes and returns a token.
func (k *Keyring) OccurrenceToken(orgID, projectID, envID string, encoding []byte) (string, error) {
	key, err := k.scopedOccurrenceKey(orgID, projectID, envID)
	if err != nil {
		return "", err
	}
	defer Zero(key)
	return tag(key, encoding), nil
}

// scopedOccurrenceKey mirrors ScopedTokenKey under its own label, with the same
// length-prefixed info encoding — load-bearing for the same reason: raw
// concatenation would let ("a","bc") and ("ab","c") derive the identical key.
func (k *Keyring) scopedOccurrenceKey(orgID, projectID, envID string) ([]byte, error) {
	info := appendLP(nil, []byte(occurrenceInfoLabel))
	info = appendLP(info, []byte(orgID))
	info = appendLP(info, []byte(projectID))
	info = appendLP(info, []byte(envID))
	key, err := hkdf.Key(sha256.New, k.token.key, nil, string(info), KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive scoped occurrence key: %w", err)
	}
	return key, nil
}
