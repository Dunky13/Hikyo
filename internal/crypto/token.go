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
	key, err := hkdf.Key(sha256.New, k.rootTokenKey(), nil, string(info), KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive scoped token key: %w", err)
	}
	return key, nil
}

// rootTokenKey reads the live root token key under the rotation mutex, so a
// derivation racing `rotate-token-key` sees exactly one version rather than a
// torn handle. Callers derive per use and never retain the result.
func (k *Keyring) rootTokenKey() []byte {
	k.tokenMu.Lock()
	defer k.tokenMu.Unlock()
	return k.token.key
}

// PrepareTokenKeyRotation mints the next root token key and returns its
// wrapped row plus the function that adopts it. The material never leaves this
// package: the caller persists the row inside its own authorized transaction
// and calls adopt only AFTER that transaction commits.
//
// The split exists because the persistence closure runs inside a retryable
// transaction: an attempt that is rolled back and retried mints fresh material
// each time, and only the attempt that actually committed may become the live
// key. Adopting inside the closure would leave the process serving tokens
// under a key version the datastore does not record.
//
// THERE IS NO TOKEN CACHE TO INVALIDATE. The encryption ADR's rotation
// protocol exists because "rotate the key and tokens change" is false when
// tokens are served from a cache; here a token is derived from the live key on
// every read and no snapshot stores one, so adopting the new handle IS the
// whole rotation. Every current published snapshot serves a token under the
// new key from the next read onward, and no snapshot's content, revision
// number or pinned input revisions move (encryption ADR CI invariant 15,
// mvp-boundary C4).
//
// The superseded key is NOT zeroed. A concurrent derivation may still be
// holding the buffer, and deriving under a zeroed key would be a silent
// confidentiality break rather than a loud failure — the same reason the DEK
// cache does not zero evicted entries.
func (k *Keyring) PrepareTokenKeyRotation() (WrappedKey, func(), error) {
	k.tokenMu.Lock()
	current := k.token
	k.tokenMu.Unlock()

	handle, row, err := k.mintTier3At(PurposeToken, "", "", current.version+1)
	if err != nil {
		return WrappedKey{}, nil, err
	}
	return row, func() {
		k.tokenMu.Lock()
		defer k.tokenMu.Unlock()
		// Monotonic: two concurrent rotations commit in some serial order, but
		// their adopts may run in the other order. The store's retire is a
		// compare-and-swap on the predecessor version, so at most one of them
		// committed -- this guard makes the losing (or late) adopt a no-op
		// instead of regressing the live handle to a retired key.
		if handle.version > k.token.version {
			k.token = handle
		}
	}, nil
}
