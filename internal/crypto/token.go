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

// deriveScopedTokenKey derives one purpose's per-scope key from the root token
// key (encryption-model ADR § Key hierarchy):
//
//	scopedTokenKey = HKDF-SHA256(rootTokenKey, info = LP(label, org_id, project_id, env_id))
//
// The info encoding is the same length-prefixed canonical encoding as the
// AADs — load-bearing: raw concatenation would let ("a","bc") and ("ab","c")
// derive the identical key, resurrecting the cross-scope equality oracle the
// revision-model ADR keyed the token to eliminate. label is immutable protocol
// data and domain-separates each token purpose. Derived per use, never cached or
// stored; callers zero the returned key after tagging.
func (k *Keyring) deriveScopedTokenKey(label, orgID, projectID, envID string) ([]byte, error) {
	info := appendLP(nil, []byte(label))
	info = appendLP(info, []byte(orgID))
	info = appendLP(info, []byte(projectID))
	info = appendLP(info, []byte(envID))
	key, err := hkdf.Key(sha256.New, k.rootTokenKey(), nil, string(info), KeySize)
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

const publishPreviewInfoLabel = "hikyo/publish-preview/v1"

// OccurrenceToken is HMAC-SHA256(scoped occurrence key, encoding), base64url,
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
	key, err := k.deriveScopedTokenKey(occurrenceInfoLabel, orgID, projectID, envID)
	if err != nil {
		return "", err
	}
	defer Zero(key)
	return tag(key, encoding), nil
}

// PublishPreviewToken binds a reviewed publish preview to its exact scoped
// inputs. It has its own derivation label so a preview token is never usable as
// a delivery cursor, occurrence token, or change token.
func (k *Keyring) PublishPreviewToken(orgID, projectID, envID string, encoding []byte) (string, error) {
	key, err := k.deriveScopedTokenKey(publishPreviewInfoLabel, orgID, projectID, envID)
	if err != nil {
		return "", err
	}
	defer Zero(key)
	return tag(key, encoding), nil
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
// THERE IS NO TOKEN CACHE TO INVALIDATE. The encryption-model ADR's rotation
// protocol exists because "rotate the key and tokens change" is false when
// tokens are served from a cache; here a token is derived from the live key on
// every read and no snapshot stores one, so adopting the new handle IS the
// whole rotation. Every current published snapshot serves a token under the
// new key from the next read onward, and no snapshot's content, revision
// number or pinned input revisions move (encryption-model ADR CI invariant 15,
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
