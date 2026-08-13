package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// The two keyed values the machine delivery path publishes (#62; revision ADR
// § Revision identity, as amended by schema-model ADR § The change token covers
// a delivery manifest).
//
// Both live here for one reason: `crypto/hmac` and `crypto/hkdf` are confined
// to this package by the import-boundary test, and that confinement is the
// reason there is one place to audit how keys are derived. The CALLERS own the
// canonical encodings — what a delivery manifest is, what the cursor's
// four-tuple contains — because those are product decisions this package has no
// business knowing. It receives bytes and returns a token.

// cursorInfoLabel domain-separates the cursor key from the change-token key.
// The two values travel differently — a change token is designed to flow into
// pod annotations and logs as ordinary non-secret metadata, a cursor is handed
// back to one caller — so they are derived from separate keys rather than from
// one key with two message prefixes. That costs one HKDF call and removes a
// class of question ("could a caller who holds one forge the other?") entirely.
const cursorInfoLabel = "hikyo/delivery-cursor/v1"

// TokenVersion is the scheme's version prefix, carried on both values.
//
// It is not decoration. A change token is a PUBLIC MACHINE CONTRACT embedded in
// pod annotations and client caches, so changing the encoding later without a
// prefix would silently invalidate every consumer's comparison. The cursor
// carries the same prefix for the duller reason that a value which looks like a
// token and is not one is worse than either.
const TokenVersion = "v1"

// ChangeToken is HMAC-SHA256(scopedTokenKey, manifest), base64url, prefixed.
//
// Keyed, never a bare digest, and the revision ADR's reasoning is worth
// restating because the naive version looks fine: a bare digest over delivered
// content is a function of secret plaintexts, so a low-entropy secret is
// brute-forceable offline by anyone holding the digest — and the Kubernetes
// operator writes this value into a pod-template annotation, readable by every
// principal who can read Deployments but not Secrets. A keyed token is
// unforgeable and un-invertible without the key.
//
// The key is derived per (org, project, environment), so a token is meaningful
// only within the environment that produced it. A single global key would make
// tokens comparable ACROSS scopes: an attacker who can write values in their
// own project constructs a candidate payload, reads its token, and compares it
// against a target environment's pod annotation.
func (k *Keyring) ChangeToken(orgID, projectID, envID string, manifest []byte) (string, error) {
	key, err := k.ScopedTokenKey(orgID, projectID, envID)
	if err != nil {
		return "", err
	}
	defer Zero(key)
	return tag(key, manifest), nil
}

// DeliveryCursor is HMAC-SHA256(scopedCursorKey, tuple), base64url, prefixed.
//
// The caller passes the whole four-tuple encoding — change token, authorized
// delivery projection, authorization revision, pin generation — and the server
// answers "current" only when the cursor it recomputes equals the one
// presented. That makes the cursor OPAQUE by construction rather than by
// convention: there is nothing inside it to parse, and a caller cannot
// construct one for a state it has not been served.
//
// It also means there is no cursor-versioning machinery, and none is needed: a
// mismatch produces a full authorized delivery, so changing what the tuple
// covers is always safe. When real revisions replace the manifest computation
// behind this seam, every outstanding cursor mismatches once and every caller
// re-syncs.
func (k *Keyring) DeliveryCursor(orgID, projectID, envID string, tuple []byte) (string, error) {
	key, err := k.scopedCursorKey(orgID, projectID, envID)
	if err != nil {
		return "", err
	}
	defer Zero(key)
	return tag(key, tuple), nil
}

// scopedCursorKey mirrors ScopedTokenKey under its own label, with the same
// length-prefixed info encoding — load-bearing for the same reason: raw
// concatenation would let ("a","bc") and ("ab","c") derive the identical key.
func (k *Keyring) scopedCursorKey(orgID, projectID, envID string) ([]byte, error) {
	info := appendLP(nil, []byte(cursorInfoLabel))
	info = appendLP(info, []byte(orgID))
	info = appendLP(info, []byte(projectID))
	info = appendLP(info, []byte(envID))
	key, err := hkdf.Key(sha256.New, k.rootTokenKey(), nil, string(info), KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive scoped cursor key: %w", err)
	}
	return key, nil
}

// tag renders one keyed value. base64url without padding, because both values
// travel in HTTP query strings, JSON and Kubernetes annotations, and each of
// those has its own opinion about `+`, `/` and `=`.
func tag(key, message []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return TokenVersion + ":" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
