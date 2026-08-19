package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// The Kubernetes operator's per-target rollout stamp (k8s-integration ADR §
// Change propagation; #64 handoff § 0.2). Same construction as Compose's stamp
// (#18 requires one explanation for both): a keyed HMAC over a versioned
// canonical encoding of the target's delivered content, per target, so blast
// radius follows consumption — rotating one API key restarts the workloads that
// consume it and never the database beside them.
//
// It lives here for the same reason the change token does: `crypto/hmac` and
// `crypto/hkdf` are confined to internal/crypto by the import-boundary test, so
// there is one place to audit how stamp keys are derived. The CALLER (the
// operator) owns nothing cryptographic — it holds the 32-byte random root, hands
// it in per computation, and receives a stamp string.

// StampVersion is the stamp's version prefix, carried on the emitted value AND
// inside the canonical encoding. Outside: the stamp flows into a pod-template
// annotation as a public machine contract, so a scheme change without a prefix
// would silently invalidate every consumer's comparison. Inside: without it two
// different encodings of the same content could collide under a scheme change,
// which an outside prefix cannot prevent (the change-token package makes the
// same argument for ManifestVersion).
const StampVersion = "v1"

// stampInfoLabel domain-separates the k8s stamp-key derivation. Only the legacy
// `wenv/change-token/v1` label is frozen; new labels use `hikyo/` (§ 0.2).
const stampInfoLabel = "hikyo/k8s-stamp/v1"

// stampCanonicalPrefix is the version byte/prefix the canonical encoding opens
// with, distinct from the info label so the derived key and the signed message
// can never be confused for one another.
const stampCanonicalPrefix = "hikyo-k8s-stamp-v1"

// StampPair is one delivered `(secretKey, value)` the stamp covers. `secretKey`
// is the managed Secret's DATA key (the mapping's destination name), not the
// Hikyo source key — the annotation follows what the workload consumes, and a
// destination rename is a delivery change the stamp must move on (cursor
// eligibility § 0.5 binds the same mapping digest).
type StampPair struct {
	SecretKey string
	Value     string
}

// StampKey derives the per-target stamp key via HKDF-SHA256 over the operator's
// local 256-bit random root, domain-separated by `(HikyoInstance UID, CR UID,
// managed-Secret name)`. A single flat key would make equal content produce
// equal stamps across namespaces and projects — a cross-scope equality oracle
// for any principal who can read workloads in two namespaces but Secrets in
// neither, which is the exact comparison the revision-model ADR's scoped
// derivation kills server-side; derivation re-kills it client-side (ADR §
// Change propagation).
//
// The info string is PIPE-JOINED exactly as § 0.2 fixes it — not the
// length-prefixed encoding scopedCursorKey uses — and it is injective anyway:
// a Kubernetes UID is a hyphenated hex UUID and a Secret name obeys RFC 1123,
// so neither component can contain the `|` separator.
func StampKey(root []byte, instanceUID, crUID, secretName string) ([]byte, error) {
	info := stampInfoLabel + "|" + instanceUID + "|" + crUID + "|" + secretName
	key, err := hkdf.Key(sha256.New, root, nil, info, KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive stamp key: %w", err)
	}
	return key, nil
}

// Stamp computes the target's rollout stamp: `v1:` + hex(first 16 bytes of
// HMAC-SHA256(stampKey, canonicalEncoding(pairs))). Truncated to 128 bits per
// the k8s ADR — a rollout trigger, not an authentication tag, and the annotation
// stays short (the key-name part is capped at 63 chars, hence `target.name` ≤
// 63).
//
// The stamp is a PURE FUNCTION of the delivered content, which is what makes the
// write path idempotent: a crash-and-redo full fetch delivering unchanged
// content yields the same stamp and moves no workload (ADR § Write ordering).
func Stamp(stampKey []byte, pairs []StampPair) string {
	mac := hmac.New(sha256.New, stampKey)
	mac.Write(canonicalStamp(pairs))
	sum := mac.Sum(nil)
	return StampVersion + ":" + hex.EncodeToString(sum[:16])
}

// canonicalStamp renders the delivered pairs injectively: the version prefix,
// the pair count, then each `(secretKey, value)` sorted by secretKey with every
// field length-prefixed (the internal/delivery appendField shape). Sorting is
// load-bearing — an unsorted encoding would make the stamp a function of
// delivery order — and the count plus per-field length prefix close the
// concatenation collision ("AB","c") vs ("A","Bc") the Manifest comment names.
//
// #63 (Compose) shares this construction, so the exact bytes are: uvarint-len
// prefix + "hikyo-k8s-stamp-v1", uvarint pair count, then per pair
// (uvarint-len + secretKey, uvarint-len + value).
func canonicalStamp(pairs []StampPair) []byte {
	sorted := slices.Clone(pairs)
	slices.SortFunc(sorted, func(a, b StampPair) int { return strings.Compare(a.SecretKey, b.SecretKey) })

	out := appendStampField(nil, stampCanonicalPrefix)
	out = binary.AppendUvarint(out, uint64(len(sorted)))
	for _, p := range sorted {
		out = appendStampField(out, p.SecretKey)
		out = appendStampField(out, p.Value)
	}
	return out
}

// appendStampField writes one uvarint-length-prefixed field, mirroring
// internal/delivery.appendField. Kept local rather than exported across the
// package boundary: the two encodings are deliberately independent (a change to
// one must not silently move the other).
func appendStampField(dst []byte, s string) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(s)))
	return append(dst, s...)
}
