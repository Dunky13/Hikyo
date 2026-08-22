package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
)

// Client-side key material for the Compose delivery path (compose-integration
// ADR § Change propagation and § Offline behaviour). Both artifacts — the
// stamp key and the snapshot key — are declared amendment 5 to the
// encryption-model ADR: client-side keys OUTSIDE the server key hierarchy, but
// bound by the same rules (XChaCha20-Poly1305, domain-separated HKDF, a
// normative AAD tuple, a version prefix). They live here for the same reason
// the rest of the module's cryptography does: crypto/hkdf and crypto/hmac are
// confined to this package by the import-boundary test, so there is exactly one
// place to audit how keys are derived.
//
// There is ONE local secret to protect — a single random 256-bit local key in
// `local.key`. The stamp key and the snapshot key are HKDF-derived from it with
// distinct labels (§ "The local stamp key is ... domain-separated by HKDF from
// the same local key material"), so a compromise of the state directory that
// reads one reads them all — which is fine, because whoever reads the state
// directory also reads the values outright.

const (
	// stampKeyLabel and snapshotKeyLabel domain-separate the two derived keys.
	stampKeyLabel    = "hikyo/compose/stamp-key/v1"
	snapshotKeyLabel = "hikyo/compose/snapshot-key/v1"

	// stampDomain is the message prefix folded in before HMAC, so a stamp can
	// never be confused with any other HMAC this key might compute. It is
	// distinct from the per-target content domain the caller applies before
	// calling Stamp (compose/generation.go: "hikyo-target-content-v1\x00").
	stampDomain = "hikyo-stamp-v1\x00"

	// stampBytes is the truncated HMAC width: 128 bits, per the ADR ("128 bits,
	// version-prefixed").
	stampBytes = 16

	// localKeyName is the single random secret; snapshotKeyID is the fixed
	// header label pinning the snapshot container to its key derivation.
	localKeyName  = "local.key"
	snapshotKeyID = "hikyo/compose/snapshot/v1"
)

// stampGrammar is the anchored, strict stamp grammar (ADR § "The stamp grammar
// is normative and strict": v<version>-<32 lowercase hex>). A stamp failing it
// is a hard error, never a fallback to a default generation — without the
// grammar a stamp is an unvalidated path segment and `/` or `..` in it would
// let a crafted file point env_file at an arbitrary path.
var stampGrammar = regexp.MustCompile(`^v1-[0-9a-f]{32}$`)

// LocalKeys is the two derived client keys. Callers hold it for the life of a
// render/fetch and let it go; the underlying local key stays on disk 0600.
type LocalKeys struct {
	stampKey    []byte
	snapshotKey []byte
}

// LoadOrCreateLocalKey loads the local key from dir/local.key, creating it (and
// dir) on first use. The state directory MUST be 0700 and the key file 0600,
// both owned by the invoking user (system-architecture ADR § Client local
// state — protection model). Every access goes through directory-relative,
// no-symlink-follow descriptors (§ *Client local state*): the directory is
// opened with O_NOFOLLOW and its mode/ownership verified through the descriptor
// (never a path stat followed by a separate open), and the key is opened
// relative to that directory. A directory or key that is a symlink,
// group/other-accessible, or not owned by the euid is REFUSED, not repaired.
func LoadOrCreateLocalKey(dir string) (*LocalKeys, error) {
	master, err := loadOrCreateMasterKey(dir)
	if err != nil {
		return nil, err
	}
	defer Zero(master)

	stampKey, err := hkdf.Key(sha256.New, master, nil, stampKeyLabel, KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive stamp key: %w", err)
	}
	snapshotKey, err := hkdf.Key(sha256.New, master, nil, snapshotKeyLabel, KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive snapshot key: %w", err)
	}
	return &LocalKeys{stampKey: stampKey, snapshotKey: snapshotKey}, nil
}

// Stamp is "v1-" + hex(HMAC-SHA256(stampKey, stampDomain+content)[:16]) — 128
// bits, 32 lowercase hex, version-prefixed. Keyed, never a bare content digest:
// a bare digest over rendered content is a function of secret plaintexts and so
// brute-forceable offline by anyone holding it (compose ADR § "The stamp is
// keyed, never a content digest", inheriting the revision ADR's rule).
func (k *LocalKeys) Stamp(content []byte) string {
	mac := hmac.New(sha256.New, k.stampKey)
	mac.Write([]byte(stampDomain))
	mac.Write(content)
	sum := mac.Sum(nil)
	return "v1-" + hex.EncodeToString(sum[:stampBytes])
}

// ParseStamp enforces the anchored stamp grammar. It validates only; it never
// returns a default.
func ParseStamp(s string) error {
	if !stampGrammar.MatchString(s) {
		return fmt.Errorf("crypto: %q is not a valid stamp (want v1-<32 lowercase hex>)", s)
	}
	return nil
}

// SnapshotAAD is the stable serialized form derived from SnapshotBinding. Its
// field names and declaration order are persisted protocol data for HKS1
// containers. Runtime save/load code accepts SnapshotBinding instead, so this
// mutable serialization DTO cannot bypass binding validation.
//
// The list fields (Projection, TargetNames) are sorted and deduplicated INSIDE
// Canonical(), so a caller-visible ordering choice or an accidental duplicate
// cannot change the authenticated bytes: identical sets always canonicalize
// identically.
//
// IssuedAt and ExpiresAt are the EXACT RFC3339 UTC strings the server returned;
// they are carried verbatim, never re-formatted through time.Time.
// InstanceOrigin is the instance identity the client actually holds: the
// client's trust store is origin-keyed, so the origin is the stable identity it
// can compare offline.
type SnapshotAAD struct {
	InstanceOrigin string `json:"instance_origin"`
	OrgID          string `json:"org_id"`
	ProjectID      string `json:"project_id"`
	EnvironmentID  string `json:"environment_id"`
	// CredentialID is the server-asserted credential id. It is authenticated
	// metadata (bound into the AAD, returned to the caller for the offline
	// records' credential_id) but is not locally knowable: it is a mutable on-disk
	// value the box could rewrite, so it supplies no offline expectation.
	CredentialID string `json:"credential_id"`
	// CredentialFingerprint is the LOCAL, offline-derivable identity of the
	// credential the snapshot was fetched with — hex(sha256(domain ‖ token)). The
	// CLI recomputes it from the PRESENTED token at load and ContextMatches
	// refuses the snapshot by name if it differs, so a rotated token cannot serve
	// the old snapshot even fully offline (nothing mutable on disk supplies the
	// expectation — the presented token does).
	CredentialFingerprint string `json:"credential_fingerprint"`
	ConfigOnly            bool   `json:"config_only"`
	// TargetNames is the render-target id set.
	TargetNames []string `json:"target_names"`
	// PinnedRevision is the resolved historical revision when the snapshot was
	// served from a pin, or 0 when serving current material (unpinned). It
	// replaces the earlier Revision+Pinned pair: a pin is exactly a non-zero
	// resolved revision, so one field is both necessary and sufficient.
	PinnedRevision int64 `json:"pinned_revision"`
	// ChangeToken is the server's keyed delivery-manifest token (`v1:`-prefixed),
	// on the wire on BOTH the delivering and config-only dispositions. It is the
	// resolved-content identity the client actually holds: an unpinned "current"
	// revision is NOT on the wire, so PinnedRevision alone cannot distinguish two
	// current snapshots with the same issuance but different content. Binding the
	// token into the header makes the header — and therefore the HWM digest over
	// it — differ whenever the delivered content differs (compose ADR § Expiry,
	// clocks and rollback). The offline box cannot reconstruct it without the
	// server; ParseSnapshotBinding recovers it from the authenticated header.
	ChangeToken string `json:"change_token"`
	// Projection is the authorized delivery capability list.
	Projection []string `json:"projection"`
	IssuedAt   string   `json:"issued_at"`
	ExpiresAt  string   `json:"expires_at"`
}

// Canonical is the deterministic header-bytes encoding of the full AAD tuple:
// the two list fields are sorted and deduplicated, then the struct is marshalled
// to JSON (Go marshals struct fields in declaration order, so the bytes are
// stable). These bytes are BOTH the cleartext container header and the AEAD's
// associated data, so tampering the header fails the open.
func (a SnapshotAAD) Canonical() ([]byte, error) {
	c := a
	c.TargetNames = CanonicalStringSet(a.TargetNames)
	c.Projection = CanonicalStringSet(a.Projection)
	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal snapshot header: %w", err)
	}
	return b, nil
}

// ParseSnapshotHeader decodes canonical header bytes back into a SnapshotAAD.
func ParseSnapshotHeader(b []byte) (SnapshotAAD, error) {
	var a SnapshotAAD
	if err := json.Unmarshal(b, &a); err != nil {
		return SnapshotAAD{}, fmt.Errorf("crypto: parse snapshot header: %w", err)
	}
	return a, nil
}

// SealSnapshot encrypts plaintext under the snapshot key with headerCanonical as
// the associated data — reusing the module's XChaCha20-Poly1305 envelope
// (versioned header, fresh 192-bit nonce). The caller passes the exact canonical
// header bytes it also stores in the container, so the cleartext header is
// authenticated by the AEAD.
func (k *LocalKeys) SealSnapshot(headerCanonical, plaintext []byte) ([]byte, error) {
	return seal(rand.Reader, k.snapshotKey, []byte(snapshotKeyID), 1, rawAAD(headerCanonical), plaintext)
}

// OpenSnapshot decrypts a snapshot payload, requiring the associated data to be
// byte-identical to the header bytes sealed alongside it. Any tampered
// header/payload byte fails as ErrDecrypt.
func (k *LocalKeys) OpenSnapshot(headerCanonical, record []byte) ([]byte, error) {
	return open(k.snapshotKey, []byte(snapshotKeyID), 1, rawAAD(headerCanonical), record)
}

// rawAAD carries opaque, pre-canonicalized associated-data bytes as one
// length-prefixed AAD field under the compose-snapshot kind. It is how the
// self-describing snapshot container binds its cleartext header to the payload.
type rawAAD []byte

func (r rawAAD) kind() Kind       { return KindComposeSnapshot }
func (r rawAAD) fields() [][]byte { return [][]byte{r} }

// CanonicalStringSet returns a sorted, deduplicated copy of items. It is the
// ONE canonicalizer shared between the snapshot AAD's list fields and the
// compose cursor's projection / target-key-id membership, so "the authorized
// projection, sorted as the CLI derives it" means exactly the same bytes in
// both places.
func CanonicalStringSet(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	cp := append([]string(nil), items...)
	sort.Strings(cp)
	out := cp[:0]
	for i, s := range cp {
		if i == 0 || s != cp[i-1] {
			out = append(out, s)
		}
	}
	return out
}
