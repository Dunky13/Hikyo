package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
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
// state — protection model). An existing directory or file that is
// group/other-accessible or not owned by the euid is REFUSED, not repaired:
// silently chmod-ing someone else's file would hide exactly the tampering the
// check exists to surface, and the caller reports it as a doctor finding.
func LoadOrCreateLocalKey(dir string) (*LocalKeys, error) {
	if err := ensureSecureDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, localKeyName)

	master, err := readOrCreateKeyFile(path)
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

// readOrCreateKeyFile returns the 32-byte local key. When the file exists it is
// permission/owner-checked and read; when absent it is created with O_EXCL and
// 0600 and filled with fresh randomness (a short random read aborts — never a
// key with weak randomness), fsynced before use.
func readOrCreateKeyFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	switch {
	case err == nil:
		defer f.Close()
		if err := checkSecureFile(f); err != nil {
			return nil, err
		}
		key := make([]byte, KeySize)
		if _, err := io.ReadFull(f, key); err != nil {
			return nil, fmt.Errorf("crypto: read %s: %w", path, err)
		}
		// A short/oversized key file is corruption, not a shorter key.
		if extra, _ := f.Read(make([]byte, 1)); extra != 0 {
			return nil, fmt.Errorf("crypto: %s is not a %d-byte local key", path, KeySize)
		}
		return key, nil
	case os.IsNotExist(err):
		return createKeyFile(path)
	default:
		return nil, fmt.Errorf("crypto: open %s: %w", path, err)
	}
}

func createKeyFile(path string) ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("crypto: randomness unavailable, refusing to create local key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		Zero(key)
		return nil, fmt.Errorf("crypto: create %s: %w", path, err)
	}
	// Umask-independent: 0600 exactly whatever the process umask was.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		Zero(key)
		return nil, fmt.Errorf("crypto: chmod %s: %w", path, err)
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		Zero(key)
		return nil, fmt.Errorf("crypto: write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		Zero(key)
		return nil, fmt.Errorf("crypto: fsync %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		Zero(key)
		return nil, fmt.Errorf("crypto: close %s: %w", path, err)
	}
	return key, nil
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

// SnapshotAAD binds an offline snapshot to its full context (compose ADR
// § "AAD binds the container to its context"). A snapshot is therefore not
// transplantable across environments, projects, principals, or projections.
//
// IssuedAt and ExpiresAt are the EXACT RFC3339 UTC strings the server returned;
// they are bound verbatim, never re-formatted through time.Time (re-formatting
// would silently break every OpenSnapshot). The caller parses them separately
// for expiry/high-water-mark arithmetic.
type SnapshotAAD struct {
	InstanceOrigin string
	OrgID          string
	ProjectID      string
	EnvironmentID  string
	CredentialID   string
	Revision       int64
	Pinned         bool
	// Projection is the authorized delivery capability list, sorted by the
	// caller; ConfigOnly is the distinct config-only projection flag.
	Projection []string
	ConfigOnly bool
	// TargetNames is the render-target id set, sorted by the caller.
	TargetNames []string
	IssuedAt    string
	ExpiresAt   string
}

func (a SnapshotAAD) kind() Kind { return KindComposeSnapshot }

func (a SnapshotAAD) fields() [][]byte {
	return [][]byte{
		[]byte(a.InstanceOrigin),
		[]byte(a.OrgID),
		[]byte(a.ProjectID),
		[]byte(a.EnvironmentID),
		[]byte(a.CredentialID),
		be64(uint64(a.Revision)),
		boolByte(a.Pinned),
		encodeList(a.Projection),
		boolByte(a.ConfigOnly),
		encodeList(a.TargetNames),
		[]byte(a.IssuedAt),
		[]byte(a.ExpiresAt),
	}
}

// SealSnapshot encrypts plaintext under the snapshot key with the container's
// AAD, reusing the module's XChaCha20-Poly1305 envelope (versioned header,
// fresh 192-bit nonce). No second AEAD wrapper.
func (k *LocalKeys) SealSnapshot(aad SnapshotAAD, plaintext []byte) ([]byte, error) {
	return seal(rand.Reader, k.snapshotKey, []byte(snapshotKeyID), 1, aad, plaintext)
}

// OpenSnapshot decrypts a snapshot container, requiring the AAD to match the
// caller's context exactly. Any tampered component fails as ErrDecrypt.
func (k *LocalKeys) OpenSnapshot(aad SnapshotAAD, record []byte) ([]byte, error) {
	return open(k.snapshotKey, []byte(snapshotKeyID), 1, aad, record)
}

// encodeList canonicalises a string list into ONE AAD field with inner
// length-prefixing, so the list boundary is injective: without it,
// (["a"],["bc"]) and (["a","bc"],[]) at adjacent fields could encode
// identically. The caller sorts; we do not, so a caller-visible ordering choice
// is not silently reordered — but the two list fields (projection, targets) are
// documented as sorted.
func encodeList(items []string) []byte {
	var out []byte
	out = binary.BigEndian.AppendUint32(out, uint32(len(items)))
	for _, s := range items {
		out = appendLP(out, []byte(s))
	}
	return out
}

func be64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func boolByte(b bool) []byte {
	if b {
		return []byte{1}
	}
	return []byte{0}
}
