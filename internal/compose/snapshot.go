package compose

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
)

// Offline snapshot store (compose-integration ADR § "Offline behaviour",
// ops-spec § 6). Every successful delivering fetch writes a ciphertext snapshot
// to persistent disk; serving from it is opt-in per stack, timestamped, and
// refused past a hard maximum age. The snapshot is a values cache at rest — the
// state directory is what protects it.
//
// The snapshot is SELF-DESCRIBING: after a reboot — the offline-boot case this
// exists for — the server is unreachable, so the box cannot reconstruct the
// full AAD tuple (revision, projection, issuance, expiry). The container
// therefore stores that tuple as a cleartext, AEAD-authenticated header and the
// caller supplies only the SnapshotContext it knows offline (identity, org,
// project, environment, credential, config-only mode, target set).
//
//	container = "HKS1" ‖ uint32-BE(len(header)) ‖ header ‖ sealed-payload
//
// where `header` is crypto.SnapshotAAD.Canonical() and the sealed payload's AAD
// IS those exact header bytes, so tampering the header fails the open.
//
// Two guards beyond the AEAD:
//   - a high-water mark of (issuance, header-digest): an older issuance is
//     refused, and an equal issuance whose header identity differs is refused
//     too, so a plain-file rollback cannot resurrect a superseded generation
//     even when it reuses the server timestamp (§ Expiry, clocks and rollback);
//   - expiry: min(server-asserted expires_at, issued_at + per-stack max_age),
//     both server-asserted and integrity-protected in the header.

const (
	snapshotFile = "snapshot.bin"
	hwmFile      = "snapshot.hwm"

	// snapshotMagic versions the container framing independently of the crypto
	// envelope's own format byte.
	snapshotMagic = "HKS1"
)

// ErrSnapshotExpired, ErrSnapshotRollback and ErrSnapshotContext are the policy
// refusals, each distinguishable from an AEAD failure (crypto.ErrDecrypt).
var (
	ErrSnapshotExpired  = errors.New("compose: snapshot expired")
	ErrSnapshotRollback = errors.New("compose: snapshot issuance is not newer than the recorded high-water mark")
	ErrSnapshotContext  = errors.New("compose: snapshot context does not match local context")
	errSnapshotFraming  = errors.New("compose: snapshot container is malformed")
)

// SnapshotRow is one delivered key inside a snapshot. KeyID is the immutable
// server key id: it travels INSIDE the sealed payload so the offline path can
// map row→key_id for its per-key reconciliation records without a cleartext
// sidecar (the self-describing snapshot subsumed the old offline.meta.json).
type SnapshotRow struct {
	Name           string `json:"name"`
	KeyID          string `json:"key_id"`
	Classification string `json:"classification"`
	Value          string `json:"value"`
}

// SnapshotPayload is the plaintext a snapshot seals: the delivered rows and the
// generation stamps that fetch produced.
type SnapshotPayload struct {
	Rows             []SnapshotRow     `json:"rows"`
	GenerationStamps map[string]string `json:"generation_stamps"`
}

// hwm is the persisted high-water mark: the newest issuance seen and the digest
// of that snapshot's header, so an equal-issuance record with a different
// identity is still refused as a rollback.
type hwm struct {
	IssuedAt string `json:"issued_at"`
	Digest   string `json:"digest"`
}

// SaveSnapshot seals payload under keys with the AAD's canonical header, frames
// the self-describing container, and writes snapshot.bin atomically (0600). It
// advances snapshot.hwm to (issued_at, header-digest) and REFUSES to save an
// issuance older than the current high-water mark (a rollback attempt).
func SaveSnapshot(stateDir string, keys *crypto.LocalKeys, aad crypto.SnapshotAAD, payload SnapshotPayload) error {
	issued, err := time.Parse(time.RFC3339, aad.IssuedAt)
	if err != nil {
		return fmt.Errorf("compose: snapshot issued_at %q is not RFC3339: %w", aad.IssuedAt, err)
	}
	header, err := aad.Canonical()
	if err != nil {
		return err
	}
	digest := headerDigest(header)

	mark, err := readHWM(stateDir)
	if err != nil {
		return err
	}
	if mark != nil {
		markTime, err := time.Parse(time.RFC3339, mark.IssuedAt)
		if err != nil {
			return fmt.Errorf("compose: high-water mark %q is not RFC3339: %w", mark.IssuedAt, err)
		}
		if issued.Before(markTime) {
			return fmt.Errorf("%w (issued %s < hwm %s)", ErrSnapshotRollback, issued, markTime)
		}
		if issued.Equal(markTime) && digest != mark.Digest {
			return fmt.Errorf("%w (issued %s equals hwm but header identity differs)", ErrSnapshotRollback, issued)
		}
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("compose: marshal snapshot payload: %w", err)
	}
	sealed, err := keys.SealSnapshot(header, plaintext)
	if err != nil {
		return fmt.Errorf("compose: seal snapshot: %w", err)
	}
	container := frameSnapshot(header, sealed)
	if err := atomicWrite(filepath.Join(stateDir, snapshotFile), container, 0o600); err != nil {
		return fmt.Errorf("compose: write snapshot: %w", err)
	}
	// Advance the HWM only after the snapshot is durable.
	nextHWM, err := json.Marshal(hwm{IssuedAt: aad.IssuedAt, Digest: digest})
	if err != nil {
		return fmt.Errorf("compose: marshal high-water mark: %w", err)
	}
	if err := atomicWrite(filepath.Join(stateDir, hwmFile), nextHWM, 0o600); err != nil {
		return fmt.Errorf("compose: write high-water mark: %w", err)
	}
	return nil
}

// LoadSnapshot reads snapshot.bin, parses its self-describing header, checks the
// offline-known context against `expect`, enforces rollback and expiry, then
// decrypts. It returns the payload and the full header (revision, projection,
// issuance and expiry are taken FROM the header, not reconstructed). maxAge is
// the per-stack downward override; the effective expiry is the earlier bound.
func LoadSnapshot(stateDir string, keys *crypto.LocalKeys, expect crypto.SnapshotContext, now time.Time, maxAge time.Duration) (SnapshotPayload, crypto.SnapshotAAD, error) {
	var zeroP SnapshotPayload
	var zeroA crypto.SnapshotAAD

	record, err := os.ReadFile(filepath.Join(stateDir, snapshotFile))
	if err != nil {
		return zeroP, zeroA, fmt.Errorf("compose: read snapshot: %w", err)
	}
	header, sealed, err := unframeSnapshot(record)
	if err != nil {
		return zeroP, zeroA, err
	}
	aad, err := crypto.ParseSnapshotHeader(header)
	if err != nil {
		return zeroP, zeroA, err
	}
	// Refuse a transplanted snapshot by name before any crypto work.
	if err := aad.ContextMatches(expect); err != nil {
		return zeroP, zeroA, fmt.Errorf("%w: %v", ErrSnapshotContext, err)
	}

	issued, err := time.Parse(time.RFC3339, aad.IssuedAt)
	if err != nil {
		return zeroP, zeroA, fmt.Errorf("compose: snapshot issued_at %q is not RFC3339: %w", aad.IssuedAt, err)
	}
	expires, err := time.Parse(time.RFC3339, aad.ExpiresAt)
	if err != nil {
		return zeroP, zeroA, fmt.Errorf("compose: snapshot expires_at %q is not RFC3339: %w", aad.ExpiresAt, err)
	}

	mark, err := readHWM(stateDir)
	if err != nil {
		return zeroP, zeroA, err
	}
	if mark != nil {
		markTime, err := time.Parse(time.RFC3339, mark.IssuedAt)
		if err != nil {
			return zeroP, zeroA, fmt.Errorf("compose: high-water mark %q is not RFC3339: %w", mark.IssuedAt, err)
		}
		if issued.Before(markTime) {
			return zeroP, zeroA, fmt.Errorf("%w (issued %s < hwm %s)", ErrSnapshotRollback, issued, markTime)
		}
		if issued.Equal(markTime) && headerDigest(header) != mark.Digest {
			return zeroP, zeroA, fmt.Errorf("%w (issued %s equals hwm but header identity differs)", ErrSnapshotRollback, issued)
		}
	}

	// Effective expiry is the earlier of the server bound and the per-stack cap.
	effective := expires
	if capped := issued.Add(maxAge); capped.Before(effective) {
		effective = capped
	}
	if now.After(effective) {
		return zeroP, zeroA, fmt.Errorf("%w (expired at %s, now %s)", ErrSnapshotExpired, effective, now)
	}

	plaintext, err := keys.OpenSnapshot(header, sealed)
	if err != nil {
		return zeroP, zeroA, err // crypto.ErrDecrypt on any tamper/AEAD failure
	}
	var payload SnapshotPayload
	dec := json.NewDecoder(bytes.NewReader(plaintext))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		return zeroP, zeroA, fmt.Errorf("compose: parse snapshot payload: %w", err)
	}
	return payload, aad, nil
}

func headerDigest(header []byte) string {
	sum := sha256.Sum256(header)
	return hex.EncodeToString(sum[:])
}

// frameSnapshot builds the container: magic ‖ uint32-BE(len(header)) ‖ header ‖ sealed.
func frameSnapshot(header, sealed []byte) []byte {
	out := make([]byte, 0, len(snapshotMagic)+4+len(header)+len(sealed))
	out = append(out, snapshotMagic...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(header)))
	out = append(out, header...)
	out = append(out, sealed...)
	return out
}

// unframeSnapshot validates the magic and header length prefix and splits the
// record into (header, sealed).
func unframeSnapshot(record []byte) (header, sealed []byte, err error) {
	if len(record) < len(snapshotMagic)+4 {
		return nil, nil, errSnapshotFraming
	}
	if string(record[:len(snapshotMagic)]) != snapshotMagic {
		return nil, nil, fmt.Errorf("%w: bad magic", errSnapshotFraming)
	}
	pos := len(snapshotMagic)
	n := int(binary.BigEndian.Uint32(record[pos:]))
	pos += 4
	if n < 0 || pos+n > len(record) {
		return nil, nil, fmt.Errorf("%w: header length out of range", errSnapshotFraming)
	}
	return record[pos : pos+n], record[pos+n:], nil
}

// readHWM returns the recorded high-water mark, or nil if none.
func readHWM(stateDir string) (*hwm, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, hwmFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("compose: read high-water mark: %w", err)
	}
	var m hwm
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("compose: parse high-water mark: %w", err)
	}
	return &m, nil
}
