package compose

import (
	"bytes"
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
// Two guards beyond the AEAD:
//   - a monotonic high-water mark of the newest issuance seen, so a plain file
//     rollback cannot resurrect a superseded generation (§ Expiry, clocks and
//     rollback);
//   - expiry: min(server-asserted expires_at, issued_at + per-stack max_age),
//     both server-asserted and integrity-protected in the AAD.

const (
	snapshotFile = "snapshot.bin"
	hwmFile      = "snapshot.hwm"
)

// ErrSnapshotExpired and ErrSnapshotRollback are the two policy refusals,
// distinguishable from an AEAD failure (crypto.ErrDecrypt).
var (
	ErrSnapshotExpired  = errors.New("compose: snapshot expired")
	ErrSnapshotRollback = errors.New("compose: snapshot issuance is older than the recorded high-water mark")
)

// SnapshotRow is one delivered key inside a snapshot.
type SnapshotRow struct {
	Name           string `json:"name"`
	Classification string `json:"classification"`
	Value          string `json:"value"`
}

// SnapshotPayload is the plaintext a snapshot seals: the delivered rows and the
// generation stamps that fetch produced.
type SnapshotPayload struct {
	Rows             []SnapshotRow     `json:"rows"`
	GenerationStamps map[string]string `json:"generation_stamps"`
}

// SaveSnapshot seals payload under keys+aad and writes snapshot.bin atomically
// (0600). It advances snapshot.hwm to the AAD's issued_at, and REFUSES to save
// an issuance older than the current high-water mark (a rollback attempt).
func SaveSnapshot(stateDir string, keys *crypto.LocalKeys, aad crypto.SnapshotAAD, payload SnapshotPayload) error {
	issued, err := time.Parse(time.RFC3339, aad.IssuedAt)
	if err != nil {
		return fmt.Errorf("compose: snapshot issued_at %q is not RFC3339: %w", aad.IssuedAt, err)
	}
	hwm, err := readHWM(stateDir)
	if err != nil {
		return err
	}
	if !hwm.IsZero() && issued.Before(hwm) {
		return fmt.Errorf("%w (issued %s < hwm %s)", ErrSnapshotRollback, issued, hwm)
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("compose: marshal snapshot payload: %w", err)
	}
	sealed, err := keys.SealSnapshot(aad, plaintext)
	if err != nil {
		return fmt.Errorf("compose: seal snapshot: %w", err)
	}
	if err := atomicWrite(filepath.Join(stateDir, snapshotFile), sealed, 0o600); err != nil {
		return fmt.Errorf("compose: write snapshot: %w", err)
	}
	// Advance the HWM only after the snapshot is durable.
	if err := atomicWrite(filepath.Join(stateDir, hwmFile), []byte(aad.IssuedAt+"\n"), 0o600); err != nil {
		return fmt.Errorf("compose: write high-water mark: %w", err)
	}
	return nil
}

// LoadSnapshot opens snapshot.bin under keys+aad and returns the payload and its
// issuance time. It refuses a rollback (issued_at < hwm), an expired snapshot
// (now past min(expires_at, issued_at+maxAge)), or any AEAD failure. maxAge is
// the per-stack downward override; the effective expiry is the earlier bound.
func LoadSnapshot(stateDir string, keys *crypto.LocalKeys, aad crypto.SnapshotAAD, now time.Time, maxAge time.Duration) (SnapshotPayload, time.Time, error) {
	var zero SnapshotPayload
	issued, err := time.Parse(time.RFC3339, aad.IssuedAt)
	if err != nil {
		return zero, time.Time{}, fmt.Errorf("compose: snapshot issued_at %q is not RFC3339: %w", aad.IssuedAt, err)
	}
	expires, err := time.Parse(time.RFC3339, aad.ExpiresAt)
	if err != nil {
		return zero, time.Time{}, fmt.Errorf("compose: snapshot expires_at %q is not RFC3339: %w", aad.ExpiresAt, err)
	}

	hwm, err := readHWM(stateDir)
	if err != nil {
		return zero, time.Time{}, err
	}
	if !hwm.IsZero() && issued.Before(hwm) {
		return zero, time.Time{}, fmt.Errorf("%w (issued %s < hwm %s)", ErrSnapshotRollback, issued, hwm)
	}

	// Effective expiry is the earlier of the server bound and the per-stack cap.
	effective := expires
	if capped := issued.Add(maxAge); capped.Before(effective) {
		effective = capped
	}
	if now.After(effective) {
		return zero, time.Time{}, fmt.Errorf("%w (expired at %s, now %s)", ErrSnapshotExpired, effective, now)
	}

	record, err := os.ReadFile(filepath.Join(stateDir, snapshotFile))
	if err != nil {
		return zero, time.Time{}, fmt.Errorf("compose: read snapshot: %w", err)
	}
	plaintext, err := keys.OpenSnapshot(aad, record)
	if err != nil {
		return zero, time.Time{}, err // crypto.ErrDecrypt on any AAD/AEAD failure
	}

	var payload SnapshotPayload
	dec := json.NewDecoder(bytes.NewReader(plaintext))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		return zero, time.Time{}, fmt.Errorf("compose: parse snapshot payload: %w", err)
	}
	return payload, issued, nil
}

// readHWM returns the recorded high-water mark, or the zero time if none.
func readHWM(stateDir string) (time.Time, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, hwmFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("compose: read high-water mark: %w", err)
	}
	s := string(bytes.TrimSpace(b))
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("compose: high-water mark %q is not RFC3339: %w", s, err)
	}
	return t, nil
}
