package compose

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
)

func snapAAD(issued, expires string) crypto.SnapshotAAD {
	return crypto.SnapshotAAD{
		InstanceOrigin: "https://hikyo.example",
		OrgID:          "org_1", ProjectID: "prj_1", EnvironmentID: "env_1",
		CredentialID: "cred_1", Revision: 3, Pinned: false,
		Projection: []string{"read", "reveal"}, ConfigOnly: false,
		TargetNames: []string{"api"},
		IssuedAt:    issued, ExpiresAt: expires,
	}
}

func snapState(t *testing.T) (string, *crypto.LocalKeys) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	if err := mkdir700(state); err != nil {
		t.Fatal(err)
	}
	return state, testKeys(t)
}

func mkdir700(p string) error { return osMkdir(p, 0o700) }

func TestSnapshotSaveLoadRoundTrip(t *testing.T) {
	state, keys := snapState(t)
	aad := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	payload := SnapshotPayload{
		Rows:             []SnapshotRow{{Name: "API_KEY", Classification: "secret", Value: "s3cr3t"}},
		GenerationStamps: map[string]string{"api": "v1-" + hex32()},
	}
	if err := SaveSnapshot(state, keys, aad, payload); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	got, issued, err := LoadSnapshot(state, keys, aad, now, DefaultSnapshotMaxAge)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got.Rows) != 1 || got.Rows[0].Value != "s3cr3t" {
		t.Errorf("payload = %+v", got)
	}
	if !issued.Equal(time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("issued = %s", issued)
	}
}

func TestSnapshotExpiryServerBound(t *testing.T) {
	state, keys := snapState(t)
	aad := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	if err := SaveSnapshot(state, keys, aad, SnapshotPayload{}); err != nil {
		t.Fatal(err)
	}
	past := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC) // after expires_at
	_, _, err := LoadSnapshot(state, keys, aad, past, DefaultSnapshotMaxAge)
	if !errors.Is(err, ErrSnapshotExpired) {
		t.Fatalf("err = %v, want ErrSnapshotExpired", err)
	}
}

func TestSnapshotExpiryDownwardMaxAge(t *testing.T) {
	state, keys := snapState(t)
	// Server expiry 7 d out, but a per-stack 1h cap bites first.
	aad := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	if err := SaveSnapshot(state, keys, aad, SnapshotPayload{}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC) // 2h after issue
	_, _, err := LoadSnapshot(state, keys, aad, now, time.Hour)
	if !errors.Is(err, ErrSnapshotExpired) {
		t.Fatalf("err = %v, want ErrSnapshotExpired (downward max_age)", err)
	}
	// Within the cap it loads.
	within := time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC)
	if _, _, err := LoadSnapshot(state, keys, aad, within, time.Hour); err != nil {
		t.Fatalf("within cap: %v", err)
	}
}

func TestSnapshotHWMRollbackRefusedOnSave(t *testing.T) {
	state, keys := snapState(t)
	newer := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	if err := SaveSnapshot(state, keys, newer, SnapshotPayload{}); err != nil {
		t.Fatal(err)
	}
	older := snapAAD("2026-08-18T10:00:00Z", "2026-08-25T10:00:00Z")
	if err := SaveSnapshot(state, keys, older, SnapshotPayload{}); !errors.Is(err, ErrSnapshotRollback) {
		t.Fatalf("save older err = %v, want ErrSnapshotRollback", err)
	}
}

func TestSnapshotHWMRollbackRefusedOnLoad(t *testing.T) {
	state, keys := snapState(t)
	// Save newer to set the HWM, then load an older snapshot record.
	newer := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	if err := SaveSnapshot(state, keys, newer, SnapshotPayload{}); err != nil {
		t.Fatal(err)
	}
	// Overwrite snapshot.bin with an older sealed record (rollback of the file),
	// HWM still names the newer issuance.
	older := snapAAD("2026-08-18T10:00:00Z", "2026-08-25T10:00:00Z")
	sealed, err := keys.SealSnapshot(older, mustJSON(SnapshotPayload{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(state, snapshotFile), sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	if _, _, err := LoadSnapshot(state, keys, older, now, DefaultSnapshotMaxAge); !errors.Is(err, ErrSnapshotRollback) {
		t.Fatalf("load rolled-back err = %v, want ErrSnapshotRollback", err)
	}
}

func TestSnapshotAEADFailureOnWrongContext(t *testing.T) {
	state, keys := snapState(t)
	aad := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	if err := SaveSnapshot(state, keys, aad, SnapshotPayload{}); err != nil {
		t.Fatal(err)
	}
	// Loading with a different environment must fail the AEAD.
	wrong := aad
	wrong.EnvironmentID = "env_2"
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	if _, _, err := LoadSnapshot(state, keys, wrong, now, DefaultSnapshotMaxAge); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
}
