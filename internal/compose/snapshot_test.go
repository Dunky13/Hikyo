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
		CredentialID: "cred_1", PinnedRevision: 3, ChangeToken: "v1:manifest-token",
		Projection: []string{"read", "reveal"}, ConfigOnly: false,
		TargetNames: []string{"api"},
		IssuedAt:    issued, ExpiresAt: expires,
	}
}

// snapCtx is the offline-known context matching snapAAD.
func snapCtx() crypto.SnapshotContext {
	return crypto.SnapshotContext{
		InstanceOrigin: "https://hikyo.example",
		OrgID:          "org_1", ProjectID: "prj_1", EnvironmentID: "env_1",
		CredentialID: "cred_1", ConfigOnly: false,
		TargetNames: []string{"api"},
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

// TestSnapshotSaveLoadRoundTrip saves, drops all in-memory AAD, and loads with
// only the offline-known context — the offline-boot case.
func TestSnapshotSaveLoadRoundTrip(t *testing.T) {
	state, keys := snapState(t)
	aad := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	payload := SnapshotPayload{
		Rows:             []SnapshotRow{{Name: "API_KEY", KeyID: "key_api", Classification: "secret", Value: "s3cr3t"}},
		GenerationStamps: map[string]string{"api": "v1-" + hex32()},
	}
	if err := SaveSnapshot(state, keys, aad, payload); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	got, hdr, err := LoadSnapshot(state, keys, snapCtx(), now, DefaultSnapshotMaxAge)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got.Rows) != 1 || got.Rows[0].Value != "s3cr3t" {
		t.Errorf("payload = %+v", got)
	}
	// KeyID travels inside the sealed payload (subsumes the old cleartext sidecar).
	if got.Rows[0].KeyID != "key_api" {
		t.Errorf("KeyID not round-tripped inside the sealed payload: %+v", got.Rows[0])
	}
	// Server-asserted fields come back from the header, not reconstructed.
	if hdr.PinnedRevision != 3 || hdr.IssuedAt != "2026-08-19T10:00:00Z" || hdr.ExpiresAt != "2026-08-26T10:00:00Z" {
		t.Errorf("header not returned intact: %+v", hdr)
	}
}

func TestSnapshotExpiryServerBound(t *testing.T) {
	state, keys := snapState(t)
	aad := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	if err := SaveSnapshot(state, keys, aad, SnapshotPayload{}); err != nil {
		t.Fatal(err)
	}
	past := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC) // after expires_at
	_, _, err := LoadSnapshot(state, keys, snapCtx(), past, DefaultSnapshotMaxAge)
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
	_, _, err := LoadSnapshot(state, keys, snapCtx(), now, time.Hour)
	if !errors.Is(err, ErrSnapshotExpired) {
		t.Fatalf("err = %v, want ErrSnapshotExpired (downward max_age)", err)
	}
	within := time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC)
	if _, _, err := LoadSnapshot(state, keys, snapCtx(), within, time.Hour); err != nil {
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
	newer := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	if err := SaveSnapshot(state, keys, newer, SnapshotPayload{}); err != nil {
		t.Fatal(err)
	}
	// Overwrite snapshot.bin with an older sealed container (file rollback);
	// HWM still names the newer issuance.
	older := snapAAD("2026-08-18T10:00:00Z", "2026-08-25T10:00:00Z")
	hdr, err := older.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := keys.SealSnapshot(hdr, mustJSON(SnapshotPayload{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(state, snapshotFile), frameSnapshot(hdr, sealed), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	if _, _, err := LoadSnapshot(state, keys, snapCtx(), now, DefaultSnapshotMaxAge); !errors.Is(err, ErrSnapshotRollback) {
		t.Fatalf("load rolled-back err = %v, want ErrSnapshotRollback", err)
	}
}

// TestSnapshotSameIssuanceRollback: a second snapshot bearing the SAME server
// issuance timestamp but different content must not resurrect a superseded
// generation (#8). The two snapshots are BOTH unpinned "current" (PinnedRevision
// 0 is not on the wire, so it cannot distinguish them); their content identity
// is the ChangeToken. A different token ⇒ different header ⇒ different HWM digest
// ⇒ load refuses it (#7+#8).
func TestSnapshotSameIssuanceRollback(t *testing.T) {
	state, keys := snapState(t)
	issued := "2026-08-19T10:00:00Z"
	first := snapAAD(issued, "2026-08-26T10:00:00Z")
	first.PinnedRevision = 0
	if err := SaveSnapshot(state, keys, first, SnapshotPayload{Rows: []SnapshotRow{{Name: "A", Value: "1"}}}); err != nil {
		t.Fatal(err)
	}
	// A different current snapshot sharing the timestamp: same (unpinned) revision,
	// different delivered content ⇒ different ChangeToken.
	second := snapAAD(issued, "2026-08-26T10:00:00Z")
	second.PinnedRevision = 0
	second.ChangeToken = "v1:manifest-token-superseding"
	hdr, err := second.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := keys.SealSnapshot(hdr, mustJSON(SnapshotPayload{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(state, snapshotFile), frameSnapshot(hdr, sealed), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	// context still matches (revision is not part of the offline context).
	if _, _, err := LoadSnapshot(state, keys, snapCtx(), now, DefaultSnapshotMaxAge); !errors.Is(err, ErrSnapshotRollback) {
		t.Fatalf("same-issuance swap err = %v, want ErrSnapshotRollback", err)
	}
}

func TestSnapshotContextMismatchRefused(t *testing.T) {
	state, keys := snapState(t)
	aad := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	if err := SaveSnapshot(state, keys, aad, SnapshotPayload{}); err != nil {
		t.Fatal(err)
	}
	wrong := snapCtx()
	wrong.EnvironmentID = "env_2"
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	_, _, err := LoadSnapshot(state, keys, wrong, now, DefaultSnapshotMaxAge)
	if !errors.Is(err, ErrSnapshotContext) {
		t.Fatalf("err = %v, want ErrSnapshotContext (refused by name, not ErrDecrypt)", err)
	}
}

func TestSnapshotTamperedContainerFailsAEAD(t *testing.T) {
	state, keys := snapState(t)
	aad := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	if err := SaveSnapshot(state, keys, aad, SnapshotPayload{Rows: []SnapshotRow{{Name: "A", Value: "1"}}}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, snapshotFile)
	raw, err := osReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip the last byte (inside the sealed ciphertext/tag).
	raw[len(raw)-1] ^= 0xff
	if err := atomicWrite(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	if _, _, err := LoadSnapshot(state, keys, snapCtx(), now, DefaultSnapshotMaxAge); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("tampered container err = %v, want ErrDecrypt", err)
	}
}
