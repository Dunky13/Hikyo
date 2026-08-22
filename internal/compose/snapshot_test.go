package compose

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
)

func snapAAD(issued, expires string) crypto.SnapshotAAD {
	return crypto.SnapshotAAD{
		InstanceOrigin: "https://hikyo.example",
		OrgID:          "org_1", ProjectID: "prj_1", EnvironmentID: "env_1",
		CredentialID: "cred_1", CredentialFingerprint: "fp_1", PinnedRevision: 3, ChangeToken: "v1:manifest-token",
		Projection: []string{"read", "reveal"}, ConfigOnly: false,
		TargetNames: []string{"api"},
		IssuedAt:    issued, ExpiresAt: expires,
	}
}

func snapBinding(t *testing.T, stateDir string, aad crypto.SnapshotAAD) crypto.SnapshotBinding {
	t.Helper()
	binding, err := crypto.NewSnapshotBinding(crypto.SnapshotBindingScope{
		StorageDir:     stateDir,
		InstanceOrigin: aad.InstanceOrigin,
		OrgID:          aad.OrgID, ProjectID: aad.ProjectID, EnvironmentID: aad.EnvironmentID,
		CredentialFingerprint: aad.CredentialFingerprint, ConfigOnly: aad.ConfigOnly,
		TargetNames: aad.TargetNames,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err = binding.WithDelivery(crypto.SnapshotBindingDelivery{
		CredentialID: aad.CredentialID, PinnedRevision: aad.PinnedRevision,
		ChangeToken: aad.ChangeToken, Projection: aad.Projection,
		IssuedAt: aad.IssuedAt, ExpiresAt: aad.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

// snapScope is the offline-known binding matching snapAAD.
func snapScope(t *testing.T, stateDir, environment string) crypto.SnapshotBinding {
	t.Helper()
	binding, err := crypto.NewSnapshotBinding(crypto.SnapshotBindingScope{
		StorageDir:     stateDir,
		InstanceOrigin: "https://hikyo.example",
		OrgID:          "org_1", ProjectID: "prj_1", EnvironmentID: environment,
		CredentialFingerprint: "fp_1", ConfigOnly: false,
		TargetNames: []string{"api"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return binding
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
	if err := SaveSnapshot(keys, snapBinding(t, state, aad), payload); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	got, binding, err := LoadSnapshot(keys, snapScope(t, state, "env_1"), now, DefaultSnapshotMaxAge)
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
	hdr, err := binding.AAD()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.PinnedRevision != 3 || hdr.IssuedAt != "2026-08-19T10:00:00Z" || hdr.ExpiresAt != "2026-08-26T10:00:00Z" {
		t.Errorf("header not returned intact: %+v", hdr)
	}
}

func TestSnapshotLegacyContainerStillLoads(t *testing.T) {
	// Fixture was produced by the pre-#221 HKS1 writer with a 32-byte zero local
	// key. It is literal so framing, HKDF/AAD, or payload drift cannot update both
	// producer and consumer and leave this test falsely green.
	const legacyContainer = "SEtTMQAAAWt7Imluc3RhbmNlX29yaWdpbiI6Imh0dHBzOi8vaGlreW8uZXhhbXBsZSIsIm9yZ19pZCI6Im9yZ18xIiwicHJvamVjdF9pZCI6InByal8xIiwiZW52aXJvbm1lbnRfaWQiOiJlbnZfMSIsImNyZWRlbnRpYWxfaWQiOiJjcmVkXzEiLCJjcmVkZW50aWFsX2ZpbmdlcnByaW50IjoiZnBfMSIsImNvbmZpZ19vbmx5IjpmYWxzZSwidGFyZ2V0X25hbWVzIjpbImFwaSJdLCJwaW5uZWRfcmV2aXNpb24iOjMsImNoYW5nZV90b2tlbiI6InYxOm1hbmlmZXN0LXRva2VuIiwicHJvamVjdGlvbiI6WyJyZWFkIiwicmV2ZWFsIl0sImlzc3VlZF9hdCI6IjIwMjYtMDgtMTlUMTA6MDA6MDBaIiwiZXhwaXJlc19hdCI6IjIwMjYtMDgtMjZUMTA6MDA6MDBaIn0BBwEAAAAZaGlreW8vY29tcG9zZS9zbmFwc2hvdC92MQAAAAEAAAAYDeYH5jDyXMo1MwLNyoquSIzQTHV357AoAcpN2Ld9fsU+q91qqmmocnWELkWj7TX4fHvrd/qd2Sn4AtkelDf4xIStV4Q9oHhgA7Ra8SA865fBMfrVRWFCj8GNy3bmCk2O3NQYGIhWwnEyBLCIk5hwMC/aJDYuqBq+B+2kPO3kpJlMiZIpL6gMQavnDVQomnw="
	const legacyHeader = `{"instance_origin":"https://hikyo.example","org_id":"org_1","project_id":"prj_1","environment_id":"env_1","credential_id":"cred_1","credential_fingerprint":"fp_1","config_only":false,"target_names":["api"],"pinned_revision":3,"change_token":"v1:manifest-token","projection":["read","reveal"],"issued_at":"2026-08-19T10:00:00Z","expires_at":"2026-08-26T10:00:00Z"}`

	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "local.key"), make([]byte, crypto.KeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := crypto.LoadOrCreateLocalKey(state)
	if err != nil {
		t.Fatal(err)
	}
	record, err := base64.StdEncoding.DecodeString(legacyContainer)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(state, snapshotFile), record, 0o600); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	got, binding, err := LoadSnapshot(keys, snapScope(t, state, "env_1"), now, DefaultSnapshotMaxAge)
	if err != nil {
		t.Fatalf("load legacy container: %v", err)
	}
	if len(got.Rows) != 1 || got.Rows[0].Value != "legacy" {
		t.Fatalf("legacy payload = %+v", got)
	}
	canonical, err := binding.CanonicalAAD()
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != legacyHeader {
		t.Fatalf("legacy header changed:\n got %s\nwant %s", canonical, legacyHeader)
	}
}

func TestSnapshotInvalidBindingFailsBeforeFilesystemWork(t *testing.T) {
	state := filepath.Join(t.TempDir(), "must-not-exist")
	keys := testKeys(t)
	incomplete := snapScope(t, state, "env_1")

	if err := SaveSnapshot(keys, incomplete, SnapshotPayload{}); err == nil {
		t.Fatal("save accepted a scope-only binding")
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid save touched state dir: %v", err)
	}

	var invalid crypto.SnapshotBinding
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	if _, _, err := LoadSnapshot(keys, invalid, now, DefaultSnapshotMaxAge); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid load reached filesystem: %v", err)
	}
}

func TestSnapshotExpiryServerBound(t *testing.T) {
	state, keys := snapState(t)
	aad := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	if err := SaveSnapshot(keys, snapBinding(t, state, aad), SnapshotPayload{}); err != nil {
		t.Fatal(err)
	}
	past := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC) // after expires_at
	_, _, err := LoadSnapshot(keys, snapScope(t, state, "env_1"), past, DefaultSnapshotMaxAge)
	if !errors.Is(err, ErrSnapshotExpired) {
		t.Fatalf("err = %v, want ErrSnapshotExpired", err)
	}
}

func TestSnapshotExpiryDownwardMaxAge(t *testing.T) {
	state, keys := snapState(t)
	// Server expiry 7 d out, but a per-stack 1h cap bites first.
	aad := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	if err := SaveSnapshot(keys, snapBinding(t, state, aad), SnapshotPayload{}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC) // 2h after issue
	_, _, err := LoadSnapshot(keys, snapScope(t, state, "env_1"), now, time.Hour)
	if !errors.Is(err, ErrSnapshotExpired) {
		t.Fatalf("err = %v, want ErrSnapshotExpired (downward max_age)", err)
	}
	within := time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC)
	if _, _, err := LoadSnapshot(keys, snapScope(t, state, "env_1"), within, time.Hour); err != nil {
		t.Fatalf("within cap: %v", err)
	}
}

func TestSnapshotHWMRollbackRefusedOnSave(t *testing.T) {
	state, keys := snapState(t)
	newer := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	if err := SaveSnapshot(keys, snapBinding(t, state, newer), SnapshotPayload{}); err != nil {
		t.Fatal(err)
	}
	older := snapAAD("2026-08-18T10:00:00Z", "2026-08-25T10:00:00Z")
	if err := SaveSnapshot(keys, snapBinding(t, state, older), SnapshotPayload{}); !errors.Is(err, ErrSnapshotRollback) {
		t.Fatalf("save older err = %v, want ErrSnapshotRollback", err)
	}
}

func TestSnapshotHWMRollbackRefusedOnLoad(t *testing.T) {
	state, keys := snapState(t)
	newer := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	if err := SaveSnapshot(keys, snapBinding(t, state, newer), SnapshotPayload{}); err != nil {
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
	if _, _, err := LoadSnapshot(keys, snapScope(t, state, "env_1"), now, DefaultSnapshotMaxAge); !errors.Is(err, ErrSnapshotRollback) {
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
	if err := SaveSnapshot(keys, snapBinding(t, state, first), SnapshotPayload{Rows: []SnapshotRow{{Name: "A", Value: "1"}}}); err != nil {
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
	if _, _, err := LoadSnapshot(keys, snapScope(t, state, "env_1"), now, DefaultSnapshotMaxAge); !errors.Is(err, ErrSnapshotRollback) {
		t.Fatalf("same-issuance swap err = %v, want ErrSnapshotRollback", err)
	}
}

func TestSnapshotContextMismatchRefused(t *testing.T) {
	state, keys := snapState(t)
	aad := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	if err := SaveSnapshot(keys, snapBinding(t, state, aad), SnapshotPayload{}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	_, _, err := LoadSnapshot(keys, snapScope(t, state, "env_2"), now, DefaultSnapshotMaxAge)
	if !errors.Is(err, ErrSnapshotContext) {
		t.Fatalf("err = %v, want ErrSnapshotContext (refused by name, not ErrDecrypt)", err)
	}
}

func TestSnapshotTamperedContainerFailsAEAD(t *testing.T) {
	state, keys := snapState(t)
	aad := snapAAD("2026-08-19T10:00:00Z", "2026-08-26T10:00:00Z")
	if err := SaveSnapshot(keys, snapBinding(t, state, aad), SnapshotPayload{Rows: []SnapshotRow{{Name: "A", Value: "1"}}}); err != nil {
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
	if _, _, err := LoadSnapshot(keys, snapScope(t, state, "env_1"), now, DefaultSnapshotMaxAge); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("tampered container err = %v, want ErrDecrypt", err)
	}
}
