package compose

import (
	"os"
	"path/filepath"
	"testing"
)

func offlineState(t *testing.T) string {
	t.Helper()
	s := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(s, 0o700); err != nil {
		t.Fatal(err)
	}
	return s
}

func rec(t *testing.T, name string) OfflineRecord {
	t.Helper()
	id, err := NewRecordID()
	if err != nil {
		t.Fatal(err)
	}
	return OfflineRecord{
		RecordID: id, KeyID: "key_" + name, KeyName: name,
		Classification: "secret", OccurredAt: "2026-08-19T10:00:00Z",
		CredentialID: "cred_1", Generation: "v1-" + hex32(), ServedFrom: "snapshot",
	}
}

func TestOfflineAppendPendingFlush(t *testing.T) {
	state := offlineState(t)
	batch := []OfflineRecord{rec(t, "A"), rec(t, "B")}
	if err := Append(state, batch); err != nil {
		t.Fatal(err)
	}
	// Second batch → a second file.
	if err := Append(state, []OfflineRecord{rec(t, "C")}); err != nil {
		t.Fatal(err)
	}
	records, handles, err := Pending(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("pending records = %d, want 3", len(records))
	}
	if len(handles) != 2 {
		t.Fatalf("pending handles = %d, want 2", len(handles))
	}
	// Flush one batch; one record file remains.
	if err := MarkFlushed(state, handles[:1]); err != nil {
		t.Fatal(err)
	}
	_, handles2, err := Pending(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(handles2) != 1 {
		t.Fatalf("after flush handles = %d, want 1", len(handles2))
	}
}

// TestMarkFlushedRefusesNonOpaqueHandle: a handle with a path separator, a
// traversal, or an absolute path is refused — MarkFlushed cannot be steered to
// delete anything outside the offline-records dir (#10).
func TestMarkFlushedRefusesNonOpaqueHandle(t *testing.T) {
	state := offlineState(t)
	if err := Append(state, []OfflineRecord{rec(t, "A")}); err != nil {
		t.Fatal(err)
	}
	// Plant a victim file outside the offline dir.
	victim := filepath.Join(state, "victim")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"../victim", "/etc/passwd", "sub/dir.json", ".."} {
		if err := MarkFlushed(state, []string{bad}); err == nil {
			t.Errorf("MarkFlushed accepted a non-opaque handle %q", bad)
		}
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatal("victim file was deleted through a crafted handle")
	}
}

func TestOfflineAppendRefusesInvalidRecords(t *testing.T) {
	state := offlineState(t)
	good := rec(t, "A")
	for name, mut := range map[string]func(*OfflineRecord){
		"empty-record-id":  func(r *OfflineRecord) { r.RecordID = "" },
		"empty-key-id":     func(r *OfflineRecord) { r.KeyID = "" },
		"empty-credential": func(r *OfflineRecord) { r.CredentialID = "" },
		"empty-served":     func(r *OfflineRecord) { r.ServedFrom = "" },
		"bad-class":        func(r *OfflineRecord) { r.Classification = "other" },
		"bad-time":         func(r *OfflineRecord) { r.OccurredAt = "yesterday" },
		"bad-generation":   func(r *OfflineRecord) { r.Generation = "not-a-stamp" },
	} {
		bad := good
		mut(&bad)
		if err := Append(state, []OfflineRecord{bad}); err == nil {
			t.Errorf("%s: expected refusal", name)
		}
	}
}

func TestOfflineAppendEmptyIsNoop(t *testing.T) {
	state := offlineState(t)
	if err := Append(state, nil); err != nil {
		t.Fatal(err)
	}
	records, handles, err := Pending(state)
	if err != nil || records != nil || handles != nil {
		t.Fatalf("empty append should leave nothing: %v %v %v", records, handles, err)
	}
}

func TestPendingMissingDir(t *testing.T) {
	records, handles, err := Pending(offlineState(t))
	if err != nil || records != nil || handles != nil {
		t.Fatalf("no dir should be empty, not error: %v %v %v", records, handles, err)
	}
}
