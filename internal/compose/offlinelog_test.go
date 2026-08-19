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
	records, files, err := Pending(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("pending records = %d, want 3", len(records))
	}
	if len(files) != 2 {
		t.Fatalf("pending files = %d, want 2", len(files))
	}
	// Flush one file; one record file remains.
	if err := MarkFlushed(files[:1]); err != nil {
		t.Fatal(err)
	}
	_, files2, err := Pending(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(files2) != 1 {
		t.Fatalf("after flush files = %d, want 1", len(files2))
	}
}

func TestOfflineAppendRefusesEmptyRecordID(t *testing.T) {
	state := offlineState(t)
	bad := OfflineRecord{KeyID: "k", KeyName: "n"} // no RecordID
	if err := Append(state, []OfflineRecord{bad}); err == nil {
		t.Fatal("expected refusal of a record with no record_id")
	}
}

func TestOfflineAppendEmptyIsNoop(t *testing.T) {
	state := offlineState(t)
	if err := Append(state, nil); err != nil {
		t.Fatal(err)
	}
	records, files, err := Pending(state)
	if err != nil || records != nil || files != nil {
		t.Fatalf("empty append should leave nothing: %v %v %v", records, files, err)
	}
}

func TestPendingMissingDir(t *testing.T) {
	records, files, err := Pending(offlineState(t))
	if err != nil || records != nil || files != nil {
		t.Fatalf("no dir should be empty, not error: %v %v %v", records, files, err)
	}
}
