package crypto

import (
	"encoding/hex"
	"testing"
)

// Golden known-answer test: pins the wire format itself, not just round-trip
// behaviour. A reorder of header fields, a changed kind byte, or a different
// AAD field order would pass every round-trip test while bricking all
// persisted ciphertext — this record, sealed once and frozen, catches that.
//
// Construction (never regenerate by re-running seal — that would defeat the
// pin): key = bytes 0x00..0x1f, wrapping_key_id "dek_test", version 7,
// nonce = 24×0xA5, kind value, AAD {org_1, prj_1, env_1, key_1, row_1,
// value}, plaintext "golden".
const goldenRecordHex = "0101010000000864656b5f746573740000000700000018" +
	"a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5" +
	"feff209099195707dc44d4c08ef6ef9a9eb224cd905c"

func TestGoldenRecordOpens(t *testing.T) {
	record, err := hex.DecodeString(goldenRecordHex)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	pt, err := open(key, []byte("dek_test"), 7, ValueAAD{
		OrgID: "org_1", ProjectID: "prj_1", EnvID: "env_1",
		KeyID: "key_1", RowID: "row_1", FieldTag: "value",
	}, record)
	if err != nil {
		t.Fatalf("golden record failed to open — the wire format changed: %v", err)
	}
	if string(pt) != "golden" {
		t.Fatalf("golden record plaintext = %q, want %q", pt, "golden")
	}
}

// The kind byte assignments are part of the persisted format: pin the exact
// values, not just their distinctness.
func TestKindBytesPinned(t *testing.T) {
	pinned := map[Kind]byte{
		ValueAAD{}.kind():           1,
		WrappedDEKAAD{}.kind():      2,
		WrappedMasterAAD{}.kind():   3,
		WrappedTokenKeyAAD{}.kind(): 4,
		ProjectFieldAAD{}.kind():    5,
		InstanceFieldAAD{}.kind():   6,
	}
	for kind, want := range pinned {
		if byte(kind) != want {
			t.Errorf("kind byte %d, want %d — kind bytes are persisted format, never renumber", byte(kind), want)
		}
	}
}
