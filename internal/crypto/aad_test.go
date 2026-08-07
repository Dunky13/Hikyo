package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Invariant 5 (encryption ADR § CI-enforced invariants): adversarial field
// values chosen to collide under naive concatenation must produce distinct
// AADs.
func TestAADInjectivity(t *testing.T) {
	pairs := []struct {
		name string
		a, b AAD
	}{
		{
			"value boundary shift org/project",
			ValueAAD{OrgID: "a", ProjectID: "bc", EnvID: "e", KeyID: "k", RowID: "r", FieldTag: "f"},
			ValueAAD{OrgID: "ab", ProjectID: "c", EnvID: "e", KeyID: "k", RowID: "r", FieldTag: "f"},
		},
		{
			"value boundary shift env/key",
			ValueAAD{OrgID: "o", ProjectID: "p", EnvID: "e1", KeyID: "k", RowID: "r", FieldTag: "f"},
			ValueAAD{OrgID: "o", ProjectID: "p", EnvID: "e", KeyID: "1k", RowID: "r", FieldTag: "f"},
		},
		{
			"empty field vs shifted content",
			ValueAAD{OrgID: "", ProjectID: "op", EnvID: "e", KeyID: "k", RowID: "r", FieldTag: "f"},
			ValueAAD{OrgID: "op", ProjectID: "", EnvID: "e", KeyID: "k", RowID: "r", FieldTag: "f"},
		},
		{
			"project field boundary shift",
			ProjectFieldAAD{OrgID: "o", ProjectID: "p", OwnerTable: "ad", OwnerRowID: "apters", FieldTag: "f"},
			ProjectFieldAAD{OrgID: "o", ProjectID: "p", OwnerTable: "adapters", OwnerRowID: "", FieldTag: "f"},
		},
		{
			"instance field boundary shift",
			InstanceFieldAAD{OwnerTable: "a", OwnerRowID: "bc", FieldTag: "f"},
			InstanceFieldAAD{OwnerTable: "ab", OwnerRowID: "c", FieldTag: "f"},
		},
		{
			"wrapped dek instance vs project empty ids",
			WrappedDEKAAD{OrgID: "", ProjectID: "", DEKID: "d", DEKVersion: 1, MasterKeyVersion: 1},
			WrappedDEKAAD{OrgID: "d", ProjectID: "", DEKID: "", DEKVersion: 1, MasterKeyVersion: 1},
		},
	}
	hdr := []byte{0x01}
	for _, p := range pairs {
		ea := appendAAD(hdr, p.a)
		eb := appendAAD(hdr, p.b)
		if bytes.Equal(ea, eb) {
			t.Errorf("%s: AADs collide", p.name)
		}
	}
}

// Different envelope kinds must never share an AAD even when their fields
// serialize identically: the kind byte lives in the authenticated header.
func TestKindsAreDistinct(t *testing.T) {
	seen := map[Kind]bool{}
	for _, a := range []AAD{
		ValueAAD{}, WrappedDEKAAD{}, WrappedMasterAAD{}, WrappedTokenKeyAAD{},
		ProjectFieldAAD{}, InstanceFieldAAD{},
	} {
		k := a.kind()
		if seen[k] {
			t.Errorf("kind %d assigned twice", k)
		}
		seen[k] = true
	}
	if len(seen) != 6 {
		t.Errorf("want 6 envelope kinds, got %d", len(seen))
	}
}

// The length-prefix encoding is uint32 big-endian length then bytes, absent
// fields emitted as length zero — pinned so the wire format cannot drift
// silently.
func TestLengthPrefixWireFormat(t *testing.T) {
	got := appendLP(nil, []byte("ab"))
	got = appendLP(got, nil)
	want := []byte{0, 0, 0, 2, 'a', 'b', 0, 0, 0, 0}
	if !bytes.Equal(got, want) {
		t.Errorf("appendLP = %x, want %x", got, want)
	}
	var be [4]byte
	binary.BigEndian.PutUint32(be[:], 7)
	if !bytes.Equal(be32(7), be[:]) {
		t.Errorf("be32(7) = %x", be32(7))
	}
}
