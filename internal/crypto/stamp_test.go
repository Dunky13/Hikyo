package crypto

import (
	"strings"
	"testing"
)

// A fixed 32-byte root for deterministic vectors. The stamp is a pure function
// of (root, target coordinates, pairs), so a golden value pins the wire format
// #63 (Compose) will share.
var stampRoot = []byte("0123456789abcdef0123456789abcdef")

func mustStampKey(t *testing.T, root []byte, inst, cr, secret string) []byte {
	t.Helper()
	key, err := StampKey(root, inst, cr, secret)
	if err != nil {
		t.Fatalf("StampKey: %v", err)
	}
	if len(key) != KeySize {
		t.Fatalf("StampKey len = %d, want %d", len(key), KeySize)
	}
	return key
}

func mustStamp(t *testing.T, key []byte, pairs []StampPair) string {
	t.Helper()
	s, err := Stamp(key, pairs)
	if err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	return s
}

func TestStampRejectsBadKeyMaterial(t *testing.T) {
	// A non-32-byte root or key must error, never silently produce a
	// publicly-reproducible stamp (§ 0.2).
	if _, err := StampKey(stampRoot[:16], "inst", "cr", "sec"); err == nil {
		t.Fatal("StampKey accepted a short root")
	}
	if _, err := StampKey(nil, "inst", "cr", "sec"); err == nil {
		t.Fatal("StampKey accepted a nil root")
	}
	if _, err := Stamp(make([]byte, 16), []StampPair{{SecretKey: "K", Value: "v"}}); err == nil {
		t.Fatal("Stamp accepted a short key")
	}
	if _, err := Stamp(nil, nil); err == nil {
		t.Fatal("Stamp accepted a nil key")
	}
}

func TestStampDeterministicAndShaped(t *testing.T) {
	key := mustStampKey(t, stampRoot, "inst-uid", "cr-uid", "app-secret")
	pairs := []StampPair{{SecretKey: "API_KEY", Value: "s3cr3t"}, {SecretKey: "DB_URL", Value: "postgres://x"}}

	got := mustStamp(t, key, pairs)
	if !strings.HasPrefix(got, "v1:") {
		t.Fatalf("stamp %q missing v1: prefix", got)
	}
	// v1: + 16 bytes hex = 3 + 32 = 35 chars.
	if len(got) != 35 {
		t.Fatalf("stamp %q len = %d, want 35 (v1: + 32 hex)", got, len(got))
	}
	if again := mustStamp(t, key, pairs); again != got {
		t.Fatalf("stamp not deterministic: %q != %q", got, again)
	}

	// Order of the input pairs must not matter — the canonical encoding sorts.
	reordered := []StampPair{{SecretKey: "DB_URL", Value: "postgres://x"}, {SecretKey: "API_KEY", Value: "s3cr3t"}}
	if shuffled := mustStamp(t, key, reordered); shuffled != got {
		t.Fatalf("stamp is order-dependent: %q != %q", shuffled, got)
	}
}

func TestStampMovesOnValueChange(t *testing.T) {
	key := mustStampKey(t, stampRoot, "inst-uid", "cr-uid", "app-secret")
	base := mustStamp(t, key, []StampPair{{SecretKey: "API_KEY", Value: "s3cr3t"}})
	changed := mustStamp(t, key, []StampPair{{SecretKey: "API_KEY", Value: "s3cr3u"}})
	if base == changed {
		t.Fatal("stamp did not move on a value change")
	}

	// A destination-key rename is a delivery change too.
	renamed := mustStamp(t, key, []StampPair{{SecretKey: "API_TOKEN", Value: "s3cr3t"}})
	if base == renamed {
		t.Fatal("stamp did not move on a secretKey rename")
	}

	// Adding a key moves it.
	added := mustStamp(t, key, []StampPair{{SecretKey: "API_KEY", Value: "s3cr3t"}, {SecretKey: "EXTRA", Value: "x"}})
	if base == added {
		t.Fatal("stamp did not move when a pair was added")
	}
}

// canonicalStamp must be injective across the pair boundary: ("AB","c") and
// ("A","Bc") — same concatenated bytes, different pairs — must not collide, the
// exact property the length prefix and count exist for.
func TestStampCanonicalInjective(t *testing.T) {
	key := mustStampKey(t, stampRoot, "inst", "cr", "sec")
	a := mustStamp(t, key, []StampPair{{SecretKey: "AB", Value: "c"}})
	b := mustStamp(t, key, []StampPair{{SecretKey: "A", Value: "Bc"}})
	if a == b {
		t.Fatal("canonical encoding collided across the field boundary")
	}
}

func TestStampPerTargetSeparation(t *testing.T) {
	pairs := []StampPair{{SecretKey: "API_KEY", Value: "same"}}

	// Same content, different target coordinates → different stamp. This is the
	// cross-scope equality oracle the per-target derivation kills.
	base := mustStamp(t, mustStampKey(t, stampRoot, "inst-A", "cr-1", "secret-x"), pairs)

	for _, tc := range []struct {
		name             string
		inst, cr, secret string
	}{
		{"different instance", "inst-B", "cr-1", "secret-x"},
		{"different cr", "inst-A", "cr-2", "secret-x"},
		{"different secret name", "inst-A", "cr-1", "secret-y"},
	} {
		other := mustStamp(t, mustStampKey(t, stampRoot, tc.inst, tc.cr, tc.secret), pairs)
		if other == base {
			t.Errorf("%s: identical content produced the same stamp across targets", tc.name)
		}
	}

	// A different root also separates (root compromise is the only oracle).
	otherRoot := make([]byte, KeySize)
	copy(otherRoot, stampRoot)
	otherRoot[0] ^= 0xff
	if mustStamp(t, mustStampKey(t, otherRoot, "inst-A", "cr-1", "secret-x"), pairs) == base {
		t.Error("different root produced the same stamp")
	}
}

func TestStampEmptyIsStable(t *testing.T) {
	// The scrub path (404) stamps over the empty pair set; it must be a stable,
	// well-formed value so opted-in workloads roll into the scrubbed state.
	key := mustStampKey(t, stampRoot, "inst", "cr", "sec")
	empty := mustStamp(t, key, nil)
	if !strings.HasPrefix(empty, "v1:") || len(empty) != 35 {
		t.Fatalf("empty-set stamp malformed: %q", empty)
	}
	if empty == mustStamp(t, key, []StampPair{{SecretKey: "K", Value: "v"}}) {
		t.Fatal("empty-set stamp collided with a non-empty delivery")
	}
}
