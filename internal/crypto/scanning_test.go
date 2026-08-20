package crypto

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// fixedScanningKeyring returns a keyring whose scanning-fingerprint key is the
// pinned bytes 0x00..0x1f, so the fingerprint is a known-answer vector rather
// than a value that changes every run.
func fixedScanningKeyring() *Keyring {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	return &Keyring{scanning: keyHandle{version: 1, key: key}}
}

// Golden known-answer vector (SS4): pins the exact fingerprint bytes for a
// fixed key and scope, through the exported API. Sealed once and frozen — a
// changed label, scope-field order, or encoding would pass a round-trip test
// while silently re-fingerprinting every stored dismissal, and this catches it.
//
// Construction: key = 0x00..0x1f; scope org_1/prj_1/env_1/key_1; value
// "AKIAIOSFODNN7EXAMPLE".
const scanningFingerprintGoldenHex = "3656555fd14a34ddc7d16315aa375bf1b1d781326023681c9e6cdfe73c986eb7"

func TestScanningFingerprintKnownAnswer(t *testing.T) {
	k := fixedScanningKeyring()
	got := k.ScanningFingerprint("org_1", "prj_1", "env_1", "key_1", []byte("AKIAIOSFODNN7EXAMPLE"))

	want, err := hex.DecodeString(scanningFingerprintGoldenHex)
	if err == nil && !bytes.Equal(got, want) {
		t.Fatalf("scanning fingerprint = %s, want golden %s", hex.EncodeToString(got), scanningFingerprintGoldenHex)
	}
	if err != nil {
		t.Fatalf("golden vector unset; actual = %s", hex.EncodeToString(got))
	}

	// The construction the golden pins, recomputed independently: HMAC-SHA256
	// over the length-prefixed label ‖ scope ‖ value. This proves the golden is
	// that construction and not an arbitrary constant.
	msg := appendLP(nil, []byte(scanningFingerprintLabel))
	for _, f := range []string{"org_1", "prj_1", "env_1", "key_1"} {
		msg = appendLP(msg, []byte(f))
	}
	msg = appendLP(msg, []byte("AKIAIOSFODNN7EXAMPLE"))
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	if !bytes.Equal(got, mac.Sum(nil)) {
		t.Fatalf("fingerprint is not HMAC-SHA256(key, LP(label‖scope‖value))")
	}
}

// TestScanningFingerprintDeterministic: identical inputs re-fingerprint to the
// same bytes, which is what lets a sticky dismissal recognise a re-saved value.
func TestScanningFingerprintDeterministic(t *testing.T) {
	k := fixedScanningKeyring()
	a := k.ScanningFingerprint("o", "p", "e", "kid", []byte("secret-value"))
	b := k.ScanningFingerprint("o", "p", "e", "kid", []byte("secret-value"))
	if !bytes.Equal(a, b) {
		t.Fatal("fingerprint is not deterministic for identical inputs")
	}
	if len(a) != sha256.Size {
		t.Fatalf("fingerprint is %d bytes, want %d", len(a), sha256.Size)
	}
}

// TestScanningFingerprintScopeSeparation: the same value under a different key
// identity — or any other scope coordinate — fingerprints differently, so a
// dismissal accepted for one key never suppresses the warn on another.
func TestScanningFingerprintScopeSeparation(t *testing.T) {
	k := fixedScanningKeyring()
	const value = "AKIAIOSFODNN7EXAMPLE"
	base := k.ScanningFingerprint("o", "p", "e", "k1", []byte(value))
	for _, c := range []struct {
		name                     string
		org, proj, env, key, val string
	}{
		{"key identity", "o", "p", "e", "k2", value},
		{"org", "o2", "p", "e", "k1", value},
		{"project", "o", "p2", "e", "k1", value},
		{"environment", "o", "p", "e2", "k1", value},
		{"value", "o", "p", "e", "k1", value + "x"},
	} {
		other := k.ScanningFingerprint(c.org, c.proj, c.env, c.key, []byte(c.val))
		if bytes.Equal(base, other) {
			t.Errorf("%s change did not change the fingerprint", c.name)
		}
	}
}

// TestScanningKeyMintedOnUpgrade: a hierarchy minted before the scanning key
// existed (a pre-#74 datastore, or a restored pre-#74 backup) has no scanning
// row. LoadKeyring must mint one rather than refuse to boot, and the minted key
// must survive a reboot.
func TestScanningKeyMintedOnUpgrade(t *testing.T) {
	ctx := context.Background()
	ks := newMemStore()
	root := newRoot(t)
	rootCopy := bytes.Clone(root)
	if _, err := LoadKeyring(ctx, ks, root); err != nil {
		t.Fatal(err)
	}
	// Simulate the pre-#74 hierarchy: drop the scanning row the fresh boot minted.
	ks.mu.Lock()
	delete(ks.tier3, t3key(PurposeScanning, "", ""))
	ks.mu.Unlock()

	// Reboot under the same root: the master unwraps from the persisted
	// hierarchy, and the missing scanning key is minted rather than refused.
	kr, err := LoadKeyring(ctx, ks, bytes.Clone(rootCopy))
	if err != nil {
		t.Fatalf("upgrade load refused to boot: %v", err)
	}
	if _, ok := ks.tier3[t3key(PurposeScanning, "", "")]; !ok {
		t.Fatal("upgrade load did not mint the scanning key")
	}
	fp := kr.ScanningFingerprint("o", "p", "e", "k", []byte("v"))
	if len(fp) != sha256.Size {
		t.Fatalf("fingerprint after upgrade is %d bytes", len(fp))
	}
	// And it is stable across a subsequent reboot (persisted, not re-minted).
	kr2, err := LoadKeyring(ctx, ks, bytes.Clone(rootCopy))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fp, kr2.ScanningFingerprint("o", "p", "e", "k", []byte("v"))) {
		t.Fatal("minted scanning key was not persisted — fingerprint changed after reboot")
	}
}

// TestScanningKeyRotationAdopt: adopting a rotated key changes every subsequent
// fingerprint (old fingerprints die, the operation's whole purpose) and
// advances the version monotonically.
func TestScanningKeyRotationAdopt(t *testing.T) {
	ctx := context.Background()
	ks := newMemStore()
	root := make([]byte, KeySize)
	for i := range root {
		root[i] = 0x11
	}
	kr, err := LoadKeyring(ctx, ks, bytes.Clone(root))
	if err != nil {
		t.Fatal(err)
	}
	before := kr.ScanningFingerprint("o", "p", "e", "k", []byte("v"))
	v0 := kr.scanning.version

	row, adopt, err := kr.PrepareScanningKeyRotation()
	if err != nil {
		t.Fatal(err)
	}
	if row.Version != v0+1 {
		t.Fatalf("rotated row version = %d, want %d", row.Version, v0+1)
	}
	// Before adopt the live key is unchanged.
	if !bytes.Equal(before, kr.ScanningFingerprint("o", "p", "e", "k", []byte("v"))) {
		t.Fatal("fingerprint changed before adopt")
	}
	adopt()
	if kr.scanning.version != v0+1 {
		t.Fatalf("live version after adopt = %d, want %d", kr.scanning.version, v0+1)
	}
	if bytes.Equal(before, kr.ScanningFingerprint("o", "p", "e", "k", []byte("v"))) {
		t.Fatal("fingerprint unchanged after rotation adopt — old fingerprints must die")
	}
}

// TestScanningFingerprintKeySeparation: a different scanning key yields a
// different fingerprint for the same value and scope — the property a rotation
// relies on to invalidate every dismissal at once.
func TestScanningFingerprintKeySeparation(t *testing.T) {
	k1 := fixedScanningKeyring()
	k2 := &Keyring{scanning: keyHandle{version: 2, key: bytes.Repeat([]byte{0xA5}, KeySize)}}
	const value = "AKIAIOSFODNN7EXAMPLE"
	if bytes.Equal(
		k1.ScanningFingerprint("o", "p", "e", "k", []byte(value)),
		k2.ScanningFingerprint("o", "p", "e", "k", []byte(value)),
	) {
		t.Fatal("distinct keys produced the same fingerprint")
	}
}
