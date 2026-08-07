package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func testValueAAD() ValueAAD {
	return ValueAAD{
		OrgID: "org_1", ProjectID: "prj_1", EnvID: "env_1",
		KeyID: "key_1", RowID: "row_1", FieldTag: "value",
	}
}

func TestSealOpenRoundtrip(t *testing.T) {
	key := testKey(t)
	pt := []byte("hunter2")
	ct, err := seal(rand.Reader, key, []byte("dek_a"), 3, testValueAAD(), pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := open(key, []byte("dek_a"), 3, testValueAAD(), ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("roundtrip = %q, want %q", got, pt)
	}
}

// Invariant 11: N encryptions of identical plaintext under one key produce N
// distinct ciphertexts (nonce freshness).
func TestCiphertextUniqueness(t *testing.T) {
	key := testKey(t)
	seen := map[string]bool{}
	for range 32 {
		ct, err := seal(rand.Reader, key, []byte("dek_a"), 1, testValueAAD(), []byte("same"))
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(ct)] {
			t.Fatal("duplicate ciphertext")
		}
		seen[string(ct)] = true
	}
}

// Invariant 3: a ciphertext moved to another row, environment, key, project,
// organization, or envelope kind must fail to decrypt.
func TestTransplantFails(t *testing.T) {
	key := testKey(t)
	ct, err := seal(rand.Reader, key, []byte("dek_a"), 1, testValueAAD(), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]AAD{
		"org":     ValueAAD{OrgID: "org_2", ProjectID: "prj_1", EnvID: "env_1", KeyID: "key_1", RowID: "row_1", FieldTag: "value"},
		"project": ValueAAD{OrgID: "org_1", ProjectID: "prj_2", EnvID: "env_1", KeyID: "key_1", RowID: "row_1", FieldTag: "value"},
		"env":     ValueAAD{OrgID: "org_1", ProjectID: "prj_1", EnvID: "env_2", KeyID: "key_1", RowID: "row_1", FieldTag: "value"},
		"key":     ValueAAD{OrgID: "org_1", ProjectID: "prj_1", EnvID: "env_1", KeyID: "key_2", RowID: "row_1", FieldTag: "value"},
		"row":     ValueAAD{OrgID: "org_1", ProjectID: "prj_1", EnvID: "env_1", KeyID: "key_1", RowID: "row_2", FieldTag: "value"},
		"field":   ValueAAD{OrgID: "org_1", ProjectID: "prj_1", EnvID: "env_1", KeyID: "key_1", RowID: "row_1", FieldTag: "other"},
		"kind": ProjectFieldAAD{
			OrgID: "org_1", ProjectID: "prj_1", OwnerTable: "env_1", OwnerRowID: "key_1", FieldTag: "row_1",
		},
	}
	for name, aad := range mutations {
		if _, err := open(key, []byte("dek_a"), 1, aad, ct); err == nil {
			t.Errorf("transplant %s: decrypt succeeded", name)
		}
	}
}

// Invariant 4: a flipped format version, envelope kind, algorithm id or key
// version must fail to decrypt — every header byte is authenticated.
func TestHeaderTamperFails(t *testing.T) {
	key := testKey(t)
	ct, err := seal(rand.Reader, key, []byte("dek_a"), 1, testValueAAD(), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range ct {
		tampered := bytes.Clone(ct)
		tampered[i] ^= 0x01
		if _, err := open(key, []byte("dek_a"), 1, testValueAAD(), tampered); err == nil {
			t.Errorf("byte %d flipped: decrypt succeeded", i)
		}
	}
	// Truncations must fail too, including header-only prefixes.
	for _, n := range []int{0, 1, 5, len(ct) / 2, len(ct) - 1} {
		if _, err := open(key, []byte("dek_a"), 1, testValueAAD(), ct[:n]); err == nil {
			t.Errorf("truncated to %d: decrypt succeeded", n)
		}
	}
}

func TestOpenChecksKeyIdentity(t *testing.T) {
	key := testKey(t)
	ct, err := seal(rand.Reader, key, []byte("dek_a"), 1, testValueAAD(), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := open(key, []byte("dek_b"), 1, testValueAAD(), ct); err == nil {
		t.Error("wrong wrapping key id accepted")
	}
	if _, err := open(key, []byte("dek_a"), 2, testValueAAD(), ct); err == nil {
		t.Error("wrong wrapping key version accepted")
	}
}

func TestUnknownFormatVersionIsDistinct(t *testing.T) {
	key := testKey(t)
	ct, err := seal(rand.Reader, key, []byte("dek_a"), 1, testValueAAD(), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	ct[0] = 0x7F
	_, err = open(key, []byte("dek_a"), 1, testValueAAD(), ct)
	if !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("err = %v, want ErrUnknownFormat", err)
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("rng down") }

// Invariant 14: crypto/rand failure is fatal — a degraded or short read
// aborts the seal and never proceeds with weak randomness.
func TestRandFailureAborts(t *testing.T) {
	key := testKey(t)
	if _, err := seal(failReader{}, key, []byte("dek_a"), 1, testValueAAD(), []byte("x")); err == nil {
		t.Error("seal succeeded with failing RNG")
	}
	short := io.LimitReader(rand.Reader, 5)
	if _, err := seal(short, key, []byte("dek_a"), 1, testValueAAD(), []byte("x")); err == nil {
		t.Error("seal succeeded with short RNG read")
	}
}

// Error strings on the decrypt path must never echo key material or
// plaintext-adjacent content.
func TestErrorsCarryNoMaterial(t *testing.T) {
	key := testKey(t)
	ct, _ := seal(rand.Reader, key, []byte("dek_a"), 1, testValueAAD(), []byte("supersecret"))
	ct[len(ct)-1] ^= 1
	_, err := open(key, []byte("dek_a"), 1, testValueAAD(), ct)
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "supersecret") {
		t.Errorf("error leaks plaintext: %v", err)
	}
}
