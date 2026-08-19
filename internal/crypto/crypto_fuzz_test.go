package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// FuzzParseHeader checks the encryption-model envelope header round-trip and bounds.
func FuzzParseHeader(f *testing.F) {
	valid := appendHeader(nil, header{
		format: formatV1, kind: KindValue, alg: algXChaCha20Poly1305,
		keyID: []byte("dek_1"), keyVersion: 7, nonce: make([]byte, 24),
	})
	f.Add(valid)
	f.Add(valid[:len(valid)-1])
	f.Add([]byte{0xff, 0, 1, 2, 3})

	f.Fuzz(func(t *testing.T, record []byte) {
		h, n, err := parseHeader(record)
		if err != nil {
			return
		}
		if n < 0 || n > len(record) {
			t.Fatalf("parseHeader consumed %d bytes from a %d-byte record", n, len(record))
		}
		if got := appendHeader(nil, h); !bytes.Equal(got, record[:n]) {
			t.Fatalf("header round-trip = %x, want %x", got, record[:n])
		}
	})
}

// FuzzReadLP checks the encryption-model length-prefix slice and position bounds.
func FuzzReadLP(f *testing.F) {
	valid := appendLP(nil, []byte("value"))
	f.Add(valid, uint64(0))
	f.Add(valid[:3], uint64(0))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}, uint64(2))

	f.Fuzz(func(t *testing.T, buf []byte, rawPos uint64) {
		pos := int(rawPos % uint64(len(buf)+1))
		value, next, err := readLP(buf, pos)
		if err != nil {
			return
		}
		start := next - len(value)
		if next > len(buf) || start < pos+4 || start < 0 || !bytes.Equal(value, buf[start:next]) {
			t.Fatalf("readLP returned slice [%d:%d] outside a %d-byte buffer from position %d", start, next, len(buf), pos)
		}
	})
}

// FuzzOpen checks the encryption-model round-trip and authenticated-tamper contract.
func FuzzOpen(f *testing.F) {
	f.Add([]byte("plaintext"), []byte("dek_1"), uint32(1), uint64(0), byte(1), []byte("raw"))
	f.Add([]byte{}, []byte{}, uint32(0), uint64(1), byte(0), []byte{})
	f.Add([]byte{0, 1, 2}, []byte{0xff}, ^uint32(0), ^uint64(0), byte(0xff), []byte{1, 2})

	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	aad := ValueAAD{OrgID: "org_1", ProjectID: "prj_1", EnvID: "env_1", KeyID: "key_1", RowID: "row_1", FieldTag: "value"}
	f.Fuzz(func(t *testing.T, plaintext, keyID []byte, version uint32, rawIndex uint64, mask byte, raw []byte) {
		record, err := seal(rand.Reader, key, keyID, version, aad, plaintext)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		got, err := open(key, keyID, version, aad, record)
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("open round-trip = (%x, %v), want (%x, nil)", got, err, plaintext)
		}

		tampered := bytes.Clone(record)
		if mask == 0 {
			mask = 1
		}
		tampered[rawIndex%uint64(len(tampered))] ^= mask
		got, err = open(key, keyID, version, aad, tampered)
		if err == nil || (!errors.Is(err, ErrDecrypt) && !errors.Is(err, ErrUnknownFormat)) {
			t.Fatalf("tampered open = (%x, %v), want ErrDecrypt or ErrUnknownFormat", got, err)
		}
		if bytes.Equal(got, plaintext) && got != nil {
			t.Fatal("tampered record returned the plaintext")
		}

		_, _ = open(key, keyID, version, aad, raw)
	})
}

// FuzzReadRootKey checks the encryption-model requirement that accepted root keys are exactly 256 bits.
func FuzzReadRootKey(f *testing.F) {
	f.Add(EncodeRootKey(make([]byte, KeySize)))
	f.Add(EncodeRootKey(make([]byte, KeySize))[:63])
	f.Add("not hex")

	f.Fuzz(func(t *testing.T, envValue string) {
		key, err := ReadRootKey("", envValue)
		if err == nil && len(key) != KeySize {
			t.Fatalf("ReadRootKey returned %d bytes, want %d", len(key), KeySize)
		}
	})
}

// FuzzParseArtifact checks the machine-identities bearer grammar returns normally for every artifact type.
func FuzzParseArtifact(f *testing.F) {
	validCLI, _, err := NewArtifact(ArtifactCLISession)
	if err != nil {
		f.Fatal(err)
	}
	validSCIM, _, err := NewArtifact(ArtifactSCIM)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validCLI)
	f.Add(validSCIM[:len(validSCIM)-1])
	f.Add("arbitrary")

	types := []ArtifactType{
		ArtifactCLISession, ArtifactBootstrap, ArtifactBrowserSession, ArtifactRecoveryCode,
		ArtifactOIDCState, ArtifactOIDCBinding, ArtifactCSRF, ArtifactWorkload,
		ArtifactAutomation, ArtifactSCIM, ArtifactInstanceConn, ArtifactWorkspaceSession,
		ArtifactHandoffState, ArtifactHandoffCode,
	}
	f.Fuzz(func(t *testing.T, value string) {
		for _, want := range types {
			_ = ParseArtifact(value, want)
		}
	})
}
