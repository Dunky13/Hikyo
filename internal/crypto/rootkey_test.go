package crypto

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Invariant 6: missing root key, non-256-bit key, and a group/world-readable
// key file each abort with their own distinct error.
func TestRootKeyRefusalsAreDistinct(t *testing.T) {
	dir := t.TempDir()
	goodHex := EncodeRootKey(make([]byte, KeySize))

	write := func(name, content string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cases := []struct {
		name      string
		file, env string
		want      error
	}{
		{"no source at all", "", "", ErrNoRootKey},
		{"file missing", filepath.Join(dir, "absent"), "", ErrNoRootKey},
		{"file group readable", write("group", goodHex, 0o640), "", ErrRootKeyPerms},
		{"file world readable", write("world", goodHex, 0o604), "", ErrRootKeyPerms},
		{"file too short", write("short", "abcd", 0o600), "", ErrRootKeyFormat},
		{"file not hex", write("nothex", strings.Repeat("zz", 32), 0o600), "", ErrRootKeyFormat},
		{"env too long", "", goodHex + "00", ErrRootKeyFormat},
		{"env empty-ish", "", "  ", ErrRootKeyFormat},
	}
	for _, c := range cases {
		_, err := ReadRootKey(c.file, c.env)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestRootKeyRoundtrip(t *testing.T) {
	dir := t.TempDir()
	raw := make([]byte, KeySize)
	for i := range raw {
		raw[i] = byte(i)
	}
	p := filepath.Join(dir, "key")
	// Trailing newline is the normal shape of a written key file.
	if err := os.WriteFile(p, []byte(EncodeRootKey(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := ReadRootKey(p, "")
	if err != nil {
		t.Fatal(err)
	}
	fromEnv, err := ReadRootKey("", EncodeRootKey(raw))
	if err != nil {
		t.Fatal(err)
	}
	if string(fromFile) != string(raw) || string(fromEnv) != string(raw) {
		t.Error("decoded key differs from source")
	}
}

// Error text must never include the key value.
func TestRootKeyErrorsCarryNoMaterial(t *testing.T) {
	secret := strings.Repeat("aa", 31) // wrong length, valid hex
	_, err := ReadRootKey("", secret)
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error echoes key material: %v", err)
	}
}
