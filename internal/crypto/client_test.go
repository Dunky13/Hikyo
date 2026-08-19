package crypto

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func loadKeys(t *testing.T) *LocalKeys {
	t.Helper()
	// A fresh non-existent subdir so LoadOrCreateLocalKey creates it 0700;
	// t.TempDir() itself is 0755 on some platforms (macOS), which the
	// protection-model check correctly refuses.
	k, err := LoadOrCreateLocalKey(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("LoadOrCreateLocalKey: %v", err)
	}
	return k
}

func TestLoadOrCreateLocalKeyModesAndReuse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	k1, err := LoadOrCreateLocalKey(dir)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if runtime.GOOS != "windows" {
		di, _ := os.Stat(dir)
		if di.Mode().Perm() != 0o700 {
			t.Errorf("state dir mode = %04o, want 0700", di.Mode().Perm())
		}
		fi, _ := os.Stat(filepath.Join(dir, "local.key"))
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("key file mode = %04o, want 0600", fi.Mode().Perm())
		}
	}
	// Reload derives identical keys (same stamp over same content).
	k2, err := LoadOrCreateLocalKey(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if k1.Stamp([]byte("x")) != k2.Stamp([]byte("x")) {
		t.Error("reload produced a different stamp key")
	}
}

func TestLoadOrCreateLocalKeyRefusesLooseDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode enforcement is the unix leg")
	}
	dir := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateLocalKey(dir); err == nil {
		t.Fatal("expected refusal for a group/other-accessible state dir")
	}
}

func TestLoadOrCreateLocalKeyRefusesLooseFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode enforcement is the unix leg")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "local.key"), make([]byte, KeySize), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateLocalKey(dir); err == nil {
		t.Fatal("expected refusal for a group/other-readable key file")
	}
}

func TestLoadOrCreateLocalKeyRejectsShortKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "local.key"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateLocalKey(dir); err == nil {
		t.Fatal("expected corruption error for a short key file")
	}
}

func TestStampShapeAndGrammar(t *testing.T) {
	k := loadKeys(t)
	s := k.Stamp([]byte("hello"))
	if err := ParseStamp(s); err != nil {
		t.Fatalf("own stamp %q rejected: %v", s, err)
	}
	if got := k.Stamp([]byte("hello")); got != s {
		t.Error("Stamp is not deterministic for equal content")
	}
	if k.Stamp([]byte("hell0")) == s {
		t.Error("distinct content produced the same stamp")
	}
	for _, bad := range []string{
		"", "v1-", "v2-" + s[3:], "v1-" + "Z0000000000000000000000000000000"[:32],
		"v1-abc", s + "0", "v1-" + "0123456789abcdef0123456789ABCDEF", // uppercase hex
		"v1-0123456789abcdef0123456789abcde/", // path separator
	} {
		if err := ParseStamp(bad); err == nil {
			t.Errorf("ParseStamp(%q) accepted a malformed stamp", bad)
		}
	}
}

func baseSnapshotAAD() SnapshotAAD {
	return SnapshotAAD{
		InstanceOrigin: "https://hikyo.example.internal",
		OrgID:          "org_1",
		ProjectID:      "prj_1",
		EnvironmentID:  "env_1",
		CredentialID:   "cred_1",
		Revision:       7,
		Pinned:         false,
		Projection:     []string{"read", "reveal"},
		ConfigOnly:     false,
		TargetNames:    []string{"api", "worker"},
		IssuedAt:       "2026-08-19T10:00:00Z",
		ExpiresAt:      "2026-08-26T10:00:00Z",
	}
}

func TestSnapshotSealOpenRoundTrip(t *testing.T) {
	k := loadKeys(t)
	aad := baseSnapshotAAD()
	pt := []byte(`{"rows":[]}`)
	rec, err := k.SealSnapshot(aad, pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := k.OpenSnapshot(aad, rec)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(got) != string(pt) {
		t.Errorf("round-trip mismatch: %q", got)
	}
}

func TestSnapshotAADTamperTable(t *testing.T) {
	k := loadKeys(t)
	base := baseSnapshotAAD()
	rec, err := k.SealSnapshot(base, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*SnapshotAAD){
		"instance":    func(a *SnapshotAAD) { a.InstanceOrigin = "https://evil.example" },
		"org":         func(a *SnapshotAAD) { a.OrgID = "org_2" },
		"project":     func(a *SnapshotAAD) { a.ProjectID = "prj_2" },
		"environment": func(a *SnapshotAAD) { a.EnvironmentID = "env_2" },
		"credential":  func(a *SnapshotAAD) { a.CredentialID = "cred_2" },
		"revision":    func(a *SnapshotAAD) { a.Revision = 8 },
		"pinned":      func(a *SnapshotAAD) { a.Pinned = true },
		"projection":  func(a *SnapshotAAD) { a.Projection = []string{"read"} },
		"config_only": func(a *SnapshotAAD) { a.ConfigOnly = true },
		"targets":     func(a *SnapshotAAD) { a.TargetNames = []string{"api"} },
		"issued_at":   func(a *SnapshotAAD) { a.IssuedAt = "2026-08-19T10:00:01Z" },
		"expires_at":  func(a *SnapshotAAD) { a.ExpiresAt = "2026-08-27T10:00:00Z" },
		// Injectivity across the list boundary: moving an element between the
		// two adjacent list fields must NOT decrypt.
		"list-shift": func(a *SnapshotAAD) {
			a.Projection = []string{"read", "reveal", "api"}
			a.TargetNames = []string{"worker"}
		},
	}
	for name, mut := range mutations {
		tampered := base
		// copy slices so mutation does not alias base
		tampered.Projection = append([]string(nil), base.Projection...)
		tampered.TargetNames = append([]string(nil), base.TargetNames...)
		mut(&tampered)
		if _, err := k.OpenSnapshot(tampered, rec); !errors.Is(err, ErrDecrypt) {
			t.Errorf("mutation %q: OpenSnapshot err = %v, want ErrDecrypt", name, err)
		}
	}
}

func TestSnapshotWrongKeyFails(t *testing.T) {
	k1 := loadKeys(t)
	k2 := loadKeys(t)
	rec, err := k1.SealSnapshot(baseSnapshotAAD(), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k2.OpenSnapshot(baseSnapshotAAD(), rec); !errors.Is(err, ErrDecrypt) {
		t.Errorf("cross-key open err = %v, want ErrDecrypt", err)
	}
}
