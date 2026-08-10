package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dunky13/hikyo/internal/config"
	"github.com/Dunky13/hikyo/internal/crypto"
)

func prodConfig(t *testing.T, extraEnv map[string]string) *config.Config {
	t.Helper()
	env := map[string]string{
		"HIKYO_DB": "sqlite:" + filepath.Join(t.TempDir(), "hikyo.db"),
	}
	for k, v := range extraEnv {
		env[k] = v
	}
	cfg, _, err := config.Load("server", []string{"--listen", "127.0.0.1:0"},
		func(k string) string { return env[k] }, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Acceptance (#43): a production server start with no root key refuses —
// hard failure, no override, and the server never generates one.
func TestProductionBootWithoutRootKeyRefuses(t *testing.T) {
	cfg := prodConfig(t, nil)
	srv, err := Boot(t.Context(), cfg, testLogger())
	if err == nil {
		srv.Close()
		t.Fatal("production boot without a root key must refuse")
	}
	if !errors.Is(err, crypto.ErrNoRootKey) {
		t.Fatalf("err = %v, want ErrNoRootKey", err)
	}
}

// Acceptance (#43): `hikyo migrate` never loads the keyring — it succeeds
// with no root key configured anywhere.
func TestMigrateNeedsNoRootKey(t *testing.T) {
	cfg := prodConfig(t, nil)
	if err := RunMigrate(t.Context(), cfg, testLogger()); err != nil {
		t.Fatalf("migrate must not need a root key: %v", err)
	}
}

func TestBootWithRootKeyFileAndWrongKeyRefused(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "root.key")
	key, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(crypto.EncodeRootKey(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"HIKYO_DB": "sqlite:" + filepath.Join(dir, "hikyo.db")}
	cfg, _, err := config.Load("server", []string{"--listen", "127.0.0.1:0", "--root-key-file", keyPath},
		func(k string) string { return env[k] }, nil)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := Boot(t.Context(), cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()

	// Same datastore, different root key: refusal 4, "does not match".
	other, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(crypto.EncodeRootKey(other)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err = Boot(t.Context(), cfg, testLogger())
	if err == nil {
		srv.Close()
		t.Fatal("boot with a mismatched root key must refuse")
	}
	if !errors.Is(err, crypto.ErrRootKeyMismatch) {
		t.Fatalf("err = %v, want ErrRootKeyMismatch", err)
	}
}

// --dev generates a persistent root key beside the dev database (recorded
// ADR deviation) and reuses it across restarts.
func TestDevBootGeneratesAndReusesRootKey(t *testing.T) {
	cfg := devConfig(t)
	keyPath := devRootKeyPath(cfg)

	srv, err := Boot(t.Context(), cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("dev root key not created: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("dev root key mode = %04o, want 0600", info.Mode().Perm())
	}
	first, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	srv, err = Boot(t.Context(), cfg, testLogger())
	if err != nil {
		t.Fatalf("dev reboot with existing key: %v", err)
	}
	srv.Close()
	second, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Error("dev root key regenerated on reboot — dev data would be bricked")
	}
	if !strings.HasSuffix(keyPath, "hikyo-dev.rootkey") {
		t.Errorf("unexpected dev key path %s", keyPath)
	}
}
