package conformance

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/keyring"
	"github.com/Dunky13/hikyo/internal/store/migrate"
)

// Keyring scenarios join the cross-engine corpus: the same lifecycle runs on
// sqlite and postgres.
func init() {
	corpus = append(corpus,
		scenario{"keyring_lifecycle", scenarioKeyringLifecycle},
		scenario{"keyring_one_active_key_per_scope", scenarioKeyringOneActive},
	)
}

func newRoot(t *testing.T) []byte {
	t.Helper()
	root := make([]byte, crypto.KeySize)
	if _, err := rand.Read(root); err != nil {
		t.Fatal(err)
	}
	return root
}

// First boot mints the hierarchy; a reboot with the same root unwraps it and
// opens ciphertext sealed before the reboot; the wrong root is refused with
// the ADR's distinct error.
func scenarioKeyringLifecycle(t *testing.T, db *store.DB) {
	ks := &keyring.Store{DB: db}
	root := newRoot(t)
	rootCopy := bytes.Clone(root)

	kr, err := crypto.LoadKeyring(t.Context(), ks, root)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := kr.ForProject(t.Context(), "org_c1", "prj_c1")
	if err != nil {
		t.Fatal(err)
	}
	aad := crypto.ValueAAD{
		OrgID: "org_c1", ProjectID: "prj_c1", EnvID: "env_1",
		KeyID: "key_1", RowID: "row_1", FieldTag: "value",
	}
	ct, err := sealer.SealValue(aad, []byte("cross-engine secret"))
	if err != nil {
		t.Fatal(err)
	}

	kr2, err := crypto.LoadKeyring(t.Context(), ks, bytes.Clone(rootCopy))
	if err != nil {
		t.Fatalf("reboot with same root: %v", err)
	}
	sealer2, err := kr2.ForProject(t.Context(), "org_c1", "prj_c1")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := sealer2.OpenValue(aad, ct)
	if err != nil || string(pt) != "cross-engine secret" {
		t.Fatalf("open after reboot: %q, %v", pt, err)
	}

	if _, err := crypto.LoadKeyring(t.Context(), ks, newRoot(t)); !errors.Is(err, crypto.ErrRootKeyMismatch) {
		t.Errorf("wrong root: err = %v, want ErrRootKeyMismatch", err)
	}
}

// The partial unique index allows exactly one active key per scope on both
// engines, and the conflict surfaces as crypto.ErrKeyExists.
func scenarioKeyringOneActive(t *testing.T, db *store.DB) {
	ks := &keyring.Store{DB: db}
	dup := crypto.WrappedKey{
		ID: "dek_conformance_dup", Purpose: crypto.PurposeProject,
		OrgID: "org_dup", ProjectID: "prj_dup",
		Version: 1, MasterKeyVersion: 1, Blob: []byte{0x01},
	}
	if err := ks.CreateTier3(t.Context(), dup); err != nil {
		t.Fatal(err)
	}
	dup.ID = "dek_conformance_dup2"
	if err := ks.CreateTier3(t.Context(), dup); !errors.Is(err, crypto.ErrKeyExists) {
		t.Errorf("second active key for one scope: err = %v, want ErrKeyExists", err)
	}
}

// Invariant 1 (threat-model mandate): a datastore dump containing a known
// secret value must not contain that plaintext — and must not contain the
// root key, which is never stored. sqlite is the engine whose dump is a
// plain file, so it carries this test.
func TestKnownPlaintextAbsentFromDump(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.db")
	cfg := store.Config{Engine: store.EngineSQLite, Path: path}
	if err := migrate.Run(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}

	root := newRoot(t)
	rootHex := crypto.EncodeRootKey(root)
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, bytes.Clone(root))
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := kr.ForProject(t.Context(), "org_dump", "prj_dump")
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("hunter2-known-plaintext-invariant-1")
	ct, err := sealer.SealValue(crypto.ValueAAD{
		OrgID: "org_dump", ProjectID: "prj_dump", EnvID: "env_1",
		KeyID: "key_db_password", RowID: "row_1", FieldTag: "value",
	}, secret)
	if err != nil {
		t.Fatal(err)
	}

	// Scratch table standing in for the value rows of the flat-model ticket;
	// the repository/crypto path under test is the real one.
	if _, err := db.SQLiteWrite().ExecContext(t.Context(),
		`CREATE TABLE dump_scratch (id TEXT PRIMARY KEY, ciphertext BLOB NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(),
		`INSERT INTO dump_scratch (id, ciphertext) VALUES ('row_1', ?)`, ct); err != nil {
		t.Fatal(err)
	}
	// Merge the WAL into the main file so the dump is complete, then close.
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	dump, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(dump, secret) {
		t.Error("known plaintext present in datastore dump")
	}
	if bytes.Contains(dump, root) || bytes.Contains(dump, []byte(rootHex)) {
		t.Error("root key material present in datastore dump")
	}
	if !bytes.Contains(dump, ct[len(ct)-16:]) {
		t.Error("ciphertext not found in dump — the scenario is not testing what it claims")
	}
}
