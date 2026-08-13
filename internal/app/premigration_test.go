package app

// The automatic pre-migration export, both ways (#76, mvp-boundary O1's
// export portion; ops spec § 11).
//
// The two behaviours the row names are "with recipients configured" and
// "LOUD SKIP without", and they are tested as what an operator can actually
// see afterwards: an artifact on disk plus a durable record in the instance
// trail, or no artifact and a durable record saying so. A warning log alone
// would satisfy neither.

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dunky13/hikyo/internal/config"
	"github.com/Dunky13/hikyo/internal/crypto/backup"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/migrate"
)

// pendingMigration builds a datastore one migration BEHIND this binary, so the
// next migrate run has genuine work to do. That is what makes the
// pre-migration hook fire: an export before every idle restart would be a
// backup policy nobody asked for.
func pendingMigration(t *testing.T, f *storeFixture) {
	t.Helper()
	max, err := migrate.MaxVersion(t.Context(), f.sc)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.RunUpTo(t.Context(), f.sc, max-1); err != nil {
		t.Fatal(err)
	}
}

type storeFixture struct {
	sc  store.Config
	dir string
}

func newStoreFixture(t *testing.T) *storeFixture {
	t.Helper()
	dir := t.TempDir()
	return &storeFixture{
		sc:  store.Config{Engine: store.EngineSQLite, Path: filepath.Join(dir, "hikyo.db")},
		dir: dir,
	}
}

func countInstanceEvents(t *testing.T, sc store.Config, typ string) int64 {
	t.Helper()
	db, err := store.Open(t.Context(), sc)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int64
	if err := db.SQLiteRead().QueryRowContext(t.Context(),
		"SELECT COUNT(*) FROM audit_instance_events WHERE type = ?", typ).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func archiveCount(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".age") {
			n++
		}
	}
	return n
}

func TestPreMigrationExportWithRecipients(t *testing.T) {
	fixture := newStoreFixture(t)
	pendingMigration(t, fixture)
	_, recipient, err := backup.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(fixture.dir, "backups")
	cfg := preMigrationConfig(fixture, backupDir, []string{recipient})

	if err := RunMigrate(t.Context(), cfg, quietLogger()); err != nil {
		t.Fatal(err)
	}
	if n := archiveCount(t, backupDir); n != 1 {
		t.Fatalf("pre-migration export published %d archives, want 1", n)
	}
	if n := countInstanceEvents(t, fixture.sc, "backup.exported"); n != 1 {
		t.Fatalf("backup.exported events = %d, want 1", n)
	}
	if n := countInstanceEvents(t, fixture.sc, "backup.export_skipped"); n != 0 {
		t.Fatalf("a configured export also recorded %d skips", n)
	}
}

func TestPreMigrationExportLoudlySkipsWithoutRecipients(t *testing.T) {
	fixture := newStoreFixture(t)
	pendingMigration(t, fixture)
	cfg := preMigrationConfig(fixture, "", nil)

	var logged strings.Builder
	log := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// The skip is NON-FATAL by the ops spec's own wording: an unconfigured
	// backup must not block a migration.
	if err := RunMigrate(t.Context(), cfg, log); err != nil {
		t.Fatalf("the skip blocked the migration: %v", err)
	}
	// Loud in the log...
	if !strings.Contains(logged.String(), "PRE-MIGRATION EXPORT SKIPPED") {
		t.Fatalf("the skip was not loud in the log; got %q", logged.String())
	}
	// ...and, more importantly, loud the morning after.
	if n := countInstanceEvents(t, fixture.sc, "backup.export_skipped"); n != 1 {
		t.Fatalf("backup.export_skipped events = %d, want 1: a warning nobody scrolls back to is not loud", n)
	}
	if n := countInstanceEvents(t, fixture.sc, "backup.exported"); n != 0 {
		t.Fatalf("an unconfigured export recorded %d exports", n)
	}
}

// TestPreMigrationExportSkipsAnIdleRestart pins the other half of the
// behaviour: no pending migration means no export at all, so an instance that
// restarts hourly does not accumulate hourly backups.
func TestPreMigrationExportSkipsAnIdleRestart(t *testing.T) {
	fixture := newStoreFixture(t)
	if err := migrate.Run(t.Context(), fixture.sc); err != nil {
		t.Fatal(err)
	}
	_, recipient, err := backup.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(fixture.dir, "backups")
	cfg := preMigrationConfig(fixture, backupDir, []string{recipient})

	if err := RunMigrate(t.Context(), cfg, quietLogger()); err != nil {
		t.Fatal(err)
	}
	if n := archiveCount(t, backupDir); n != 0 {
		t.Fatalf("an idle restart published %d archives", n)
	}
	if n := countInstanceEvents(t, fixture.sc, "backup.exported"); n != 0 {
		t.Fatalf("an idle restart recorded %d exports", n)
	}
}

func quietLogger() *slog.Logger { return testLogger() }

// preMigrationConfig is the operator configuration the hook reads: a datastore,
// a destination, and a recipient set that may deliberately be empty.
func preMigrationConfig(f *storeFixture, backupDir string, recipients []string) *config.Config {
	return &config.Config{
		Store:            config.Datastore{Engine: config.EngineSQLite, Path: f.sc.Path},
		AutoMigrate:      true,
		BackupDir:        backupDir,
		BackupRecipients: recipients,
	}
}

// MinRestoreSchemaVersion is a hand-written pin on a migration number, and
// this repo renumbers migrations when parallel tickets land. A desync fails
// in the WRONG direction — a too-low pin admits archives missing the restore
// state — so the pin is asserted against the migration files themselves.
func TestMinRestoreSchemaVersionMatchesTheMigration(t *testing.T) {
	for _, engine := range []string{"sqlite", "postgres"} {
		entries, err := store.MigrationsFS.ReadDir("migrations/" + engine)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), "_restore_reconciliation.sql") {
				continue
			}
			found = true
			var version int64
			if _, err := fmt.Sscanf(e.Name(), "%d_", &version); err != nil {
				t.Fatalf("%s/%s: unparseable migration number: %v", engine, e.Name(), err)
			}
			if version != MinRestoreSchemaVersion {
				t.Errorf("%s restore_reconciliation migration is %05d but MinRestoreSchemaVersion = %d — renumbered without re-pinning",
					engine, version, MinRestoreSchemaVersion)
			}
		}
		if !found {
			t.Errorf("%s has no restore_reconciliation migration to pin against", engine)
		}
	}
}
