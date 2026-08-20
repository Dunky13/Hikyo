package migrate

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/store"
)

// The upgrade path old→new as one cross-engine E2E (mvp-boundary O1): a database
// one migration behind fails the schema check (a server would refuse to serve,
// fail-closed), data seeded on the old schema survives the upgrade, and the
// check passes afterwards (the server would serve). The fail-closed boot
// sequence itself is proven in internal/app; this pins the migrate-level
// mechanics on both engines, where app's sqlite-only boot tests are blind.

func TestUpgradeOldToNewSQLite(t *testing.T) {
	runUpgradeOldToNew(t, store.Config{Engine: store.EngineSQLite, Path: filepath.Join(t.TempDir(), "upgrade.db")})
}

func TestUpgradeOldToNewPostgres(t *testing.T) {
	dsn := os.Getenv("HIKYO_TEST_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI run without HIKYO_TEST_POSTGRES_DSN: the postgres upgrade leg must not silently skip in CI")
		}
		t.Skip("HIKYO_TEST_POSTGRES_DSN not set")
	}
	// A dedicated scratch database so the partial-schema (N-1) state never
	// collides with other postgres legs sharing the server.
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	base := strings.TrimPrefix(parsed.Path, "/")
	database := fmt.Sprintf("%s_upgrade_%d", base, time.Now().UnixNano())
	admin, err := store.Open(t.Context(), store.Config{Engine: store.EnginePostgres, DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.PG().Exec(context.Background(), `DROP DATABASE IF EXISTS "`+strings.ReplaceAll(database, `"`, ``)+`" WITH (FORCE)`)
		admin.Close()
	})
	if _, err := admin.PG().Exec(t.Context(), `CREATE DATABASE "`+strings.ReplaceAll(database, `"`, ``)+`"`); err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + database
	runUpgradeOldToNew(t, store.Config{Engine: store.EnginePostgres, DSN: parsed.String()})
}

func runUpgradeOldToNew(t *testing.T, cfg store.Config) {
	t.Helper()
	ctx := t.Context()

	max, err := MaxVersion(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := RunUpTo(ctx, cfg, max-1); err != nil {
		t.Fatalf("migrate to the old (N-1) schema: %v", err)
	}

	// Fail-closed: one migration behind, the schema check refuses. This is the
	// state a server boots into with auto-migrate off, and it must not serve.
	if pending, err := HasPending(ctx, cfg); err != nil || !pending {
		t.Fatalf("N-1 schema should report a pending migration: pending=%v err=%v", pending, err)
	}
	if err := Check(ctx, cfg); err == nil {
		t.Fatal("a database one migration behind must fail the schema check (fail-closed serving)")
	}

	// Seed a row on the OLD schema. orgs exists from the earliest migrations, so
	// it is present at N-1 and must survive the upgrade untouched.
	seed := "org_upgrade_survivor"
	execUpgrade(t, cfg, "INSERT INTO orgs (id, name, active, metadata, created_at) "+
		"VALUES ('"+seed+"', 'survivor', TRUE, '{}', '2026-01-01T00:00:00Z')")

	// Upgrade to the new schema.
	if err := Run(ctx, cfg); err != nil {
		t.Fatalf("upgrade old→new: %v", err)
	}
	// Serves: exact schema match now.
	if err := Check(ctx, cfg); err != nil {
		t.Fatalf("after the upgrade the schema check must pass: %v", err)
	}
	// Data survived old→new.
	if n := countUpgrade(t, cfg, "SELECT COUNT(*) FROM orgs WHERE id = '"+seed+"'"); n != 1 {
		t.Fatalf("the org seeded on the old schema did not survive the upgrade: count=%d", n)
	}
}

func execUpgrade(t *testing.T, cfg store.Config, stmt string) {
	t.Helper()
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if db.Engine() == store.EnginePostgres {
		if _, err := db.PG().Exec(t.Context(), stmt); err != nil {
			t.Fatalf("seed exec: %v", err)
		}
		return
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), stmt); err != nil {
		t.Fatalf("seed exec: %v", err)
	}
}

func countUpgrade(t *testing.T, cfg store.Config, query string) int {
	t.Helper()
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if db.Engine() == store.EnginePostgres {
		if err := db.PG().QueryRow(t.Context(), query).Scan(&n); err != nil {
			t.Fatalf("count query: %v", err)
		}
		return n
	}
	if err := db.SQLiteWrite().QueryRowContext(t.Context(), query).Scan(&n); err != nil {
		t.Fatalf("count query: %v", err)
	}
	return n
}
