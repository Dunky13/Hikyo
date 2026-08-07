// Package conformance runs one scenario corpus against both engines
// (system-architecture ADR § Data layer): canonical cross-engine semantics
// are asserted on sqlite and postgres, not just unit-tested per dialect.
//
// The sqlite leg always runs. The postgres leg needs WENV_TEST_POSTGRES_DSN;
// locally it skips without one, but in CI (CI=true) an unset DSN FAILS —
// "harness green on postgres" must never be vacuously true.
package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Dunky13/wenv/internal/service"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/migrate"
	"github.com/Dunky13/wenv/internal/store/tx"
)

type scenario struct {
	name string
	fn   func(t *testing.T, db *store.DB)
}

// corpus is the shared scenario list. Every scenario gets a freshly migrated
// database per engine run; scenarios run in order on one database.
var corpus = []scenario{
	{"create_get_roundtrip", scenarioRoundtrip},
	{"list_ordered_by_name", scenarioListOrder},
	{"rollback_leaves_no_row", scenarioRollback},
	{"duplicate_name_refused", scenarioDuplicate},
	{"invalid_metadata_refused", scenarioInvalidMetadata},
	{"missing_org_not_found", scenarioNotFound},
	{"concurrent_writes_all_succeed", scenarioConcurrent},
}

func runCorpus(t *testing.T, db *store.DB) {
	for _, s := range corpus {
		t.Run(s.name, func(t *testing.T) { s.fn(t, db) })
	}
}

func TestConformanceSQLite(t *testing.T) {
	cfg := store.Config{Engine: store.EngineSQLite, Path: filepath.Join(t.TempDir(), "conformance.db")}
	if err := migrate.Run(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	runCorpus(t, db)
}

// TestSQLiteActiveDomainEnforced proves the CHECK constraint refuses
// non-boolean integers at the engine, sqlite lacking a boolean type. (The
// read-side validation in store is defense-in-depth for databases that
// predate the constraint and cannot be reached through it.)
func TestSQLiteActiveDomainEnforced(t *testing.T) {
	cfg := store.Config{Engine: store.EngineSQLite, Path: filepath.Join(t.TempDir(), "check.db")}
	if err := migrate.Run(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	_, err = db.SQLiteWrite().ExecContext(t.Context(),
		`INSERT INTO orgs (id, name, active, metadata, created_at) VALUES ('org_bad', 'bad', 2, '{}', '2026-01-01T00:00:00Z')`)
	if err == nil {
		t.Fatal("active=2 must be refused by the CHECK constraint")
	}
}

func TestConformancePostgres(t *testing.T) {
	dsn := os.Getenv("WENV_TEST_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI run without WENV_TEST_POSTGRES_DSN: the postgres conformance leg must not silently skip in CI")
		}
		t.Skip("WENV_TEST_POSTGRES_DSN not set")
	}
	cfg := store.Config{Engine: store.EnginePostgres, DSN: dsn}
	resetPostgres(t, cfg)
	if err := migrate.Run(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	runCorpus(t, db)
}

// resetPostgres drops only the tables this harness owns, so a dedicated test
// database is reusable across runs.
func resetPostgres(t *testing.T, cfg store.Config) {
	t.Helper()
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// tier3_keys references master_keys: drop order matters.
	for _, table := range []string{"orgs", "tier3_keys", "master_keys", "key_generations", "goose_db_version"} {
		if _, err := db.PG().Exec(t.Context(), "DROP TABLE IF EXISTS "+table); err != nil {
			t.Fatal(err)
		}
	}
}

// --- scenarios (driven through the service layer, so tx and store are both
// under test) ---

func scenarioRoundtrip(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	meta := json.RawMessage(`{"tier":"gold","limits":{"projects":3}}`)
	created, err := orgs.Create(t.Context(), "roundtrip", true, meta)
	if err != nil {
		t.Fatal(err)
	}
	got, err := orgs.Get(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("created_at did not round-trip: stored %v, got %v", created.CreatedAt, got.CreatedAt)
	}
	if got.CreatedAt.Location() != time.UTC {
		t.Errorf("created_at not UTC: %v", got.CreatedAt.Location())
	}
	if !got.Active {
		t.Error("active=true did not round-trip")
	}
	inactive, err := orgs.Create(t.Context(), "roundtrip-inactive", false, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	gotInactive, err := orgs.Get(t.Context(), inactive.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotInactive.Active {
		t.Error("active=false did not round-trip")
	}
	var m1, m2 any
	if err := json.Unmarshal(created.Metadata, &m1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got.Metadata, &m2); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(m1) != fmt.Sprint(m2) {
		t.Errorf("metadata did not round-trip: %s vs %s", created.Metadata, got.Metadata)
	}
}

func scenarioListOrder(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	for _, name := range []string{"zebra", "alpha", "mango"} {
		if _, err := orgs.Create(t.Context(), name, false, json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	list, err := orgs.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var prev string
	for _, o := range list {
		if prev > o.Name {
			t.Fatalf("list not ordered by name: %q before %q", prev, o.Name)
		}
		prev = o.Name
	}
}

func scenarioRollback(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	before, err := orgs.Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	sentinel := fmt.Errorf("sentinel")
	err = tx.Write(t.Context(), db, func(ctx context.Context, r store.Repos) error {
		if err := r.Orgs().Create(ctx, store.Org{
			ID: "org_rollback", Name: "rollback-victim",
			Metadata: json.RawMessage(`{}`), CreatedAt: time.Now(),
		}); err != nil {
			return err
		}
		return sentinel
	})
	if err == nil {
		t.Fatal("closure error must surface")
	}
	after, err := orgs.Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("rollback leaked a row: count %d -> %d", before, after)
	}
}

func scenarioDuplicate(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	if _, err := orgs.Create(t.Context(), "dupe", false, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := orgs.Create(t.Context(), "dupe", false, json.RawMessage(`{}`)); err == nil {
		t.Fatal("duplicate org name must be refused by the unique constraint")
	}
}

func scenarioInvalidMetadata(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	if _, err := orgs.Create(t.Context(), "badjson", false, json.RawMessage(`{not json`)); err == nil {
		t.Fatal("invalid JSON metadata must be refused at the boundary")
	}
}

func scenarioNotFound(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	_, err := orgs.Get(t.Context(), "org_does_not_exist")
	if err != store.ErrNotFound {
		t.Fatalf("want store.ErrNotFound, got %v", err)
	}
}

// scenarioConcurrent exercises the tx retry machinery: BEGIN IMMEDIATE
// contention on sqlite, serializable commits on postgres. All writers must
// succeed within the bounded-retry budget.
func scenarioConcurrent(t *testing.T, db *store.DB) {
	orgs := &service.Orgs{DB: db}
	before, err := orgs.Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	const writers = 8
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := orgs.Create(context.Background(), fmt.Sprintf("concurrent-%d", i), true, json.RawMessage(`{}`))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent create failed: %v", err)
		}
	}
	after, err := orgs.Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if after != before+writers {
		t.Fatalf("count %d -> %d, want +%d", before, after, writers)
	}
}
