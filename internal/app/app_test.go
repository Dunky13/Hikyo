package app

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/Hikyo-Org/hikyo/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func devConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, _, err := config.Load("server", []string{"--dev", "--listen", "127.0.0.1:0"},
		func(k string) string {
			if k == "HIKYO_DB" {
				return "sqlite:" + filepath.Join(t.TempDir(), "hikyo.db")
			}
			return ""
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestDevBootServesHealthAndReady(t *testing.T) {
	cfg := devConfig(t)
	srv, err := Boot(t.Context(), cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	for path, want := range map[string]int{"/healthz": 200, "/readyz": 200} {
		resp, err := http.Get("http://" + srv.Addr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s = %d, want %d", path, resp.StatusCode, want)
		}
	}
}

// The slow-client limits are stdlib machinery; what can regress silently is
// them being unset, so assert the configuration itself.
func TestHTTPServerSlowClientLimitsConfigured(t *testing.T) {
	srv := newHTTPServer(nil)
	if srv.ReadHeaderTimeout <= 0 {
		t.Error("ReadHeaderTimeout must be bounded")
	}
	if srv.ReadTimeout <= 0 {
		t.Error("ReadTimeout must be bounded")
	}
	if srv.IdleTimeout <= 0 {
		t.Error("IdleTimeout must be bounded")
	}
	if srv.MaxHeaderBytes <= 0 {
		t.Error("MaxHeaderBytes must be bounded")
	}
	if srv.WriteTimeout != 0 {
		t.Error("WriteTimeout must stay unset until SSE decides it")
	}
}

func TestPendingMigrationsWithAutoMigrateOffRefusesToServe(t *testing.T) {
	cfg := devConfig(t)
	cfg.AutoMigrate = false
	srv, err := Boot(t.Context(), cfg, testLogger())
	if err == nil {
		srv.Close()
		t.Fatal("boot with pending migrations and auto-migrate disabled must refuse to serve")
	}
}

func TestSchemaAheadOfBinaryRefusesToServe(t *testing.T) {
	cfg := devConfig(t)
	if err := RunMigrate(t.Context(), cfg, testLogger()); err != nil {
		t.Fatal(err)
	}
	// Simulate a newer binary having applied an unknown migration.
	db, err := sql.Open("sqlite", "file:"+cfg.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO goose_db_version (version_id, is_applied, tstamp) VALUES (99999, 1, CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	srv, err := Boot(t.Context(), cfg, testLogger())
	if err == nil {
		srv.Close()
		t.Fatal("a database migrated by a newer binary must refuse to serve")
	}
	if !strings.Contains(err.Error(), "unknown to this binary") {
		t.Fatalf("refusal must name the unknown-schema cause, got: %v", err)
	}
}

func TestExplicitMigrateThenBootWithoutAutoMigrate(t *testing.T) {
	cfg := devConfig(t)
	if err := RunMigrate(t.Context(), cfg, testLogger()); err != nil {
		t.Fatal(err)
	}
	cfg.AutoMigrate = false
	srv, err := Boot(t.Context(), cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()
}
