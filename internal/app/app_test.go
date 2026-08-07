package app

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/Dunky13/wenv/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func devConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, _, err := config.Load("server", []string{"--dev", "--listen", "127.0.0.1:0"},
		func(k string) string {
			if k == "WENV_DB" {
				return "sqlite:" + filepath.Join(t.TempDir(), "wenv.db")
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

func TestPendingMigrationsWithAutoMigrateOffRefusesToServe(t *testing.T) {
	cfg := devConfig(t)
	cfg.AutoMigrate = false
	srv, err := Boot(t.Context(), cfg, testLogger())
	if err == nil {
		srv.Close()
		t.Fatal("boot with pending migrations and auto-migrate disabled must refuse to serve")
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
