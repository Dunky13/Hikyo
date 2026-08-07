// Package app wires config, store, migrations, service, and the HTTP layer
// into the runnable subcommands.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Dunky13/wenv/internal/config"
	"github.com/Dunky13/wenv/internal/server"
	"github.com/Dunky13/wenv/internal/service"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/migrate"
)

// Logger builds the process logger: text in dev, JSON in production.
func Logger(dev bool) *slog.Logger {
	if dev {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, nil))
}

func storeConfig(cfg *config.Config) store.Config {
	return store.Config{
		Engine: store.Engine(cfg.Store.Engine),
		Path:   cfg.Store.Path,
		DSN:    cfg.Store.DSN,
	}
}

// RunMigrate is `wenv migrate`: explicit migration application. Loads no
// keyring (DDL only).
func RunMigrate(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	sc := storeConfig(cfg)
	log.Info("applying migrations", "engine", sc.Engine)
	if err := migrate.Run(ctx, sc); err != nil {
		return err
	}
	log.Info("migrations current")
	return nil
}

// Server is a booted, listening server that has not started serving yet.
type Server struct {
	Addr    string
	db      *store.DB
	ln      net.Listener
	handler http.Handler
	log     *slog.Logger
}

// Boot runs the fail-closed startup sequence: migrations (auto-apply by
// default; with auto-apply disabled a pending migration state refuses to
// serve), then datastore open with the boot-enforced pragma policy, then the
// listener. Any error means the process must exit without serving.
func Boot(ctx context.Context, cfg *config.Config, log *slog.Logger) (*Server, error) {
	sc := storeConfig(cfg)

	if cfg.AutoMigrate {
		if err := migrate.Run(ctx, sc); err != nil {
			return nil, fmt.Errorf("boot: refusing to serve: %w", err)
		}
	}
	// Always verify exact schema match — with auto-migrate off this catches
	// pending migrations; in both modes it catches a database migrated by a
	// newer binary (Run applies nothing there and the schema stays ahead).
	if err := migrate.Check(ctx, sc); err != nil {
		return nil, fmt.Errorf("boot: refusing to serve: %w", err)
	}

	db, err := store.Open(ctx, sc)
	if err != nil {
		return nil, fmt.Errorf("boot: refusing to serve: %w", err)
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("boot: listen %s: %w", cfg.Listen, err)
	}

	log.Info("boot complete", "engine", sc.Engine, "addr", ln.Addr().String(), "dev", cfg.Dev)
	return &Server{
		Addr:    ln.Addr().String(),
		db:      db,
		ln:      ln,
		handler: server.New(&service.System{DB: db, Store: sc}),
		log:     log,
	}, nil
}

// Serve blocks until ctx is cancelled, then shuts down gracefully.
func (s *Server) Serve(ctx context.Context) error {
	defer s.db.Close()
	// Baseline slow-client hardening; tuned values belong to the ops spec.
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(s.ln) }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// Close releases resources for a booted server that never served.
func (s *Server) Close() error {
	err := s.ln.Close()
	return errors.Join(err, s.db.Close())
}
