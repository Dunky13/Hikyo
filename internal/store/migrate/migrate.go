// Package migrate applies the embedded goose migrations. Concurrent
// migrators (boot racing an explicit `wenv migrate` racing an old server) are
// serialized per engine: a goose session-level advisory lock on postgres; on
// sqlite, per-migration transactions do not lock the whole run against a
// second process, so the entire run holds an advisory file lock beside the
// database — sound because sqlite is same-host by construction.
package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"

	"github.com/gofrs/flock"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"
	"github.com/pressly/goose/v3/lock"

	"github.com/Dunky13/wenv/internal/store"
)

// Run applies all pending migrations, roll-forward only. Any error means the
// caller must refuse to serve (fail closed, loud).
func Run(ctx context.Context, cfg store.Config) error {
	if cfg.Engine == store.EngineSQLite {
		fl := flock.New(cfg.Path + ".lock")
		if err := fl.Lock(); err != nil {
			return fmt.Errorf("migrate: acquire sqlite migration lock: %w", err)
		}
		defer fl.Unlock()
	}
	return withProvider(ctx, cfg, func(p *goose.Provider) error {
		if _, err := p.Up(ctx); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		return nil
	})
}

// HasPending reports whether unapplied migrations exist. A pending state with
// auto-apply disabled must refuse to serve.
func HasPending(ctx context.Context, cfg store.Config) (bool, error) {
	var pending bool
	err := withProvider(ctx, cfg, func(p *goose.Provider) error {
		var err error
		pending, err = p.HasPending(ctx)
		return err
	})
	return pending, err
}

func withProvider(ctx context.Context, cfg store.Config, fn func(*goose.Provider) error) error {
	var (
		db      *sql.DB
		dialect database.Dialect
		dir     string
		opts    []goose.ProviderOption
		err     error
	)
	switch cfg.Engine {
	case store.EngineSQLite:
		db, err = sql.Open("sqlite", store.SQLiteDSN(cfg.Path))
		dialect, dir = database.DialectSQLite3, "migrations/sqlite"
		if db != nil {
			db.SetMaxOpenConns(1)
		}
	case store.EnginePostgres:
		db, err = sql.Open("pgx", cfg.DSN)
		dialect, dir = database.DialectPostgres, "migrations/postgres"
		// Running pg migrations without the session lock would be a
		// silent downgrade; a locker failure is a hard failure.
		locker, lockErr := lock.NewPostgresSessionLocker()
		if lockErr != nil {
			if db != nil {
				db.Close()
			}
			return fmt.Errorf("migrate: postgres session locker: %w", lockErr)
		}
		opts = append(opts, goose.WithSessionLocker(locker))
	default:
		return fmt.Errorf("migrate: unknown engine %q", cfg.Engine)
	}
	if err != nil {
		return fmt.Errorf("migrate: open %s: %w", cfg.Engine, err)
	}
	defer db.Close()

	fsys, err := fs.Sub(store.MigrationsFS, dir)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	provider, err := goose.NewProvider(dialect, db, fsys, opts...)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return fn(provider)
}
