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
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"
	"github.com/pressly/goose/v3/lock"

	"github.com/Dunky13/wenv/internal/store"
)

// Run applies all pending migrations, roll-forward only. Any error means the
// caller must refuse to serve (fail closed, loud).
func Run(ctx context.Context, cfg store.Config) (err error) {
	if cfg.Engine == store.EngineSQLite {
		lockPath, pathErr := canonicalPath(cfg.Path)
		if pathErr != nil {
			return fmt.Errorf("migrate: resolve sqlite path: %w", pathErr)
		}
		fl := flock.New(lockPath + ".lock")
		locked, lockErr := fl.TryLockContext(ctx, 100*time.Millisecond)
		if lockErr != nil {
			return fmt.Errorf("migrate: acquire sqlite migration lock: %w", lockErr)
		}
		if !locked {
			return fmt.Errorf("migrate: sqlite migration lock %s.lock is held", lockPath)
		}
		defer func() {
			err = errors.Join(err, fl.Unlock())
		}()
	}
	return withProvider(ctx, cfg, func(p *goose.Provider) error {
		if _, err := p.Up(ctx); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		return nil
	})
}

// Check verifies the database schema matches this binary exactly: no
// unapplied embedded migrations (behind) and no applied version newer than
// this binary knows (ahead — an old binary running against a database a
// newer binary migrated must refuse, not report ready; goose's HasPending
// alone cannot see this case). Any mismatch is a refuse-to-serve error.
func Check(ctx context.Context, cfg store.Config) error {
	return withProvider(ctx, cfg, func(p *goose.Provider) error {
		pending, err := p.HasPending(ctx)
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		if pending {
			return errors.New("migrate: pending migrations — run `wenv migrate` or enable auto-migrate")
		}
		dbVersion, err := p.GetDBVersion(ctx)
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		var maxEmbedded int64
		for _, src := range p.ListSources() {
			if src.Version > maxEmbedded {
				maxEmbedded = src.Version
			}
		}
		if dbVersion > maxEmbedded {
			return fmt.Errorf("migrate: database schema version %d is newer than this binary's %d — refusing to serve with an unknown schema", dbVersion, maxEmbedded)
		}
		return nil
	})
}

// canonicalPath resolves symlinks and relativity so two spellings of the
// same database file contend on the same lock file. The database itself may
// not exist yet, so symlinks are resolved on its directory.
func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(abs)), nil
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
