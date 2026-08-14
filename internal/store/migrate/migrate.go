// Package migrate applies the embedded goose migrations. Concurrent
// migrators (boot racing an explicit `hikyo migrate` racing an old server) are
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

	"github.com/Hikyo-Org/hikyo/internal/store"
)

// Run applies all pending migrations, roll-forward only. Any error means the
// caller must refuse to serve (fail closed, loud).
func Run(ctx context.Context, cfg store.Config) (err error) {
	if cfg.Engine == store.EngineSQLite {
		unlock, lockErr := lockSQLite(ctx, cfg.Path)
		if lockErr != nil {
			return lockErr
		}
		defer func() { err = errors.Join(err, unlock()) }()
	}
	return withProvider(ctx, cfg, func(p *goose.Provider, _ *sql.DB) error {
		if _, err := p.Up(ctx); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		return nil
	})
}

// lockSQLite takes the advisory file lock beside the database for the whole
// migration run, since sqlite's per-migration transactions do not lock the
// run against a second process.
func lockSQLite(ctx context.Context, path string) (func() error, error) {
	lockPath, err := canonicalPath(path)
	if err != nil {
		return nil, fmt.Errorf("migrate: resolve sqlite path: %w", err)
	}
	fl := flock.New(lockPath + ".lock")
	locked, err := fl.TryLockContext(ctx, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("migrate: acquire sqlite migration lock: %w", err)
	}
	if !locked {
		return nil, fmt.Errorf("migrate: sqlite migration lock %s.lock is held", lockPath)
	}
	return fl.Unlock, nil
}

// RunUpTo applies migrations up to and including version, and no further. It
// exists for one caller: restore (#76), which must create the schema AT THE
// ARCHIVE'S VERSION before loading the archive's rows, and only then roll
// forward with Run. Migrating first and loading afterwards would mean loading
// old rows into a newer shape — the case where a restore silently drops a
// column a later migration added.
func RunUpTo(ctx context.Context, cfg store.Config, version int64) (err error) {
	if cfg.Engine == store.EngineSQLite {
		unlock, lockErr := lockSQLite(ctx, cfg.Path)
		if lockErr != nil {
			return lockErr
		}
		defer func() { err = errors.Join(err, unlock()) }()
	}
	return withProvider(ctx, cfg, func(p *goose.Provider, _ *sql.DB) error {
		if _, err := p.UpTo(ctx, version); err != nil {
			return fmt.Errorf("migrate: up to %d: %w", version, err)
		}
		return nil
	})
}

// HasPending reports whether this binary embeds a migration the database has
// not applied. It exists so the automatic pre-migration export (#76) runs
// before a schema change and NOT before every ordinary restart — an export
// per boot would be a backup policy nobody asked for and a disk bill nobody
// budgeted.
func HasPending(ctx context.Context, cfg store.Config) (bool, error) {
	var pending bool
	err := withProvider(ctx, cfg, func(p *goose.Provider, _ *sql.DB) error {
		var err error
		pending, err = p.HasPending(ctx)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("migrate: pending check: %w", err)
	}
	return pending, nil
}

// MaxVersion reports the highest migration version this binary embeds. A
// restore refuses an archive above it rather than guessing at a schema it
// does not have.
func MaxVersion(ctx context.Context, cfg store.Config) (int64, error) {
	var max int64
	err := withProvider(ctx, cfg, func(p *goose.Provider, _ *sql.DB) error {
		for _, src := range p.ListSources() {
			if src.Version > max {
				max = src.Version
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return max, nil
}

// Check verifies the database schema matches this binary exactly: no
// unapplied embedded migrations (behind) and no applied migration this
// binary does not embed (ahead or diverged — an old binary running against
// a database a newer binary migrated must refuse, not report ready; goose's
// HasPending alone cannot see that case, and comparing only maximum
// versions would miss an unknown version numbered below the embedded
// maximum). Any mismatch is a refuse-to-serve error.
func Check(ctx context.Context, cfg store.Config) error {
	return withProvider(ctx, cfg, func(p *goose.Provider, db *sql.DB) error {
		pending, err := p.HasPending(ctx)
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		if pending {
			return errors.New("migrate: pending migrations — run `hikyo migrate` or enable auto-migrate")
		}
		embedded := map[int64]bool{}
		for _, src := range p.ListSources() {
			embedded[src.Version] = true
		}
		// Applied set straight from goose's version table; version 0 is
		// goose's own bookkeeping row.
		rows, err := db.QueryContext(ctx, "SELECT DISTINCT version_id FROM goose_db_version WHERE version_id <> 0")
		if err != nil {
			return fmt.Errorf("migrate: read applied versions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var v int64
			if err := rows.Scan(&v); err != nil {
				return fmt.Errorf("migrate: read applied versions: %w", err)
			}
			if !embedded[v] {
				return fmt.Errorf("migrate: database has applied migration %d unknown to this binary — refusing to serve with an unknown schema", v)
			}
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("migrate: read applied versions: %w", err)
		}
		return nil
	})
}

// canonicalPath resolves symlinks and relativity so two spellings of the
// same database file contend on the same lock file. The file itself is
// resolved when it exists; a database that does not exist yet falls back to
// resolving its directory. Hard links stay distinct — they are not
// detectable by path canonicalization.
func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(abs)), nil
}

func withProvider(ctx context.Context, cfg store.Config, fn func(*goose.Provider, *sql.DB) error) error {
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
	return fn(provider, db)
}
