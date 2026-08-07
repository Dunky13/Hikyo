// Package store owns datastore access. All generated query code sits behind
// per-aggregate repository interfaces here — no service code ever sees a pgx
// or sqlite type. Canonical cross-engine semantics are fixed in this package:
// timestamps UTC (RFC 3339 text on sqlite, timestamptz on postgres, both
// truncated to microseconds), booleans as integers on sqlite, JSON as text
// validated at the boundary.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "modernc.org/sqlite"
)

type Engine string

const (
	EngineSQLite   Engine = "sqlite"
	EnginePostgres Engine = "postgres"
)

// Config selects and locates the datastore. Exactly one of Path (sqlite) or
// DSN (postgres) is used, per Engine.
type Config struct {
	Engine Engine
	Path   string
	DSN    string
}

// Org is the demonstration aggregate for the walking skeleton.
type Org struct {
	ID        string
	Name      string
	Active    bool
	Metadata  json.RawMessage
	CreatedAt time.Time
}

// OrgRepo is the per-aggregate repository interface.
type OrgRepo interface {
	Create(ctx context.Context, org Org) error
	Get(ctx context.Context, id string) (Org, error)
	List(ctx context.Context) ([]Org, error)
	Count(ctx context.Context) (int64, error)
}

// Repos bundles the repositories bound to one execution scope (a transaction
// or the read pool).
type Repos interface {
	Orgs() OrgRepo
}

// ErrNotFound is the canonical cross-engine "no such row".
var ErrNotFound = errors.New("not found")

// DB holds the open datastore. SQLite keeps a single write connection
// (pool of one) and a separate read pool, per the boot-enforced connection
// policy; postgres uses one pgx pool.
type DB struct {
	engine Engine
	path   string

	sqWrite *sql.DB // sqlite only, MaxOpenConns(1), BEGIN IMMEDIATE via _txlock
	sqRead  *sql.DB // sqlite only
	pool    *pgxpool.Pool
}

func (d *DB) Engine() Engine       { return d.engine }
func (d *DB) SQLitePath() string   { return d.path }
func (d *DB) SQLiteWrite() *sql.DB { return d.sqWrite }
func (d *DB) PG() *pgxpool.Pool    { return d.pool }

// sqlitePragmas is the boot-enforced connection policy
// (system-architecture ADR § Data layer). _pragma parameters apply on every
// new connection; _txlock=immediate makes write transactions BEGIN IMMEDIATE.
const sqlitePragmas = "?_txlock=immediate" +
	"&_pragma=foreign_keys(1)" +
	"&_pragma=journal_mode(wal)" +
	"&_pragma=synchronous(FULL)" +
	"&_pragma=busy_timeout(5000)"

// SQLiteDSN builds the canonical connection string for a database file.
func SQLiteDSN(path string) string {
	return "file:" + url.PathEscape(path) + sqlitePragmas
}

// Open opens the datastore and, for sqlite, verifies the pragma policy took
// effect — if any pragma cannot be established, boot refuses (no silent
// downgrade).
func Open(ctx context.Context, cfg Config) (*DB, error) {
	switch cfg.Engine {
	case EngineSQLite:
		return openSQLite(ctx, cfg.Path)
	case EnginePostgres:
		return openPostgres(ctx, cfg.DSN)
	default:
		return nil, fmt.Errorf("store: unknown engine %q", cfg.Engine)
	}
}

func openSQLite(ctx context.Context, path string) (*DB, error) {
	if path == "" {
		return nil, errors.New("store: sqlite path is empty")
	}
	dsn := SQLiteDSN(path)
	write, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite write pool: %w", err)
	}
	write.SetMaxOpenConns(1)
	read, err := sql.Open("sqlite", dsn)
	if err != nil {
		write.Close()
		return nil, fmt.Errorf("store: open sqlite read pool: %w", err)
	}
	d := &DB{engine: EngineSQLite, path: path, sqWrite: write, sqRead: read}
	for name, pool := range map[string]*sql.DB{"write": write, "read": read} {
		if err := verifySQLitePragmas(ctx, pool); err != nil {
			d.Close()
			return nil, fmt.Errorf("store: sqlite %s pool: %w", name, err)
		}
	}
	return d, nil
}

// verifySQLitePragmas re-reads the policy pragmas and refuses on mismatch.
// Pragmas are per-connection; the DSN applies them to every new connection,
// so verifying one connection per pool proves the DSN is effective.
func verifySQLitePragmas(ctx context.Context, db *sql.DB) error {
	checks := []struct {
		query string
		want  string
	}{
		{"PRAGMA foreign_keys", "1"},
		{"PRAGMA journal_mode", "wal"},
		{"PRAGMA synchronous", "2"}, // FULL
		{"PRAGMA busy_timeout", "5000"},
	}
	for _, c := range checks {
		var got string
		if err := db.QueryRowContext(ctx, c.query).Scan(&got); err != nil {
			return fmt.Errorf("%s: %w", c.query, err)
		}
		if got != c.want {
			return fmt.Errorf("%s = %q, want %q — refusing to boot without the enforced pragma policy", c.query, got, c.want)
		}
	}
	return nil
}

func openPostgres(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: postgres ping: %w", err)
	}
	return &DB{engine: EnginePostgres, pool: pool}, nil
}

func (d *DB) Ping(ctx context.Context) error {
	if d.engine == EnginePostgres {
		return d.pool.Ping(ctx)
	}
	return d.sqRead.PingContext(ctx)
}

func (d *DB) Close() error {
	var errs []error
	if d.sqWrite != nil {
		errs = append(errs, d.sqWrite.Close())
	}
	if d.sqRead != nil {
		errs = append(errs, d.sqRead.Close())
	}
	if d.pool != nil {
		d.pool.Close()
	}
	return errors.Join(errs...)
}

// Read returns repositories bound to the read side (sqlite read pool /
// postgres pool), outside any explicit transaction. Writes go through
// internal/store/tx.
func (d *DB) Read() Repos {
	if d.engine == EnginePostgres {
		return pgRepos{db: d.pool}
	}
	return sqliteRepos{db: d.sqRead}
}
