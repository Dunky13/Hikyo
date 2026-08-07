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

	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/domain"
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

// Org is the demonstration aggregate for the walking skeleton. Its
// operations are instance-scoped (org administration is cross-tenant by
// definition), so callers address orgs by id — unlike tenant-owned
// aggregates, whose addressing comes exclusively from the proof's chain.
type Org struct {
	ID        string
	Name      string
	Active    bool
	Metadata  json.RawMessage
	CreatedAt time.Time
}

// Project is a tenant-owned aggregate (chain: org). OrgID appears on reads
// only; writes bind it from the proof.
type Project struct {
	ID        string
	OrgID     string
	Name      string
	CreatedAt time.Time
}

// NewProject carries the caller-suppliable fields of a project insert. It
// deliberately has no chain fields: the org id is bound from the proof by
// the repository layer, so caller arguments structurally cannot reach the
// chain columns (tenant-isolation ADR § row shape and lookup discipline).
type NewProject struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

// Environment is a tenant-owned aggregate (chain: org, project).
type Environment struct {
	ID        string
	OrgID     string
	ProjectID string
	Name      string
	Note      string
	CreatedAt time.Time
}

// NewEnvironment carries the caller-suppliable fields of an environment
// insert; chain columns are bound from the proof, as with NewProject.
type NewEnvironment struct {
	ID        string
	Name      string
	Note      string
	CreatedAt time.Time
}

// Every repository method takes a proof as its first argument (after ctx)
// and verifies it at the store boundary before touching any query — nil,
// foreign-transaction, ended-transaction and operation-mismatched proofs are
// rejected fail-closed. Tenant-owned aggregates take no identifiers at all:
// the addressed chain comes out of the proof, which authorize() resolved
// in this same transaction.

// OrgReader is the read side of the demonstration aggregate's repository.
type OrgReader interface {
	Get(ctx context.Context, p authz.Proof, id string) (Org, error)
	List(ctx context.Context, p authz.Proof) ([]Org, error)
	Count(ctx context.Context, p authz.Proof) (int64, error)
}

// OrgRepo is the full per-aggregate repository interface. Only transaction
// closures (internal/store/tx) ever hold one.
type OrgRepo interface {
	OrgReader
	Create(ctx context.Context, p authz.Proof, org Org) error
}

// ProjectRepo is the projects aggregate (writes only for now; the CRUD
// surface lands with #48).
type ProjectRepo interface {
	Create(ctx context.Context, p authz.Proof, proj NewProject) error
}

// EnvironmentReader is the read side of the environments aggregate.
type EnvironmentReader interface {
	// Get returns the environment addressed by the proof's resolved chain.
	Get(ctx context.Context, p authz.Proof) (Environment, error)
}

// EnvironmentRepo is the full environments aggregate.
type EnvironmentRepo interface {
	EnvironmentReader
	Create(ctx context.Context, p authz.Proof, env NewEnvironment) error
	// UpdateNote mutates the non-chain note column of the environment
	// addressed by the proof's chain. Chain columns are immutable —
	// re-parenting is a new row (tenant-isolation ADR).
	UpdateNote(ctx context.Context, p authz.Proof, note string) error
}

// Repos bundles the full repositories bound to one write transaction.
type Repos interface {
	Orgs() OrgRepo
	Keys() KeyRepo
	Projects() ProjectRepo
	Environments() EnvironmentRepo
}

// ReadRepos bundles the read-only repositories bound to one read
// transaction. There is no proof-free read path: authorization is evaluated
// in-transaction, so reads run under internal/store/tx too.
type ReadRepos interface {
	Orgs() OrgReader
	Keys() KeyReader
	Environments() EnvironmentReader
}

// ErrNotFound is the canonical cross-engine "no such row" — aliased from
// domain so every layer shares one sentinel for the unauthorized ≡
// nonexistent rule without importing the store.
var ErrNotFound = domain.ErrNotFound

// DB holds the open datastore. SQLite keeps a single write connection
// (pool of one) and a separate read pool, per the boot-enforced connection
// policy; postgres uses one pgx pool.
type DB struct {
	engine Engine

	sqWrite *sql.DB // sqlite only, MaxOpenConns(1), BEGIN IMMEDIATE via _txlock
	sqRead  *sql.DB // sqlite only
	pool    *pgxpool.Pool
}

// Engine, SQLiteWrite, SQLiteRead, and PG are the doors internal/store/tx
// and the test harness need; Go has no friend packages, so the "service
// never sees a pgx or sqlite type" rule is carried by the import-boundary
// test and review, not the type system.
func (d *DB) Engine() Engine       { return d.engine }
func (d *DB) SQLiteWrite() *sql.DB { return d.sqWrite }
func (d *DB) SQLiteRead() *sql.DB  { return d.sqRead }
func (d *DB) PG() *pgxpool.Pool    { return d.pool }

// sqlitePragmas is the boot-enforced connection policy
// (system-architecture ADR § Data layer). _pragma parameters apply on every
// new connection.
const sqlitePragmas = "_pragma=foreign_keys(1)" +
	"&_pragma=journal_mode(wal)" +
	"&_pragma=synchronous(FULL)" +
	"&_pragma=busy_timeout(5000)"

// SQLiteDSN builds the canonical WRITE connection string for a database
// file: _txlock=immediate makes write transactions BEGIN IMMEDIATE, so
// write intent is acquired before any read.
func SQLiteDSN(path string) string {
	return "file:" + url.PathEscape(path) + "?_txlock=immediate&" + sqlitePragmas
}

// sqliteReadDSN is the read-pool connection string: same enforced pragmas,
// but NO _txlock=immediate — read transactions open plain deferred BEGINs,
// and under WAL a reader never blocks the writer. With the write-pool DSN a
// held read transaction would take sqlite's write intent and starve the
// single writer through its whole busy_timeout.
func sqliteReadDSN(path string) string {
	return "file:" + url.PathEscape(path) + "?" + sqlitePragmas
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
	write, err := sql.Open("sqlite", SQLiteDSN(path))
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite write pool: %w", err)
	}
	write.SetMaxOpenConns(1)
	read, err := sql.Open("sqlite", sqliteReadDSN(path))
	if err != nil {
		write.Close()
		return nil, fmt.Errorf("store: open sqlite read pool: %w", err)
	}
	d := &DB{engine: EngineSQLite, sqWrite: write, sqRead: read}
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
		{"PRAGMA read_uncommitted", "0"}, // prohibited by the tx boundary contract
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
