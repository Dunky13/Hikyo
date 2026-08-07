// Package tx owns the transactional boundary (system-architecture ADR
// § Transaction boundary). Publish-class writes run SERIALIZABLE on postgres
// and BEGIN IMMEDIATE on sqlite; the retried unit is the whole closure, and
// no external effect (adapter push, SSE emit, response write) may escape
// before commit — effects are emitted after Write returns nil.
package tx

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	sqlite "modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"

	"github.com/Dunky13/wenv/internal/store"
)

// Ops-spec bounds: an initial try plus 3 retry attempts with jittered
// 10/50/250 ms backoff (one delay per retry); a 15 s overall deadline clamps
// cumulative sqlite busy waits (busy_timeout bounds each lock wait, not the
// transaction).
var backoff = [...]time.Duration{10 * time.Millisecond, 50 * time.Millisecond, 250 * time.Millisecond}

const attempts = len(backoff) + 1

const deadline = 15 * time.Second

// Write runs fn inside a write transaction with bounded retries. Retry
// exhaustion surfaces as a loud failure wrapping the last error — never an
// infinite loop or a silent drop.
func Write(ctx context.Context, db *store.DB, fn func(ctx context.Context, r store.Repos) error) error {
	return retryLoop(ctx, db.Engine(), func(ctx context.Context) error {
		return once(ctx, db, fn)
	})
}

// retryLoop is the engine-agnostic bounded-retry machinery, separated from
// the driver plumbing so its attempt accounting is unit-testable.
func retryLoop(ctx context.Context, engine store.Engine, attemptFn func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			d := backoff[attempt-1]
			// Equal jitter in [d/2, d).
			d = d/2 + rand.N(d/2)
			select {
			case <-time.After(d):
			case <-ctx.Done():
				return fmt.Errorf("tx: deadline while retrying: %w", errors.Join(ctx.Err(), last))
			}
		}
		err := attemptFn(ctx)
		if err == nil {
			return nil
		}
		if !retryable(engine, err) {
			return err
		}
		last = err
	}
	return fmt.Errorf("tx: retries exhausted after %d attempts: %w", attempts, last)
}

func once(ctx context.Context, db *store.DB, fn func(ctx context.Context, r store.Repos) error) error {
	if db.Engine() == store.EnginePostgres {
		pgtx, err := db.PG().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			return err
		}
		if err := fn(ctx, store.PGTxRepos(pgtx)); err != nil {
			_ = pgtx.Rollback(ctx)
			return err
		}
		return pgtx.Commit(ctx)
	}
	// sqlite: the write pool's DSN carries _txlock=immediate, so BeginTx
	// opens BEGIN IMMEDIATE — write intent acquired before reads.
	sqtx, err := db.SQLiteWrite().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(ctx, store.SQLiteTxRepos(sqtx)); err != nil {
		_ = sqtx.Rollback()
		return err
	}
	return sqtx.Commit()
}

// retryable classifies engine-specific transient serialization failures:
// postgres SQLSTATE 40001 (serialization_failure) / 40P01 (deadlock_detected);
// sqlite SQLITE_BUSY / SQLITE_LOCKED including extended codes such as
// SQLITE_BUSY_SNAPSHOT.
func retryable(engine store.Engine, err error) bool {
	if engine == store.EnginePostgres {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && (pgErr.Code == "40001" || pgErr.Code == "40P01")
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		primary := se.Code() & 0xff
		return primary == sqlitelib.SQLITE_BUSY || primary == sqlitelib.SQLITE_LOCKED
	}
	return false
}
