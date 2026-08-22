// Package tx owns the transactional boundary (system-architecture ADR
// § Transaction boundary). Publish-class writes run SERIALIZABLE on postgres
// and BEGIN IMMEDIATE on sqlite; the retried unit is the whole closure, and
// no external effect (adapter push, SSE emit, response write) may escape
// before commit — effects are emitted after Write returns nil.
//
// This package is also where authorization meets the transaction: every
// attempt mints a fresh transaction token, builds the resolution surface
// (internal/store/authn) on the attempt's own transaction, and hands the
// closure a TxAuthorizer bound to both. Proofs minted inside an attempt die
// with it — the token is invalidated at commit or rollback, so a proof
// cannot outlive its transaction or leak into a retry attempt.
package tx

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	sqlite "modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/authn"
)

// Ops-spec bounds: an initial try plus 3 retry attempts with jittered
// 10/50/250 ms backoff (one delay per retry); a 15 s overall deadline clamps
// cumulative sqlite busy waits (busy_timeout bounds each lock wait, not the
// transaction).
var backoff = [...]time.Duration{10 * time.Millisecond, 50 * time.Millisecond, 250 * time.Millisecond}

const attempts = len(backoff) + 1

const deadline = 15 * time.Second

// WriteFn is one write-transaction attempt: full repositories plus the
// authorizer minting proofs valid exactly for this attempt.
type WriteFn func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error

// WriteResultFn is one result-bearing write-transaction attempt. Returned
// values must be detached data: repositories, authorizers, proofs, and other
// attempt-owned references must not escape the closure.
type WriteResultFn[T any] func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) (T, error)

// ReadFn is one read-transaction attempt: read-only repositories plus the
// attempt's authorizer. There is no proof-free read path — authorization is
// evaluated in-transaction (permission-model ADR), so reads transact too.
type ReadFn func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error

const serializationLockNamespace int32 = 1212760911

// Write runs fn inside a write transaction with bounded retries. Retry
// exhaustion surfaces as a loud failure wrapping the last error — never an
// infinite loop or a silent drop.
func Write(ctx context.Context, db *store.DB, fn WriteFn) error {
	_, err := WriteResult(ctx, db, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) (struct{}, error) {
		return struct{}{}, fn(ctx, r, az)
	})
	return err
}

// WriteSerialized is Write with a cross-instance admission lock acquired
// before postgres begins the SERIALIZABLE transaction. It is for rare
// control-plane mutations that update a shared row after authorization reads:
// a row lock taken inside the transaction is too late because waiters already
// own stale snapshots and must abort when the shared row changes. SQLite's
// BEGIN IMMEDIATE already provides the same admission ordering.
//
// Names are hashed only to fit postgres's two-int advisory-lock API. A hash
// collision merely serializes two uncommon operations; it cannot admit an
// unsafe interleaving.
func WriteSerialized(ctx context.Context, db *store.DB, name string, fn WriteFn) error {
	return retryLoop(ctx, db.Engine(), func(ctx context.Context) error {
		if db.Engine() != store.EnginePostgres {
			return writeOnce(ctx, db, fn)
		}
		return writePostgresSerializedOnce(ctx, db, serializationKey(name), fn)
	})
}

func serializationKey(name string) int32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return int32(h.Sum32())
}

// WriteResult runs fn inside a write transaction with bounded retries and
// returns only the value produced by the attempt whose transaction committed.
// Values from rolled-back attempts are discarded, including when Commit itself
// reports the retryable failure.
func WriteResult[T any](ctx context.Context, db *store.DB, fn WriteResultFn[T]) (T, error) {
	return retryResult(ctx, db.Engine(), func(ctx context.Context) (T, error) {
		var result T
		err := writeOnce(ctx, db, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
			var err error
			result, err = fn(ctx, r, az)
			return err
		})
		return result, err
	})
}

// retryResult publishes an attempt's result only when the complete attempt —
// including commit — succeeds. Keeping this boundary separate makes commit
// failure injection deterministic without driver-specific fault hooks.
func retryResult[T any](ctx context.Context, engine store.Engine, attemptFn func(context.Context) (T, error)) (T, error) {
	var committed T
	err := retryLoop(ctx, engine, func(ctx context.Context) error {
		attemptResult, err := attemptFn(ctx)
		if err != nil {
			return err
		}
		committed = attemptResult
		return nil
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return committed, nil
}

// Read runs fn inside a read-only transaction with the same bounded-retry
// machinery (sqlite can return SQLITE_BUSY on the read pool; postgres
// read-only transactions can still be cancelled).
func Read(ctx context.Context, db *store.DB, fn ReadFn) error {
	return retryLoop(ctx, db.Engine(), func(ctx context.Context) error {
		return readOnce(ctx, db, fn)
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

func writeOnce(ctx context.Context, db *store.DB, fn WriteFn) error {
	tok := authz.NewTxToken()
	defer tok.Invalidate() // the proof dies with the attempt, success or not

	if db.Engine() == store.EnginePostgres {
		return writePostgresOnce(ctx, db, db.PG(), tok, fn)
	}
	// sqlite: the write pool's DSN carries _txlock=immediate, so BeginTx
	// opens BEGIN IMMEDIATE — write intent acquired before reads.
	sqtx, err := db.SQLiteWrite().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	az := authz.NewTxAuthorizer(authn.NewSQLite(sqtx), tok)
	err = fn(ctx, store.SQLiteTxRepos(sqtx, tok), az)
	if err != nil {
		_ = sqtx.Rollback()
	} else {
		err = sqtx.Commit()
	}
	return settleDenials(ctx, db, az, err)
}

type postgresBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

func writePostgresOnce(ctx context.Context, db *store.DB, beginner postgresBeginner, tok *authz.TxToken, fn WriteFn) error {
	az, err := runPostgresTransaction(ctx, beginner, tok, fn)
	if az == nil {
		return err
	}
	return settleDenials(ctx, db, az, err)
}

func runPostgresTransaction(ctx context.Context, beginner postgresBeginner, tok *authz.TxToken, fn WriteFn) (*authz.TxAuthorizer, error) {
	pgtx, err := beginner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, err
	}
	az := authz.NewTxAuthorizer(authn.NewPG(pgtx), tok)
	err = fn(ctx, store.PGTxRepos(pgtx, tok), az)
	if err != nil {
		_ = pgtx.Rollback(ctx)
	} else {
		err = pgtx.Commit(ctx)
	}
	return az, err
}

func writePostgresSerializedOnce(ctx context.Context, db *store.DB, key int32, fn WriteFn) error {
	conn, err := db.PG().Acquire(ctx)
	if err != nil {
		return err
	}
	locked, released := false, false
	discard := func() {
		raw := conn.Hijack()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = raw.Close(cleanupCtx)
		released = true
	}
	release := func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		var unlocked bool
		unlockErr := conn.QueryRow(cleanupCtx,
			"SELECT pg_advisory_unlock($1, $2)", serializationLockNamespace, key).Scan(&unlocked)
		if unlockErr == nil && unlocked {
			conn.Release()
			released = true
			return
		}
		// A session lock survives transaction rollback. If explicit unlock is
		// unavailable, discard the physical connection so postgres releases it
		// instead of poisoning a pooled session.
		discard()
	}
	defer func() {
		if released {
			return
		}
		if locked {
			release()
			return
		}
		conn.Release()
	}()

	if _, err := conn.Exec(ctx,
		"SELECT pg_advisory_lock($1, $2)", serializationLockNamespace, key); err != nil {
		// The server may have acquired the session lock before the client saw an
		// error. Never return that session to the pool on an ambiguous result.
		discard()
		return err
	}
	locked = true

	tok := authz.NewTxToken()
	defer tok.Invalidate()
	az, err := runPostgresTransaction(ctx, conn, tok, fn)
	release()
	if az == nil {
		return err
	}
	// Denial audit settlement may acquire another pool connection. Release the
	// admission lock and its connection first so queued creators cannot exhaust
	// the pool while the lock holder waits to record its refusal.
	return settleDenials(ctx, db, az, err)
}

func readOnce(ctx context.Context, db *store.DB, fn ReadFn) error {
	tok := authz.NewTxToken()
	defer tok.Invalidate()

	if db.Engine() == store.EnginePostgres {
		// REPEATABLE READ, not the server default: a proof certifies what
		// authorize() saw, so chain resolution, grant evaluation and the
		// store read must observe ONE snapshot. Under READ COMMITTED each
		// statement takes a fresh snapshot, and a grant revoked between the
		// grant lookup and the store query would leave the minted proof
		// certifying a policy no single snapshot ever held. It also matches
		// sqlite's WAL reader snapshot, so the engines agree.
		pgtx, err := db.PG().BeginTx(ctx, pgx.TxOptions{
			IsoLevel:   pgx.RepeatableRead,
			AccessMode: pgx.ReadOnly,
		})
		if err != nil {
			return err
		}
		az := authz.NewTxAuthorizer(authn.NewPG(pgtx), tok)
		err = fn(ctx, store.PGTxReadRepos(pgtx, tok), az)
		if err != nil {
			_ = pgtx.Rollback(ctx)
		} else {
			err = pgtx.Commit(ctx)
		}
		return settleDenials(ctx, db, az, err)
	}
	// sqlite: plain deferred BEGIN on the read pool (its DSN carries no
	// _txlock=immediate, so a held read transaction never takes write
	// intent); the narrowed ReadRepos interface keeps writes out at compile
	// time.
	sqtx, err := db.SQLiteRead().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	az := authz.NewTxAuthorizer(authn.NewSQLite(sqtx), tok)
	err = fn(ctx, store.SQLiteTxReadRepos(sqtx, tok), az)
	if err != nil {
		_ = sqtx.Rollback()
	} else {
		err = sqtx.Commit()
	}
	return settleDenials(ctx, db, az, err)
}

// settleDenials makes every denial the attempt captured durable BEFORE the
// attempt's outcome reaches the caller (audit-model ADR § Denials: the
// denial event is durable before the error response is sent; no async path
// exists). The attempt's transaction is already rolled back or committed —
// ordering that matters on sqlite, whose single write connection must be
// free before the flush transaction begins.
//
//   - Retryable attempt errors skip the flush: the retry re-runs
//     authorize(), which re-captures; flushing here would duplicate events.
//   - A flush failure is returned as a loud error wrapping both causes,
//     never the uniform denial — a denial response without its durable
//     record is exactly what fail-closed forbids (the A4 induced-commit-
//     failure criterion).
func settleDenials(ctx context.Context, db *store.DB, az *authz.TxAuthorizer, attemptErr error) error {
	if attemptErr != nil && retryable(db.Engine(), attemptErr) {
		return attemptErr // the retry re-runs authorize() and re-captures
	}
	if cerr := az.DenialCaptureError(); cerr != nil {
		// A denial existed but could not even be captured: same fail-closed
		// posture as a flush failure — loud, never the uniform denial.
		return fmt.Errorf("tx: denial audit record not durable — refusing to answer (capture: %w; suppressed outcome: %v)", cerr, attemptErr)
	}
	denials := az.PendingDenials()
	if len(denials) == 0 {
		return attemptErr
	}
	flushErr := retryLoop(ctx, db.Engine(), func(ctx context.Context) error {
		return flushOnce(ctx, db, denials)
	})
	if flushErr != nil {
		// The suppressed outcome is reported as TEXT (%v), deliberately not
		// wrapped: keeping ErrNotFound/ErrUnauthorized in the chain would let
		// the response layer render the uniform denial after all — exactly
		// the unrecorded-denial answer fail-closed forbids.
		return fmt.Errorf("tx: denial audit record not durable — refusing to answer (flush: %w; suppressed outcome: %v)", flushErr, attemptErr)
	}
	return attemptErr
}

// flushOnce writes the captured denials through the resolution surface's
// pinned write paths (authn.WriteDenial) in one dedicated transaction.
func flushOnce(ctx context.Context, db *store.DB, denials []authz.Denial) error {
	if db.Engine() == store.EnginePostgres {
		pgtx, err := db.PG().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			return err
		}
		w := authn.NewPG(pgtx)
		for _, d := range denials {
			if err := w.WriteDenial(ctx, d.Event, d.Trail, d.Scope); err != nil {
				_ = pgtx.Rollback(ctx)
				return err
			}
		}
		return pgtx.Commit(ctx)
	}
	sqtx, err := db.SQLiteWrite().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	w := authn.NewSQLite(sqtx)
	for _, d := range denials {
		if err := w.WriteDenial(ctx, d.Event, d.Trail, d.Scope); err != nil {
			_ = sqtx.Rollback()
			return err
		}
	}
	return sqtx.Commit()
}

// retryable classifies engine-specific transient serialization failures:
// postgres SQLSTATE 40001 (serialization_failure) / 40P01 (deadlock_detected);
// sqlite SQLITE_BUSY / SQLITE_LOCKED including extended codes such as
// SQLITE_BUSY_SNAPSHOT.
func retryable(engine store.Engine, err error) bool {
	// A caller that has itself classified an error as a transient race — the
	// SCIM provisioning create's identity-uniqueness loser, today — opts in
	// explicitly. The engine cannot tell that race from a real conflict:
	// postgres answers both 23505, and widening the classifier to every unique
	// violation would make a genuine duplicate spin the full retry budget.
	if errors.Is(err, store.ErrRetrySerialization) {
		return true
	}
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
