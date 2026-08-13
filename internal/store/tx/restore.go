package tx

// Restore, bound to the transaction that loads it (#76).
//
// These two wrappers exist for one reason and it is a correctness reason, not
// a tidiness one: the credential-epoch bump a restore performs MUST commit in
// the same act as the data it invalidates. A restore that committed the rows
// first and advanced the epoch second would leave a window — one crash wide —
// in which a reconstructed instance is reachable with every pre-restore
// bearer credential, session and single-use artifact still live. That is
// precisely the failure the whole restore checklist exists to prevent.
//
// They live here because this is the package whose job is binding an
// authorizer to a transaction. Doing it in the service layer would mean
// handing a pgx type upward, which the architecture forbids; doing it in
// internal/store would mean a raw write to a class=authn table outside the
// enumerated resolution surface.

import (
	"context"
	"io"

	"github.com/jackc/pgx/v5"

	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/authn"
)

// RestoreFn runs inside the restore's own transaction, against the restored
// state, before anything is published or committed.
type RestoreFn func(ctx context.Context, az *authz.TxAuthorizer) error

// RestoreSQLite reconstructs a sqlite datastore at path from archive, runs fn
// against the staged file, and only then publishes it under its final name.
func RestoreSQLite(ctx context.Context, archive io.Reader, path string, fn RestoreFn) (store.Manifest, error) {
	return store.RestoreSQLite(ctx, archive, path, func(ctx context.Context, db *store.DB) error {
		return Write(ctx, db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
			return fn(ctx, az)
		})
	})
}

// RestorePostgres loads archive into an already-migrated empty database and
// runs fn inside the same transaction as the load.
//
// It deliberately does not go through Write: the retry loop cannot replay a
// restore, because the archive reader has already been consumed by the
// attempt that failed. A failed restore is a failed restore — the transaction
// rolls back, nothing is committed, and the operator runs it again with a
// fresh reader.
func RestorePostgres(ctx context.Context, db *store.DB, archive io.Reader, fn RestoreFn) (store.Manifest, error) {
	return store.RestorePostgres(ctx, db, archive, func(ctx context.Context, pgtx pgx.Tx) error {
		tok := authz.NewTxToken()
		defer tok.Invalidate()
		return fn(ctx, authz.NewTxAuthorizer(authn.NewPG(pgtx), tok))
	})
}

// Reconcile runs one per-principal reconciliation in its own write
// transaction. It exists so the service layer never has to reach for Write
// with a raw closure for something this security-relevant.
func Reconcile(ctx context.Context, db *store.DB, fn RestoreFn) error {
	return Write(ctx, db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		return fn(ctx, az)
	})
}
