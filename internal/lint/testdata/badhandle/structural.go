package badhandle

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hikyo-Org/hikyo/internal/store"
)

// poolHolder is the structural-interface escape: *store.DB satisfies it
// without this package importing anything privileged, and the PG() selector
// below resolves to THIS interface's method, not the store's — so an
// accessor-call check alone never sees it.
type poolHolder interface{ PG() *pgxpool.Pool }

func viaStructuralInterface(ctx context.Context, h poolHolder, sql string) error {
	_, err := h.PG().Exec(ctx, sql)
	return err
}

// viaTypeAssertion is the same escape through an assertion.
func viaTypeAssertion(ctx context.Context, db any, q string) error {
	if h, ok := db.(interface{ SQLiteWrite() *sql.DB }); ok {
		_, err := h.SQLiteWrite().ExecContext(ctx, q)
		return err
	}
	return nil
}

// viaParameter never calls an accessor at all: it just receives the handle.
func viaParameter(ctx context.Context, pool *pgxpool.Pool, q string) error {
	_, err := pool.Exec(ctx, q)
	return err
}

var _ = viaStructuralInterface
var _ = viaTypeAssertion
var _ = viaParameter
var _ *store.DB
