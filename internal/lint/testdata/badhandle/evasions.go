package badhandle

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// pool is the alias escape: `*pool` is spelled without ever writing
// pgxpool.Pool at the use site, so a String()-match on the written type —
// and the module-scope guard — both miss it unless aliases are unwrapped.
type pool = pgxpool.Pool

type aliasHolder interface{ PG() *pool }

func viaAlias(ctx context.Context, h aliasHolder, q string) error {
	_, err := h.PG().Exec(ctx, q)
	return err
}

// holder is the generic escape: the declaration carries only the type
// parameter T, so the concrete handle type exists solely in the
// instantiation expression below.
type holder[T any] interface{ Handle() T }

func viaGenericInstantiation(ctx context.Context, db any, q string) error {
	if h, ok := db.(holder[*pgxpool.Pool]); ok {
		_, err := h.Handle().Exec(ctx, q)
		return err
	}
	return nil
}

var _ = viaAlias
var _ = viaGenericInstantiation
