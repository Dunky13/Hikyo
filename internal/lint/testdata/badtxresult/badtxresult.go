package badtxresult

import (
	"context"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

func repositories(ctx context.Context, db *store.DB) {
	_, _ = tx.WriteResult(ctx, db, func(context.Context, store.Repos, *authz.TxAuthorizer) (store.Repos, error) {
		return nil, nil
	})
}

func hiddenInterface(ctx context.Context, db *store.DB) {
	type result struct{ Value any }
	_, _ = tx.WriteResult(ctx, db, func(context.Context, store.Repos, *authz.TxAuthorizer) (result, error) {
		return result{}, nil
	})
}

func closure(ctx context.Context, db *store.DB) {
	_, _ = tx.WriteResult(ctx, db, func(context.Context, store.Repos, *authz.TxAuthorizer) (func(), error) {
		return func() {}, nil
	})
}
