// Package keyring implements crypto.KeyStore over the datastore: reads from
// the read pool, key creation through the transactional boundary with the
// hierarchy-generation fence acquired in the same transaction.
package keyring

import (
	"context"
	"time"

	"github.com/Dunky13/wenv/internal/crypto"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/tx"
)

// Store adapts *store.DB to crypto.KeyStore.
type Store struct{ DB *store.DB }

var _ crypto.KeyStore = (*Store)(nil)

func (s *Store) ActiveMaster(ctx context.Context) (crypto.WrappedKey, error) {
	return s.DB.Read().Keys().ActiveMaster(ctx)
}

func (s *Store) ActiveTier3(ctx context.Context, p crypto.Purpose, orgID, projectID string) (crypto.WrappedKey, error) {
	return s.DB.Read().Keys().ActiveTier3(ctx, p, orgID, projectID)
}

func (s *Store) CreateHierarchy(ctx context.Context, master crypto.WrappedKey, tier3 []crypto.WrappedKey) error {
	now := store.CanonTime(time.Now())
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos) error {
		keys := r.Keys()
		if err := keys.TouchHierarchyGeneration(ctx); err != nil {
			return err
		}
		master.CreatedAt = now
		if err := keys.InsertMaster(ctx, master); err != nil {
			return err
		}
		for _, k := range tier3 {
			k.CreatedAt = now
			if err := keys.InsertTier3(ctx, k); err != nil {
				return err
			}
			if err := keys.InsertScopeGeneration(ctx, k.Purpose, k.OrgID, k.ProjectID); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) CreateTier3(ctx context.Context, key crypto.WrappedKey) error {
	key.CreatedAt = store.CanonTime(time.Now())
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos) error {
		keys := r.Keys()
		if err := keys.TouchHierarchyGeneration(ctx); err != nil {
			return err
		}
		if err := keys.InsertTier3(ctx, key); err != nil {
			return err
		}
		return keys.InsertScopeGeneration(ctx, key.Purpose, key.OrgID, key.ProjectID)
	})
}
