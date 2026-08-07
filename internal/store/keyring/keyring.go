// Package keyring implements crypto.KeyStore over the datastore: reads from
// the read pool, key creation through the transactional boundary with the
// hierarchy-generation fence acquired in the same transaction.
package keyring

import (
	"context"
	"errors"
	"time"

	"github.com/Dunky13/wenv/internal/crypto"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/tx"
)

// Store adapts *store.DB to crypto.KeyStore.
type Store struct{ DB *store.DB }

var _ crypto.KeyStore = (*Store)(nil)

func (s *Store) ActiveMasterWrappers(ctx context.Context) ([]crypto.WrappedKey, error) {
	return s.DB.Read().Keys().ActiveMasterWrappers(ctx)
}

func (s *Store) ActiveTier3(ctx context.Context, p crypto.Purpose, orgID, projectID string) (crypto.WrappedKey, error) {
	return s.DB.Read().Keys().ActiveTier3(ctx, p, orgID, projectID)
}

func (s *Store) CreateHierarchy(ctx context.Context, master crypto.WrappedKey, tier3 []crypto.WrappedKey) error {
	now := store.CanonTime(time.Now())
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos) error {
		keys := r.Keys()
		if err := keys.AcquireHierarchyGeneration(ctx); err != nil {
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
		if err := keys.AcquireHierarchyGeneration(ctx); err != nil {
			return err
		}
		// The fence's teeth: with the hierarchy generation held, the key's
		// wrapping master must still be the active one. A writer that sealed
		// under a master a rotation has since retired is refused, never
		// committed — CI invariant 9's race, structurally closed.
		wrappers, err := keys.ActiveMasterWrappers(ctx)
		if err != nil {
			return err
		}
		if len(wrappers) == 0 {
			return errors.New("store: no active master key — hierarchy missing")
		}
		for _, w := range wrappers {
			if w.Version != key.MasterKeyVersion {
				return crypto.ErrStaleMaster
			}
		}
		if err := keys.InsertTier3(ctx, key); err != nil {
			return err
		}
		return keys.InsertScopeGeneration(ctx, key.Purpose, key.OrgID, key.ProjectID)
	})
}
