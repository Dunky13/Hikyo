// Package keyring implements crypto.KeyStore over the datastore: every
// access runs through the transactional boundary, with the
// hierarchy-generation fence acquired in the same transaction as the writes
// it fences.
//
// The keyring runs before any principal exists, so it cannot present an
// ordinary proof. It uses the tenant-isolation ADR's named carve-out
// instead: a SystemProof minted at the boot mint site, whose closed
// operation set is exactly these keyring methods. That is the ADR's own
// wording — "boot to its pragma/keyring checks" — so this is not an
// exemption from the chokepoint but a registered path through it, and a
// keyring call for any unregistered operation dies at the store boundary
// like any other mismatched proof.
package keyring

import (
	"context"
	"errors"
	"time"

	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/tx"
)

// Store adapts *store.DB to crypto.KeyStore.
type Store struct{ DB *store.DB }

var _ crypto.KeyStore = (*Store)(nil)

func (s *Store) ActiveMasterWrappers(ctx context.Context) ([]crypto.WrappedKey, error) {
	var out []crypto.WrappedKey
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		pf, err := authz.SystemAuthority(authz.SiteBoot, az.Token())
		if err != nil {
			return err
		}
		out, err = r.Keys().ActiveMasterWrappers(ctx, pf)
		return err
	})
	return out, err
}

func (s *Store) ActiveTier3(ctx context.Context, p crypto.Purpose, orgID, projectID string) (crypto.WrappedKey, error) {
	var out crypto.WrappedKey
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		pf, err := authz.SystemAuthority(authz.SiteBoot, az.Token())
		if err != nil {
			return err
		}
		out, err = r.Keys().ActiveTier3(ctx, pf, p, orgID, projectID)
		return err
	})
	return out, err
}

func (s *Store) CreateHierarchy(ctx context.Context, master crypto.WrappedKey, tier3 []crypto.WrappedKey) error {
	now := store.CanonTime(time.Now())
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		pf, err := authz.SystemAuthority(authz.SiteBoot, az.Token())
		if err != nil {
			return err
		}
		keys := r.Keys()
		if err := keys.AcquireHierarchyGeneration(ctx, pf); err != nil {
			return err
		}
		master.CreatedAt = now
		if err := keys.InsertMaster(ctx, pf, master); err != nil {
			return err
		}
		for _, k := range tier3 {
			k.CreatedAt = now
			if err := keys.InsertTier3(ctx, pf, k); err != nil {
				return err
			}
			if err := keys.InsertScopeGeneration(ctx, pf, k.Purpose, k.OrgID, k.ProjectID); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) CreateTier3(ctx context.Context, key crypto.WrappedKey) error {
	key.CreatedAt = store.CanonTime(time.Now())
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		pf, err := authz.SystemAuthority(authz.SiteBoot, az.Token())
		if err != nil {
			return err
		}
		keys := r.Keys()
		if err := keys.AcquireHierarchyGeneration(ctx, pf); err != nil {
			return err
		}
		// The fence's teeth: with the hierarchy generation held, the key's
		// wrapping master must still be the active one. A writer that sealed
		// under a master a rotation has since retired is refused, never
		// committed — CI invariant 9's race, structurally closed.
		wrappers, err := keys.ActiveMasterWrappers(ctx, pf)
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
		if err := keys.InsertTier3(ctx, pf, key); err != nil {
			return err
		}
		return keys.InsertScopeGeneration(ctx, pf, key.Purpose, key.OrgID, key.ProjectID)
	})
}
