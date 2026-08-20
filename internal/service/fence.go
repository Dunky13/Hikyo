package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// The writer fence (encryption-model ADR § Rotation, CI invariant 7). Every
// ciphertext write calls one of these inside its own transaction, before the
// store insert, so a sealer built before a `rotate-dek` — now sealing under a
// retiring or retired DEK version — is refused rather than committing a write
// that reencrypt would strand. The store method reads (and, on postgres,
// FOR SHARE-locks) the sealed version's state; a non-active state blocks the
// demote/retire that would move it, and refuses the stale write.
//
// A refusal is a conflict, not a fault: the caller re-fetches a fresh sealer and
// retries. It is mapped to domain.ErrConflict here so every write path inherits
// the mapping without repeating it.

// fenceProject asserts the project sealer's active DEK version is still active
// for the scope, in this transaction.
func fenceProject(ctx context.Context, r store.Repos, p authz.Proof, sealer *crypto.ProjectSealer, scope domain.Scope) error {
	return fenceProjectVersion(ctx, r, p, scope, sealer.ActiveVersion())
}

// fenceProjectVersion asserts a specific project DEK version is still active.
// reencrypt fences on the version it captured for the walk rather than on a
// sealer it no longer needs to hold.
func fenceProjectVersion(ctx context.Context, r store.Repos, p authz.Proof, scope domain.Scope, version uint32) error {
	err := r.Keys().AssertActiveDEKVersion(ctx, p, crypto.PurposeProject,
		string(scope.Org), string(scope.Project), version)
	return mapStaleDEK(err)
}

// fenceInstance asserts the instance sealer's active DEK version is still active.
func fenceInstance(ctx context.Context, r store.Repos, p authz.Proof, sealer *crypto.InstanceSealer) error {
	return fenceInstanceVersion(ctx, r, p, sealer.Version())
}

// fenceInstanceVersion asserts a specific instance DEK version is still active.
// Instance-credential write paths already thread the version they sealed under
// (rows stamp dek_version), so they fence on that value directly rather than
// re-reading it from the sealer.
func fenceInstanceVersion(ctx context.Context, r store.Repos, p authz.Proof, version uint32) error {
	err := r.Keys().AssertActiveDEKVersion(ctx, p, crypto.PurposeInstance, "", "", version)
	return mapStaleDEK(err)
}

func mapStaleDEK(err error) error {
	if errors.Is(err, store.ErrStaleDEK) {
		return fmt.Errorf("%w: %s", domain.ErrConflict, err)
	}
	return err
}
