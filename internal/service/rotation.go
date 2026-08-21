package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// Rotation is the operator surface for the four key-hierarchy rotations that
// are not the token key (encryption-model ADR § Rotation): rotate-dek,
// reencrypt, rotate-master-key and rotate-root-key. Each is its own
// instance-level capability, never bundled, so the post-compromise recovery
// order can run each under a distinct authority. Token-key rotation lives on
// Revisions because it is coupled to the change-token cache; these four are
// pure crypto-hierarchy hygiene.
type Rotation struct {
	DB      *store.DB
	Keyring *crypto.Keyring
	// RootKey re-reads the operator root from its source on demand. The master
	// is wrapped by the root and the root is zeroed after boot, so master and
	// root rotation both re-read it here rather than holding it in memory. Nil
	// refuses those two rotations loudly.
	RootKey RootKeySource
	// Budget applies the §179 fail-closed default to master-key rotation, which
	// rewraps every project DEK (project-proportional). Nil disables it.
	Budget *Budget
	Now    func() time.Time
}

// RootKeySource re-reads operator root key material from its configured source.
// The keyring never retains the root (it is zeroed after boot), so the two
// rotations that need it read it through this seam. Every returned buffer is the
// caller's to zero.
type RootKeySource interface {
	// Current reads the primary root key (the one this instance boots under).
	Current(ctx context.Context) ([]byte, error)
	// Next reads the operator's NEW root key from its configured new-root
	// source, for rotate-root-key --prepare. It errors when no new-root source
	// is configured, so the request never carries key material.
	Next(ctx context.Context) ([]byte, error)
}

func (s *Rotation) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

// DEKScope selects what rotate-dek / reencrypt operate on: one project's DEK,
// or the instance DEK. The zero value (Instance false, empty ids) is invalid
// and refused, so a caller that forgets to name a scope gets a loud error
// rather than silently rotating the wrong key.
type DEKScope struct {
	Instance         bool
	OrgID, ProjectID string
}

func (sc DEKScope) validate() error {
	if sc.Instance {
		if sc.OrgID != "" || sc.ProjectID != "" {
			return fmt.Errorf("%w: instance DEK scope carries no org or project", domain.ErrInvalid)
		}
		return nil
	}
	if sc.OrgID == "" || sc.ProjectID == "" {
		return fmt.Errorf("%w: project DEK scope requires org and project ids", domain.ErrInvalid)
	}
	return nil
}

func (sc DEKScope) name() string {
	if sc.Instance {
		return "instance"
	}
	return "project"
}

// DEKRotation is one `rotate-dek`: the scope rotated and the new active version.
type DEKRotation struct {
	Scope     string
	OrgID     string
	ProjectID string
	Version   uint32
}

// RotateDEK appends a new DEK version for one project or the instance scope. New
// writes seal under it immediately; ciphertext under the previous version stays
// readable until `reencrypt` walks it. This is the append half of the ADR's
// keyring semantics — free, and incomplete on its own.
func (s *Rotation) RotateDEK(ctx context.Context, actor Actor, scope DEKScope) (DEKRotation, error) {
	if s.Keyring == nil {
		return DEKRotation{}, errors.New("service: DEK rotation requires a keyring")
	}
	if err := scope.validate(); err != nil {
		return DEKRotation{}, err
	}

	// Mint the successor outside the operator's transaction, like the token
	// rotation: the persistence closure is retryable, and only the attempt that
	// commits may adopt.
	var (
		next  crypto.WrappedKey
		adopt func()
		err   error
	)
	if scope.Instance {
		next, adopt, err = s.Keyring.PrepareInstanceDEKRotation()
	} else {
		next, adopt, err = s.Keyring.PrepareProjectDEKRotation(ctx, scope.OrgID, scope.ProjectID)
	}
	if err != nil {
		return DEKRotation{}, err
	}
	next.CreatedAt = store.CanonTime(s.now())

	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRotateDEK, domain.Scope{})
		if err != nil {
			return err
		}
		if err := r.Keys().RotateDEK(ctx, p, next); err != nil {
			return err
		}
		ev, err := newAuditEvent(ctx, audit.EventDEKRotated, caller.Principal,
			audit.Object{Type: "instance", ID: "instance"}, audit.OutcomeSuccess, "",
			audit.Payload{
				"scope":       scope.name(),
				"org_id":      scope.OrgID,
				"project_id":  scope.ProjectID,
				"key_version": int64(next.Version),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, ev)
	})
	if errors.Is(err, store.ErrRotationSuperseded) || errors.Is(err, crypto.ErrStaleMaster) {
		// A concurrent rotation won the store's compare-and-swap, or a master
		// rotation moved the wrapping master between mint and commit. Conflict,
		// not a fault: the caller retries against the current key state.
		return DEKRotation{}, fmt.Errorf("%w: %s", domain.ErrConflict, err)
	}
	if err != nil {
		return DEKRotation{}, err
	}
	// Only after commit: an attempt that rolled back must not leave the process
	// treating a version the datastore never recorded as active.
	adopt()
	return DEKRotation{
		Scope: scope.name(), OrgID: scope.OrgID, ProjectID: scope.ProjectID, Version: next.Version,
	}, nil
}

// MasterKeyRotation is one `rotate-master-key`: the new master version.
type MasterKeyRotation struct {
	Version uint32
}

// RotateMasterKey generates a new master key, re-wraps every tier-3 key under
// it, and retires the old master after a fenced check. It is step 2 of the
// post-compromise recovery order — an attacker who held process memory holds the
// master, so every DEK must be re-wrapped under a master they never saw.
//
// It refuses while the root is dual-wrapped: the two rotations are mutually
// exclusive, and the operator runs `rotate-root-key --finalize` first.
func (s *Rotation) RotateMasterKey(ctx context.Context, actor Actor) (MasterKeyRotation, error) {
	if s.Keyring == nil {
		return MasterKeyRotation{}, errors.New("service: master rotation requires a keyring")
	}
	if s.RootKey == nil {
		return MasterKeyRotation{}, errors.New("service: master rotation requires a root key source")
	}
	// §179 fail-closed default: master rotation rewraps every project DEK. Charged
	// (authorized-then-acquired) before the process-wide hierarchy lock, so a
	// rate-limited caller is refused without contending for the global lock.
	release, err := chargeDefaultAtEntry(ctx, s.DB, s.Budget, actor, authz.OpRotateMasterKey, domain.Scope{}, s.now)
	if err != nil {
		return MasterKeyRotation{}, err
	}
	defer release()
	// Process-wide serialization lives on the shared keyring, not this service:
	// two Rotation instances over one keyring must still not prepare the same
	// master version concurrently.
	s.Keyring.LockHierarchyRotation()
	defer s.Keyring.UnlockHierarchyRotation()
	root, err := s.RootKey.Current(ctx)
	if err != nil {
		return MasterKeyRotation{}, fmt.Errorf("service: read root key for master rotation: %w", err)
	}
	defer crypto.Zero(root)

	newMaster, rewrapped, adopt, abort, err := s.Keyring.PrepareMasterKeyRotation(ctx, root)
	if errors.Is(err, crypto.ErrMasterRotationBlocked) {
		return MasterKeyRotation{}, fmt.Errorf("%w: %s", domain.ErrConflict, err)
	}
	if errors.Is(err, crypto.ErrRootKeyMismatch) {
		return MasterKeyRotation{}, fmt.Errorf("%w: the configured root source does not match this instance", domain.ErrConflict)
	}
	if err != nil {
		return MasterKeyRotation{}, err
	}
	newMaster.CreatedAt = store.CanonTime(s.now())

	// The new master is resolvable in the keyring from prepare; abort removes and
	// zeroes it if the transaction never commits, so a rolled-back attempt leaves
	// no phantom master and leaks no key bytes.
	committed := false
	defer func() {
		if !committed {
			abort()
		}
	}()

	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRotateMasterKey, domain.Scope{})
		if err != nil {
			return err
		}
		if err := r.Keys().RotateMasterKey(ctx, p, newMaster, rewrapped); err != nil {
			return err
		}
		ev, err := newAuditEvent(ctx, audit.EventMasterKeyRotated, caller.Principal,
			audit.Object{Type: "instance", ID: "instance"}, audit.OutcomeSuccess, "",
			audit.Payload{"key_version": int64(newMaster.Version)})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, ev)
	})
	if errors.Is(err, store.ErrRotationSuperseded) || errors.Is(err, crypto.ErrMasterRotationBlocked) {
		return MasterKeyRotation{}, fmt.Errorf("%w: %s", domain.ErrConflict, err)
	}
	if err != nil {
		return MasterKeyRotation{}, err
	}
	committed = true
	adopt()
	return MasterKeyRotation{Version: newMaster.Version}, nil
}

// RootKeyRotationPhase selects one phase of the crash-safe root rotation.
type RootKeyRotationPhase string

const (
	RootRotatePrepare  RootKeyRotationPhase = "prepare"
	RootRotateVerify   RootKeyRotationPhase = "verify"
	RootRotateFinalize RootKeyRotationPhase = "finalize"
)

// RootKeyRotation is one phase of `rotate-root-key`: the phase run and the epoch
// it concerns (the new epoch for prepare/verify, the surviving epoch after
// finalize).
type RootKeyRotation struct {
	Phase string
	Epoch uint32
}

// RotateRootKey runs one phase of the crash-safe root rotation (encryption-model
// ADR § Rotation). No key material ever crosses the wire: prepare reads the NEW
// root from its server-side source and seals a second wrapper; verify re-reads
// the PRIMARY source and confirms the operator installed the new root there;
// finalize retires the old wrapper. A crash at any point leaves the instance
// bootable under either root until finalize.
func (s *Rotation) RotateRootKey(ctx context.Context, actor Actor, phase RootKeyRotationPhase) (RootKeyRotation, error) {
	if s.Keyring == nil {
		return RootKeyRotation{}, errors.New("service: root rotation requires a keyring")
	}
	if s.RootKey == nil {
		return RootKeyRotation{}, errors.New("service: root rotation requires a root key source")
	}
	// Same shared-keyring hierarchy lock as master rotation: root rotation reads
	// the live master to seal a wrapper, and prepare/finalize must not interleave
	// with a master rotation mutating the master set.
	s.Keyring.LockHierarchyRotation()
	defer s.Keyring.UnlockHierarchyRotation()
	switch phase {
	case RootRotatePrepare:
		return s.rootRotatePrepare(ctx, actor)
	case RootRotateVerify:
		return s.rootRotateVerify(ctx, actor)
	case RootRotateFinalize:
		return s.rootRotateFinalize(ctx, actor)
	default:
		return RootKeyRotation{}, fmt.Errorf("%w: unknown root rotation phase %q", domain.ErrInvalid, phase)
	}
}

func (s *Rotation) rootRotatePrepare(ctx context.Context, actor Actor) (RootKeyRotation, error) {
	newRoot, err := s.RootKey.Next(ctx)
	if err != nil {
		return RootKeyRotation{}, fmt.Errorf("service: read new root key: %w", err)
	}
	defer crypto.Zero(newRoot)
	wrapper, err := s.Keyring.PrepareRootKeyRotation(ctx, newRoot)
	if errors.Is(err, crypto.ErrRootRotationBlocked) {
		return RootKeyRotation{}, fmt.Errorf("%w: %s", domain.ErrConflict, err)
	}
	if err != nil {
		return RootKeyRotation{}, err
	}
	wrapper.CreatedAt = store.CanonTime(s.now())
	epoch := wrapper.RootKeyEpoch
	err = s.rootRotationTx(ctx, actor, audit.EventRootKeyRotationPrepared, epoch,
		func(ctx context.Context, r store.Repos, p authz.Proof) error {
			return r.Keys().RootKeyRotatePrepare(ctx, p, wrapper)
		})
	if errors.Is(err, store.ErrRotationSuperseded) || errors.Is(err, crypto.ErrRootRotationBlocked) {
		return RootKeyRotation{}, fmt.Errorf("%w: %s", domain.ErrConflict, err)
	}
	if err != nil {
		return RootKeyRotation{}, err
	}
	return RootKeyRotation{Phase: string(RootRotatePrepare), Epoch: epoch}, nil
}

func (s *Rotation) rootRotateVerify(ctx context.Context, actor Actor) (RootKeyRotation, error) {
	primary, err := s.RootKey.Current(ctx)
	if err != nil {
		return RootKeyRotation{}, fmt.Errorf("service: read primary root key: %w", err)
	}
	defer crypto.Zero(primary)
	epoch, err := s.Keyring.VerifyRootKeyRotation(ctx, primary)
	if errors.Is(err, crypto.ErrNotDualWrapped) {
		return RootKeyRotation{}, fmt.Errorf("%w: %s", domain.ErrConflict, err)
	}
	if errors.Is(err, crypto.ErrRootKeyMismatch) {
		return RootKeyRotation{}, fmt.Errorf("%w: the primary root source does not hold the new root yet; install it before verifying", domain.ErrConflict)
	}
	if err != nil {
		return RootKeyRotation{}, err
	}
	err = s.rootRotationTx(ctx, actor, audit.EventRootKeyRotationVerified, epoch, nil)
	if err != nil {
		return RootKeyRotation{}, err
	}
	return RootKeyRotation{Phase: string(RootRotateVerify), Epoch: epoch}, nil
}

func (s *Rotation) rootRotateFinalize(ctx context.Context, actor Actor) (RootKeyRotation, error) {
	// Re-verify before retiring anything: finalize is destructive (the old
	// wrapper is gone after it), so it must confirm the primary source holds the
	// new root — otherwise an operator who ran --prepare and skipped --verify, or
	// whose primary still holds the old root, retires the only wrapper their
	// installed root can open and bricks the next boot. The three-phase order
	// stays, but finalize no longer trusts that verify was run.
	primary, err := s.RootKey.Current(ctx)
	if err != nil {
		return RootKeyRotation{}, fmt.Errorf("service: read primary root key: %w", err)
	}
	defer crypto.Zero(primary)
	if _, err := s.Keyring.VerifyRootKeyRotation(ctx, primary); errors.Is(err, crypto.ErrNotDualWrapped) {
		return RootKeyRotation{}, fmt.Errorf("%w: %s", domain.ErrConflict, err)
	} else if errors.Is(err, crypto.ErrRootKeyMismatch) {
		return RootKeyRotation{}, fmt.Errorf("%w: the primary root source does not hold the new root; install it and verify before finalizing", domain.ErrConflict)
	} else if err != nil {
		return RootKeyRotation{}, err
	}

	var newEpoch uint32
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRotateRootKey, domain.Scope{})
		if err != nil {
			return err
		}
		newEpoch, err = r.Keys().RootKeyRotateFinalize(ctx, p)
		if err != nil {
			return err
		}
		ev, err := newAuditEvent(ctx, audit.EventRootKeyRotationFinalized, caller.Principal,
			audit.Object{Type: "instance", ID: "instance"}, audit.OutcomeSuccess, "",
			audit.Payload{"root_key_epoch": int64(newEpoch)})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, ev)
	})
	if errors.Is(err, store.ErrRotationSuperseded) || errors.Is(err, crypto.ErrNotDualWrapped) {
		return RootKeyRotation{}, fmt.Errorf("%w: %s", domain.ErrConflict, err)
	}
	if err != nil {
		return RootKeyRotation{}, err
	}
	// The old root no longer boots; the running process should stop warning.
	s.Keyring.ClearRootRotationPending()
	return RootKeyRotation{Phase: string(RootRotateFinalize), Epoch: newEpoch}, nil
}

// rootRotationTx authorizes OpRotateRootKey, runs the optional store mutation,
// and writes the phase's audit event with a known epoch. prepare and verify use
// it — both know their epoch before the transaction; finalize learns its epoch
// inside its own transaction and does not.
func (s *Rotation) rootRotationTx(ctx context.Context, actor Actor, event audit.EventType, epoch uint32, mutate func(context.Context, store.Repos, authz.Proof) error) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRotateRootKey, domain.Scope{})
		if err != nil {
			return err
		}
		if mutate != nil {
			if err := mutate(ctx, r, p); err != nil {
				return err
			}
		}
		ev, err := newAuditEvent(ctx, event, caller.Principal,
			audit.Object{Type: "instance", ID: "instance"}, audit.OutcomeSuccess, "",
			audit.Payload{"root_key_epoch": int64(epoch)})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, ev)
	})
}
