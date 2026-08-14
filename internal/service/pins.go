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

const (
	PinQuotaPerProject     = 100
	DefaultPinLifetimeDays = 180
	MaxPinLifetimeDays     = 365
	DefaultPinLifetime     = DefaultPinLifetimeDays * 24 * time.Hour
	MaxPinLifetime         = MaxPinLifetimeDays * 24 * time.Hour
)

type PinAction string

const (
	PinCreated    PinAction = "created"
	PinReassigned PinAction = "reassigned"
	PinRenewed    PinAction = "renewed"
)

type Pins struct {
	DB      *store.DB
	Keyring *crypto.Keyring
	Now     func() time.Time
}

func (s *Pins) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

type SetPinRequest struct {
	WorkloadPrincipalID domain.PrincipalID
	Revision            int64
	ExpiresAt           time.Time
	OverrideSchema      bool
}

type PinView struct {
	ID                   string
	WorkloadPrincipalID  string
	Revision             int64
	AuthorityPrincipalID string
	ExpiresAt            time.Time
	CreatedAt            time.Time
	AuthorizedAt         time.Time
	HistoryAuthorized    bool
	SchemaOverride       bool
	Expired              bool
}

type SetPinResult struct {
	Action PinAction
	Pin    PinView
}

func (s *Pins) Set(ctx context.Context, actor Actor, scope domain.Scope, request SetPinRequest) (SetPinResult, error) {
	if scope.Env == "" {
		return SetPinResult{}, fmt.Errorf("%w: a pin addresses an environment", domain.ErrInvalid)
	}
	if request.WorkloadPrincipalID == "" {
		return SetPinResult{}, invalidDetail("pin workload principal is required")
	}
	if request.Revision <= 0 {
		return SetPinResult{}, invalidDetail("pin revision must be positive")
	}
	now := store.CanonTime(s.now())
	expiresAt := request.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = now.Add(DefaultPinLifetime)
	}
	expiresAt = store.CanonTime(expiresAt)
	var expiryRefusal error
	expiryCause := ""
	if !expiresAt.After(now) {
		expiryRefusal = invalidDetail("pin expiry must be in the future")
		expiryCause = "not-future"
	} else if expiresAt.After(now.Add(MaxPinLifetime)) {
		expiryRefusal = invalidDetail("pin expiry exceeds the maximum %d days", MaxPinLifetimeDays)
		expiryCause = "beyond-maximum"
	}
	sealer, err := sealerFor(ctx, s.DB, s.Keyring, actor, authz.OpPinSet, scope)
	if err != nil {
		return SetPinResult{}, err
	}

	var out SetPinResult
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpPinSet, scope)
		if err != nil {
			return err
		}
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		if expiryRefusal != nil {
			ev, err := newAuditEvent(ctx, audit.EventPinExpiryRefused, caller.Principal,
				audit.Object{Type: "environment", ID: string(scope.Env)}, audit.OutcomeFailure, "", audit.Payload{
					"workload_principal_id": string(request.WorkloadPrincipalID),
					"requested_expires_at":  expiresAt.Format(time.RFC3339Nano),
					"max_days":              MaxPinLifetimeDays,
					"cause":                 expiryCause,
				})
			if err != nil {
				return err
			}
			return r.Audit().InsertTenant(ctx, p, ev)
		}
		workload, err := az.ServiceAccountByPrincipal(ctx, request.WorkloadPrincipalID)
		if err != nil {
			return fmt.Errorf("service: resolve pin workload: %w", err)
		}
		if workload.Kind != domain.ClassWorkload || workload.Org != scope.Org || workload.Project != scope.Project {
			return domain.ErrNotFound
		}
		existing, existingErr := r.Pins().GetForWorkload(ctx, p, string(request.WorkloadPrincipalID))
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			return existingErr
		}
		latest, err := r.Snapshots().Latest(ctx, p)
		if err != nil {
			return err
		}
		target, err := r.Snapshots().AtRevision(ctx, p, request.Revision)
		if err != nil {
			return err
		}
		if !target.PayloadPresent {
			return invalidDetail("pin revision %d payload was collected", request.Revision)
		}
		renewing := existingErr == nil && existing.Revision == target.Revision
		historyGated := target.Revision != latest.Revision
		schemaOverride := false
		if renewing {
			// Renewal rechecks exactly the grants recorded at creation or
			// reassignment. A later publish cannot retroactively add a history
			// requirement, and existing schema-invalid pins are grandfathered.
			historyGated = existing.HistoryAuthorized
			schemaOverride = existing.SchemaOverride
		}
		if historyGated {
			if _, err := az.Authorize(ctx, caller, authz.OpPinSetHistory, scope); err != nil {
				return err
			}
		}
		if !renewing {
			if err := validatePinnedSnapshot(ctx, r, p, sealer, scope, target); err != nil {
				if !request.OverrideSchema || !errors.Is(err, domain.ErrInvalid) {
					return err
				}
				schemaOverride = true
			}
		}
		action := PinCreated
		eventType := audit.EventPinCreated
		id, err := newID("pin")
		if err != nil {
			return err
		}
		createdAt := now
		if existingErr == nil {
			if renewing {
				action, eventType = PinRenewed, audit.EventPinRenewed
				id, createdAt = existing.ID, existing.CreatedAt
			} else {
				action, eventType = PinReassigned, audit.EventPinReassigned
			}
		} else {
			count, err := r.Pins().CountProject(ctx, p)
			if err != nil {
				return err
			}
			if count >= PinQuotaPerProject {
				return invalidDetail("pin quota %d per project is exhausted", PinQuotaPerProject)
			}
		}
		if existingErr == nil {
			deleted, err := r.Pins().Delete(ctx, p, string(request.WorkloadPrincipalID))
			if err != nil {
				return err
			}
			if !deleted {
				return domain.ErrNotFound
			}
		}
		pin := store.NewRevisionPin{
			ID: id, WorkloadPrincipalID: string(request.WorkloadPrincipalID),
			SnapshotID: target.ID, Revision: target.Revision,
			AuthorityPrincipalID: string(caller.Principal), ExpiresAt: expiresAt,
			CreatedAt: createdAt, AuthorizedAt: now, HistoryAuthorized: historyGated,
			SchemaOverride: schemaOverride,
		}
		if err := r.Pins().Insert(ctx, p, pin); err != nil {
			return err
		}
		generation, err := az.PinGeneration(ctx, request.WorkloadPrincipalID, scope.Env)
		if err != nil {
			return err
		}
		if err := az.SetPinGeneration(ctx, request.WorkloadPrincipalID, scope.Env, generation+1); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, eventType, caller.Principal,
			audit.Object{Type: "environment", ID: string(scope.Env)}, audit.Payload{
				"workload_principal_id": string(request.WorkloadPrincipalID),
				"revision":              target.Revision, "expires_at": expiresAt.Format(time.RFC3339Nano),
				"schema_override":    schemaOverride,
				"history_authorized": historyGated,
			})
		if err != nil {
			return err
		}
		if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
			return err
		}
		out = SetPinResult{Action: action, Pin: pinView(store.RevisionPin{
			ID: id, WorkloadPrincipalID: string(request.WorkloadPrincipalID), Revision: target.Revision,
			AuthorityPrincipalID: string(caller.Principal), ExpiresAt: expiresAt,
			CreatedAt: createdAt, AuthorizedAt: now, HistoryAuthorized: historyGated,
			SchemaOverride: schemaOverride,
		}, now)}
		return nil
	})
	if err != nil {
		return SetPinResult{}, err
	}
	if expiryRefusal != nil {
		return SetPinResult{}, expiryRefusal
	}
	return out, nil
}

func validatePinnedSnapshot(ctx context.Context, r store.Repos, p authz.Proof, sealer *crypto.ProjectSealer,
	scope domain.Scope, snapshot store.Snapshot) error {
	keys, err := r.Catalogue().List(ctx, p)
	if err != nil {
		return err
	}
	presence, err := r.Catalogue().ListPresence(ctx, p)
	if err != nil {
		return err
	}
	entries, err := r.Snapshots().Entries(ctx, p, snapshot.ID)
	if err != nil {
		return err
	}
	entryByKey := make(map[string]store.SnapshotEntry, len(entries))
	for _, entry := range entries {
		entryByKey[entry.KeyID] = entry
	}
	if err := validateSnapshotEntryKeys("pin revision", snapshot.Revision, keys, entries); err != nil {
		return err
	}
	cells := make([]resolvedCell, 0, len(keys))
	for _, key := range keys {
		cell := resolvedCell{key: key}
		if entry, ok := entryByKey[key.ID]; ok {
			plain, err := sealer.OpenField(snapshotAAD(entry.OrgID, entry.ProjectID,
				entry.EnvironmentID, entry.KeyID, entry.SnapshotID, entry.ID), entry.Ciphertext)
			if err != nil {
				return fmt.Errorf("service: snapshot entry %s: %w", entry.ID, err)
			}
			cell.set, cell.value = true, string(plain)
		}
		cells = append(cells, cell)
	}
	return validateResolved(cells, presence, string(scope.Env))
}

func (s *Pins) List(ctx context.Context, actor Actor, scope domain.Scope) ([]PinView, error) {
	now := s.now()
	var out []PinView
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpPinList, scope)
		if err != nil {
			return err
		}
		pins, err := r.Pins().List(ctx, p)
		if err != nil {
			return err
		}
		out = make([]PinView, 0, len(pins))
		for _, pin := range pins {
			out = append(out, pinView(pin, now))
		}
		return nil
	})
	return out, err
}

func (s *Pins) Release(ctx context.Context, actor Actor, scope domain.Scope, workloadPrincipalID domain.PrincipalID) error {
	if workloadPrincipalID == "" {
		return invalidDetail("pin workload principal is required")
	}
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpPinRelease, scope)
		if err != nil {
			return err
		}
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		pin, err := r.Pins().GetForWorkload(ctx, p, string(workloadPrincipalID))
		if err != nil {
			return err
		}
		deleted, err := r.Pins().Delete(ctx, p, string(workloadPrincipalID))
		if err != nil {
			return err
		}
		if !deleted {
			return domain.ErrNotFound
		}
		generation, err := az.PinGeneration(ctx, workloadPrincipalID, scope.Env)
		if err != nil {
			return err
		}
		if err := az.SetPinGeneration(ctx, workloadPrincipalID, scope.Env, generation+1); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventPinReleased, caller.Principal,
			audit.Object{Type: "environment", ID: string(scope.Env)}, audit.Payload{
				"workload_principal_id": string(workloadPrincipalID), "revision": pin.Revision,
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
}

func pinView(pin store.RevisionPin, now time.Time) PinView {
	return PinView{
		ID: pin.ID, WorkloadPrincipalID: pin.WorkloadPrincipalID, Revision: pin.Revision,
		AuthorityPrincipalID: pin.AuthorityPrincipalID, ExpiresAt: pin.ExpiresAt,
		CreatedAt: pin.CreatedAt, AuthorizedAt: pin.AuthorizedAt,
		HistoryAuthorized: pin.HistoryAuthorized, SchemaOverride: pin.SchemaOverride,
		Expired: !pin.ExpiresAt.After(now),
	}
}
