package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

type Adapters struct {
	DB      *store.DB
	Auth    *Auth
	Keyring *crypto.Keyring
	// Budget applies the § 179 adapter sync/trigger concurrency bound (4 per
	// org). Nil disables it. The per-principal 10/min rate is deferred (see
	// budget.go).
	Budget         *Budget
	Now            func() time.Time
	PlanModule     func(origin, credential string) (adapter.Module, func(), error)
	ProviderModule func(provider, origin, credential string) (adapter.Module, func(), error)
}

func (s *Adapters) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

type AdapterTargetView struct {
	Target    store.AdapterTarget
	Conflicts []store.AdapterConflictArtifact
	Mapping   []adapter.ManifestEntry
	Workflow  string
}

type AdapterView struct {
	Adapter         store.AdapterRecord
	Targets         []AdapterTarget
	TargetConflicts map[string][]store.AdapterConflictArtifact
}

type AdapterTarget = store.AdapterTarget
type AdapterConflictEntry = store.AdapterConflictEntry
type AdapterConflictArtifact = store.AdapterConflictArtifact
type AdapterRecord = store.AdapterRecord
type AdapterMove = store.AdapterMove

type AdapterTargetInput struct {
	EnvironmentID          string
	DestinationKind        string
	DestinationOwner       string
	DestinationName        string
	DestinationEnvironment string
	Visibility             string
	SelectedRepositoryIDs  []int64
	NamePrefix             string
	KeyIDs                 []string
}

func adapterDestination(input AdapterTargetInput) adapter.Destination {
	return adapter.Destination{
		Kind: adapter.DestinationKind(input.DestinationKind), Owner: input.DestinationOwner,
		Name: input.DestinationName, Environment: input.DestinationEnvironment,
		Visibility: input.Visibility, SelectedRepositoryIDs: append([]int64(nil), input.SelectedRepositoryIDs...),
	}
}

func targetMutation(id, adapterID string, input AdapterTargetInput, connection adapter.Connection) store.AdapterTargetMutation {
	repositoryID := int64(0)
	if input.DestinationKind == string(adapter.Environment) {
		repositoryID = connection.RepositoryID
	}
	return store.AdapterTargetMutation{
		ID: id, AdapterID: adapterID, EnvironmentID: input.EnvironmentID,
		DestinationKind: input.DestinationKind, DestinationOwner: input.DestinationOwner,
		DestinationName: input.DestinationName, DestinationEnvironment: input.DestinationEnvironment,
		DestinationID: connection.DestinationID, RepositoryID: repositoryID,
		Visibility: input.Visibility, SelectedRepositoryIDs: append([]int64(nil), input.SelectedRepositoryIDs...),
		NamePrefix: input.NamePrefix, KeyIDs: append([]string(nil), input.KeyIDs...),
	}
}

func (s *Adapters) environmentCreateAudit(actor Actor, scope domain.Scope, targetID string, input AdapterTargetInput, correlationID string) (func(context.Context) error, func(context.Context, error) error) {
	var effectID string
	payload := audit.Payload{"surface": "environment", "effective_name": input.DestinationEnvironment, "disposition": "create"}
	before := func(ctx context.Context) error {
		return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
			now := store.CanonTime(s.now())
			caller, err := actor.resolve(ctx, az, now)
			if err != nil {
				return err
			}
			proof, err := az.Authorize(ctx, caller, authz.OpAdapterConfigure, scope)
			if err != nil {
				return err
			}
			event, err := newAuditEvent(ctx, audit.EventAdapterPushIntent, caller.Principal, audit.Object{Type: "adapter-target", ID: targetID}, audit.OutcomeIntent, correlationID, payload)
			if err != nil {
				return err
			}
			fence := store.AdapterConfigureFence{
				TargetID: targetID, EnvironmentID: input.EnvironmentID, DestinationKind: input.DestinationKind,
				DestinationOwner: input.DestinationOwner, DestinationName: input.DestinationName, DestinationEnvironment: input.DestinationEnvironment,
				Generation: 1, EffectID: event.ID, LeaseExpiresAt: now.Add(adapter.LeaseTime), At: now,
			}
			if err := r.Adapters().BeginConfigureEffect(ctx, proof, fence); err != nil {
				return err
			}
			if err := r.Audit().InsertTenant(ctx, proof, event); err != nil {
				return err
			}
			effectID = event.ID
			return nil
		})
	}
	after := func(ctx context.Context, providerErr error) error {
		if effectID == "" {
			return fmt.Errorf("%w: environment configure effect has no durable fence", domain.ErrConflict)
		}
		return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
			now := store.CanonTime(s.now())
			caller, err := actor.resolve(ctx, az, now)
			if err != nil {
				return err
			}
			proof, err := az.Authorize(ctx, caller, authz.OpAdapterConfigure, scope)
			if err != nil {
				return err
			}
			outcome, state := audit.OutcomeSuccess, "succeeded"
			if providerErr != nil {
				outcome, state = audit.OutcomeFailure, "failed"
			}
			event, err := newAuditEvent(ctx, audit.EventAdapterPushOutcome, caller.Principal, audit.Object{Type: "adapter-target", ID: targetID}, outcome, correlationID, payload)
			if err != nil {
				return err
			}
			if err := r.Adapters().FinishConfigureEffect(ctx, proof, targetID, effectID, state, now); err != nil {
				return err
			}
			return r.Audit().InsertTenant(ctx, proof, event)
		})
	}
	return before, after
}

type CreateAdapterRequest struct {
	Provider   string
	Origin     string
	Credential []byte
	Target     AdapterTargetInput
}

type UpdateAdapterTargetRequest struct {
	TargetID           string
	ExpectedGeneration int64
	Target             AdapterTargetInput
}

type AdoptAdapterRequest struct {
	TargetID              string
	ArtifactID            string
	ExpectedGeneration    int64
	ExpectedDestinationID int64
	ExpectedRepositoryID  int64
	Entries               []store.AdapterConflictEntry
}

type AdoptAdapterResult struct {
	Generation int64
	JobID      string
}

type AdapterPlanResult struct {
	ArtifactID string
	Plan       adapter.Plan
}

type AdapterTeardownResult struct {
	Targets  []store.AdapterTeardownResult
	Orphaned []string
}

func (s *Adapters) providerGate(actor Actor, operation authz.Operation, projectScope domain.Scope, environmentID string) func(context.Context) error {
	return func(ctx context.Context) error {
		return tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
			caller, err := actor.resolve(ctx, az, s.now())
			if err != nil {
				return err
			}
			if _, err := az.Authorize(ctx, caller, operation, projectScope); err != nil {
				return err
			}
			_, err = az.Authorize(ctx, caller, authz.OpAdapterPush, domain.Scope{Org: projectScope.Org, Project: projectScope.Project, Env: domain.EnvID(environmentID)})
			return err
		})
	}
}

func (s *Adapters) requireAdapterCeremony(ctx context.Context, az *authz.TxAuthorizer, caller authz.Identity, projectScope domain.Scope, environmentIDs []string, operation authz.Operation, now time.Time) error {
	for _, environmentID := range environmentIDs {
		envScope := domain.Scope{Org: projectScope.Org, Project: projectScope.Project, Env: domain.EnvID(environmentID)}
		if _, err := az.Authorize(ctx, caller, authz.OpAdapterPush, envScope); err != nil {
			return err
		}
		if skipsCeremony(caller) {
			continue
		}
		if s.Auth == nil {
			return ErrNoCeremonySeam
		}
		if err := s.Auth.ConsumeAdapterReauthWindow(ctx, az, caller.SessionID, environmentID, operation, environmentIDs, now); err != nil {
			return fmt.Errorf("%w (%s)", ErrReauthRequired, environmentID)
		}
	}
	return nil
}

func adapterEnvironmentSet(environmentIDs []string, additional ...string) []string {
	out := append([]string(nil), environmentIDs...)
	out = append(out, additional...)
	slices.Sort(out)
	return slices.Compact(out)
}

func (s *Adapters) consumeAdapterCeremony(ctx context.Context, actor Actor, scope domain.Scope, environmentIDs []string, operation authz.Operation, now time.Time) (authz.Identity, error) {
	var caller authz.Identity
	err := tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		var err error
		caller, err = actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		if _, err := az.Authorize(ctx, caller, operation, scope); err != nil {
			return err
		}
		return s.requireAdapterCeremony(ctx, az, caller, scope, adapterEnvironmentSet(environmentIDs), operation, now)
	})
	return caller, err
}

func (s *Adapters) Create(ctx context.Context, actor Actor, scope domain.Scope, request CreateAdapterRequest) (AdapterView, error) {
	if request.Provider == "" {
		request.Provider = "forgejo"
	}
	if scope.Project == "" || scope.Env != "" || request.Origin == "" || len(request.Credential) == 0 || request.Target.EnvironmentID == "" || len(request.Target.KeyIDs) == 0 {
		return AdapterView{}, fmt.Errorf("%w: adapter create requires project scope, credential, and first target", domain.ErrInvalid)
	}
	now := store.CanonTime(s.now())
	if _, err := s.consumeAdapterCeremony(ctx, actor, scope, []string{request.Target.EnvironmentID}, authz.OpAdapterConfigure, now); err != nil {
		return AdapterView{}, err
	}
	adapterID, err := newID("adp")
	if err != nil {
		return AdapterView{}, err
	}
	targetID, err := newID("tgt")
	if err != nil {
		return AdapterView{}, err
	}
	sealer, err := sealerFor(ctx, s.DB, s.Keyring, actor, authz.OpAdapterConfigure, scope)
	if err != nil {
		return AdapterView{}, err
	}
	plain := append([]byte(nil), request.Credential...)
	defer crypto.Zero(plain)
	sealed, err := sealer.SealField(crypto.ProjectFieldAAD{OrgID: string(scope.Org), ProjectID: string(scope.Project), OwnerTable: "adapters", OwnerRowID: adapterID, FieldTag: "credential"}, plain)
	if err != nil {
		return AdapterView{}, err
	}
	module, release, err := s.planModule(request.Provider, request.Origin, string(plain))
	if err != nil {
		return AdapterView{}, err
	}
	if release != nil {
		defer release()
	}
	if err := module.ValidateConfig(adapter.Config{Origin: request.Origin}); err != nil {
		return AdapterView{}, err
	}
	configureEventID, err := audit.NewEventID()
	if err != nil {
		return AdapterView{}, err
	}
	beforeCreate, afterCreate := s.environmentCreateAudit(actor, scope, targetID, request.Target, configureEventID)
	destination := adapterDestination(request.Target)
	connection, err := module.TestConnection(ctx, adapter.ConnectionRequest{Config: adapter.Config{Origin: request.Origin}, Destination: destination, Access: adapter.Access{Credential: string(plain)}, Gate: s.providerGate(actor, authz.OpAdapterConfigure, scope, request.Target.EnvironmentID), AllowEnvironmentCreate: true, BeforeEnvironmentCreate: beforeCreate, AfterEnvironmentCreate: afterCreate})
	if err != nil {
		return AdapterView{}, err
	}
	var out AdapterView
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpAdapterConfigure, scope)
		if err != nil {
			return err
		}
		// Writer fence (invariant 7): refuse if a rotate-dek retired the DEK
		// version the credential was sealed under.
		if err := fenceProject(ctx, r, proof, sealer, scope); err != nil {
			return err
		}
		mutation := store.AdapterCreate{ID: adapterID, Provider: request.Provider, Origin: request.Origin, CredentialCiphertext: sealed, CredentialExpiresAt: connection.CredentialExpiresAt, AuthorityPrincipalID: string(caller.Principal), At: now, Target: targetMutation(targetID, adapterID, request.Target, connection)}
		record, target, err := r.Adapters().Create(ctx, proof, mutation)
		if err != nil {
			return err
		}
		out = AdapterView{Adapter: record, Targets: []store.AdapterTarget{target}}
		ev, err := domainEvent(ctx, audit.EventAdapterConfigure, caller.Principal, audit.Object{Type: "adapter", ID: adapterID}, audit.Payload{"mutation": "adapter-create", "authority": string(caller.Principal)})
		if err != nil {
			return err
		}
		ev.ID = configureEventID
		return r.Audit().InsertTenant(ctx, proof, ev)
	})
	return out, err
}

func (s *Adapters) Get(ctx context.Context, actor Actor, scope domain.Scope, adapterID string) (AdapterView, error) {
	if scope.Project == "" || scope.Env != "" || adapterID == "" {
		return AdapterView{}, fmt.Errorf("%w: adapter show requires project scope and adapter id", domain.ErrInvalid)
	}
	var out AdapterView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpAdapterInspect, scope)
		if err != nil {
			return err
		}
		out.Adapter, err = r.Adapters().Get(ctx, p, adapterID)
		if err != nil {
			return err
		}
		out.Targets, err = r.Adapters().ListTargets(ctx, p, adapterID)
		if err != nil {
			return err
		}
		out.TargetConflicts = make(map[string][]store.AdapterConflictArtifact, len(out.Targets))
		for _, target := range out.Targets {
			conflicts, err := r.Adapters().Conflicts(ctx, p, target.ID)
			if err != nil {
				return err
			}
			out.TargetConflicts[target.ID] = conflicts
		}
		ev, err := domainEvent(ctx, audit.EventAdapterInspect, caller.Principal, audit.Object{Type: "adapter", ID: adapterID}, audit.Payload{"row_count": 1})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	return out, err
}

func (s *Adapters) List(ctx context.Context, actor Actor, scope domain.Scope) ([]AdapterView, error) {
	if scope.Project == "" || scope.Env != "" {
		return nil, fmt.Errorf("%w: adapter list requires project scope", domain.ErrInvalid)
	}
	var out []AdapterView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpAdapterInspect, scope)
		if err != nil {
			return err
		}
		records, err := r.Adapters().List(ctx, p)
		if err != nil {
			return err
		}
		for _, record := range records {
			targets, err := r.Adapters().ListTargets(ctx, p, record.ID)
			if err != nil {
				return err
			}
			view := AdapterView{Adapter: record, Targets: targets, TargetConflicts: make(map[string][]store.AdapterConflictArtifact, len(targets))}
			for _, target := range targets {
				conflicts, err := r.Adapters().Conflicts(ctx, p, target.ID)
				if err != nil {
					return err
				}
				view.TargetConflicts[target.ID] = conflicts
			}
			out = append(out, view)
		}
		ev, err := domainEvent(ctx, audit.EventAdapterInspect, caller.Principal, audit.Object{Type: "adapter-list", ID: string(scope.Project)}, audit.Payload{"row_count": len(out)})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	return out, err
}

func (s *Adapters) AddTarget(ctx context.Context, actor Actor, scope domain.Scope, adapterID string, input AdapterTargetInput) (store.AdapterTarget, error) {
	if scope.Project == "" || scope.Env != "" || adapterID == "" || input.EnvironmentID == "" || len(input.KeyIDs) == 0 {
		return store.AdapterTarget{}, fmt.Errorf("%w: target add requires adapter, environment, destination, and keys", domain.ErrInvalid)
	}
	var record store.AdapterRecord
	var ciphertext []byte
	var authorizedEnvironments []string
	now := store.CanonTime(s.now())
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpAdapterConfigure, scope)
		if err != nil {
			return err
		}
		authorizedEnvironments, err = r.Adapters().Environments(ctx, p, adapterID)
		if err != nil {
			return err
		}
		authorizedEnvironments = adapterEnvironmentSet(authorizedEnvironments, input.EnvironmentID)
		return s.requireAdapterCeremony(ctx, az, caller, scope, authorizedEnvironments, authz.OpAdapterConfigure, now)
	})
	if err != nil {
		return store.AdapterTarget{}, err
	}
	sealer, err := sealerFor(ctx, s.DB, s.Keyring, actor, authz.OpAdapterConfigure, scope)
	if err != nil {
		return store.AdapterTarget{}, err
	}
	err = tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpAdapterConfigure, scope)
		if err != nil {
			return err
		}
		record, ciphertext, err = r.Adapters().Configuration(ctx, p, adapterID)
		return err
	})
	if err != nil {
		return store.AdapterTarget{}, err
	}
	if len(ciphertext) == 0 {
		return store.AdapterTarget{}, adapter.ErrProviderAuth
	}
	plain, err := sealer.OpenField(crypto.ProjectFieldAAD{OrgID: string(scope.Org), ProjectID: string(scope.Project), OwnerTable: "adapters", OwnerRowID: adapterID, FieldTag: "credential"}, ciphertext)
	if err != nil {
		return store.AdapterTarget{}, err
	}
	defer crypto.Zero(plain)
	module, release, err := s.planModule(record.Provider, record.Origin, string(plain))
	if err != nil {
		return store.AdapterTarget{}, err
	}
	if release != nil {
		defer release()
	}
	targetID, err := newID("tgt")
	if err != nil {
		return store.AdapterTarget{}, err
	}
	configureEventID, err := audit.NewEventID()
	if err != nil {
		return store.AdapterTarget{}, err
	}
	beforeCreate, afterCreate := s.environmentCreateAudit(actor, scope, targetID, input, configureEventID)
	destination := adapterDestination(input)
	connection, err := module.TestConnection(ctx, adapter.ConnectionRequest{Config: adapter.Config{Origin: record.Origin}, Destination: destination, Access: adapter.Access{Credential: string(plain)}, Gate: s.providerGate(actor, authz.OpAdapterConfigure, scope, input.EnvironmentID), AllowEnvironmentCreate: true, BeforeEnvironmentCreate: beforeCreate, AfterEnvironmentCreate: afterCreate})
	if err != nil {
		return store.AdapterTarget{}, err
	}
	var out store.AdapterTarget
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpAdapterConfigure, scope)
		if err != nil {
			return err
		}
		environmentIDs, err := r.Adapters().Environments(ctx, p, adapterID)
		if err != nil {
			return err
		}
		if currentSet := adapterEnvironmentSet(environmentIDs, input.EnvironmentID); !slices.Equal(currentSet, authorizedEnvironments) {
			return ErrReauthUnitMismatch
		}
		added, err := r.Adapters().AddTarget(ctx, p, store.AdapterTargetUpdate{CredentialExpiresAt: connection.CredentialExpiresAt, AuthorityPrincipalID: string(caller.Principal), At: now, Target: targetMutation(targetID, adapterID, input, connection)})
		if err != nil {
			return err
		}
		out = added.Target
		ev, err := domainEvent(ctx, audit.EventAdapterConfigure, caller.Principal, audit.Object{Type: "adapter-target", ID: targetID}, audit.Payload{
			"mutation": "target-add", "previous_authority": added.PreviousAuthorityPrincipalID, "authority": added.AuthorityPrincipalID,
		})
		if err != nil {
			return err
		}
		ev.ID = configureEventID
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	return out, err
}

func (s *Adapters) UpdateTarget(ctx context.Context, actor Actor, scope domain.Scope, request UpdateAdapterTargetRequest) (store.AdapterTarget, error) {
	if scope.Project == "" || scope.Env != "" || request.TargetID == "" || request.ExpectedGeneration <= 0 || len(request.Target.KeyIDs) == 0 {
		return store.AdapterTarget{}, fmt.Errorf("%w: target update requires target, generation, and full keys replacement", domain.ErrInvalid)
	}
	if err := s.preflightTargetRouting(ctx, actor, scope, request); err != nil {
		return store.AdapterTarget{}, err
	}
	now := store.CanonTime(s.now())
	var out store.AdapterTarget
	err := retryAdapterProviderFence(ctx, func() error {
		return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
			caller, err := actor.resolve(ctx, az, now)
			if err != nil {
				return err
			}
			p, err := az.Authorize(ctx, caller, authz.OpAdapterConfigure, scope)
			if err != nil {
				return err
			}
			current, err := r.Adapters().Target(ctx, p, request.TargetID)
			if err != nil {
				return err
			}
			if current.Generation != request.ExpectedGeneration {
				return adapter.ErrSuperseded
			}
			if current.Provider == "github-actions" && request.Target.DestinationKind == string(adapter.Organization) && request.Target.Visibility == "" {
				return fmt.Errorf("%w: GitHub organization target requires all, private, or selected visibility", domain.ErrInvalid)
			}
			oldIDs, err := r.Adapters().TargetKeyIDs(ctx, p, request.TargetID)
			if err != nil {
				return err
			}
			slices.Sort(oldIDs)
			newIDs := append([]string(nil), request.Target.KeyIDs...)
			slices.Sort(newIDs)
			widened := false
			for _, id := range newIDs {
				if !slices.Contains(oldIDs, id) {
					widened = true
					break
				}
			}
			full := widened || request.Target.NamePrefix != current.NamePrefix ||
				adapter.RecipientSetNeedsCeremony(current.Visibility, current.SelectedRepositoryIDs, request.Target.Visibility, request.Target.SelectedRepositoryIDs)
			authority := current.AuthorityPrincipalID
			if full {
				environmentIDs, err := r.Adapters().Environments(ctx, p, current.AdapterID)
				if err != nil {
					return err
				}
				if err := s.requireAdapterCeremony(ctx, az, caller, scope, adapterEnvironmentSet(environmentIDs), authz.OpAdapterConfigure, now); err != nil {
					return err
				}
				authority = string(caller.Principal)
			}
			updated, err := r.Adapters().UpdateTarget(ctx, p, store.AdapterTargetUpdate{ExpectedGeneration: request.ExpectedGeneration, AuthorityPrincipalID: authority, At: now, Target: store.AdapterTargetMutation{ID: request.TargetID, AdapterID: current.AdapterID, EnvironmentID: request.Target.EnvironmentID, DestinationKind: request.Target.DestinationKind, DestinationOwner: request.Target.DestinationOwner, DestinationName: request.Target.DestinationName, DestinationEnvironment: request.Target.DestinationEnvironment, DestinationID: current.DestinationID, RepositoryID: current.RepositoryID, Visibility: request.Target.Visibility, SelectedRepositoryIDs: append([]int64(nil), request.Target.SelectedRepositoryIDs...), NamePrefix: request.Target.NamePrefix, KeyIDs: newIDs}})
			if err != nil {
				return err
			}
			out = updated.Target
			payload := audit.Payload{"mutation": "target-update", "authority": updated.AuthorityPrincipalID}
			if full {
				payload["previous_authority"] = updated.PreviousAuthorityPrincipalID
			}
			ev, err := domainEvent(ctx, audit.EventAdapterConfigure, caller.Principal, audit.Object{Type: "adapter-target", ID: request.TargetID}, payload)
			if err != nil {
				return err
			}
			if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
				return err
			}
			requested, err := newAuditEvent(ctx, audit.EventAdapterSyncRequested, caller.Principal,
				audit.Object{Type: "adapter-target", ID: request.TargetID}, audit.OutcomeSuccess,
				updated.Enqueue.JobID, audit.Payload{"trigger": "manual"})
			if err != nil {
				return err
			}
			requested.AuthorityID = updated.Enqueue.AuthorityPrincipalID
			if err := r.Audit().InsertTenant(ctx, p, requested); err != nil {
				return err
			}
			if updated.Enqueue.SupersededJobID == "" {
				return nil
			}
			superseded, err := domainEvent(ctx, audit.EventAdapterSuperseded, caller.Principal,
				audit.Object{Type: "adapter-target", ID: request.TargetID}, audit.Payload{
					"previous_job_id": updated.Enqueue.SupersededJobID, "job_id": updated.Enqueue.JobID,
				})
			if err != nil {
				return err
			}
			return r.Audit().InsertTenant(ctx, p, superseded)
		})
	})
	return out, err
}

func (s *Adapters) preflightTargetRouting(ctx context.Context, actor Actor, scope domain.Scope, request UpdateAdapterTargetRequest) error {
	var current store.AdapterTarget
	var record store.AdapterRecord
	var ciphertext []byte
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpAdapterConfigure, scope)
		if err != nil {
			return err
		}
		current, err = r.Adapters().Target(ctx, proof, request.TargetID)
		if err != nil {
			return err
		}
		if current.Generation != request.ExpectedGeneration {
			return adapter.ErrSuperseded
		}
		if current.Provider != "github-actions" || current.DestinationKind != string(adapter.Organization) || (current.Visibility == request.Target.Visibility && slices.Equal(current.SelectedRepositoryIDs, request.Target.SelectedRepositoryIDs)) {
			return nil
		}
		record, ciphertext, err = r.Adapters().Configuration(ctx, proof, current.AdapterID)
		return err
	})
	if err != nil || record.ID == "" {
		return err
	}
	if len(ciphertext) == 0 {
		return adapter.ErrProviderAuth
	}
	sealer, err := sealerFor(ctx, s.DB, s.Keyring, actor, authz.OpAdapterConfigure, scope)
	if err != nil {
		return err
	}
	plain, err := sealer.OpenField(crypto.ProjectFieldAAD{OrgID: string(scope.Org), ProjectID: string(scope.Project), OwnerTable: "adapters", OwnerRowID: current.AdapterID, FieldTag: "credential"}, ciphertext)
	if err != nil {
		return err
	}
	defer crypto.Zero(plain)
	module, release, err := s.planModule(record.Provider, record.Origin, string(plain))
	if err != nil {
		return err
	}
	if release != nil {
		defer release()
	}
	destination := adapterDestination(request.Target)
	destination.NumericID = current.DestinationID
	destination.RepositoryID = current.RepositoryID
	_, err = module.TestConnection(ctx, adapter.ConnectionRequest{
		Config: adapter.Config{Origin: record.Origin}, Destination: destination, Access: adapter.Access{Credential: string(plain)},
		Gate: s.providerGate(actor, authz.OpAdapterConfigure, scope, current.EnvironmentID),
	})
	return err
}

// MoveTarget begins the scrub-before-switch transition for a destination or
// environment move. The current route stays stored for the scrub job; the new
// route is pending and cannot receive a push until activation tests it.
func (s *Adapters) MoveTarget(ctx context.Context, actor Actor, scope domain.Scope, request UpdateAdapterTargetRequest, keepRemote bool) (store.AdapterRouteMoveResult, error) {
	if scope.Project == "" || scope.Env != "" || request.TargetID == "" || request.ExpectedGeneration <= 0 || len(request.Target.KeyIDs) == 0 {
		return store.AdapterRouteMoveResult{}, fmt.Errorf("%w: target move requires target, generation, and full keys replacement", domain.ErrInvalid)
	}
	now := store.CanonTime(s.now())
	var out store.AdapterRouteMoveResult
	err := retryAdapterProviderFence(ctx, func() error {
		return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
			caller, err := actor.resolve(ctx, az, now)
			if err != nil {
				return err
			}
			proof, err := az.Authorize(ctx, caller, authz.OpAdapterConfigure, scope)
			if err != nil {
				return err
			}
			current, err := r.Adapters().Target(ctx, proof, request.TargetID)
			if err != nil {
				return err
			}
			if current.Generation != request.ExpectedGeneration {
				return adapter.ErrSuperseded
			}
			if request.Target.EnvironmentID != current.EnvironmentID {
				return fmt.Errorf("%w: target environment is immutable; remove and add the target", domain.ErrConflict)
			}
			environments, err := r.Adapters().Environments(ctx, proof, current.AdapterID)
			if err != nil {
				return err
			}
			environments = adapterEnvironmentSet(environments, request.Target.EnvironmentID)
			if err := s.requireAdapterCeremony(ctx, az, caller, scope, environments, authz.OpAdapterConfigure, now); err != nil {
				return err
			}
			out, err = r.Adapters().MoveTarget(ctx, proof, store.AdapterRouteMoveMutation{
				Target: store.AdapterTargetMutation{
					ID: request.TargetID, AdapterID: current.AdapterID, EnvironmentID: request.Target.EnvironmentID,
					DestinationKind: request.Target.DestinationKind, DestinationOwner: request.Target.DestinationOwner,
					DestinationName: request.Target.DestinationName, DestinationEnvironment: request.Target.DestinationEnvironment,
					Visibility: request.Target.Visibility, SelectedRepositoryIDs: append([]int64(nil), request.Target.SelectedRepositoryIDs...), NamePrefix: request.Target.NamePrefix,
					KeyIDs: append([]string(nil), request.Target.KeyIDs...),
				},
				ExpectedGeneration: request.ExpectedGeneration, AuthorityPrincipalID: string(caller.Principal),
				KeepRemote: keepRemote, At: now,
			})
			if err != nil {
				return err
			}
			configured, err := domainEvent(ctx, audit.EventAdapterConfigure, caller.Principal,
				audit.Object{Type: "adapter-target", ID: request.TargetID}, audit.Payload{
					"mutation": "target-move", "previous_authority": current.AuthorityPrincipalID,
					"authority": string(caller.Principal),
				})
			if err != nil {
				return err
			}
			if err := r.Audit().InsertTenant(ctx, proof, configured); err != nil {
				return err
			}
			if out.SupersededJobID != "" {
				superseded, err := domainEvent(ctx, audit.EventAdapterSuperseded, caller.Principal,
					audit.Object{Type: "adapter-target", ID: request.TargetID}, audit.Payload{
						"previous_job_id": out.SupersededJobID, "job_id": out.JobID,
					})
				if err != nil {
					return err
				}
				if err := r.Audit().InsertTenant(ctx, proof, superseded); err != nil {
					return err
				}
			}
			if !keepRemote {
				return nil
			}
			scrubbed, err := domainEvent(ctx, audit.EventAdapterScrub, caller.Principal,
				audit.Object{Type: "adapter-target", ID: request.TargetID}, audit.Payload{"orphaned": append([]string(nil), out.Orphaned...)})
			if err != nil {
				return err
			}
			return r.Audit().InsertTenant(ctx, proof, scrubbed)
		})
	})
	return out, err
}

// MoveOrigin keeps the old credential and origin authoritative through every
// target scrub. New credential remains sealed in the pending move and is used
// only by activation probes after old-route cleanup reaches terminal state.
func (s *Adapters) MoveOrigin(ctx context.Context, actor Actor, scope domain.Scope, adapterID, origin string, credential []byte, keepRemote bool) (store.AdapterRouteMoveBatch, error) {
	if scope.Project == "" || scope.Env != "" || adapterID == "" || origin == "" || len(credential) == 0 {
		return store.AdapterRouteMoveBatch{}, fmt.Errorf("%w: origin move requires adapter, new origin, and new credential", domain.ErrInvalid)
	}
	plain := append([]byte(nil), credential...)
	defer crypto.Zero(plain)
	provider, err := s.providerForAdapter(ctx, actor, scope, adapterID)
	if err != nil {
		return store.AdapterRouteMoveBatch{}, err
	}
	module, release, err := s.planModule(provider, origin, string(plain))
	if err != nil {
		return store.AdapterRouteMoveBatch{}, err
	}
	if release != nil {
		defer release()
	}
	if err := module.ValidateConfig(adapter.Config{Origin: origin}); err != nil {
		return store.AdapterRouteMoveBatch{}, err
	}
	sealer, err := sealerFor(ctx, s.DB, s.Keyring, actor, authz.OpAdapterConfigure, scope)
	if err != nil {
		return store.AdapterRouteMoveBatch{}, err
	}
	sealed, err := sealer.SealField(crypto.ProjectFieldAAD{
		OrgID: string(scope.Org), ProjectID: string(scope.Project), OwnerTable: "adapters", OwnerRowID: adapterID, FieldTag: "credential",
	}, plain)
	if err != nil {
		return store.AdapterRouteMoveBatch{}, err
	}
	now := store.CanonTime(s.now())
	var out store.AdapterRouteMoveBatch
	err = retryAdapterProviderFence(ctx, func() error {
		return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
			caller, err := actor.resolve(ctx, az, now)
			if err != nil {
				return err
			}
			proof, err := az.Authorize(ctx, caller, authz.OpAdapterConfigure, scope)
			if err != nil {
				return err
			}
			current, _, err := r.Adapters().Configuration(ctx, proof, adapterID)
			if err != nil {
				return err
			}
			environments, err := r.Adapters().Environments(ctx, proof, adapterID)
			if err != nil {
				return err
			}
			if err := s.requireAdapterCeremony(ctx, az, caller, scope, adapterEnvironmentSet(environments), authz.OpAdapterConfigure, now); err != nil {
				return err
			}
			// Writer fence (invariant 7): refuse if a rotate-dek retired the DEK
			// version the pending credential was sealed under.
			if err := fenceProject(ctx, r, proof, sealer, scope); err != nil {
				return err
			}
			out, err = r.Adapters().MoveOrigin(ctx, proof, store.AdapterOriginMoveMutation{
				AdapterID: adapterID, Origin: origin, PendingCredentialCiphertext: sealed,
				AuthorityPrincipalID: string(caller.Principal), KeepRemote: keepRemote, At: now,
			})
			if err != nil {
				return err
			}
			configured, err := domainEvent(ctx, audit.EventAdapterConfigure, caller.Principal,
				audit.Object{Type: "adapter", ID: adapterID}, audit.Payload{
					"mutation": "origin-move", "previous_authority": current.AuthorityPrincipalID,
					"authority": string(caller.Principal),
				})
			if err != nil {
				return err
			}
			if err := r.Audit().InsertTenant(ctx, proof, configured); err != nil {
				return err
			}
			for _, target := range out.Targets {
				if target.SupersededJobID != "" {
					superseded, err := domainEvent(ctx, audit.EventAdapterSuperseded, caller.Principal,
						audit.Object{Type: "adapter-target", ID: target.TargetID}, audit.Payload{
							"previous_job_id": target.SupersededJobID, "job_id": target.JobID,
						})
					if err != nil {
						return err
					}
					if err := r.Audit().InsertTenant(ctx, proof, superseded); err != nil {
						return err
					}
				}
				if keepRemote {
					scrubbed, err := domainEvent(ctx, audit.EventAdapterScrub, caller.Principal,
						audit.Object{Type: "adapter-target", ID: target.TargetID}, audit.Payload{"orphaned": append([]string(nil), target.Orphaned...)})
					if err != nil {
						return err
					}
					if err := r.Audit().InsertTenant(ctx, proof, scrubbed); err != nil {
						return err
					}
				}
			}
			return nil
		})
	})
	return out, err
}

func (s *Adapters) Move(ctx context.Context, actor Actor, scope domain.Scope, moveID string) (store.AdapterMove, error) {
	if scope.Project == "" || scope.Env != "" || moveID == "" {
		return store.AdapterMove{}, fmt.Errorf("%w: adapter move show requires project scope and move id", domain.ErrInvalid)
	}
	var out store.AdapterMove
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpAdapterInspect, scope)
		if err != nil {
			return err
		}
		out, err = r.Adapters().Move(ctx, proof, moveID)
		if err != nil {
			return err
		}
		event, err := domainEvent(ctx, audit.EventAdapterInspect, caller.Principal, audit.Object{Type: "adapter-move", ID: moveID}, audit.Payload{"row_count": 1})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, proof, event)
	})
	return out, err
}

func (s *Adapters) CancelMove(ctx context.Context, actor Actor, scope domain.Scope, moveID string) (store.AdapterMove, error) {
	if scope.Project == "" || scope.Env != "" || moveID == "" {
		return store.AdapterMove{}, fmt.Errorf("%w: adapter move cancellation requires project scope and move id", domain.ErrInvalid)
	}
	now := store.CanonTime(s.now())
	var out store.AdapterMove
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpAdapterConfigure, scope)
		if err != nil {
			return err
		}
		current, err := r.Adapters().Move(ctx, proof, moveID)
		if err != nil {
			return err
		}
		environments := make([]string, 0, len(current.Targets))
		for _, target := range current.Targets {
			environments = append(environments, target.EnvironmentID)
		}
		environments = adapterEnvironmentSet(environments)
		if err := s.requireAdapterCeremony(ctx, az, caller, scope, environments, authz.OpAdapterConfigure, now); err != nil {
			return err
		}
		out, err = r.Adapters().CancelMove(ctx, proof, moveID, string(caller.Principal), now)
		if err != nil {
			return err
		}
		event, err := domainEvent(ctx, audit.EventAdapterConfigure, caller.Principal, audit.Object{Type: "adapter-move", ID: moveID}, audit.Payload{
			"mutation": "move-cancel", "previous_authority": out.PreviousAuthorityPrincipalID, "authority": out.AuthorityPrincipalID,
		})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, proof, event)
	})
	return out, err
}

func (s *Adapters) ResumeTargetMove(ctx context.Context, actor Actor, scope domain.Scope, moveID string, request UpdateAdapterTargetRequest) (store.AdapterMove, error) {
	if scope.Project == "" || scope.Env != "" || moveID == "" || request.TargetID == "" || len(request.Target.KeyIDs) == 0 {
		return store.AdapterMove{}, fmt.Errorf("%w: pending target replacement requires project, move, target, and full keys", domain.ErrInvalid)
	}
	now := store.CanonTime(s.now())
	var out store.AdapterMove
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpAdapterConfigure, scope)
		if err != nil {
			return err
		}
		move, err := r.Adapters().Move(ctx, proof, moveID)
		if err != nil {
			return err
		}
		if move.Kind != "target" || len(move.Targets) != 1 || move.Targets[0].TargetID != request.TargetID || move.Targets[0].EnvironmentID != request.Target.EnvironmentID {
			return fmt.Errorf("%w: pending target replacement cannot change target identity or environment", domain.ErrConflict)
		}
		environments, err := r.Adapters().Environments(ctx, proof, move.AdapterID)
		if err != nil {
			return err
		}
		if err := s.requireAdapterCeremony(ctx, az, caller, scope, adapterEnvironmentSet(environments), authz.OpAdapterConfigure, now); err != nil {
			return err
		}
		out, err = r.Adapters().ReplaceMoveTarget(ctx, proof, moveID, store.AdapterTargetMutation{
			ID: request.TargetID, AdapterID: move.AdapterID, EnvironmentID: request.Target.EnvironmentID,
			DestinationKind: request.Target.DestinationKind, DestinationOwner: request.Target.DestinationOwner,
			DestinationName: request.Target.DestinationName, NamePrefix: request.Target.NamePrefix,
			KeyIDs: append([]string(nil), request.Target.KeyIDs...),
		}, string(caller.Principal), now)
		if err != nil {
			return err
		}
		event, err := domainEvent(ctx, audit.EventAdapterConfigure, caller.Principal, audit.Object{Type: "adapter-move", ID: moveID}, audit.Payload{
			"mutation": "pending-target-replace", "previous_authority": out.PreviousAuthorityPrincipalID, "authority": out.AuthorityPrincipalID,
		})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, proof, event)
	})
	return out, err
}

func (s *Adapters) ResumeOriginMove(ctx context.Context, actor Actor, scope domain.Scope, moveID, origin string, credential []byte) (store.AdapterMove, error) {
	if scope.Project == "" || scope.Env != "" || moveID == "" || origin == "" || len(credential) == 0 {
		return store.AdapterMove{}, fmt.Errorf("%w: pending origin replacement requires project, move, origin, and credential", domain.ErrInvalid)
	}
	plain := append([]byte(nil), credential...)
	defer crypto.Zero(plain)
	provider, err := s.providerForMove(ctx, actor, scope, moveID)
	if err != nil {
		return store.AdapterMove{}, err
	}
	module, release, err := s.planModule(provider, origin, string(plain))
	if err != nil {
		return store.AdapterMove{}, err
	}
	if release != nil {
		defer release()
	}
	if err := module.ValidateConfig(adapter.Config{Origin: origin}); err != nil {
		return store.AdapterMove{}, err
	}
	now := store.CanonTime(s.now())
	var out store.AdapterMove
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpAdapterConfigure, scope)
		if err != nil {
			return err
		}
		move, err := r.Adapters().Move(ctx, proof, moveID)
		if err != nil {
			return err
		}
		if move.Kind != "origin" {
			return fmt.Errorf("%w: pending origin replacement requires an origin move", domain.ErrConflict)
		}
		environments := make([]string, 0, len(move.Targets))
		for _, target := range move.Targets {
			environments = append(environments, target.EnvironmentID)
		}
		environments = adapterEnvironmentSet(environments)
		if err := s.requireAdapterCeremony(ctx, az, caller, scope, environments, authz.OpAdapterConfigure, now); err != nil {
			return err
		}
		sealer, err := s.Keyring.ForProject(ctx, string(scope.Org), string(scope.Project))
		if err != nil {
			return err
		}
		sealed, err := sealer.SealField(crypto.ProjectFieldAAD{OrgID: string(scope.Org), ProjectID: string(scope.Project), OwnerTable: "adapters", OwnerRowID: move.AdapterID, FieldTag: "credential"}, plain)
		if err != nil {
			return err
		}
		// Writer fence (invariant 7): refuse if a rotate-dek retired the DEK
		// version this replacement credential was sealed under.
		if err := fenceProject(ctx, r, proof, sealer, scope); err != nil {
			return err
		}
		out, err = r.Adapters().ReplaceMoveOrigin(ctx, proof, moveID, origin, sealed, string(caller.Principal), now)
		if err != nil {
			return err
		}
		event, err := domainEvent(ctx, audit.EventAdapterConfigure, caller.Principal, audit.Object{Type: "adapter-move", ID: moveID}, audit.Payload{
			"mutation": "pending-origin-replace", "previous_authority": out.PreviousAuthorityPrincipalID, "authority": out.AuthorityPrincipalID,
		})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, proof, event)
	})
	return out, err
}

func (s *Adapters) SyncTarget(ctx context.Context, actor Actor, scope domain.Scope, targetID string) (store.AdapterEnqueueResult, error) {
	if scope.Project == "" || scope.Env != "" || targetID == "" {
		return store.AdapterEnqueueResult{}, fmt.Errorf("%w: manual adapter sync requires project scope and target id", domain.ErrInvalid)
	}
	// § 179 adapter sync/trigger concurrency: 4 per org. Held for the enqueue.
	release, err := s.Budget.acquire(budgetAdapter, budgetKeys{Org: scope.Org})
	if err != nil {
		return store.AdapterEnqueueResult{}, err
	}
	defer release()
	now := store.CanonTime(s.now())
	var result store.AdapterEnqueueResult
	err = retryAdapterProviderFence(ctx, func() error {
		return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
			caller, err := actor.resolve(ctx, az, now)
			if err != nil {
				return err
			}
			proof, err := az.Authorize(ctx, caller, authz.OpAdapterSync, scope)
			if err != nil {
				return err
			}
			target, err := r.Adapters().Target(ctx, proof, targetID)
			if err != nil {
				return err
			}
			environments, err := r.Adapters().Environments(ctx, proof, target.AdapterID)
			if err != nil {
				return err
			}
			for _, environmentID := range environments {
				envScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(environmentID)}
				if _, err := az.Authorize(ctx, caller, authz.OpAdapterPush, envScope); err != nil {
					return err
				}
				if !skipsCeremony(caller) {
					if s.Auth == nil {
						return ErrNoCeremonySeam
					}
					if err := s.Auth.ConsumeAdapterReauthWindow(ctx, az, caller.SessionID, environmentID, authz.OpAdapterSync, environments, now); err != nil {
						return fmt.Errorf("%w (%s)", ErrReauthRequired, environmentID)
					}
				}
			}
			result, err = r.Adapters().EnqueueManual(ctx, proof, targetID, string(caller.Principal), now)
			if err != nil {
				return err
			}
			requested, err := newAuditEvent(ctx, audit.EventAdapterSyncRequested, caller.Principal,
				audit.Object{Type: "adapter-target", ID: targetID}, audit.OutcomeSuccess,
				result.JobID, audit.Payload{"trigger": "manual"})
			if err != nil {
				return err
			}
			requested.AuthorityID = result.AuthorityPrincipalID
			if err := r.Audit().InsertTenant(ctx, proof, requested); err != nil {
				return err
			}
			if result.SupersededJobID == "" {
				return nil
			}
			superseded, err := domainEvent(ctx, audit.EventAdapterSuperseded, caller.Principal,
				audit.Object{Type: "adapter-target", ID: targetID}, audit.Payload{
					"previous_job_id": result.SupersededJobID, "job_id": result.JobID,
				})
			if err != nil {
				return err
			}
			return r.Audit().InsertTenant(ctx, proof, superseded)
		})
	})
	return result, err
}

func (s *Adapters) TestTarget(ctx context.Context, actor Actor, scope domain.Scope, targetID string) (adapter.Connection, error) {
	if scope.Project == "" || scope.Env != "" || targetID == "" {
		return adapter.Connection{}, fmt.Errorf("%w: adapter connection test requires project scope and target id", domain.ErrInvalid)
	}
	sealer, err := sealerFor(ctx, s.DB, s.Keyring, actor, authz.OpAdapterTest, scope)
	if err != nil {
		return adapter.Connection{}, err
	}
	var material store.AdapterPlanMaterial
	err = tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpAdapterTest, scope)
		if err != nil {
			return err
		}
		material, err = r.Adapters().PlanMaterial(ctx, proof, targetID)
		return err
	})
	if err != nil {
		return adapter.Connection{}, err
	}
	if len(material.CredentialCiphertext) == 0 {
		return adapter.Connection{}, adapter.ErrProviderAuth
	}
	credential, err := sealer.OpenField(crypto.ProjectFieldAAD{
		OrgID: string(scope.Org), ProjectID: string(scope.Project), OwnerTable: "adapters", OwnerRowID: material.Target.AdapterID, FieldTag: "credential",
	}, material.CredentialCiphertext)
	if err != nil {
		return adapter.Connection{}, err
	}
	defer crypto.Zero(credential)
	module, release, err := s.planModule(material.Target.Provider, material.Target.Origin, string(credential))
	if err != nil {
		return adapter.Connection{}, err
	}
	if release != nil {
		defer release()
	}
	providerGate := func(gateCtx context.Context) error {
		return tx.Read(gateCtx, s.DB, func(gateCtx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
			caller, err := actor.resolve(gateCtx, az, s.now())
			if err != nil {
				return err
			}
			_, err = az.Authorize(gateCtx, caller, authz.OpAdapterTest, scope)
			return err
		})
	}
	connection, err := module.TestConnection(ctx, adapter.ConnectionRequest{
		Config: adapter.Config{Origin: material.Target.Origin}, Destination: adapterTarget(material.Target).Destination,
		Access: adapter.Access{Credential: string(credential)}, Gate: providerGate,
	})
	if err != nil {
		return adapter.Connection{}, err
	}
	now := store.CanonTime(s.now())
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpAdapterTest, scope)
		if err != nil {
			return err
		}
		current, err := r.Adapters().Target(ctx, proof, targetID)
		if err != nil {
			return err
		}
		if current.Generation != material.Target.Generation || current.DestinationID != material.Target.DestinationID || current.RepositoryID != material.Target.RepositoryID {
			return fmt.Errorf("%w: adapter target changed while testing", domain.ErrConflict)
		}
		if !connection.CredentialExpiresAt.IsZero() {
			if err := r.Adapters().RecordCredentialExpiry(ctx, proof, material.Target.AdapterID, connection.CredentialExpiresAt); err != nil {
				return err
			}
		}
		event, err := domainEvent(ctx, audit.EventAdapterTest, caller.Principal,
			audit.Object{Type: "adapter-target", ID: targetID}, audit.Payload{
				"version": connection.Version, "destination_id": connection.DestinationID,
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, proof, event)
	})
	if err != nil {
		return adapter.Connection{}, err
	}
	return connection, nil
}

var ErrAdapterBootstrapCeremonyUnspecified = errors.New("service: zero-target adapter credential ceremony is not specified")

func (s *Adapters) ReplaceCredential(ctx context.Context, actor Actor, scope domain.Scope, adapterID string, credential []byte) (store.AdapterCredentialResult, error) {
	if scope.Project == "" || scope.Env != "" || adapterID == "" || len(credential) == 0 {
		return store.AdapterCredentialResult{}, fmt.Errorf("%w: credential replacement requires project scope, adapter id, and non-empty token", domain.ErrInvalid)
	}
	sealer, err := sealerFor(ctx, s.DB, s.Keyring, actor, authz.OpAdapterCredentialSet, scope)
	if err != nil {
		return store.AdapterCredentialResult{}, err
	}
	plain := append([]byte(nil), credential...)
	defer crypto.Zero(plain)
	sealed, err := sealer.SealField(crypto.ProjectFieldAAD{
		OrgID: string(scope.Org), ProjectID: string(scope.Project), OwnerTable: "adapters", OwnerRowID: adapterID, FieldTag: "credential",
	}, plain)
	if err != nil {
		return store.AdapterCredentialResult{}, err
	}
	now := store.CanonTime(s.now())
	var result store.AdapterCredentialResult
	err = retryAdapterProviderFence(ctx, func() error {
		return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
			caller, err := actor.resolve(ctx, az, now)
			if err != nil {
				return err
			}
			proof, err := az.Authorize(ctx, caller, authz.OpAdapterCredentialSet, scope)
			if err != nil {
				return err
			}
			environments, err := r.Adapters().Environments(ctx, proof, adapterID)
			if err != nil {
				return err
			}
			if len(environments) == 0 {
				return ErrAdapterBootstrapCeremonyUnspecified
			}
			for _, environmentID := range environments {
				envScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(environmentID)}
				if _, err := az.Authorize(ctx, caller, authz.OpAdapterPush, envScope); err != nil {
					return err
				}
				if skipsCeremony(caller) {
					continue
				}
				if s.Auth == nil {
					return ErrNoCeremonySeam
				}
				if err := s.Auth.ConsumeAdapterReauthWindow(ctx, az, caller.SessionID, environmentID, authz.OpAdapterCredentialSet, environments, now); err != nil {
					return fmt.Errorf("%w (%s)", ErrReauthRequired, environmentID)
				}
			}
			// Writer fence (invariant 7): refuse if a rotate-dek retired the DEK
			// version the new credential was sealed under.
			if err := fenceProject(ctx, r, proof, sealer, scope); err != nil {
				return err
			}
			result, err = r.Adapters().ReplaceCredential(ctx, proof, store.AdapterCredentialMutation{
				AdapterID: adapterID, CredentialCiphertext: sealed,
				AuthorityPrincipalID: string(caller.Principal), At: now,
			})
			if err != nil {
				return err
			}
			event, err := domainEvent(ctx, audit.EventAdapterCredentialReplace, caller.Principal,
				audit.Object{Type: "adapter", ID: adapterID}, audit.Payload{
					"credential_present": true, "previous_authority": result.PreviousAuthorityPrincipalID, "authority": result.AuthorityPrincipalID,
				})
			if err != nil {
				return err
			}
			return r.Audit().InsertTenant(ctx, proof, event)
		})
	})
	return result, err
}

func (s *Adapters) RevokeCredential(ctx context.Context, actor Actor, scope domain.Scope, adapterID string) (store.AdapterCredentialResult, error) {
	if scope.Project == "" || scope.Env != "" || adapterID == "" {
		return store.AdapterCredentialResult{}, fmt.Errorf("%w: credential revocation requires project scope and adapter id", domain.ErrInvalid)
	}
	now := store.CanonTime(s.now())
	var result store.AdapterCredentialResult
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpAdapterCredentialRevoke, scope)
		if err != nil {
			return err
		}
		result, err = r.Adapters().RevokeCredential(ctx, proof, adapterID, now)
		if err != nil {
			return err
		}
		event, err := domainEvent(ctx, audit.EventAdapterCredentialRevoke, caller.Principal,
			audit.Object{Type: "adapter", ID: adapterID}, audit.Payload{"credential_present": false})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, proof, event)
	})
	return result, err
}

func (s *Adapters) planModule(provider, origin, credential string) (adapter.Module, func(), error) {
	if s.ProviderModule != nil {
		return s.ProviderModule(provider, origin, credential)
	}
	if s.PlanModule == nil {
		return nil, nil, errors.New("service: adapter plan module is not configured")
	}
	return s.PlanModule(origin, credential)
}

func (s *Adapters) providerForAdapter(ctx context.Context, actor Actor, scope domain.Scope, adapterID string) (string, error) {
	var provider string
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpAdapterConfigure, scope)
		if err != nil {
			return err
		}
		record, _, err := r.Adapters().Configuration(ctx, proof, adapterID)
		if err != nil {
			return err
		}
		provider = record.Provider
		return nil
	})
	return provider, err
}

func (s *Adapters) providerForMove(ctx context.Context, actor Actor, scope domain.Scope, moveID string) (string, error) {
	var provider string
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpAdapterConfigure, scope)
		if err != nil {
			return err
		}
		move, err := r.Adapters().Move(ctx, proof, moveID)
		if err != nil {
			return err
		}
		record, _, err := r.Adapters().Configuration(ctx, proof, move.AdapterID)
		if err != nil {
			return err
		}
		provider = record.Provider
		return nil
	})
	return provider, err
}

func adapterTarget(target store.AdapterTarget) adapter.Target {
	return adapter.Target{
		ID: target.ID, Environment: target.EnvironmentID, NamePrefix: target.NamePrefix, Generation: target.Generation,
		Destination: adapter.Destination{Kind: adapter.DestinationKind(target.DestinationKind), Owner: target.DestinationOwner, Name: target.DestinationName, Environment: target.DestinationEnvironment, NumericID: target.DestinationID, RepositoryID: target.RepositoryID, Visibility: target.Visibility, SelectedRepositoryIDs: append([]int64(nil), target.SelectedRepositoryIDs...)},
	}
}

func (s *Adapters) Plan(ctx context.Context, actor Actor, scope domain.Scope, targetID string) (AdapterPlanResult, error) {
	if scope.Project == "" || scope.Env != "" || targetID == "" {
		return AdapterPlanResult{}, fmt.Errorf("%w: adapter plan requires project scope and target id", domain.ErrInvalid)
	}
	sealer, err := sealerFor(ctx, s.DB, s.Keyring, actor, authz.OpAdapterPlan, scope)
	if err != nil {
		return AdapterPlanResult{}, err
	}
	var material store.AdapterPlanMaterial
	err = tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpAdapterPlan, scope)
		if err != nil {
			return err
		}
		material, err = r.Adapters().PlanMaterial(ctx, p, targetID)
		return err
	})
	if err != nil {
		return AdapterPlanResult{}, err
	}
	if len(material.CredentialCiphertext) == 0 {
		return AdapterPlanResult{}, adapter.ErrProviderAuth
	}
	credential, err := sealer.OpenField(crypto.ProjectFieldAAD{OrgID: string(scope.Org), ProjectID: string(scope.Project), OwnerTable: "adapters", OwnerRowID: material.Target.AdapterID, FieldTag: "credential"}, material.CredentialCiphertext)
	if err != nil {
		return AdapterPlanResult{}, err
	}
	defer crypto.Zero(credential)
	module, release, err := s.planModule(material.Target.Provider, material.Target.Origin, string(credential))
	if err != nil {
		return AdapterPlanResult{}, err
	}
	if release != nil {
		defer release()
	}
	providerGate := func(gateCtx context.Context) error {
		return tx.Read(gateCtx, s.DB, func(gateCtx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
			caller, err := actor.resolve(gateCtx, az, s.now())
			if err != nil {
				return err
			}
			_, err = az.Authorize(gateCtx, caller, authz.OpAdapterPlan, scope)
			return err
		})
	}
	plan, err := module.Plan(ctx, adapter.PlanRequest{Config: adapter.Config{Origin: material.Target.Origin}, Target: adapterTarget(material.Target), Manifest: material.Manifest, Ledger: material.Ledger, Gate: providerGate})
	if err != nil {
		return AdapterPlanResult{}, err
	}
	artifactID, err := newID("apl")
	if err != nil {
		return AdapterPlanResult{}, err
	}
	now := store.CanonTime(s.now())
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpAdapterPlan, scope)
		if err != nil {
			return err
		}
		current, err := r.Adapters().Target(ctx, p, targetID)
		if err != nil {
			return err
		}
		if current.Generation != material.Target.Generation || current.DestinationID != material.Target.DestinationID || current.RepositoryID != material.Target.RepositoryID {
			return fmt.Errorf("%w: adapter target changed while planning", domain.ErrConflict)
		}
		conflicts := make([]store.AdapterConflictEntry, 0)
		changes := make([]string, 0, len(plan.Changes))
		for _, change := range plan.Changes {
			changes = append(changes, string(change.Surface)+":"+change.EffectiveName+":"+string(change.Disposition))
			if change.Disposition == adapter.Conflict {
				conflicts = append(conflicts, store.AdapterConflictEntry{Surface: string(change.Surface), EffectiveName: change.EffectiveName})
			}
		}
		if len(conflicts) != 0 {
			if err := r.Adapters().RecordPlan(ctx, p, targetID, artifactID, material.Target.Generation, material.Target.RepositoryID, material.Target.DestinationID, conflicts, now); err != nil {
				return err
			}
		}
		ev, err := domainEvent(ctx, audit.EventAdapterPlan, caller.Principal, audit.Object{Type: "adapter-target", ID: targetID}, audit.Payload{"changes": changes})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	if err != nil {
		return AdapterPlanResult{}, err
	}
	return AdapterPlanResult{ArtifactID: artifactID, Plan: plan}, nil
}

func (s *Adapters) InspectTarget(ctx context.Context, actor Actor, scope domain.Scope, targetID string) (AdapterTargetView, error) {
	if scope.Project == "" || scope.Env != "" || targetID == "" {
		return AdapterTargetView{}, fmt.Errorf("%w: adapter target inspection requires project scope and target id", domain.ErrInvalid)
	}
	var out AdapterTargetView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpAdapterInspect, scope)
		if err != nil {
			return err
		}
		out.Target, err = r.Adapters().Target(ctx, p, targetID)
		if err != nil {
			return err
		}
		out.Conflicts, err = r.Adapters().Conflicts(ctx, p, targetID)
		if err != nil {
			return err
		}
		out.Mapping, err = r.Adapters().Mapping(ctx, p, targetID)
		if err != nil {
			return err
		}
		out.Workflow, err = adapter.WorkflowForProvider(out.Target.Provider, out.Target.NamePrefix, out.Mapping)
		if err != nil {
			return err
		}
		if out.Target.Provider == "github-actions" && out.Target.DestinationKind == string(adapter.Environment) {
			out.Workflow = "environment: " + strconv.Quote(out.Target.DestinationEnvironment) + "\n" + out.Workflow
		}
		ev, err := domainEvent(ctx, audit.EventAdapterInspect, caller.Principal, audit.Object{Type: "adapter-target", ID: targetID}, audit.Payload{"row_count": 1})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	return out, err
}

func (s *Adapters) Adopt(ctx context.Context, actor Actor, scope domain.Scope, request AdoptAdapterRequest) (AdoptAdapterResult, error) {
	if scope.Project == "" || scope.Env != "" || request.TargetID == "" || request.ArtifactID == "" || request.ExpectedGeneration <= 0 || request.ExpectedDestinationID <= 0 || len(request.Entries) == 0 {
		return AdoptAdapterResult{}, fmt.Errorf("%w: adoption requires project scope, target, artifact, and enumerated entries", domain.ErrInvalid)
	}
	ledgerIDs := make([]string, len(request.Entries))
	for i := range ledgerIDs {
		id, err := newID("adl")
		if err != nil {
			return AdoptAdapterResult{}, err
		}
		ledgerIDs[i] = id
	}
	jobID, err := newID("job")
	if err != nil {
		return AdoptAdapterResult{}, err
	}
	now := store.CanonTime(s.now())
	var out AdoptAdapterResult
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpAdapterAdopt, scope)
		if err != nil {
			return err
		}
		target, err := r.Adapters().Target(ctx, p, request.TargetID)
		if err != nil {
			return err
		}
		if target.Generation != request.ExpectedGeneration || target.RepositoryID != request.ExpectedRepositoryID || target.DestinationID != request.ExpectedDestinationID {
			return fmt.Errorf("%w: adoption target no longer matches the selected artifact", domain.ErrConflict)
		}
		environments, err := r.Adapters().TargetEnvironments(ctx, p, request.TargetID)
		if err != nil {
			return err
		}
		if len(environments) == 0 {
			return domain.ErrNotFound
		}
		for _, environmentID := range environments {
			envScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(environmentID)}
			if _, err := az.Authorize(ctx, caller, authz.OpAdapterPush, envScope); err != nil {
				return err
			}
			if skipsCeremony(caller) {
				continue
			}
			if s.Auth == nil {
				return ErrNoCeremonySeam
			}
			err := s.Auth.ConsumeAdapterReauthWindow(ctx, az, caller.SessionID, environmentID, authz.OpAdapterAdopt, environments, now)
			switch {
			case err == nil:
			case errors.Is(err, ErrNoReauthWindow), errors.Is(err, ErrReauthWindowExpired), errors.Is(err, ErrReauthUnitMismatch), errors.Is(err, ErrReauthWindowSpent):
				return fmt.Errorf("%w (%s)", ErrReauthRequired, environmentID)
			default:
				return err
			}
		}
		result, err := r.Adapters().Adopt(ctx, p, store.AdapterAdoption{
			TargetID: request.TargetID, ArtifactID: request.ArtifactID, Entries: request.Entries,
			AuthorityPrincipalID: string(caller.Principal), LedgerIDs: ledgerIDs, JobID: jobID, AuditAt: now,
		})
		if err != nil {
			return err
		}
		entryNames := make([]string, 0, len(request.Entries))
		for _, entry := range request.Entries {
			entryNames = append(entryNames, entry.Surface+":"+entry.EffectiveName)
		}
		sort.Strings(entryNames)
		ev, err := domainEvent(ctx, audit.EventAdapterAdopt, caller.Principal, audit.Object{Type: "adapter-target", ID: request.TargetID}, audit.Payload{
			"artifact_id": request.ArtifactID, "target_generation": target.Generation, "entries": entryNames,
		})
		if err != nil {
			return err
		}
		if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
			return err
		}
		if result.SupersededJobID != "" {
			superseded, err := domainEvent(ctx, audit.EventAdapterSuperseded, caller.Principal, audit.Object{Type: "adapter-target", ID: request.TargetID}, audit.Payload{
				"previous_job_id": result.SupersededJobID, "job_id": result.JobID,
			})
			if err != nil {
				return err
			}
			if err := r.Audit().InsertTenant(ctx, p, superseded); err != nil {
				return err
			}
		}
		out = AdoptAdapterResult{Generation: result.Generation, JobID: result.JobID}
		return nil
	})
	return out, err
}

func (s *Adapters) RemoveTarget(ctx context.Context, actor Actor, scope domain.Scope, targetID string, keepRemote bool) (AdapterTeardownResult, error) {
	if scope.Project == "" || scope.Env != "" || targetID == "" {
		return AdapterTeardownResult{}, fmt.Errorf("%w: adapter target removal requires project scope and target id", domain.ErrInvalid)
	}
	now := store.CanonTime(s.now())
	var result store.AdapterTeardownResult
	err := retryAdapterProviderFence(ctx, func() error {
		return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
			caller, err := actor.resolve(ctx, az, now)
			if err != nil {
				return err
			}
			proof, err := az.Authorize(ctx, caller, authz.OpAdapterDelete, scope)
			if err != nil {
				return err
			}
			result, err = r.Adapters().TeardownTarget(ctx, proof, targetID, keepRemote, now)
			if err != nil {
				return err
			}
			if err := insertAdapterTeardownAudits(ctx, r, proof, caller.Principal, "target-remove", result.AuthorityPrincipalID, result); err != nil {
				return err
			}
			return nil
		})
	})
	if err != nil {
		return AdapterTeardownResult{}, err
	}
	return AdapterTeardownResult{Targets: []store.AdapterTeardownResult{result}, Orphaned: append([]string(nil), result.Orphaned...)}, nil
}

func (s *Adapters) Delete(ctx context.Context, actor Actor, scope domain.Scope, adapterID string, keepRemote bool) (AdapterTeardownResult, error) {
	if scope.Project == "" || scope.Env != "" || adapterID == "" {
		return AdapterTeardownResult{}, fmt.Errorf("%w: adapter deletion requires project scope and adapter id", domain.ErrInvalid)
	}
	now := store.CanonTime(s.now())
	var batch store.AdapterTeardownBatch
	err := retryAdapterProviderFence(ctx, func() error {
		return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
			caller, err := actor.resolve(ctx, az, now)
			if err != nil {
				return err
			}
			proof, err := az.Authorize(ctx, caller, authz.OpAdapterDelete, scope)
			if err != nil {
				return err
			}
			batch, err = r.Adapters().TeardownAdapter(ctx, proof, adapterID, keepRemote, now)
			if err != nil {
				return err
			}
			configured, err := domainEvent(ctx, audit.EventAdapterConfigure, caller.Principal,
				audit.Object{Type: "adapter", ID: adapterID}, audit.Payload{
					"mutation": "adapter-delete", "authority": batch.AuthorityPrincipalID,
				})
			if err != nil {
				return err
			}
			if err := r.Audit().InsertTenant(ctx, proof, configured); err != nil {
				return err
			}
			for _, target := range batch.Targets {
				if err := insertAdapterTeardownJobAudits(ctx, r, proof, caller.Principal, target); err != nil {
					return err
				}
			}
			return nil
		})
	})
	if err != nil {
		return AdapterTeardownResult{}, err
	}
	out := AdapterTeardownResult{Targets: batch.Targets}
	for _, target := range batch.Targets {
		out.Orphaned = append(out.Orphaned, target.Orphaned...)
	}
	sort.Strings(out.Orphaned)
	return out, nil
}

func retryAdapterProviderFence(ctx context.Context, attempt func() error) error {
	for {
		err := attempt()
		if !errors.Is(err, adapter.ErrProviderBusy) {
			return err
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("%w: %v", adapter.ErrProviderBusy, ctx.Err())
		case <-timer.C:
		}
	}
}

func insertAdapterTeardownAudits(ctx context.Context, r store.Repos, proof authz.Proof, principal domain.PrincipalID, mutation, authority string, result store.AdapterTeardownResult) error {
	configured, err := domainEvent(ctx, audit.EventAdapterConfigure, principal,
		audit.Object{Type: "adapter-target", ID: result.TargetID}, audit.Payload{
			"mutation": mutation, "authority": authority,
		})
	if err != nil {
		return err
	}
	if err := r.Audit().InsertTenant(ctx, proof, configured); err != nil {
		return err
	}
	return insertAdapterTeardownJobAudits(ctx, r, proof, principal, result)
}

func insertAdapterTeardownJobAudits(ctx context.Context, r store.Repos, proof authz.Proof, principal domain.PrincipalID, result store.AdapterTeardownResult) error {
	if result.SupersededJobID != "" && result.JobID != "" {
		superseded, err := domainEvent(ctx, audit.EventAdapterSuperseded, principal,
			audit.Object{Type: "adapter-target", ID: result.TargetID}, audit.Payload{
				"previous_job_id": result.SupersededJobID, "job_id": result.JobID,
			})
		if err != nil {
			return err
		}
		if err := r.Audit().InsertTenant(ctx, proof, superseded); err != nil {
			return err
		}
	}
	if result.JobID != "" {
		return nil
	}
	orphaned := append([]string{}, result.Orphaned...)
	scrubbed, err := domainEvent(ctx, audit.EventAdapterScrub, principal,
		audit.Object{Type: "adapter-target", ID: result.TargetID}, audit.Payload{"orphaned": orphaned})
	if err != nil {
		return err
	}
	return r.Audit().InsertTenant(ctx, proof, scrubbed)
}
