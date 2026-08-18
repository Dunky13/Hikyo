package server

import (
	"context"
	"fmt"
	"time"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

func adapterScope(org apigen.OrgID, project apigen.ProjectID) domain.Scope {
	return domain.Scope{Org: domain.OrgID(org), Project: domain.ProjectID(project)}
}

func targetInput(in apigen.AdapterTargetInput) service.AdapterTargetInput {
	keys := make([]string, len(in.KeyIds))
	for i := range in.KeyIds {
		keys[i] = string(in.KeyIds[i])
	}
	return service.AdapterTargetInput{EnvironmentID: string(in.EnvironmentId), DestinationKind: string(in.DestinationKind), DestinationOwner: in.DestinationOwner, DestinationName: in.DestinationName, NamePrefix: in.NamePrefix, KeyIDs: keys}
}

func adapterConflictResponses(in []service.AdapterConflictArtifact) []apigen.AdapterConflictArtifact {
	out := make([]apigen.AdapterConflictArtifact, 0, len(in))
	for _, artifact := range in {
		row := apigen.AdapterConflictArtifact{Id: apigen.ID(artifact.ID), DestinationId: artifact.DestinationID, TargetGeneration: artifact.TargetGeneration, CreatedAt: artifact.CreatedAt, Entries: []apigen.AdapterConflictEntry{}}
		for _, entry := range artifact.Entries {
			row.Entries = append(row.Entries, apigen.AdapterConflictEntry{Surface: apigen.AdapterConflictEntrySurface(entry.Surface), EffectiveName: entry.EffectiveName})
		}
		out = append(out, row)
	}
	return out
}

func adapterTargetResponse(in service.AdapterTarget, conflicts ...service.AdapterConflictArtifact) apigen.AdapterTarget {
	return apigen.AdapterTarget{Id: apigen.ID(in.ID), AdapterId: apigen.ID(in.AdapterID), EnvironmentId: apigen.ID(in.EnvironmentID), DestinationKind: apigen.AdapterDestinationKind(in.DestinationKind), DestinationOwner: in.DestinationOwner, DestinationName: in.DestinationName, DestinationId: in.DestinationID, NamePrefix: in.NamePrefix, Generation: in.Generation, State: apigen.AdapterTargetState(in.State), SyncStatus: apigen.AdapterTargetSyncStatus(in.SyncStatus), ConvergedRevision: in.ConvergedRevision, FailureNames: append([]string{}, in.FailureNames...), Conflicts: adapterConflictResponses(conflicts)}
}

func adapterResponse(in service.AdapterView) (apigen.Adapter, error) {
	targets := make([]apigen.AdapterTarget, 0, len(in.Targets))
	for _, target := range in.Targets {
		targets = append(targets, adapterTargetResponse(target, in.TargetConflicts[target.ID]...))
	}
	created, err := time.Parse(time.RFC3339Nano, in.Adapter.CreatedAt)
	if err != nil {
		return apigen.Adapter{}, fmt.Errorf("server: parse adapter created_at: %w", err)
	}
	var credentialSet *time.Time
	if in.Adapter.CredentialSetAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, in.Adapter.CredentialSetAt)
		if err != nil {
			return apigen.Adapter{}, fmt.Errorf("server: parse adapter credential_set_at: %w", err)
		}
		credentialSet = &parsed
	}
	return apigen.Adapter{Id: apigen.ID(in.Adapter.ID), Provider: apigen.AdapterProvider(in.Adapter.Provider), Origin: in.Adapter.Origin, CredentialPresent: in.Adapter.CredentialPresent, CredentialSetAt: credentialSet, AuthorityPrincipalId: apigen.ID(in.Adapter.AuthorityPrincipalID), State: apigen.AdapterState(in.Adapter.State), CreatedAt: created, Targets: targets}, nil
}

func teardownResponse(in service.AdapterTeardownResult) apigen.AdapterTeardown {
	out := apigen.AdapterTeardown{Orphaned: append([]string{}, in.Orphaned...), Jobs: []apigen.AdapterJob{}}
	for _, target := range in.Targets {
		if target.JobID != "" {
			out.Jobs = append(out.Jobs, apigen.AdapterJob{JobId: apigen.ID(target.JobID), Generation: target.Generation})
		}
	}
	return out
}

func adapterMoveResponse(in service.AdapterMove) (apigen.AdapterMove, error) {
	created, err := time.Parse(time.RFC3339Nano, in.CreatedAt)
	if err != nil {
		return apigen.AdapterMove{}, fmt.Errorf("server: parse adapter move created_at: %w", err)
	}
	out := apigen.AdapterMove{Id: apigen.ID(in.ID), AdapterId: apigen.ID(in.AdapterID), Kind: apigen.AdapterMoveKind(in.Kind), State: apigen.AdapterMoveState(in.State), KeepRemote: in.KeepRemote, PendingOrigin: in.PendingOrigin, CreatedAt: created, Targets: []apigen.AdapterMoveTarget{}}
	for _, target := range in.Targets {
		row := apigen.AdapterMoveTarget{TargetId: apigen.ID(target.TargetID), EnvironmentId: apigen.ID(target.EnvironmentID), DestinationKind: apigen.AdapterDestinationKind(target.DestinationKind), DestinationOwner: target.DestinationOwner, DestinationName: target.DestinationName, DestinationId: target.DestinationID, NamePrefix: target.NamePrefix, OrphanedNames: append([]string{}, target.Orphaned...), Jobs: []apigen.AdapterMoveJob{}}
		for _, job := range target.Jobs {
			row.Jobs = append(row.Jobs, apigen.AdapterMoveJob{Id: apigen.ID(job.ID), TargetId: apigen.ID(job.TargetID), Kind: apigen.AdapterMoveJobKind(job.Kind), State: apigen.AdapterMoveJobState(job.State)})
		}
		out.Targets = append(out.Targets, row)
	}
	return out, nil
}

func (a *API) ListAdapters(ctx context.Context, req apigen.ListAdaptersRequestObject) (apigen.ListAdaptersResponseObject, error) {
	rows, err := a.Adapters.List(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project))
	if err != nil {
		return nil, err
	}
	out := apigen.AdapterList{Items: []apigen.Adapter{}}
	for _, row := range rows {
		response, err := adapterResponse(row)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, response)
	}
	return apigen.ListAdapters200JSONResponse(out), nil
}

func (a *API) CreateAdapter(ctx context.Context, req apigen.CreateAdapterRequestObject) (apigen.CreateAdapterResponseObject, error) {
	view, err := a.Adapters.Create(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), service.CreateAdapterRequest{Origin: req.Body.Origin, Credential: []byte(req.Body.Credential), Target: targetInput(req.Body.Target)})
	if err != nil {
		return nil, err
	}
	out, err := adapterResponse(view)
	if err != nil {
		return nil, err
	}
	return apigen.CreateAdapter201JSONResponse(out), nil
}

func (a *API) ShowAdapter(ctx context.Context, req apigen.ShowAdapterRequestObject) (apigen.ShowAdapterResponseObject, error) {
	view, err := a.Adapters.Get(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), string(req.Adapter))
	if err != nil {
		return nil, err
	}
	out, err := adapterResponse(view)
	if err != nil {
		return nil, err
	}
	return apigen.ShowAdapter200JSONResponse(out), nil
}

func (a *API) UpdateAdapterOrigin(ctx context.Context, req apigen.UpdateAdapterOriginRequestObject) (apigen.UpdateAdapterOriginResponseObject, error) {
	credential := []byte(req.Body.Credential)
	defer func() {
		for i := range credential {
			credential[i] = 0
		}
	}()
	started, err := a.Adapters.MoveOrigin(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), string(req.Adapter), req.Body.Origin, credential, req.Body.KeepRemote != nil && *req.Body.KeepRemote)
	if err != nil {
		return nil, err
	}
	move, err := a.Adapters.Move(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), started.MoveID)
	if err != nil {
		return nil, err
	}
	out, err := adapterMoveResponse(move)
	if err != nil {
		return nil, err
	}
	return apigen.UpdateAdapterOrigin202JSONResponse(out), nil
}

func (a *API) ShowAdapterMove(ctx context.Context, req apigen.ShowAdapterMoveRequestObject) (apigen.ShowAdapterMoveResponseObject, error) {
	move, err := a.Adapters.Move(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), string(req.Move))
	if err != nil {
		return nil, err
	}
	out, err := adapterMoveResponse(move)
	if err != nil {
		return nil, err
	}
	return apigen.ShowAdapterMove200JSONResponse(out), nil
}

func (a *API) ResumeAdapterMove(ctx context.Context, req apigen.ResumeAdapterMoveRequestObject) (apigen.ResumeAdapterMoveResponseObject, error) {
	origin, originErr := req.Body.AsResumeAdapterOriginMoveRequest()
	target, targetErr := req.Body.AsResumeAdapterTargetMoveRequest()
	isOrigin := originErr == nil && (origin.Origin != "" || origin.Credential != "")
	isTarget := targetErr == nil && (target.TargetId != "" || target.EnvironmentId != "" || target.DestinationOwner != "" || len(target.KeyIds) != 0)
	if isOrigin == isTarget {
		return nil, fmt.Errorf("%w: adapter move resume requires exactly one pending origin or pending target route", domain.ErrInvalid)
	}
	scope := adapterScope(req.Org, req.Project)
	var (
		move service.AdapterMove
		err  error
	)
	if isOrigin {
		credential := []byte(origin.Credential)
		defer func() {
			for i := range credential {
				credential[i] = 0
			}
		}()
		move, err = a.Adapters.ResumeOriginMove(ctx, service.Bearer(bearer(ctx)), scope, string(req.Move), origin.Origin, credential)
	} else {
		input := service.AdapterTargetInput{
			EnvironmentID:    string(target.EnvironmentId),
			DestinationKind:  string(target.DestinationKind),
			DestinationOwner: target.DestinationOwner,
			DestinationName:  target.DestinationName,
			NamePrefix:       target.NamePrefix,
		}
		for _, id := range target.KeyIds {
			input.KeyIDs = append(input.KeyIDs, string(id))
		}
		move, err = a.Adapters.ResumeTargetMove(ctx, service.Bearer(bearer(ctx)), scope, string(req.Move), service.UpdateAdapterTargetRequest{TargetID: string(target.TargetId), Target: input})
	}
	if err != nil {
		return nil, err
	}
	out, err := adapterMoveResponse(move)
	if err != nil {
		return nil, err
	}
	return apigen.ResumeAdapterMove202JSONResponse(out), nil
}

func (a *API) CancelAdapterMove(ctx context.Context, req apigen.CancelAdapterMoveRequestObject) (apigen.CancelAdapterMoveResponseObject, error) {
	move, err := a.Adapters.CancelMove(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), string(req.Move))
	if err != nil {
		return nil, err
	}
	out, err := adapterMoveResponse(move)
	if err != nil {
		return nil, err
	}
	return apigen.CancelAdapterMove202JSONResponse(out), nil
}

func (a *API) DeleteAdapter(ctx context.Context, req apigen.DeleteAdapterRequestObject) (apigen.DeleteAdapterResponseObject, error) {
	keep := req.Params.KeepRemote != nil && *req.Params.KeepRemote
	out, err := a.Adapters.Delete(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), string(req.Adapter), keep)
	if err != nil {
		return nil, err
	}
	return apigen.DeleteAdapter200JSONResponse(teardownResponse(out)), nil
}

func (a *API) SetAdapterCredential(ctx context.Context, req apigen.SetAdapterCredentialRequestObject) (apigen.SetAdapterCredentialResponseObject, error) {
	_, err := a.Adapters.ReplaceCredential(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), string(req.Adapter), []byte(req.Body.Credential))
	if err != nil {
		return nil, err
	}
	return apigen.SetAdapterCredential204Response{}, nil
}

func (a *API) RevokeAdapterCredential(ctx context.Context, req apigen.RevokeAdapterCredentialRequestObject) (apigen.RevokeAdapterCredentialResponseObject, error) {
	_, err := a.Adapters.RevokeCredential(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), string(req.Adapter))
	if err != nil {
		return nil, err
	}
	return apigen.RevokeAdapterCredential204Response{}, nil
}

func (a *API) ListAdapterTargets(ctx context.Context, req apigen.ListAdapterTargetsRequestObject) (apigen.ListAdapterTargetsResponseObject, error) {
	view, err := a.Adapters.Get(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), string(req.Adapter))
	if err != nil {
		return nil, err
	}
	out := apigen.AdapterTargetList{Items: []apigen.AdapterTarget{}}
	for _, target := range view.Targets {
		out.Items = append(out.Items, adapterTargetResponse(target, view.TargetConflicts[target.ID]...))
	}
	return apigen.ListAdapterTargets200JSONResponse(out), nil
}

func (a *API) AddAdapterTarget(ctx context.Context, req apigen.AddAdapterTargetRequestObject) (apigen.AddAdapterTargetResponseObject, error) {
	target, err := a.Adapters.AddTarget(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), string(req.Adapter), targetInput(*req.Body))
	if err != nil {
		return nil, err
	}
	return apigen.AddAdapterTarget201JSONResponse(adapterTargetResponse(target)), nil
}

func (a *API) ShowAdapterTarget(ctx context.Context, req apigen.ShowAdapterTargetRequestObject) (apigen.ShowAdapterTargetResponseObject, error) {
	view, err := a.Adapters.InspectTarget(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), string(req.Target))
	if err != nil {
		return nil, err
	}
	if req.Params.Format != nil && string(*req.Params.Format) == "workflow" {
		return apigen.ShowAdapterTarget200TextResponse(view.Workflow), nil
	}
	out := apigen.AdapterTargetDetail{Target: adapterTargetResponse(view.Target, view.Conflicts...), Conflicts: adapterConflictResponses(view.Conflicts), Mapping: []apigen.AdapterMappingEntry{}}
	for _, entry := range view.Mapping {
		surface := "secret"
		if entry.Classification == adapter.ConfigClassification {
			surface = "variable"
		}
		out.Mapping = append(out.Mapping, apigen.AdapterMappingEntry{KeyId: apigen.ID(entry.KeyID), CanonicalName: entry.CanonicalName, Surface: apigen.AdapterMappingEntrySurface(surface), EffectiveName: view.Target.NamePrefix + entry.CanonicalName})
	}
	return apigen.ShowAdapterTarget200JSONResponse(out), nil
}

func (a *API) UpdateAdapterTarget(ctx context.Context, req apigen.UpdateAdapterTargetRequestObject) (apigen.UpdateAdapterTargetResponseObject, error) {
	input := service.AdapterTargetInput{EnvironmentID: string(req.Body.EnvironmentId), DestinationKind: string(req.Body.DestinationKind), DestinationOwner: req.Body.DestinationOwner, DestinationName: req.Body.DestinationName, NamePrefix: req.Body.NamePrefix}
	for _, id := range req.Body.KeyIds {
		input.KeyIDs = append(input.KeyIDs, string(id))
	}
	request := service.UpdateAdapterTargetRequest{TargetID: string(req.Target), ExpectedGeneration: req.Body.ExpectedGeneration, Target: input}
	current, err := a.Adapters.InspectTarget(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), string(req.Target))
	if err != nil {
		return nil, err
	}
	if input.EnvironmentID != current.Target.EnvironmentID {
		return nil, fmt.Errorf("%w: target environment is immutable; remove and add the target", domain.ErrConflict)
	}
	sameDestination := input.DestinationKind == current.Target.DestinationKind &&
		input.DestinationOwner == current.Target.DestinationOwner && input.DestinationName == current.Target.DestinationName
	if sameDestination {
		if req.Body.KeepRemote != nil && *req.Body.KeepRemote {
			return nil, fmt.Errorf("%w: keep_remote applies only to a destination move", domain.ErrInvalid)
		}
		updated, err := a.Adapters.UpdateTarget(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), request)
		if err != nil {
			return nil, err
		}
		return apigen.UpdateAdapterTarget200JSONResponse(adapterTargetResponse(updated)), nil
	}
	started, err := a.Adapters.MoveTarget(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), request, req.Body.KeepRemote != nil && *req.Body.KeepRemote)
	if err != nil {
		return nil, err
	}
	move, err := a.Adapters.Move(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), started.MoveID)
	if err != nil {
		return nil, err
	}
	out, err := adapterMoveResponse(move)
	if err != nil {
		return nil, err
	}
	return apigen.UpdateAdapterTarget202JSONResponse(out), nil
}

func (a *API) RemoveAdapterTarget(ctx context.Context, req apigen.RemoveAdapterTargetRequestObject) (apigen.RemoveAdapterTargetResponseObject, error) {
	keep := req.Params.KeepRemote != nil && *req.Params.KeepRemote
	out, err := a.Adapters.RemoveTarget(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), string(req.Target), keep)
	if err != nil {
		return nil, err
	}
	return apigen.RemoveAdapterTarget200JSONResponse(teardownResponse(out)), nil
}

func (a *API) PlanAdapterTarget(ctx context.Context, req apigen.PlanAdapterTargetRequestObject) (apigen.PlanAdapterTargetResponseObject, error) {
	plan, err := a.Adapters.Plan(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), string(req.Target))
	if err != nil {
		return nil, err
	}
	out := apigen.AdapterPlan{ArtifactId: apigen.ID(plan.ArtifactID), Changes: []apigen.AdapterChange{}}
	for _, change := range plan.Plan.Changes {
		row := apigen.AdapterChange{Surface: apigen.AdapterChangeSurface(change.Surface), EffectiveName: change.EffectiveName, Disposition: apigen.AdapterChangeDisposition(change.Disposition)}
		out.Changes = append(out.Changes, row)
	}
	return apigen.PlanAdapterTarget200JSONResponse(out), nil
}

func (a *API) SyncAdapterTarget(ctx context.Context, req apigen.SyncAdapterTargetRequestObject) (apigen.SyncAdapterTargetResponseObject, error) {
	job, err := a.Adapters.SyncTarget(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), string(req.Target))
	if err != nil {
		return nil, err
	}
	return apigen.SyncAdapterTarget202JSONResponse{JobId: apigen.ID(job.JobID), Generation: job.Generation}, nil
}

func (a *API) TestAdapterTarget(ctx context.Context, req apigen.TestAdapterTargetRequestObject) (apigen.TestAdapterTargetResponseObject, error) {
	connection, err := a.Adapters.TestTarget(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), string(req.Target))
	if err != nil {
		return nil, err
	}
	return apigen.TestAdapterTarget200JSONResponse{Version: connection.Version, DestinationId: connection.DestinationID}, nil
}

func (a *API) AdoptAdapterTargetNames(ctx context.Context, req apigen.AdoptAdapterTargetNamesRequestObject) (apigen.AdoptAdapterTargetNamesResponseObject, error) {
	entries := make([]service.AdapterConflictEntry, 0, len(req.Body.Entries))
	for _, entry := range req.Body.Entries {
		entries = append(entries, service.AdapterConflictEntry{Surface: string(entry.Surface), EffectiveName: entry.EffectiveName})
	}
	result, err := a.Adapters.Adopt(ctx, service.Bearer(bearer(ctx)), adapterScope(req.Org, req.Project), service.AdoptAdapterRequest{TargetID: string(req.Target), ArtifactID: string(req.Body.ArtifactId), ExpectedGeneration: req.Body.TargetGeneration, ExpectedDestinationID: req.Body.DestinationId, Entries: entries})
	if err != nil {
		return nil, err
	}
	return apigen.AdoptAdapterTargetNames202JSONResponse{JobId: apigen.ID(result.JobID), Generation: result.Generation}, nil
}
