package server

import (
	"context"
	"net/http"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

// canonicalDefinitionsResponse writes the service's already-canonical bytes
// directly. Going through json.Encoder would append a newline and make the
// HTTP export differ from the digestable canonical bundle.
type canonicalDefinitionsResponse []byte

func (r canonicalDefinitionsResponse) VisitExportDefinitionsResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(r)
	return err
}

func (a *API) ExportDefinitions(ctx context.Context, req apigen.ExportDefinitionsRequestObject) (apigen.ExportDefinitionsResponseObject, error) {
	portable := req.Params.Portable != nil && *req.Params.Portable
	raw, err := a.Definitions.Export(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), portable)
	if err != nil {
		return nil, err
	}
	return canonicalDefinitionsResponse(raw), nil
}

func (a *API) CheckDefinitions(ctx context.Context, req apigen.CheckDefinitionsRequestObject) (apigen.CheckDefinitionsResponseObject, error) {
	got, err := a.Definitions.Check(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), []byte(*req.Body))
	if err != nil {
		return nil, err
	}
	resp := apigen.CheckDefinitions200JSONResponse{
		State: apigen.DefinitionsCheckResultState(got.State), BaseRevision: got.BaseRevision,
		CurrentRevision: got.CurrentRevision, Differences: wireDefinitionsDiff(got.Differences),
	}
	if fs := wireScanFindings(got.Findings); len(fs) > 0 {
		resp.Findings = &fs
	}
	return resp, nil
}

func (a *API) CreateDefinitionsPlan(ctx context.Context, req apigen.CreateDefinitionsPlanRequestObject) (apigen.CreateDefinitionsPlanResponseObject, error) {
	var acks []string
	if req.Params.Acknowledge != nil {
		acks = []string(*req.Params.Acknowledge)
	}
	got, err := a.Definitions.Plan(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), []byte(*req.Body), acks)
	if err != nil {
		return nil, err
	}
	return apigen.CreateDefinitionsPlan201JSONResponse{Plan: wireDefinitionsPlan(got)}, nil
}

func (a *API) GetDefinitionsPlan(ctx context.Context, req apigen.GetDefinitionsPlanRequestObject) (apigen.GetDefinitionsPlanResponseObject, error) {
	got, err := a.Definitions.GetPlan(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), req.Plan)
	if err != nil {
		return nil, err
	}
	return apigen.GetDefinitionsPlan200JSONResponse{Plan: wireDefinitionsPlan(got)}, nil
}

func (a *API) ApplyDefinitionsPlan(ctx context.Context, req apigen.ApplyDefinitionsPlanRequestObject) (apigen.ApplyDefinitionsPlanResponseObject, error) {
	var acks []string
	if req.Body.Acknowledgements != nil {
		acks = []string(*req.Body.Acknowledgements)
	}
	got, err := a.Definitions.Apply(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), req.Plan, service.ApplyOptions{
		AllowDelete:      req.Body.AllowDelete,
		Digest:           deref(req.Body.Digest),
		Commit:           deref(req.Body.Commit),
		Ref:              deref(req.Body.Ref),
		Actor:            deref(req.Body.Actor),
		Acknowledgements: acks,
	})
	if err != nil {
		return nil, err
	}
	return apigen.ApplyDefinitionsPlan200JSONResponse{
		Revision: got.Revision, Published: got.Published, PlanId: got.PlanID,
	}, nil
}

func (a *API) GetDefinitionsSettings(ctx context.Context, req apigen.GetDefinitionsSettingsRequestObject) (apigen.GetDefinitionsSettingsResponseObject, error) {
	got, err := a.Definitions.GetSettings(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project))
	if err != nil {
		return nil, err
	}
	return apigen.GetDefinitionsSettings200JSONResponse(wireDefinitionsSettings(got)), nil
}

func (a *API) SetDefinitionsSettings(ctx context.Context, req apigen.SetDefinitionsSettingsRequestObject) (apigen.SetDefinitionsSettingsResponseObject, error) {
	got, err := a.Definitions.SetSettings(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), string(req.Body.DefinitionsSource))
	if err != nil {
		return nil, err
	}
	return apigen.SetDefinitionsSettings200JSONResponse(wireDefinitionsSettings(got)), nil
}

func wireDefinitionsKindDiff(d definitions.KindDiff) apigen.DefinitionsKindDiff {
	renamed := make([]apigen.DefinitionsRename, 0, len(d.Renames))
	for _, r := range d.Renames {
		renamed = append(renamed, apigen.DefinitionsRename{Id: r.ID, From: r.From, To: r.To})
	}
	return apigen.DefinitionsKindDiff{Creates: d.Creates, Updates: d.Updates, Renames: renamed, Deletes: d.Deletes}
}

func wireDefinitionsDiff(d definitions.Diff) apigen.DefinitionsDiff {
	return apigen.DefinitionsDiff{
		Environments: wireDefinitionsKindDiff(d.Environments), KeyGroups: wireDefinitionsKindDiff(d.KeyGroups),
		Keys: wireDefinitionsKindDiff(d.Keys), RevealRequired: d.RevealRequired,
	}
}

func wireDefinitionsPlanDiff(d service.PlanDiff) apigen.DefinitionsPlanDiff {
	keys := make([]apigen.DefinitionsKeyDeletion, 0, len(d.KeyDeletions))
	for _, k := range d.KeyDeletions {
		keys = append(keys, apigen.DefinitionsKeyDeletion{Name: k.Name, LiveIn: k.LiveIn})
	}
	envs := make([]apigen.DefinitionsEnvironmentDeletion, 0, len(d.EnvDeletions))
	for _, e := range d.EnvDeletions {
		envs = append(envs, apigen.DefinitionsEnvironmentDeletion{Name: e.Name, Occurrences: e.Occurrences})
	}
	return apigen.DefinitionsPlanDiff{
		Environments: wireDefinitionsKindDiff(d.Environments), KeyGroups: wireDefinitionsKindDiff(d.KeyGroups),
		Keys: wireDefinitionsKindDiff(d.Keys), KeyDeletions: keys, EnvDeletions: envs, RevealRequired: d.RevealRequired,
	}
}

func wireDefinitionsPlan(p service.PlanView) apigen.DefinitionsPlan {
	return apigen.DefinitionsPlan{
		Id: p.ID, Digest: p.Digest, BaseRevision: p.BaseRevision, CurrentRevision: p.CurrentRevision,
		Additive: p.Additive, ExpiresAt: p.ExpiresAt, ProtectedEnvironments: p.ProtectedEnvironments,
		Diff: wireDefinitionsPlanDiff(p.Diff), DeletionsPresent: p.DeletionsPresent, RevealRequired: p.RevealRequired,
	}
}

func wireDefinitionsSettings(s service.DefinitionsSettings) apigen.DefinitionsSettings {
	out := apigen.DefinitionsSettings{DefinitionsSource: apigen.DefinitionsSettingsDefinitionsSource(s.Source)}
	if s.LastApply != nil {
		out.LastApply = &apigen.DefinitionsLastApply{
			PlanId: s.LastApply.PlanID, AppliedAt: s.LastApply.AppliedAt, AppliedBy: s.LastApply.AppliedBy,
			Commit: optional(s.LastApply.Commit), Ref: optional(s.LastApply.Ref), Actor: optional(s.LastApply.Actor),
			Revision: s.LastApply.Revision,
		}
	}
	return out
}
