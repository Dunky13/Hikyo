package server

import (
	"context"

	"github.com/Dunky13/hikyo/api/apigen"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/service"
)

// The value transport (#50). Same discipline as the rest: this file
// TRANSLATES and decides nothing. Every refusal is a bare domain error routed
// through the one uniform writer.
//
// Two shapes are worth reading twice, because both are disclosure boundaries
// that a careless translation would quietly widen:
//
//   - `value` is emitted only when the service says it was REVEALED. An
//     unrevealed cell has no `value` member at all, rather than an empty
//     string that a client could not tell from an empty value the operator
//     actually set.
//   - `equal` on a diff row is a POINTER all the way to the wire: absent means
//     "not answerable without disclosing something", which is a different fact
//     from `false`, and flattening the two would hand a non-revealer a
//     one-bit oracle on secret equality.

// ValueService is the domain surface this transport exposes.
type ValueService interface {
	Get(ctx context.Context, actor service.Actor, scope domain.Scope, keyName string, reveal bool) (service.ValueCell, error)
	List(ctx context.Context, actor service.Actor, scope domain.Scope, reveal bool) ([]service.ValueCell, error)
	Set(ctx context.Context, actor service.Actor, scope domain.Scope, keyName, value string) (service.StagedChange, error)
	Unset(ctx context.Context, actor service.Actor, scope domain.Scope, keyName string) (service.StagedChange, error)
	Declare(ctx context.Context, actor service.Actor, scope domain.Scope, envIDs []string, keyName, value string) ([]service.ValueCell, error)
	Copy(ctx context.Context, actor service.Actor, scope domain.Scope, req service.CopyRequest) (service.CopyResult, error)
	Diff(ctx context.Context, actor service.Actor, scope domain.Scope, left, right string, reveal bool) ([]service.DiffRow, error)
}

func (a *API) ListValues(ctx context.Context, req apigen.ListValuesRequestObject) (apigen.ListValuesResponseObject, error) {
	cells, err := a.Values.List(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment), false)
	if err != nil {
		return nil, err
	}
	return apigen.ListValues200JSONResponse(wireValueList(cells)), nil
}

func (a *API) GetValue(ctx context.Context, req apigen.GetValueRequestObject) (apigen.GetValueResponseObject, error) {
	cell, err := a.Values.Get(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment), req.Key, false)
	if err != nil {
		return nil, err
	}
	return apigen.GetValue200JSONResponse(wireValueCell(cell)), nil
}

// SetValue and ClearValue STAGE. Neither publishes, so neither answers with a
// value cell: what they return is the immutable version id a later selective
// publish names, which is the only thing the caller can act on.
func (a *API) SetValue(ctx context.Context, req apigen.SetValueRequestObject) (apigen.SetValueResponseObject, error) {
	staged, err := a.Values.Set(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment), req.Key, req.Body.Value)
	if err != nil {
		return nil, err
	}
	return apigen.SetValue200JSONResponse(wireStagedChange(staged)), nil
}

func (a *API) ClearValue(ctx context.Context, req apigen.ClearValueRequestObject) (apigen.ClearValueResponseObject, error) {
	staged, err := a.Values.Unset(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment), req.Key)
	if err != nil {
		return nil, err
	}
	return apigen.ClearValue200JSONResponse(wireStagedChange(staged)), nil
}

func wireStagedChange(c service.StagedChange) apigen.PendingChange {
	return apigen.PendingChange{
		VersionId:          c.VersionID,
		KeyId:              c.KeyID,
		Name:               c.Name,
		Classification:     apigen.KeyClassification(c.Classification),
		Operation:          apigen.PendingChangeOperation(c.Operation),
		StagedFromRevision: c.StagedFromRevision,
		CreatedAt:          c.CreatedAt,
	}
}

func (a *API) DeclareValues(ctx context.Context, req apigen.DeclareValuesRequestObject) (apigen.DeclareValuesResponseObject, error) {
	cells, err := a.Values.Declare(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.Body.EnvironmentIds, req.Body.Key, req.Body.Value)
	if err != nil {
		return nil, err
	}
	return apigen.DeclareValues200JSONResponse(wireValueList(cells)), nil
}

func (a *API) CopyValues(ctx context.Context, req apigen.CopyValuesRequestObject) (apigen.CopyValuesResponseObject, error) {
	result, err := a.Values.Copy(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project),
		service.CopyRequest{
			SourceEnvironmentID:       req.Body.SourceEnvironmentId,
			KeyNames:                  req.Body.Keys,
			DestinationEnvironmentIDs: req.Body.DestinationEnvironmentIds,
			ConfirmProtected:          derefBool(req.Body.ConfirmProtected),
		})
	if err != nil {
		return nil, err
	}
	var out apigen.CopyValuesResult
	for _, c := range result.Copied {
		out.Copied = append(out.Copied, struct {
			DestinationEnvironmentId apigen.ID      `json:"destination_environment_id"`
			Key                      apigen.KeyName `json:"key"`
		}{DestinationEnvironmentId: c.DestinationEnvironment, Key: c.KeyName})
	}
	return apigen.CopyValues200JSONResponse(out), nil
}

func (a *API) DiffValues(ctx context.Context, req apigen.DiffValuesRequestObject) (apigen.DiffValuesResponseObject, error) {
	rows, err := a.Values.Diff(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project),
		req.Params.Left, req.Params.Right, false)
	if err != nil {
		return nil, err
	}
	return apigen.DiffValues200JSONResponse(wireDiff(req.Params.Left, req.Params.Right, rows)), nil
}

// The three reveal routes. They are POSTs and routes of their own because
// disclosure is an ACT: each writes one audit event per disclosed key before
// the plaintext leaves the server, and the ADR's rule is one verb per
// disclosure path, one gate.

func (a *API) RevealValues(ctx context.Context, req apigen.RevealValuesRequestObject) (apigen.RevealValuesResponseObject, error) {
	cells, err := a.Values.List(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment), true)
	if err != nil {
		return nil, err
	}
	return apigen.RevealValues200JSONResponse(wireValueList(cells)), nil
}

func (a *API) RevealValue(ctx context.Context, req apigen.RevealValueRequestObject) (apigen.RevealValueResponseObject, error) {
	cell, err := a.Values.Get(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment), req.Key, true)
	if err != nil {
		return nil, err
	}
	return apigen.RevealValue200JSONResponse(wireValueCell(cell)), nil
}

func (a *API) RevealValueDiff(ctx context.Context, req apigen.RevealValueDiffRequestObject) (apigen.RevealValueDiffResponseObject, error) {
	rows, err := a.Values.Diff(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project),
		req.Body.Left, req.Body.Right, true)
	if err != nil {
		return nil, err
	}
	return apigen.RevealValueDiff200JSONResponse(wireDiff(req.Body.Left, req.Body.Right, rows)), nil
}

func wireDiff(left, right string, rows []service.DiffRow) apigen.ValueDiff {
	items := make([]apigen.ValueDiffRow, 0, len(rows))
	for _, row := range rows {
		items = append(items, apigen.ValueDiffRow{
			KeyId:          row.KeyID,
			Name:           row.Name,
			Classification: apigen.KeyClassification(row.Classification),
			Left:           wireValueCell(row.Left),
			Right:          wireValueCell(row.Right),
			Equal:          row.Equal,
		})
	}
	return apigen.ValueDiff{
		LeftEnvironmentId: left, RightEnvironmentId: right, Items: items,
	}
}

func (a *API) CloneEnvironment(ctx context.Context, req apigen.CloneEnvironmentRequestObject) (apigen.CloneEnvironmentResponseObject, error) {
	env, result, err := a.Environments.Clone(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.Body.Name, req.Body.SourceEnvironmentId)
	if err != nil {
		return nil, err
	}
	// Both lists are non-nil on the wire: `[]` says "nothing was blocked",
	// and a JSON null would read as "unknown" for a fact the server knows
	// exactly.
	copied := result.Copied
	if copied == nil {
		copied = []string{}
	}
	uncopied := result.UncopiedSecrets
	if uncopied == nil {
		uncopied = []string{}
	}
	return apigen.CloneEnvironment201JSONResponse{
		Environment:     wireEnvironment(env),
		Copied:          copied,
		UncopiedSecrets: uncopied,
	}, nil
}

func wireValueCell(c service.ValueCell) apigen.ValueCell {
	out := apigen.ValueCell{
		KeyId:          c.KeyID,
		Name:           c.Name,
		Classification: apigen.KeyClassification(c.Classification),
		Set:            c.Set,
		Revealed:       c.Revealed,
	}
	if c.Revealed {
		value := c.Value
		out.Value = &value
	}
	if c.Set {
		updatedAt := c.UpdatedAt
		updatedBy := c.UpdatedBy
		out.UpdatedAt = &updatedAt
		out.UpdatedBy = &updatedBy
	}
	return out
}

func wireValueList(cells []service.ValueCell) apigen.ValueList {
	items := make([]apigen.ValueCell, 0, len(cells))
	for _, c := range cells {
		items = append(items, wireValueCell(c))
	}
	return apigen.ValueList{Items: items, Count: len(items)}
}
