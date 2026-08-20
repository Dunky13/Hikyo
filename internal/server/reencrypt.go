package server

import (
	"context"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

// ReencryptService is the crypto reencrypt surface (#75/#187): move a scope's
// ciphertext onto the active DEK version and retire the old.
type ReencryptService interface {
	ReencryptProject(ctx context.Context, actor service.Actor, orgID, projectID string) (service.ReencryptResult, error)
	ReencryptInstance(ctx context.Context, actor service.Actor) (service.ReencryptResult, error)
}

func (a *API) ReencryptProject(ctx context.Context, req apigen.ReencryptProjectRequestObject) (apigen.ReencryptProjectResponseObject, error) {
	res, err := a.Reencrypt.ReencryptProject(ctx, service.Bearer(bearer(ctx)), req.Org, req.Project)
	if err != nil {
		return nil, err
	}
	return apigen.ReencryptProject200JSONResponse(reencryptBody(res)), nil
}

func (a *API) ReencryptInstance(ctx context.Context, _ apigen.ReencryptInstanceRequestObject) (apigen.ReencryptInstanceResponseObject, error) {
	res, err := a.Reencrypt.ReencryptInstance(ctx, service.Bearer(bearer(ctx)))
	if err != nil {
		return nil, err
	}
	return apigen.ReencryptInstance200JSONResponse(reencryptBody(res)), nil
}

func reencryptBody(res service.ReencryptResult) apigen.ReencryptResult {
	out := apigen.ReencryptResult{Scope: apigen.ReencryptResultScope(res.Scope), RowsMoved: int64(res.RowsMoved)}
	if res.OrgID != "" {
		out.Org = &res.OrgID
	}
	if res.ProjectID != "" {
		out.Project = &res.ProjectID
	}
	return out
}
