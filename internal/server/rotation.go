package server

import (
	"context"
	"fmt"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

// RotationService is the crypto key-hierarchy rotation surface (#75): the four
// operations that are not the token key. Like every service interface here the
// transport translates and decides nothing.
type RotationService interface {
	RotateDEK(ctx context.Context, actor service.Actor, scope service.DEKScope) (service.DEKRotation, error)
	RotateMasterKey(ctx context.Context, actor service.Actor) (service.MasterKeyRotation, error)
	RotateRootKey(ctx context.Context, actor service.Actor, phase service.RootKeyRotationPhase) (service.RootKeyRotation, error)
}

func (a *API) RotateDEK(ctx context.Context, req apigen.RotateDEKRequestObject) (apigen.RotateDEKResponseObject, error) {
	scope, err := dekScopeFromWire(req.Body.Scope, req.Body.Org, req.Body.Project)
	if err != nil {
		return nil, err
	}
	rot, err := a.Rotation.RotateDEK(ctx, service.Bearer(bearer(ctx)), scope)
	if err != nil {
		return nil, err
	}
	out := apigen.DEKRotation{
		Scope:      apigen.DEKRotationScope(rot.Scope),
		KeyVersion: int64(rot.Version),
	}
	if rot.OrgID != "" {
		out.Org = &rot.OrgID
	}
	if rot.ProjectID != "" {
		out.Project = &rot.ProjectID
	}
	return apigen.RotateDEK200JSONResponse(out), nil
}

func (a *API) RotateMasterKey(ctx context.Context, _ apigen.RotateMasterKeyRequestObject) (apigen.RotateMasterKeyResponseObject, error) {
	rot, err := a.Rotation.RotateMasterKey(ctx, service.Bearer(bearer(ctx)))
	if err != nil {
		return nil, err
	}
	return apigen.RotateMasterKey200JSONResponse(apigen.MasterKeyRotation{
		KeyVersion: int64(rot.Version),
	}), nil
}

func (a *API) RotateRootKey(ctx context.Context, req apigen.RotateRootKeyRequestObject) (apigen.RotateRootKeyResponseObject, error) {
	var phase service.RootKeyRotationPhase
	switch req.Body.Phase {
	case apigen.RotateRootKeyRequestPhasePrepare:
		phase = service.RootRotatePrepare
	case apigen.RotateRootKeyRequestPhaseVerify:
		phase = service.RootRotateVerify
	case apigen.RotateRootKeyRequestPhaseFinalize:
		phase = service.RootRotateFinalize
	default:
		return nil, fmt.Errorf("%w: unknown root rotation phase %q", domain.ErrInvalid, req.Body.Phase)
	}
	rot, err := a.Rotation.RotateRootKey(ctx, service.Bearer(bearer(ctx)), phase)
	if err != nil {
		return nil, err
	}
	return apigen.RotateRootKey200JSONResponse(apigen.RootKeyRotation{
		Phase:        apigen.RootKeyRotationPhase(rot.Phase),
		RootKeyEpoch: int64(rot.Epoch),
	}), nil
}

// dekScopeFromWire translates the request enum into the service scope. An
// unknown scope, or a project scope missing its ids, is a bad request; the
// service validates the ids again so the rule holds regardless of transport.
func dekScopeFromWire(scope apigen.RotateDEKRequestScope, org, project *string) (service.DEKScope, error) {
	switch scope {
	case apigen.RotateDEKRequestScopeInstance:
		if org != nil || project != nil {
			return service.DEKScope{}, fmt.Errorf("%w: instance scope carries no org or project", domain.ErrInvalid)
		}
		return service.DEKScope{Instance: true}, nil
	case apigen.RotateDEKRequestScopeProject:
		if org == nil || project == nil {
			return service.DEKScope{}, fmt.Errorf("%w: project scope requires org and project", domain.ErrInvalid)
		}
		return service.DEKScope{OrgID: *org, ProjectID: *project}, nil
	default:
		return service.DEKScope{}, fmt.Errorf("%w: unknown DEK scope %q", domain.ErrInvalid, scope)
	}
}
