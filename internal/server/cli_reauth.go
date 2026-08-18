package server

import (
	"context"
	"errors"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

func (a *API) StartCLIReauth(ctx context.Context, req apigen.StartCLIReauthRequestObject) (apigen.StartCLIReauthResponseObject, error) {
	environments := make([]string, 0, len(req.Body.EnvironmentIds))
	for _, environmentID := range req.Body.EnvironmentIds {
		environments = append(environments, string(environmentID))
	}
	result, err := a.Auth.StartCLIReauth(ctx, bearer(ctx), string(req.Body.Purpose), string(req.Body.Operation), environments, req.Body.PkceChallenge, req.Body.RedirectUri)
	if err != nil {
		return nil, err
	}
	return apigen.StartCLIReauth201JSONResponse{State: result.State, ExpiresAt: result.ExpiresAt}, nil
}

func (a *API) ShowCLIReauthTransaction(ctx context.Context, req apigen.ShowCLIReauthTransactionRequestObject) (apigen.ShowCLIReauthTransactionResponseObject, error) {
	result, err := a.Auth.CLIReauthTransaction(ctx, service.Bearer(bearer(ctx)), req.State)
	if err != nil {
		if errors.Is(err, service.ErrCLIReauthInvalid) || errors.Is(err, service.ErrReauthRequired) {
			return apigen.ShowCLIReauthTransaction409JSONResponse{ConflictJSONResponse: apigen.ConflictJSONResponse(errorBody(apigen.ErrorCodeConflict, ""))}, nil
		}
		return nil, err
	}
	environments := make([]apigen.CLIReauthEnvironmentPolicy, 0, len(result.Environments))
	for _, environment := range result.Environments {
		environments = append(environments, apigen.CLIReauthEnvironmentPolicy{EnvironmentId: apigen.ID(environment.EnvironmentID), EffectiveWindowSeconds: environment.EffectiveWindowSeconds, RequiresWebauthn: environment.RequiresWebAuthn})
	}
	return apigen.ShowCLIReauthTransaction200JSONResponse{State: result.State, Operation: apigen.CLIReauthTransactionOperation(result.Operation), Environments: environments, RedirectUri: result.RedirectURI, ExpiresAt: result.ExpiresAt}, nil
}

func (a *API) ApproveCLIReauth(ctx context.Context, req apigen.ApproveCLIReauthRequestObject) (apigen.ApproveCLIReauthResponseObject, error) {
	approved, err := a.Auth.ApproveCLIReauth(ctx, service.Bearer(bearer(ctx)), req.Body.State)
	if err != nil {
		if errors.Is(err, service.ErrReauthRequired) || errors.Is(err, service.ErrCLIReauthInvalid) {
			return apigen.ApproveCLIReauth409JSONResponse{ConflictJSONResponse: apigen.ConflictJSONResponse(errorBody(apigen.ErrorCodeConflict, ""))}, nil
		}
		return nil, err
	}
	return apigen.ApproveCLIReauth200JSONResponse{Code: approved.Code, State: approved.State, RedirectUri: approved.RedirectURI}, nil
}

func (a *API) RedeemCLIReauth(ctx context.Context, req apigen.RedeemCLIReauthRequestObject) (apigen.RedeemCLIReauthResponseObject, error) {
	result, err := a.Auth.RedeemCLIReauth(ctx, req.Body.Code, req.Body.PkceVerifier)
	if err != nil {
		if errors.Is(err, service.ErrCLIReauthInvalid) {
			return apigen.RedeemCLIReauth409JSONResponse{ConflictJSONResponse: apigen.ConflictJSONResponse(errorBody(apigen.ErrorCodeConflict, ""))}, nil
		}
		if errors.Is(err, domain.ErrUnauthenticated) {
			return apigen.RedeemCLIReauth401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		}
		return nil, err
	}
	windows := make([]apigen.ReauthResult, 0, len(result.Windows))
	for _, window := range result.Windows {
		windows = append(windows, apigen.ReauthResult{SessionId: apigen.ID(window.SessionID), EnvironmentId: window.EnvironmentID, SingleDecision: window.SingleDecision, WindowExpires: window.WindowExpires})
	}
	return apigen.RedeemCLIReauth200JSONResponse{SessionId: apigen.ID(result.SessionID), SessionToken: result.SessionToken, Windows: windows}, nil
}
