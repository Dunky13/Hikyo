package server

import (
	"context"
	"fmt"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

func (a *API) StartCLIReauth(ctx context.Context, req apigen.StartCLIReauthRequestObject) (apigen.StartCLIReauthResponseObject, error) {
	environments := make([]string, 0, len(req.Body.EnvironmentIds))
	for _, environmentID := range req.Body.EnvironmentIds {
		environments = append(environments, string(environmentID))
	}
	var keyIDs []string
	if req.Body.KeyIds != nil {
		for _, keyID := range *req.Body.KeyIds {
			keyIDs = append(keyIDs, string(keyID))
		}
	}
	var intent service.ReauthIntent
	var err error
	if req.Body.Purpose == apigen.CLIReauthStartRequestPurposeAdapter {
		if len(keyIDs) != 0 {
			return nil, fmt.Errorf("%w: adapter reauthentication does not carry key ids", domain.ErrInvalid)
		}
		intent, err = service.NewAdapterReauthIntent(string(req.Body.Operation), environments)
	} else {
		intent, err = service.NewDisclosureReauthIntent(service.ReauthPurpose(req.Body.Purpose), environments, keyIDs)
		if err == nil {
			operation, operationErr := intent.Operation()
			err = operationErr
			if operationErr == nil && string(operation) != string(req.Body.Operation) {
				err = fmt.Errorf("%w: reauthentication purpose and operation disagree", domain.ErrInvalid)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	result, err := a.Auth.StartCLIReauth(ctx, bearer(ctx), intent, req.Body.PkceChallenge, req.Body.RedirectUri)
	if err != nil {
		return nil, err
	}
	return apigen.StartCLIReauth201JSONResponse{State: result.State, ExpiresAt: result.ExpiresAt}, nil
}

func (a *API) ShowCLIReauthTransaction(ctx context.Context, req apigen.ShowCLIReauthTransactionRequestObject) (apigen.ShowCLIReauthTransactionResponseObject, error) {
	result, err := a.Auth.CLIReauthTransaction(ctx, service.Bearer(bearer(ctx)), req.State)
	if err != nil {
		if wireErrorFor(err).code == apigen.ErrorCodeConflict {
			return apigen.ShowCLIReauthTransaction409JSONResponse{ConflictJSONResponse: apigen.ConflictJSONResponse(errorBody(apigen.ErrorCodeConflict, ""))}, nil
		}
		return nil, err
	}
	environments := make([]apigen.CLIReauthEnvironmentPolicy, 0, len(result.Environments))
	for _, environment := range result.Environments {
		environments = append(environments, apigen.CLIReauthEnvironmentPolicy{EnvironmentId: apigen.ID(environment.EnvironmentID), EffectiveWindowSeconds: environment.EffectiveWindowSeconds, RequiresWebauthn: environment.RequiresWebAuthn})
	}
	keyIDs := make([]apigen.ID, 0, len(result.KeyIDs))
	for _, keyID := range result.KeyIDs {
		keyIDs = append(keyIDs, apigen.ID(keyID))
	}
	return apigen.ShowCLIReauthTransaction200JSONResponse{State: result.State, Purpose: apigen.CLIReauthTransactionPurpose(result.Purpose), Operation: apigen.CLIReauthTransactionOperation(result.Operation), Environments: environments, KeyIds: keyIDs, RedirectUri: result.RedirectURI, ExpiresAt: result.ExpiresAt}, nil
}

func (a *API) ApproveCLIReauth(ctx context.Context, req apigen.ApproveCLIReauthRequestObject) (apigen.ApproveCLIReauthResponseObject, error) {
	approved, err := a.Auth.ApproveCLIReauth(ctx, service.Bearer(bearer(ctx)), req.Body.State)
	if err != nil {
		if wireErrorFor(err).code == apigen.ErrorCodeConflict {
			return apigen.ApproveCLIReauth409JSONResponse{ConflictJSONResponse: apigen.ConflictJSONResponse(errorBody(apigen.ErrorCodeConflict, ""))}, nil
		}
		return nil, err
	}
	return apigen.ApproveCLIReauth200JSONResponse{Code: approved.Code, State: approved.State, RedirectUri: approved.RedirectURI}, nil
}

func (a *API) RedeemCLIReauth(ctx context.Context, req apigen.RedeemCLIReauthRequestObject) (apigen.RedeemCLIReauthResponseObject, error) {
	result, err := a.Auth.RedeemCLIReauth(ctx, req.Body.Code, req.Body.PkceVerifier)
	if err != nil {
		switch wireErrorFor(err).code {
		case apigen.ErrorCodeConflict:
			return apigen.RedeemCLIReauth409JSONResponse{ConflictJSONResponse: apigen.ConflictJSONResponse(errorBody(apigen.ErrorCodeConflict, ""))}, nil
		case apigen.ErrorCodeUnauthenticated:
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
