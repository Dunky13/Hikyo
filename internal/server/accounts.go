package server

import (
	"context"
	"errors"

	"github.com/Dunky13/hikyo/api/apigen"
	"github.com/Dunky13/hikyo/internal/service"
)

// Administrator-issued credential reset (#54, human-auth ADR - Recovery).
//
// The route is enumeration-uniform (classified unauthenticated): every failure
// that could reveal the target's grant shape — an unknown target, a caller
// lacking credential-reset, an org-P holder reaching for an org-O target, and a
// target holding an instance capability (break-glass only) — answers the same
// uniform 401 (B2). There is no differential status a reset holder could probe
// grant shapes with; the operator learns to use break-glass from the docs, and
// the true cause of every refusal is durable in the audit trail.
func (a *API) ResetCredential(ctx context.Context, req apigen.ResetCredentialRequestObject) (apigen.ResetCredentialResponseObject, error) {
	// The authority is delivered in the HTTP response to the credential-reset
	// holder, who transmits it to the target out of band.
	result, err := a.Auth.ResetCredential(ctx, service.Bearer(bearer(ctx)), string(req.Principal), "response")
	if err != nil {
		// An unknown or non-human target — and an instance-capability target with
		// no network path — answer the SAME uniform 401 as an unauthorized one, so
		// the response cannot distinguish "exists but is not reachable here" from
		// "you may not reach it" (classify would otherwise fault it to 500 — a
		// status-code oracle on an enumeration-uniform route).
		if errors.Is(err, service.ErrNoResetTarget) {
			return apigen.ResetCredential401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
			}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeTooManyRequests:
			return apigen.ResetCredential429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		case apigen.ErrorCodeInternal:
			a.fault(ctx, "credential reset", err)
			return apigen.ResetCredential500JSONResponse{
				InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
			}, nil
		default:
			// Unknown target, unauthorized (org-bounded ErrNotFound or instance
			// ErrUnauthorized) and unauthenticated all collapse to one uniform 401,
			// so the response cannot enumerate the target's reachability.
			return apigen.ResetCredential401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
			}, nil
		}
	}
	return apigen.ResetCredential200JSONResponse{
		Authority: result.Authority,
		ExpiresAt: result.ExpiresAt,
	}, nil
}
