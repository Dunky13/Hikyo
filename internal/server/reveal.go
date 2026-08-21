package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

// The reveal-ceremony transport (#58).
//
// Two routes, and both exist because the reveal guard's rule is that the
// window gates the PROMPT, never the authorization check. A browser that
// cannot ask "will this prompt me, and with what" has to guess, and a client
// that guesses either prompts for a window that is already open (noise) or
// discloses without one (a refusal the human cannot act on).
//
// Neither route discloses material.

// RevealService is the guard's read surface.
type RevealService interface {
	Window(ctx context.Context, actor service.Actor, scope domain.Scope) (service.RevealWindow, error)
}

func (a *API) GetRevealWindow(ctx context.Context, req apigen.GetRevealWindowRequestObject) (apigen.GetRevealWindowResponseObject, error) {
	got, err := a.Reveal.Window(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment))
	if err != nil {
		return nil, err
	}
	out := apigen.RevealWindow{
		EffectiveWindowSeconds: got.EffectiveWindowSeconds,
		Protected:              got.Protected,
		TotpOffered:            got.TOTPOffered,
		Live:                   got.Live,
		SingleDecision:         got.SingleDecision,
		CanReveal:              got.CanReveal,
	}
	// Absent rather than a zero timestamp when nothing is live: "no window"
	// and "a window that expired at the zero instant" must not read the same,
	// and a countdown chip rendering 1970 is how that mistake shows up.
	if got.Live {
		expires := got.ExpiresAt
		out.ExpiresAt = &expires
	}
	return apigen.GetRevealWindow200JSONResponse(out), nil
}

// ReauthTotp opens a disclosure window with a TOTP code.
//
// The one refusal worth reading twice is the 409. A `0` effective window — what
// every protected environment is capped at — has no TOTP path at all, because
// TOTP cannot bind its challenge to the enumerated unit and therefore cannot
// authorize one decision over exactly those keys. That is not an authorization
// answer about this caller, it is the ENVIRONMENT's state refusing the factor,
// which is what conflict means. Answering 401 instead would tell the human
// their code was wrong and send them to re-enrol an authenticator that was
// never the problem.
func (a *API) ReauthTotp(ctx context.Context, req apigen.ReauthTotpRequestObject) (apigen.ReauthTotpResponseObject, error) {
	var (
		results []service.ReauthResult
		err     error
	)
	adapterPurpose := req.Body.Purpose != nil && *req.Body.Purpose == apigen.ReauthPurposeAdapter
	if adapterPurpose {
		if req.Body.Operation == nil || req.Body.EnvironmentIds == nil || len(*req.Body.EnvironmentIds) == 0 || req.Body.EnvironmentId != nil {
			return apigen.ReauthTotp400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
		}
		rawIDs := make([]string, 0, len(*req.Body.EnvironmentIds))
		for _, environmentID := range *req.Body.EnvironmentIds {
			rawIDs = append(rawIDs, string(environmentID))
		}
		results, err = a.Auth.ReauthAdapterTOTP(ctx, bearer(ctx), string(*req.Body.Operation), rawIDs, req.Body.Code)
	} else {
		if req.Body.Purpose != nil || req.Body.Operation != nil || req.Body.EnvironmentIds != nil || req.Body.EnvironmentId == nil {
			return apigen.ReauthTotp400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
		}
		var result service.ReauthResult
		result, err = a.Auth.ReauthTOTP(ctx, bearer(ctx), string(*req.Body.EnvironmentId), req.Body.Code)
		if err == nil {
			results = []service.ReauthResult{result}
		}
	}
	if err != nil {
		policy := wireErrorFor(err)
		switch policy.code {
		case apigen.ErrorCodeConflict:
			// Single-use and closed-window refusals are post-authentication
			// conflicts. Only an explicit SafeDetail carrier can add detail.
			return apigen.ReauthTotp409JSONResponse{
				ConflictJSONResponse: apigen.ConflictJSONResponse(policy.body(err)),
			}, nil
		case apigen.ErrorCodeBadRequest:
			return apigen.ReauthTotp400JSONResponse{
				BadRequestJSONResponse: apigen.BadRequestJSONResponse(policy.body(err)),
			}, nil
		case apigen.ErrorCodeUnauthenticated:
			return apigen.ReauthTotp401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(policy.body(err)),
			}, nil
		case apigen.ErrorCodeNotFound:
			// An environment the caller cannot reach answers the uniform
			// nonexistent here exactly as it does everywhere else — a reauth
			// route must not become the enumeration oracle the value routes
			// are careful not to be.
			return apigen.ReauthTotp401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
			}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.ReauthTotp429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "totp reauth", err)
			return apigen.ReauthTotp500JSONResponse{
				InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
			}, nil
		}
	}
	resp, err := makeReauthTotpResponse(requestFrom(ctx), results, adapterPurpose)
	if err != nil {
		a.fault(ctx, "totp reauth response", err)
		return apigen.ReauthTotp500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
	}
	return resp, nil
}

func makeReauthTotpResponse(request *http.Request, results []service.ReauthResult, adapterPurpose bool) (reauthTotpResponse, error) {
	if request == nil || len(results) == 0 || results[0].SessionToken == "" {
		return reauthTotpResponse{}, errors.New("server: TOTP reauth result has no delivery channel or rotated token")
	}
	first := results[0]
	earliest := first.WindowExpires
	environments := make([]apigen.ID, 0, len(results))
	for _, result := range results {
		if result.SessionID != first.SessionID || result.SessionToken != first.SessionToken {
			return reauthTotpResponse{}, errors.New("server: TOTP reauth results disagree on rotated session")
		}
		environments = append(environments, apigen.ID(result.EnvironmentID))
		if result.WindowExpires.Before(earliest) {
			earliest = result.WindowExpires
		}
	}
	resp := reauthTotpResponse{body: apigen.ReauthResult{
		SessionId: first.SessionID, EnvironmentId: first.EnvironmentID,
		SingleDecision: first.SingleDecision, WindowExpires: earliest,
	}}
	if adapterPurpose {
		resp.body.EnvironmentIds = &environments
	}
	if cookie, err := request.Cookie(browserSessionCookie); err == nil && strings.TrimSpace(cookie.Value) != "" {
		resp.cookies = browserCookiesFor(first.SessionToken, first.CSRFToken)
		return resp, nil
	}
	if value, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer "); ok && strings.TrimSpace(value) != "" {
		resp.body.SessionToken = &first.SessionToken
		return resp, nil
	}
	return reauthTotpResponse{}, fmt.Errorf("server: TOTP reauth request carried no recognized session artifact")
}

type reauthTotpResponse struct {
	body    apigen.ReauthResult
	cookies []*http.Cookie
}

func (r reauthTotpResponse) VisitReauthTotpResponse(w http.ResponseWriter) error {
	return writeJSONWithCookies(w, r.cookies, http.StatusOK, r.body)
}
