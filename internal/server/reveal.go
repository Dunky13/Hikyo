package server

import (
	"context"
	"errors"
	"net/http"

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
	result, err := a.Auth.ReauthTOTP(ctx, bearer(ctx), req.Body.EnvironmentId, req.Body.Code)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrReauthWindowClosed):
			return apigen.ReauthTotp409JSONResponse{
				ConflictJSONResponse: apigen.ConflictJSONResponse(errorBody(apigen.ErrorCodeConflict, "")),
			}, nil
		case errors.Is(err, service.ErrNoTOTPFactor):
			return apigen.ReauthTotp400JSONResponse{
				BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, "")),
			}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.ReauthTotp401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
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
		case apigen.ErrorCodeBadRequest:
			return apigen.ReauthTotp400JSONResponse{
				BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, "")),
			}, nil
		default:
			a.fault(ctx, "totp reauth", err)
			return apigen.ReauthTotp500JSONResponse{
				InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
			}, nil
		}
	}
	resp := reauthTotpResponse{body: apigen.ReauthResult{
		SessionId:      result.SessionID,
		EnvironmentId:  result.EnvironmentID,
		SingleDecision: result.SingleDecision,
		WindowExpires:  result.WindowExpires,
	}}
	// Every reauth rotates the acting session. Deliver the rotated token on
	// the channel that carried the presented one, exactly as the passkey
	// reauth does: a browser gets its cookie, a bearer caller re-reads nothing
	// from the body by contract.
	if result.SessionToken != "" {
		if r := requestFrom(ctx); r != nil {
			if _, cerr := r.Cookie(browserSessionCookie); cerr == nil {
				resp.cookies = browserCookiesFor(result.SessionToken, "")
			}
		}
	}
	return resp, nil
}

type reauthTotpResponse struct {
	body    apigen.ReauthResult
	cookies []*http.Cookie
}

func (r reauthTotpResponse) VisitReauthTotpResponse(w http.ResponseWriter) error {
	return writeJSONWithCookies(w, r.cookies, http.StatusOK, r.body)
}
