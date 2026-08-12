package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Dunky13/hikyo/api/apigen"
	"github.com/Dunky13/hikyo/internal/service"
)

// WebAuthn / passkey handlers (#54). Like every other authentication surface
// these carry the raw bearer via the Actor pattern and resolve it only at the
// chokepoint inside the service transaction; the router classifies them all as
// unauthenticated. The ceremony options and authenticator responses are opaque
// browser-generated JSON, carried as free-form objects and round-tripped as
// raw bytes to and from the service so the base64url fields the authenticator
// signs over survive untouched.
//
// WebAuthn is a browser-only ceremony (the CLI refuses it by name), so a
// minted, reissued or rotated session is a browser session: its token is
// delivered on the `__Host-hikyo` cookie exactly as the OIDC callback delivers
// one, and the JSON body carries the same session for a fetch-based caller.

// webauthnPrecondition reports a loud structural refusal on a caller acting on
// their OWN authenticated account — WebAuthn unavailable on this instance, no
// live ceremony, no usable passkey, a passkey-only-floor violation, or no
// pre-existing credential to prove the change. A bad assertion or proof stays
// the uniform 401.
func webauthnPrecondition(err error) bool {
	return errors.Is(err, service.ErrWebAuthnUnavailable) ||
		errors.Is(err, service.ErrNoWebAuthnCeremony) ||
		errors.Is(err, service.ErrNoPasskey) ||
		errors.Is(err, service.ErrPasskeyOnlyViolation) ||
		errors.Is(err, service.ErrNoProofCredential)
}

// loginPrecondition is the login-endpoint precondition: ONLY the instance-wide
// "WebAuthn not configured" refusal is a loud 400 — it carries no per-account
// signal. Every other login outcome (missing/disabled/unowned/invalid
// credential, no live ceremony) normalises to the uniform 401 so login-start
// and finish cannot be probed for whether a discoverable passkey exists or which
// credential ids are enrolled (B3). Structural 400s stay on the OWN-account
// surfaces (enrol/step-up/reauth/remove), never on pre-auth login.
func loginPrecondition(err error) bool {
	return errors.Is(err, service.ErrWebAuthnUnavailable)
}

// webauthnOptions decodes the opaque service options bytes into the free-form
// wire object. Round-tripping through a map preserves every field verbatim.
func webauthnOptions(raw []byte) (apigen.WebauthnOptions, error) {
	var m apigen.WebauthnOptions
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// finishBody recovers the opaque authenticator response bytes from the wire
// object. A nil body cannot reach here past contract validation (the request
// body is required), but it is checked so a change to that contract fails loud.
func finishBody(body *apigen.WebauthnResponse) ([]byte, bool) {
	if body == nil {
		return nil, false
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, false
	}
	return raw, true
}

// ---------------------------------------------------------------------------
// Enrolment
// ---------------------------------------------------------------------------

func (a *API) EnrolPasskeyStart(ctx context.Context, req apigen.EnrolPasskeyStartRequestObject) (apigen.EnrolPasskeyStartResponseObject, error) {
	if req.Body == nil {
		return apigen.EnrolPasskeyStart400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
	}
	raw, err := a.Auth.EnrolPasskeyStart(ctx, bearer(ctx), strDeref(req.Body.Password), strDeref(req.Body.Code))
	if err != nil {
		if webauthnPrecondition(err) {
			return apigen.EnrolPasskeyStart400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.EnrolPasskeyStart401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.EnrolPasskeyStart429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "passkey enrol start", err)
			return apigen.EnrolPasskeyStart500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
		}
	}
	m, err := webauthnOptions(raw)
	if err != nil {
		a.fault(ctx, "passkey enrol start options", err)
		return apigen.EnrolPasskeyStart500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
	}
	return apigen.EnrolPasskeyStart200JSONResponse(m), nil
}

func (a *API) EnrolPasskeyFinish(ctx context.Context, req apigen.EnrolPasskeyFinishRequestObject) (apigen.EnrolPasskeyFinishResponseObject, error) {
	raw, ok := finishBody(req.Body)
	if !ok {
		return apigen.EnrolPasskeyFinish400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
	}
	result, err := a.Auth.EnrolPasskeyFinish(ctx, bearer(ctx), raw)
	if err != nil {
		if webauthnPrecondition(err) {
			return apigen.EnrolPasskeyFinish400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.EnrolPasskeyFinish401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.EnrolPasskeyFinish429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "passkey enrol finish", err)
			return apigen.EnrolPasskeyFinish500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
		}
	}
	return sessionResponse(result), nil
}

// ---------------------------------------------------------------------------
// Discoverable login (fully pre-auth)
// ---------------------------------------------------------------------------

func (a *API) PasskeyLoginStart(ctx context.Context, _ apigen.PasskeyLoginStartRequestObject) (apigen.PasskeyLoginStartResponseObject, error) {
	raw, err := a.Auth.PasskeyLoginStart(ctx)
	if err != nil {
		if loginPrecondition(err) {
			return apigen.PasskeyLoginStart400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.PasskeyLoginStart401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.PasskeyLoginStart429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "passkey login start", err)
			return apigen.PasskeyLoginStart500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
		}
	}
	m, err := webauthnOptions(raw)
	if err != nil {
		a.fault(ctx, "passkey login start options", err)
		return apigen.PasskeyLoginStart500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
	}
	return apigen.PasskeyLoginStart200JSONResponse(m), nil
}

func (a *API) PasskeyLoginFinish(ctx context.Context, req apigen.PasskeyLoginFinishRequestObject) (apigen.PasskeyLoginFinishResponseObject, error) {
	raw, ok := finishBody(req.Body)
	if !ok {
		return apigen.PasskeyLoginFinish400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
	}
	result, err := a.Auth.PasskeyLoginFinish(ctx, raw)
	if err != nil {
		if loginPrecondition(err) {
			return apigen.PasskeyLoginFinish400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.PasskeyLoginFinish401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.PasskeyLoginFinish429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "passkey login finish", err)
			return apigen.PasskeyLoginFinish500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
		}
	}
	return sessionResponse(result), nil
}

// ---------------------------------------------------------------------------
// Step-up
// ---------------------------------------------------------------------------

func (a *API) StepUpPasskeyStart(ctx context.Context, _ apigen.StepUpPasskeyStartRequestObject) (apigen.StepUpPasskeyStartResponseObject, error) {
	raw, err := a.Auth.StepUpPasskeyStart(ctx, bearer(ctx))
	if err != nil {
		if webauthnPrecondition(err) {
			return apigen.StepUpPasskeyStart400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.StepUpPasskeyStart401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.StepUpPasskeyStart429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "passkey step-up start", err)
			return apigen.StepUpPasskeyStart500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
		}
	}
	m, err := webauthnOptions(raw)
	if err != nil {
		a.fault(ctx, "passkey step-up start options", err)
		return apigen.StepUpPasskeyStart500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
	}
	return apigen.StepUpPasskeyStart200JSONResponse(m), nil
}

func (a *API) StepUpPasskeyFinish(ctx context.Context, req apigen.StepUpPasskeyFinishRequestObject) (apigen.StepUpPasskeyFinishResponseObject, error) {
	raw, ok := finishBody(req.Body)
	if !ok {
		return apigen.StepUpPasskeyFinish400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
	}
	result, err := a.Auth.StepUpPasskeyFinish(ctx, bearer(ctx), raw)
	if err != nil {
		if webauthnPrecondition(err) {
			return apigen.StepUpPasskeyFinish400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.StepUpPasskeyFinish401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.StepUpPasskeyFinish429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "passkey step-up finish", err)
			return apigen.StepUpPasskeyFinish500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
		}
	}
	return sessionResponse(result), nil
}

// ---------------------------------------------------------------------------
// Reauthentication
// ---------------------------------------------------------------------------

func (a *API) ReauthPasskeyStart(ctx context.Context, req apigen.ReauthPasskeyStartRequestObject) (apigen.ReauthPasskeyStartResponseObject, error) {
	if req.Body == nil {
		return apigen.ReauthPasskeyStart400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
	}
	raw, err := a.Auth.ReauthPasskeyStart(ctx, bearer(ctx), req.Body.EnvironmentId, req.Body.KeyIds)
	if err != nil {
		if webauthnPrecondition(err) {
			return apigen.ReauthPasskeyStart400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.ReauthPasskeyStart401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.ReauthPasskeyStart429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "passkey reauth start", err)
			return apigen.ReauthPasskeyStart500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
		}
	}
	m, err := webauthnOptions(raw)
	if err != nil {
		a.fault(ctx, "passkey reauth start options", err)
		return apigen.ReauthPasskeyStart500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
	}
	return apigen.ReauthPasskeyStart200JSONResponse(m), nil
}

// reauthPasskeyResponse carries the window body and, for a session that arrived
// on the cookie, the rotated token back onto that same cookie.
type reauthPasskeyResponse struct {
	body    apigen.WebauthnReauthResult
	cookies []*http.Cookie
}

func (r reauthPasskeyResponse) VisitReauthPasskeyFinishResponse(w http.ResponseWriter) error {
	return writeJSONWithCookies(w, r.cookies, http.StatusOK, r.body)
}

func (a *API) ReauthPasskeyFinish(ctx context.Context, req apigen.ReauthPasskeyFinishRequestObject) (apigen.ReauthPasskeyFinishResponseObject, error) {
	raw, ok := finishBody(req.Body)
	if !ok {
		return apigen.ReauthPasskeyFinish400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
	}
	result, err := a.Auth.ReauthPasskeyFinish(ctx, bearer(ctx), raw)
	if err != nil {
		if webauthnPrecondition(err) {
			return apigen.ReauthPasskeyFinish400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.ReauthPasskeyFinish401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.ReauthPasskeyFinish429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "passkey reauth finish", err)
			return apigen.ReauthPasskeyFinish500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
		}
	}
	resp := reauthPasskeyResponse{body: apigen.WebauthnReauthResult{
		SessionId:      result.SessionID,
		EnvironmentId:  result.EnvironmentID,
		SingleDecision: result.SingleDecision,
		WindowExpires:  result.WindowExpires,
	}}
	// The reauth always rotates the acting session; deliver the rotated token on
	// the channel that carried the presented one. A cookie-borne browser session
	// gets its rotated cookie; a bearer caller reads the token from nowhere here
	// (the body omits it by contract), which is fine — WebAuthn is browser-only.
	if result.SessionToken != "" {
		if r := requestFrom(ctx); r != nil {
			if _, cerr := r.Cookie(browserSessionCookie); cerr == nil {
				resp.cookies = browserCookiesFor(result.SessionToken, result.CSRFToken)
			}
		}
	}
	return resp, nil
}

// ---------------------------------------------------------------------------
// Credential inventory
// ---------------------------------------------------------------------------

func (a *API) ListPasskeys(ctx context.Context, _ apigen.ListPasskeysRequestObject) (apigen.ListPasskeysResponseObject, error) {
	rows, err := a.Auth.ListPasskeys(ctx, bearer(ctx))
	if err != nil {
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.ListPasskeys401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.ListPasskeys429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "list passkeys", err)
			return apigen.ListPasskeys500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
		}
	}
	out := apigen.PasskeyList{Passkeys: make([]apigen.Passkey, 0, len(rows))}
	for _, r := range rows {
		out.Passkeys = append(out.Passkeys, apigen.Passkey{
			Id: r.ID, Label: r.Label, Discoverable: r.Discoverable, Disabled: r.Disabled,
			CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt,
		})
	}
	return apigen.ListPasskeys200JSONResponse(out), nil
}

func (a *API) RemovePasskey(ctx context.Context, req apigen.RemovePasskeyRequestObject) (apigen.RemovePasskeyResponseObject, error) {
	if req.Body == nil {
		return apigen.RemovePasskey400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
	}
	result, err := a.Auth.RemovePasskey(ctx, bearer(ctx), string(req.Id), strDeref(req.Body.Password), strDeref(req.Body.Code))
	if err != nil {
		if webauthnPrecondition(err) {
			return apigen.RemovePasskey400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.RemovePasskey401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.RemovePasskey429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "passkey remove", err)
			return apigen.RemovePasskey500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
		}
	}
	return sessionResponse(result), nil
}
