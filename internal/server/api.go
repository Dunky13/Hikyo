package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Dunky13/wenv/api"
	"github.com/Dunky13/wenv/api/apigen"
	"github.com/Dunky13/wenv/internal/admission"
	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/service"
)

// The API transport. It owns exactly three things — moving bytes, attaching
// wire metadata, and rendering refusals uniformly — and no policy whatsoever.
// Authentication is resolved at the chokepoint inside the request's own
// transaction, so there is deliberately no "authenticated principal" value
// living in a context between middleware and handler.

// AuthService is the human-authentication surface this transport needs.
type AuthService interface {
	LocalLogin(ctx context.Context, username, password string) (service.LoginResult, error)
	EstablishCredential(ctx context.Context, authority, password string) error
	Identity(ctx context.Context, presented string) (service.Identity, error)
	Logout(ctx context.Context, presented string) error
	SlideIdleClock(ctx context.Context, presented string) error
	EnrolTOTPStart(ctx context.Context, presented, password string) (string, error)
	EnrolTOTPConfirm(ctx context.Context, presented, code string) (service.LoginResult, error)
	StepUpTOTP(ctx context.Context, presented, code string) (service.LoginResult, error)
	RemoveTOTP(ctx context.Context, presented, password string) (service.LoginResult, error)
	GenerateRecoveryCodes(ctx context.Context, presented, proof string) ([]string, service.LoginResult, error)
	ConsumeRecoveryCode(ctx context.Context, username, code string) (service.RecoveryResult, error)
	AuthMethods(ctx context.Context) ([]service.AuthMethodProvider, bool, error)
	OIDCStart(ctx context.Context, slug, purpose, environmentID, presented, proof string) (service.OIDCStartResult, error)
	OIDCCallback(ctx context.Context, slug, code, state, iss, idpError, bindingCookie, presented string) (service.OIDCCallbackResult, error)
	ListIdentities(ctx context.Context, presented string) ([]authnIdentity, error)
	UnlinkIdentity(ctx context.Context, presented, identityID, proof string) (service.LoginResult, error)
	EnrolPasskeyStart(ctx context.Context, presented, password, code string) ([]byte, error)
	EnrolPasskeyFinish(ctx context.Context, presented string, responseJSON []byte) (service.LoginResult, error)
	PasskeyLoginStart(ctx context.Context) ([]byte, error)
	PasskeyLoginFinish(ctx context.Context, responseJSON []byte) (service.LoginResult, error)
	StepUpPasskeyStart(ctx context.Context, presented string) ([]byte, error)
	StepUpPasskeyFinish(ctx context.Context, presented string, responseJSON []byte) (service.LoginResult, error)
	ReauthPasskeyStart(ctx context.Context, presented, environmentID string, keyIDs []string) ([]byte, error)
	ReauthPasskeyFinish(ctx context.Context, presented string, responseJSON []byte) (service.ReauthResult, error)
	RemovePasskey(ctx context.Context, presented, credentialID, password, code string) (service.LoginResult, error)
	ListPasskeys(ctx context.Context, presented string) ([]service.PasskeyView, error)
}

// authnIdentity is the transport's view of a linked identity (the service
// returns authz.ExternalIdentity; this alias keeps internal/server off the
// authz import, which the boundary test forbids).
type authnIdentity = service.ExternalIdentityView

// ProviderService is the OIDC provider administration surface.
type ProviderService interface {
	Put(ctx context.Context, actor service.Actor, slug string, in service.ProviderInput) (service.ProviderView, error)
	Get(ctx context.Context, actor service.Actor, slug string) (service.ProviderView, error)
	List(ctx context.Context, actor service.Actor) ([]service.ProviderView, error)
	Delete(ctx context.Context, actor service.Actor, slug string) error
}

// OrgService is the domain surface this slice exposes.
//
// Every method takes a service.Actor, never a principal id: the transport
// hands over the RAW artifact and the service resolves it inside the
// transaction that authorizes the operation. Resolving here and passing an id
// would put the decision about who the caller is on one side of a transaction
// boundary and the authorization that trusts it on the other — a session
// revoked in between would still authorize the operation. That is the
// cross-request cache the permission model forbids, wearing an argument's
// clothes.
type OrgService interface {
	Create(ctx context.Context, actor service.Actor, name string, active bool, metadata json.RawMessage) (org service.Org, err error)
	Get(ctx context.Context, actor service.Actor, id string) (service.Org, error)
	List(ctx context.Context, actor service.Actor) ([]service.Org, error)
}

// API implements the generated strict server.
type API struct {
	Auth      AuthService
	Orgs      OrgService
	Providers ProviderService
	// Admission bounds the unauthenticated discovery endpoint. The expensive
	// pre-auth paths take their own slot inside the service, where the cost
	// they bound actually lives; /meta is cheap and only needs a per-IP
	// ceiling, so it is charged here. Nil means unlimited, which is only for
	// tests.
	Admission *admission.Limiter
	Version   string
	Log       *slog.Logger
	// TrustedProxies are the CIDRs whose forwarded headers are believed.
	// Empty means none: proxy trust is explicit configuration, never
	// inferred, because an unauthenticated header is not evidence.
	TrustedProxies []*net.IPNet
}

var _ apigen.StrictServerInterface = (*API)(nil)

// bearerKey carries the presented artifact from the transport into the
// handler. It is the RAW value only — never a resolved identity — because a
// resolved identity outside a transaction is precisely the authorization
// cache the permission model forbids.
type bearerKey struct{}

func withBearer(ctx context.Context, v string) context.Context {
	return context.WithValue(ctx, bearerKey{}, v)
}

func bearer(ctx context.Context) string {
	v, _ := ctx.Value(bearerKey{}).(string)
	return v
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

func (a *API) GetMeta(ctx context.Context, _ apigen.GetMetaRequestObject) (apigen.GetMetaResponseObject, error) {
	// Under the instance-wide pre-auth admission limits like every other
	// pre-auth path, with its own looser per-IP allowance: `login` calls this
	// before every authentication, so charging it against the verification
	// budget would make the client's own capability check the thing that
	// throttles the client.
	if a.Admission != nil && !a.Admission.AllowDiscovery(audit.FromContext(ctx).SourceIP) {
		return apigen.GetMeta429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
	}
	// The closed allowlist, and nothing else. `login` needs the protocol
	// capabilities before any session exists; everything past protocol
	// selection happens after authentication.
	//
	// This instance serves the local floor only. The loopback handoff and
	// device-code transports arrive with #54 and will advertise themselves
	// here — which is exactly why the client asks rather than assumes.
	return apigen.GetMeta200JSONResponse{
		ServerVersion:        a.Version,
		ApiRevision:          api.Revision,
		ProtocolCapabilities: []apigen.ProtocolCapability{"local-password"},
	}, nil
}

// ---------------------------------------------------------------------------
// Identity-protocol endpoints
// ---------------------------------------------------------------------------

func (a *API) LocalLogin(ctx context.Context, req apigen.LocalLoginRequestObject) (apigen.LocalLoginResponseObject, error) {
	result, err := a.Auth.LocalLogin(ctx, req.Body.Username, req.Body.Password)
	if err != nil {
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.LocalLogin401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
			}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.LocalLogin429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "local login", err)
			return apigen.LocalLogin500JSONResponse{
				InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
			}, nil
		}
	}
	return apigen.LocalLogin200JSONResponse{
		SessionToken: result.SessionToken,
		Session: apigen.Session{
			Id:                result.SessionID,
			Artifact:          result.Artifact,
			CreatedAt:         result.CreatedAt,
			IdleExpiresAt:     result.IdleExpires,
			AbsoluteExpiresAt: result.AbsExpires,
			Assurance:         assuranceOf(result.Assurance),
		},
		Principal: apigen.Principal{
			Id:          string(result.Principal),
			Kind:        apigen.Human,
			DisplayName: optional(result.DisplayName),
		},
	}, nil
}

func (a *API) EstablishCredential(ctx context.Context, req apigen.EstablishCredentialRequestObject) (apigen.EstablishCredentialResponseObject, error) {
	err := a.Auth.EstablishCredential(ctx, req.Body.Authority, req.Body.Password)
	switch {
	case err == nil:
		return apigen.EstablishCredential204Response{}, nil
	case errors.Is(err, service.ErrWeakPassword), errors.Is(err, service.ErrCommonPassword):
		// The one loud refusal on this path: it is the caller's own input,
		// evaluated before anything is looked up, so naming the rule helps
		// the human and reveals nothing.
		return apigen.EstablishCredential400JSONResponse{
			BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, "password")),
		}, nil
	}
	switch classify(err) {
	case apigen.ErrorCodeUnauthenticated:
		return apigen.EstablishCredential401JSONResponse{
			UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
		}, nil
	case apigen.ErrorCodeTooManyRequests:
		return apigen.EstablishCredential429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
	default:
		a.fault(ctx, "establish credential", err)
		return apigen.EstablishCredential500JSONResponse{
			InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
		}, nil
	}
}

func (a *API) Whoami(ctx context.Context, _ apigen.WhoamiRequestObject) (apigen.WhoamiResponseObject, error) {
	id, err := a.Auth.Identity(ctx, bearer(ctx))
	if err != nil {
		if classify(err) == apigen.ErrorCodeUnauthenticated {
			return apigen.Whoami401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
			}, nil
		}
		a.fault(ctx, "whoami", err)
		return apigen.Whoami500JSONResponse{
			InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
		}, nil
	}
	return apigen.Whoami200JSONResponse{
		Session: apigen.Session{
			Id:                id.SessionID,
			Artifact:          id.Artifact,
			CreatedAt:         id.CreatedAt,
			IdleExpiresAt:     id.IdleExpiresAt,
			AbsoluteExpiresAt: id.AbsoluteExpiresAt,
			Assurance:         assuranceOf(id.Assurance),
		},
		Principal: apigen.Principal{Id: string(id.Principal), Kind: apigen.Human},
	}, nil
}

func (a *API) Logout(ctx context.Context, _ apigen.LogoutRequestObject) (apigen.LogoutResponseObject, error) {
	err := a.Auth.Logout(ctx, bearer(ctx))
	switch {
	case err == nil:
		return apigen.Logout204Response{}, nil
	case classify(err) == apigen.ErrorCodeUnauthenticated:
		return apigen.Logout401JSONResponse{
			UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
		}, nil
	default:
		a.fault(ctx, "logout", err)
		return apigen.Logout500JSONResponse{
			InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
		}, nil
	}
}

// ---------------------------------------------------------------------------
// Factor endpoints (#54)
// ---------------------------------------------------------------------------
//
// These carry the raw bearer via the Actor pattern and resolve it only at the
// chokepoint, like every other authenticated surface. The account-security
// mutations reissue the acting session and step-up rotates it, so each returns
// a fresh token the client must persist in place of the old one.

// factorPrecondition reports a loud structural refusal — a caller acting on
// their OWN authenticated account, so the state (already enrolled, nothing to
// confirm, no factor) is theirs to know and 400 names it. A bad code or
// password stays the uniform 401.
func factorPrecondition(err error) bool {
	return errors.Is(err, service.ErrTOTPAlreadyEnrolled) ||
		errors.Is(err, service.ErrNoPendingTOTP) ||
		errors.Is(err, service.ErrNoTOTPFactor) ||
		errors.Is(err, service.ErrNoProofCredential)
}

func (a *API) EnrolTotpStart(ctx context.Context, req apigen.EnrolTotpStartRequestObject) (apigen.EnrolTotpStartResponseObject, error) {
	uri, err := a.Auth.EnrolTOTPStart(ctx, bearer(ctx), req.Body.Password)
	if err != nil {
		if factorPrecondition(err) {
			return apigen.EnrolTotpStart400JSONResponse{
				BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, "")),
			}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.EnrolTotpStart401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
			}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.EnrolTotpStart429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "totp enrol start", err)
			return apigen.EnrolTotpStart500JSONResponse{
				InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
			}, nil
		}
	}
	return apigen.EnrolTotpStart200JSONResponse{OtpauthUri: uri}, nil
}

func (a *API) EnrolTotpConfirm(ctx context.Context, req apigen.EnrolTotpConfirmRequestObject) (apigen.EnrolTotpConfirmResponseObject, error) {
	result, err := a.Auth.EnrolTOTPConfirm(ctx, bearer(ctx), req.Body.Code)
	if err != nil {
		if factorPrecondition(err) {
			return apigen.EnrolTotpConfirm400JSONResponse{
				BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, "")),
			}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.EnrolTotpConfirm401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
			}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.EnrolTotpConfirm429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "totp enrol confirm", err)
			return apigen.EnrolTotpConfirm500JSONResponse{
				InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
			}, nil
		}
	}
	return apigen.EnrolTotpConfirm200JSONResponse(loginResultOf(result)), nil
}

func (a *API) StepUpTotp(ctx context.Context, req apigen.StepUpTotpRequestObject) (apigen.StepUpTotpResponseObject, error) {
	result, err := a.Auth.StepUpTOTP(ctx, bearer(ctx), req.Body.Code)
	if err != nil {
		if factorPrecondition(err) {
			return apigen.StepUpTotp400JSONResponse{
				BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, "")),
			}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.StepUpTotp401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
			}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.StepUpTotp429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "totp step-up", err)
			return apigen.StepUpTotp500JSONResponse{
				InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
			}, nil
		}
	}
	return apigen.StepUpTotp200JSONResponse(loginResultOf(result)), nil
}

func (a *API) RemoveTotp(ctx context.Context, req apigen.RemoveTotpRequestObject) (apigen.RemoveTotpResponseObject, error) {
	result, err := a.Auth.RemoveTOTP(ctx, bearer(ctx), req.Body.Password)
	if err != nil {
		if factorPrecondition(err) {
			return apigen.RemoveTotp400JSONResponse{
				BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, "")),
			}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.RemoveTotp401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
			}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.RemoveTotp429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "totp remove", err)
			return apigen.RemoveTotp500JSONResponse{
				InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
			}, nil
		}
	}
	return apigen.RemoveTotp200JSONResponse(loginResultOf(result)), nil
}

func (a *API) RegenerateRecoveryCodes(ctx context.Context, req apigen.RegenerateRecoveryCodesRequestObject) (apigen.RegenerateRecoveryCodesResponseObject, error) {
	codes, result, err := a.Auth.GenerateRecoveryCodes(ctx, bearer(ctx), req.Body.Proof)
	if err != nil {
		if factorPrecondition(err) {
			return apigen.RegenerateRecoveryCodes400JSONResponse{
				BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, "")),
			}, nil
		}
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.RegenerateRecoveryCodes401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
			}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.RegenerateRecoveryCodes429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "recovery codes regenerate", err)
			return apigen.RegenerateRecoveryCodes500JSONResponse{
				InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
			}, nil
		}
	}
	return apigen.RegenerateRecoveryCodes200JSONResponse{
		RecoveryCodes: codes,
		Login:         loginResultOf(result),
	}, nil
}

func (a *API) BeginRecovery(ctx context.Context, req apigen.BeginRecoveryRequestObject) (apigen.BeginRecoveryResponseObject, error) {
	result, err := a.Auth.ConsumeRecoveryCode(ctx, req.Body.Username, req.Body.Code)
	if err != nil {
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.BeginRecovery401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
			}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.BeginRecovery429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "recovery begin", err)
			return apigen.BeginRecovery500JSONResponse{
				InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
			}, nil
		}
	}
	return apigen.BeginRecovery200JSONResponse{
		Authority: result.Authority,
		ExpiresAt: result.ExpiresAt,
	}, nil
}

// loginResultOf renders a freshly minted or rotated session for the wire.
func loginResultOf(r service.LoginResult) apigen.LoginResult {
	return apigen.LoginResult{
		SessionToken: r.SessionToken,
		Session: apigen.Session{
			Id:                r.SessionID,
			Artifact:          r.Artifact,
			CreatedAt:         r.CreatedAt,
			IdleExpiresAt:     r.IdleExpires,
			AbsoluteExpiresAt: r.AbsExpires,
			Assurance:         assuranceOf(r.Assurance),
		},
		Principal: apigen.Principal{
			Id:          string(r.Principal),
			Kind:        apigen.Human,
			DisplayName: optional(r.DisplayName),
		},
	}
}

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

func (a *API) CreateOrg(ctx context.Context, req apigen.CreateOrgRequestObject) (apigen.CreateOrgResponseObject, error) {
	active := true
	if req.Body.Active != nil {
		active = *req.Body.Active
	}
	metadata, err := marshalMetadata(req.Body.Metadata)
	if err != nil {
		return apigen.CreateOrg400JSONResponse{
			BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, "metadata")),
		}, nil
	}
	org, err := a.Orgs.Create(ctx, service.Bearer(bearer(ctx)), req.Body.Name, active, metadata)
	if err != nil {
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.CreateOrg401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
			}, nil
		case apigen.ErrorCodeForbidden:
			return apigen.CreateOrg403JSONResponse{
				ForbiddenJSONResponse: apigen.ForbiddenJSONResponse(errorBody(apigen.ErrorCodeForbidden, "")),
			}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.CreateOrg429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "create org", err)
			return apigen.CreateOrg500JSONResponse{
				InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
			}, nil
		}
	}
	return apigen.CreateOrg201JSONResponse(wireOrg(org)), nil
}

func (a *API) ListOrgs(ctx context.Context, _ apigen.ListOrgsRequestObject) (apigen.ListOrgsResponseObject, error) {
	orgs, err := a.Orgs.List(ctx, service.Bearer(bearer(ctx)))
	if err != nil {
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.ListOrgs401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
			}, nil
		case apigen.ErrorCodeForbidden:
			return apigen.ListOrgs403JSONResponse{
				ForbiddenJSONResponse: apigen.ForbiddenJSONResponse(errorBody(apigen.ErrorCodeForbidden, "")),
			}, nil
		default:
			a.fault(ctx, "list orgs", err)
			return apigen.ListOrgs500JSONResponse{
				InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
			}, nil
		}
	}
	items := make([]apigen.Org, 0, len(orgs))
	for _, o := range orgs {
		items = append(items, wireOrg(o))
	}
	return apigen.ListOrgs200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) GetOrg(ctx context.Context, req apigen.GetOrgRequestObject) (apigen.GetOrgResponseObject, error) {
	org, err := a.Orgs.Get(ctx, service.Bearer(bearer(ctx)), req.Org)
	if err != nil {
		switch classify(err) {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.GetOrg401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
			}, nil
		case apigen.ErrorCodeForbidden:
			return apigen.GetOrg403JSONResponse{
				ForbiddenJSONResponse: apigen.ForbiddenJSONResponse(errorBody(apigen.ErrorCodeForbidden, "")),
			}, nil
		case apigen.ErrorCodeNotFound:
			return apigen.GetOrg404JSONResponse{
				NotFoundJSONResponse: apigen.NotFoundJSONResponse(errorBody(apigen.ErrorCodeNotFound, "")),
			}, nil
		default:
			a.fault(ctx, "get org", err)
			return apigen.GetOrg500JSONResponse{
				InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, "")),
			}, nil
		}
	}
	return apigen.GetOrg200JSONResponse(wireOrg(org)), nil
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

// Middleware returns the API stack, outermost first.
func (a *API) Middleware() []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{
		a.wireContext,
		a.stashRequest,
		a.extractBearer,
		a.validateAgainstContract,
	}
}

// requestKey carries the raw request so the OIDC handlers can read cookies (the
// browser-binding cookie and the __Host-wenv session cookie), which the strict
// server does not thread into a handler.
type requestKey struct{}

func (a *API) stashRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestKey{}, r)))
	})
}

func requestFrom(ctx context.Context) *http.Request {
	r, _ := ctx.Value(requestKey{}).(*http.Request)
	return r
}

// browserSessionCookie is the __Host- browser session cookie name.
const browserSessionCookie = "__Host-wenv"

// oidcBindingCookiePrefix is the per-transaction browser-binding cookie name
// prefix (A16): the suffix is derived from the state so concurrent tabs do not
// clobber each other's binding.
const oidcBindingCookiePrefix = "__Host-wenv-oidc-tx-"

// bindingCookieName derives the per-transaction binding cookie name from the
// state value, deterministically at both start and callback.
func bindingCookieName(state string) string {
	suffix := state
	if i := strings.LastIndex(state, "_"); i >= 0 && i+1 < len(state) {
		suffix = state[i+1:]
	}
	if len(suffix) > 24 {
		suffix = suffix[:24]
	}
	return oidcBindingCookiePrefix + suffix
}

// wireContext attaches the per-request metadata every audit event records.
// The audit-model ADR made this an inherited obligation on this ticket, and
// it is discharged here: without it every event would record `origin: system`
// and lose the source of the act.
func (a *API) wireContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := audit.WithContext(r.Context(), audit.Context{
			SourceIP:  a.sourceIP(r),
			UserAgent: r.UserAgent(),
			Origin:    audit.OriginAPI,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sourceIP resolves the client address. Forwarded headers are believed ONLY
// from a configured trusted proxy: proxy-trust configuration is explicit,
// never inferred, because an unauthenticated header is not evidence — and a
// forged one would poison both the audit trail and the per-IP admission
// bucket.
func (a *API) sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if len(a.TrustedProxies) == 0 || !a.trusted(host) {
		return host
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return host
	}
	// RIGHT to left, discarding trusted hops. The leftmost entry is the one
	// the CLIENT can set: a normal proxy appends rather than overwrites, so
	// reading leftmost hands an attacker their own choice of source address —
	// bypassing the per-IP admission bucket and poisoning audit attribution
	// in the same move. Walking backwards, the first address that is not a
	// configured proxy is the furthest hop we have any reason to believe.
	entries := strings.Split(forwarded, ",")
	for i := len(entries) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(entries[i])
		// A malformed entry ends the walk rather than being skipped: past it
		// nothing is attributable, so the last trustworthy hop is the answer.
		if net.ParseIP(candidate) == nil {
			return host
		}
		if !a.trusted(candidate) {
			return candidate
		}
	}
	return host
}

// trusted reports whether an address is a configured proxy.
func (a *API) trusted(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, cidr := range a.TrustedProxies {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// extractBearer moves the presented artifact into the request context. It
// resolves nothing: the value is opaque here and stays opaque until the
// chokepoint reads the row it points at, inside a transaction.
func (a *API) extractBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var headerVal string
		if value, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			headerVal = strings.TrimSpace(value)
		}
		var cookieVal string
		if c, err := r.Cookie(browserSessionCookie); err == nil {
			cookieVal = strings.TrimSpace(c.Value)
		}
		// A10: a request carrying BOTH a cookie session and a bearer header is
		// refused. The two legs are distinct artifact types with distinct CSRF
		// contracts; accepting both would let a caller pick which contract
		// applies. The refusal is uniform.
		if headerVal != "" && cookieVal != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(errorBody(apigen.ErrorCodeUnauthenticated, ""))
			return
		}
		// The cookie leg maps to the same raw artifact path; it is resolved only
		// at the chokepoint like the header leg. CSRF for cookie-authenticated
		// state-changing requests is #56's SPA surface (the token is delivered
		// via whoami, A9); the browser-binding of the OIDC transaction, which is
		// the load-bearing anti-fixation control, is enforced in the service.
		if headerVal != "" {
			r = r.WithContext(withBearer(r.Context(), headerVal))
		} else if cookieVal != "" {
			r = r.WithContext(withBearer(r.Context(), cookieVal))
		}
		next.ServeHTTP(w, r)
	})
}

// validateAgainstContract is the runtime request-validation duty: a request
// that does not satisfy api/openapi.yaml never reaches a handler, so the
// document is enforced rather than merely published.
// MaxRequestBytes bounds a request body before anything decodes it. Contract
// validation runs before the handler and before any pre-auth admission
// decision, so without this an unauthenticated client could make the server
// allocate an arbitrary amount of memory parsing JSON it was always going to
// reject. The bound is far above any legitimate request this contract
// describes.
const MaxRequestBytes = 1 << 20

func (a *API) validateAgainstContract(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBytes)
		}
		err := api.ValidateRequest(r)
		switch {
		case err == nil:
			next.ServeHTTP(w, r)
		case errors.Is(err, api.ErrNoRoute):
			// A path the contract does not describe. 404, like any other
			// thing that is not there.
			writeError(w, apigen.ErrorCodeNotFound, "")
		default:
			var verr *api.ValidationError
			detail := ""
			if errors.As(err, &verr) {
				detail = verr.Member
			}
			writeError(w, apigen.ErrorCodeBadRequest, detail)
		}
	})
}

// SlideSessionClocks is the post-response idle-clock touch. It runs after the
// handler so a write never sits between authorization and the answer, and it
// is rate-limited by granularity inside the service so an authenticated GET
// storm does not become a write storm.
func (a *API) SlideSessionClocks(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		presented := bearer(r.Context())
		if presented == "" {
			return
		}
		// Detached from the request context: the client may already have
		// disconnected, and the session's clock is still the server's to keep.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer cancel()
		if err := a.Auth.SlideIdleClock(ctx, presented); err != nil {
			a.fault(ctx, "slide session idle clock", err)
		}
	})
}

// fault logs an unexpected error. Nothing about it reaches the caller: the
// response is the fixed `internal` body, so a fault cannot become an oracle.
func (a *API) fault(ctx context.Context, what string, err error) {
	if a.Log == nil {
		return
	}
	a.Log.ErrorContext(ctx, "request failed", "op", what, "err", err)
}

func tooMany() apigen.TooManyRequestsJSONResponse {
	return apigen.TooManyRequestsJSONResponse{
		Body:    errorBody(apigen.ErrorCodeTooManyRequests, ""),
		Headers: apigen.TooManyRequestsResponseHeaders{RetryAfter: retryAfterSeconds},
	}
}

func assuranceOf(a service.Assurance) apigen.Assurance {
	factors := a.Factors
	if factors == nil {
		factors = []apigen.FactorClass{}
	}
	out := apigen.Assurance{
		Method:          a.Method,
		Factors:         factors,
		AuthenticatedAt: a.AuthenticatedAt,
	}
	if a.CeremonyID != "" {
		id := a.CeremonyID
		out.CeremonyId = &id
	}
	return out
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
