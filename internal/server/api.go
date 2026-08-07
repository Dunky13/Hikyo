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
	"github.com/Dunky13/wenv/internal/domain"
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
}

// OrgService is the domain surface this slice exposes.
type OrgService interface {
	Create(ctx context.Context, principal domain.PrincipalID, name string, active bool, metadata json.RawMessage) (org service.Org, err error)
	Get(ctx context.Context, principal domain.PrincipalID, id string) (service.Org, error)
	List(ctx context.Context, principal domain.PrincipalID) ([]service.Org, error)
}

// API implements the generated strict server.
type API struct {
	Auth AuthService
	Orgs OrgService
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
// Domain
// ---------------------------------------------------------------------------

// principal resolves the acting principal for a domain call. Note what it
// does NOT do: it does not authorize. Authorization happens in the service's
// own transaction at the chokepoint, against the operation's formula — this
// only says who is asking.
func (a *API) principal(ctx context.Context) (domain.PrincipalID, error) {
	id, err := a.Auth.Identity(ctx, bearer(ctx))
	if err != nil {
		return "", err
	}
	return id.Principal, nil
}

func (a *API) CreateOrg(ctx context.Context, req apigen.CreateOrgRequestObject) (apigen.CreateOrgResponseObject, error) {
	principal, err := a.principal(ctx)
	if err != nil {
		return apigen.CreateOrg401JSONResponse{
			UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
		}, nil
	}
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
	org, err := a.Orgs.Create(ctx, principal, req.Body.Name, active, metadata)
	if err != nil {
		switch classify(err) {
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
	principal, err := a.principal(ctx)
	if err != nil {
		return apigen.ListOrgs401JSONResponse{
			UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
		}, nil
	}
	orgs, err := a.Orgs.List(ctx, principal)
	if err != nil {
		switch classify(err) {
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
	principal, err := a.principal(ctx)
	if err != nil {
		return apigen.GetOrg401JSONResponse{
			UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
		}, nil
	}
	org, err := a.Orgs.Get(ctx, principal, req.Org)
	if err != nil {
		switch classify(err) {
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
		a.extractBearer,
		a.validateAgainstContract,
	}
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
	if len(a.TrustedProxies) == 0 {
		return host
	}
	peer := net.ParseIP(host)
	trusted := false
	for _, cidr := range a.TrustedProxies {
		if peer != nil && cidr.Contains(peer) {
			trusted = true
			break
		}
	}
	if !trusted {
		return host
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return host
	}
	// The left-most entry is the original client as the trusted proxy saw it.
	if first, _, ok := strings.Cut(forwarded, ","); ok {
		return strings.TrimSpace(first)
	}
	return strings.TrimSpace(forwarded)
}

// extractBearer moves the presented artifact into the request context. It
// resolves nothing: the value is opaque here and stays opaque until the
// chokepoint reads the row it points at, inside a transaction.
func (a *API) extractBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if value, ok := strings.CutPrefix(header, "Bearer "); ok {
			r = r.WithContext(withBearer(r.Context(), strings.TrimSpace(value)))
		}
		next.ServeHTTP(w, r)
	})
}

// validateAgainstContract is the runtime request-validation duty: a request
// that does not satisfy api/openapi.yaml never reaches a handler, so the
// document is enforced rather than merely published.
func (a *API) validateAgainstContract(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
