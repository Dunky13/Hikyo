package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

// OIDC and provider-administration handlers (#54). They carry the raw bearer
// via the Actor pattern like every other authenticated surface and read the
// browser-binding and session cookies from the stashed raw request; the
// security decisions all live in the service.

func (a *API) AuthMethods(ctx context.Context, _ apigen.AuthMethodsRequestObject) (apigen.AuthMethodsResponseObject, error) {
	if a.Admission != nil && !a.Admission.AllowDiscovery(audit.FromContext(ctx).SourceIP) {
		return apigen.AuthMethods429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
	}
	providers, localEnabled, err := a.Auth.AuthMethods(ctx)
	if err != nil {
		a.fault(ctx, "auth methods", err)
		return apigen.AuthMethods500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
	}
	out := apigen.AuthMethods{
		LocalLoginEnabled: localEnabled,
		Providers:         make([]apigen.AuthMethodProvider, 0, len(providers)),
	}
	for _, p := range providers {
		out.Providers = append(out.Providers, apigen.AuthMethodProvider{
			Slug: p.Slug, DisplayName: p.DisplayName, Kind: apigen.IdentityProviderKind(p.Kind),
		})
	}
	return apigen.AuthMethods200JSONResponse(out), nil
}

// oidcStartResponse sets the browser-binding cookie (A2/A16) on an anonymous
// login start before writing the JSON body.
type oidcStartResponse struct {
	body   apigen.OidcStartResult
	cookie *http.Cookie
}

func (r oidcStartResponse) VisitOidcStartResponse(w http.ResponseWriter) error {
	if r.cookie != nil {
		writeHTTPOnlyCookie(w, r.cookie)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(r.body)
}

func (a *API) OidcStart(ctx context.Context, req apigen.OidcStartRequestObject) (apigen.OidcStartResponseObject, error) {
	if req.Body == nil {
		// A missing body folds into the uniform 401 like every other start
		// refusal: this endpoint never distinguishes its refusals on the wire.
		return apigen.OidcStart401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
	}
	env, proof := "", ""
	if req.Body.EnvironmentId != nil {
		env = *req.Body.EnvironmentId
	}
	if req.Body.Proof != nil {
		proof = *req.Body.Proof
	}
	result, err := a.Auth.OIDCStart(ctx, string(req.Provider), string(req.Body.Purpose), env, bearer(ctx), proof)
	if err != nil {
		return oidcStartError(a, ctx, err), nil
	}
	resp := oidcStartResponse{body: apigen.OidcStartResult{AuthorizationUrl: result.AuthURL}}
	if result.BindingCookie != "" {
		resp.cookie = &http.Cookie{
			Name: bindingCookieName(result.State), Value: result.BindingCookie,
			Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		}
	}
	return resp, nil
}

func oidcStartError(a *API, ctx context.Context, err error) apigen.OidcStartResponseObject {
	// Every expected start refusal collapses to one uniform 401 body: an
	// unknown or disabled slug, a bad purpose, and a reauth against a
	// policy-less provider or with no environment all look identical to an
	// unauthenticated link/reauth, so a pre-auth prober cannot enumerate
	// provider config by status (the timing is uniform too — login admission
	// runs before provider resolution in the service).
	policy := wireErrorFor(err)
	switch policy.code {
	case apigen.ErrorCodeTooManyRequests:
		return apigen.OidcStart429JSONResponse{TooManyRequestsJSONResponse: tooMany()}
	case apigen.ErrorCodeInternal:
		a.fault(ctx, "oidc start", err)
		return apigen.OidcStart500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}
	default:
		return apigen.OidcStart401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}
	}
}

func (a *API) OidcCallback(ctx context.Context, req apigen.OidcCallbackRequestObject) (apigen.OidcCallbackResponseObject, error) {
	code, state, iss, idpErr := strDeref(req.Params.Code), strDeref(req.Params.State), strDeref(req.Params.Iss), strDeref(req.Params.Error)
	bindingCookie := ""
	if r := requestFrom(ctx); r != nil && state != "" {
		if c, err := r.Cookie(bindingCookieName(state)); err == nil {
			bindingCookie = c.Value
		}
	}
	result, err := a.Auth.OIDCCallback(ctx, string(req.Provider), code, state, iss, idpErr, bindingCookie, bearer(ctx))
	if err != nil {
		// Every expected callback refusal is one uniform 401 body: a closed
		// reauth window, a wrong-purpose transaction (the dispatch default
		// returns ErrBadPurpose), an unknown/expired state, and every
		// oidc_refused cause are indistinguishable on the wire, so a stolen or
		// observed state cannot be probed for the transaction's purpose or
		// lifecycle. Only a true fault is 500.
		policy := wireErrorFor(err)
		switch policy.code {
		case apigen.ErrorCodeTooManyRequests:
			return apigen.OidcCallback429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		case apigen.ErrorCodeInternal:
			a.fault(ctx, "oidc callback", err)
			return apigen.OidcCallback500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
		default:
			return apigen.OidcCallback401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		}
	}
	return sessionResponse(result.Login), nil
}

func (a *API) ListIdentities(ctx context.Context, _ apigen.ListIdentitiesRequestObject) (apigen.ListIdentitiesResponseObject, error) {
	rows, err := a.Auth.ListIdentities(ctx, bearer(ctx))
	if err != nil {
		if wireErrorFor(err).code == apigen.ErrorCodeUnauthenticated {
			return apigen.ListIdentities401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		}
		a.fault(ctx, "list identities", err)
		return apigen.ListIdentities500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
	}
	out := apigen.IdentityList{Identities: make([]apigen.ExternalIdentity, 0, len(rows))}
	for _, r := range rows {
		out.Identities = append(out.Identities, apigen.ExternalIdentity{
			Id: r.ID, Kind: apigen.IdentityProviderKind(r.Kind), Issuer: r.Issuer,
			Subject: r.Subject, ProviderId: r.ProviderID, CreatedAt: r.CreatedAt,
		})
	}
	return apigen.ListIdentities200JSONResponse(out), nil
}

func (a *API) LinkIdentity(ctx context.Context, req apigen.LinkIdentityRequestObject) (apigen.LinkIdentityResponseObject, error) {
	if req.Body == nil {
		return apigen.LinkIdentity400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
	}
	result, err := a.Auth.OIDCStart(ctx, req.Body.Provider, "link", "", bearer(ctx), req.Body.Proof)
	if err != nil {
		policy := wireErrorFor(err)
		switch policy.code {
		case apigen.ErrorCodeNotFound:
			return apigen.LinkIdentity404JSONResponse{NotFoundJSONResponse: apigen.NotFoundJSONResponse(policy.body(err))}, nil
		case apigen.ErrorCodeBadRequest:
			return apigen.LinkIdentity400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(policy.body(err))}, nil
		case apigen.ErrorCodeUnauthenticated:
			return apigen.LinkIdentity401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(policy.body(err))}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.LinkIdentity429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "link identity", err)
			return apigen.LinkIdentity500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
		}
	}
	return apigen.LinkIdentity200JSONResponse{AuthorizationUrl: result.AuthURL}, nil
}

func (a *API) UnlinkIdentity(ctx context.Context, req apigen.UnlinkIdentityRequestObject) (apigen.UnlinkIdentityResponseObject, error) {
	if req.Body == nil {
		return apigen.UnlinkIdentity400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
	}
	result, err := a.Auth.UnlinkIdentity(ctx, bearer(ctx), string(req.Id), req.Body.Proof)
	if err != nil {
		policy := wireErrorFor(err)
		switch policy.code {
		case apigen.ErrorCodeBadRequest:
			return apigen.UnlinkIdentity400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(policy.body(err))}, nil
		case apigen.ErrorCodeUnauthenticated:
			return apigen.UnlinkIdentity401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(policy.body(err))}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.UnlinkIdentity429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "unlink identity", err)
			return apigen.UnlinkIdentity500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
		}
	}
	return sessionResponse(result), nil
}

// ---------------------------------------------------------------------------
// Provider administration
// ---------------------------------------------------------------------------

func providerViewWire(v service.ProviderView) apigen.OidcProvider {
	return apigen.OidcProvider{
		Slug: v.Slug, DisplayName: v.DisplayName, Issuer: v.Issuer, ClientId: v.ClientID,
		Scopes: v.Scopes, RedirectUri: v.RedirectURI, JitPolicy: v.JITPolicy,
		AssurancePolicy: v.AssurancePolicy, Enabled: v.Enabled,
	}
}

func (a *API) ListOidcProviders(ctx context.Context, _ apigen.ListOidcProvidersRequestObject) (apigen.ListOidcProvidersResponseObject, error) {
	rows, err := a.Providers.List(ctx, service.Bearer(bearer(ctx)))
	if err != nil {
		return providerListErr(a, ctx, err), nil
	}
	out := apigen.OidcProviderList{}
	for _, v := range rows {
		out.Providers = append(out.Providers, providerViewWire(v))
	}
	return apigen.ListOidcProviders200JSONResponse(out), nil
}

func providerListErr(a *API, ctx context.Context, err error) apigen.ListOidcProvidersResponseObject {
	switch wireErrorFor(err).code {
	case apigen.ErrorCodeUnauthenticated:
		return apigen.ListOidcProviders401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}
	case apigen.ErrorCodeForbidden:
		return apigen.ListOidcProviders403JSONResponse{ForbiddenJSONResponse: apigen.ForbiddenJSONResponse(errorBody(apigen.ErrorCodeForbidden, ""))}
	case apigen.ErrorCodeTooManyRequests:
		return apigen.ListOidcProviders429JSONResponse{TooManyRequestsJSONResponse: tooMany()}
	default:
		a.fault(ctx, "list oidc providers", err)
		return apigen.ListOidcProviders500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}
	}
}

func (a *API) GetOidcProvider(ctx context.Context, req apigen.GetOidcProviderRequestObject) (apigen.GetOidcProviderResponseObject, error) {
	v, err := a.Providers.Get(ctx, service.Bearer(bearer(ctx)), string(req.Slug))
	if err != nil {
		policy := wireErrorFor(err)
		switch policy.code {
		case apigen.ErrorCodeNotFound:
			return apigen.GetOidcProvider404JSONResponse{NotFoundJSONResponse: apigen.NotFoundJSONResponse(policy.body(err))}, nil
		case apigen.ErrorCodeUnauthenticated:
			return apigen.GetOidcProvider401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		case apigen.ErrorCodeForbidden:
			return apigen.GetOidcProvider403JSONResponse{ForbiddenJSONResponse: apigen.ForbiddenJSONResponse(errorBody(apigen.ErrorCodeForbidden, ""))}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.GetOidcProvider429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "get oidc provider", err)
			return apigen.GetOidcProvider500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
		}
	}
	return apigen.GetOidcProvider200JSONResponse(providerViewWire(v)), nil
}

func (a *API) PutOidcProvider(ctx context.Context, req apigen.PutOidcProviderRequestObject) (apigen.PutOidcProviderResponseObject, error) {
	if req.Body == nil {
		return apigen.PutOidcProvider400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
	}
	in := service.ProviderInput{
		DisplayName: req.Body.DisplayName, Issuer: req.Body.Issuer, ClientID: req.Body.ClientId,
		ClientSecret: req.Body.ClientSecret, Scopes: req.Body.Scopes,
		JITPolicy: req.Body.JitPolicy, AssurancePolicy: req.Body.AssurancePolicy, Enabled: req.Body.Enabled,
	}
	v, err := a.Providers.Put(ctx, service.Bearer(bearer(ctx)), string(req.Slug), in)
	if err != nil {
		policy := wireErrorFor(err)
		switch policy.code {
		case apigen.ErrorCodeBadRequest:
			return apigen.PutOidcProvider400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(policy.body(err))}, nil
		case apigen.ErrorCodeUnauthenticated:
			return apigen.PutOidcProvider401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		case apigen.ErrorCodeForbidden:
			return apigen.PutOidcProvider403JSONResponse{ForbiddenJSONResponse: apigen.ForbiddenJSONResponse(errorBody(apigen.ErrorCodeForbidden, ""))}, nil
		case apigen.ErrorCodeTooManyRequests:
			return apigen.PutOidcProvider429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
		default:
			a.fault(ctx, "put oidc provider", err)
			return apigen.PutOidcProvider500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
		}
	}
	return apigen.PutOidcProvider200JSONResponse(providerViewWire(v)), nil
}

func (a *API) DeleteOidcProvider(ctx context.Context, req apigen.DeleteOidcProviderRequestObject) (apigen.DeleteOidcProviderResponseObject, error) {
	err := a.Providers.Delete(ctx, service.Bearer(bearer(ctx)), string(req.Slug))
	switch policy := wireErrorFor(err); {
	case err == nil:
		return apigen.DeleteOidcProvider204Response{}, nil
	case policy.code == apigen.ErrorCodeNotFound:
		return apigen.DeleteOidcProvider404JSONResponse{NotFoundJSONResponse: apigen.NotFoundJSONResponse(policy.body(err))}, nil
	}
	switch wireErrorFor(err).code {
	case apigen.ErrorCodeUnauthenticated:
		return apigen.DeleteOidcProvider401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
	case apigen.ErrorCodeForbidden:
		return apigen.DeleteOidcProvider403JSONResponse{ForbiddenJSONResponse: apigen.ForbiddenJSONResponse(errorBody(apigen.ErrorCodeForbidden, ""))}, nil
	case apigen.ErrorCodeTooManyRequests:
		return apigen.DeleteOidcProvider429JSONResponse{TooManyRequestsJSONResponse: tooMany()}, nil
	default:
		a.fault(ctx, "delete oidc provider", err)
		return apigen.DeleteOidcProvider500JSONResponse{InternalJSONResponse: apigen.InternalJSONResponse(errorBody(apigen.ErrorCodeInternal, ""))}, nil
	}
}

func strDeref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
