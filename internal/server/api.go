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

	"github.com/Dunky13/hikyo/api"
	"github.com/Dunky13/hikyo/api/apigen"
	"github.com/Dunky13/hikyo/internal/admission"
	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/service"
)

// The API transport. It owns exactly three things — moving bytes, attaching
// wire metadata, and rendering refusals uniformly — and no policy whatsoever.
// Authentication is resolved at the chokepoint inside the request's own
// transaction, so there is deliberately no "authenticated principal" value
// living in a context between middleware and handler.

// AuthService is the human-authentication surface this transport needs.
type AuthService interface {
	LocalLogin(ctx context.Context, username, password string, artifact service.Artifact) (service.LoginResult, error)
	EstablishCredential(ctx context.Context, authority, password string) error
	Identity(ctx context.Context, presented string) (service.Identity, error)
	Logout(ctx context.Context, presented string) error
	VerifyBrowserCSRF(ctx context.Context, presented, csrfToken string) error
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
	ReauthPasskeyStart(ctx context.Context, presented string, purpose service.ReauthPurpose, environmentID string, keyIDs []string) ([]byte, error)
	ReauthPasskeyFinish(ctx context.Context, presented string, responseJSON []byte) (service.ReauthResult, error)
	ReauthTOTP(ctx context.Context, presented, environmentID, code string) (service.ReauthResult, error)
	RemovePasskey(ctx context.Context, presented, credentialID, password, code string) (service.LoginResult, error)
	ListPasskeys(ctx context.Context, presented string) ([]service.PasskeyView, error)
	ResetCredential(ctx context.Context, actor service.Actor, targetPrincipal, delivery string) (service.ResetResult, error)
}

type SAMLAuthService interface {
	SAMLStart(ctx context.Context, slug, purpose, environmentID, presented, proof string) (service.SAMLStartResult, error)
	SAMLACS(ctx context.Context, slug, encodedResponse, relayState, initiatorCookie string) (service.LoginResult, error)
	SAMLMetadata(ctx context.Context, slug string) ([]byte, error)
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

// SAMLProviderService is the instance-scoped SAML provider administration
// surface, including the metadata diff-and-confirm ceremony.
type SAMLProviderService interface {
	Put(ctx context.Context, actor service.Actor, slug string, in service.SAMLProviderInput) (service.SAMLProviderMutationResult, error)
	Patch(ctx context.Context, actor service.Actor, slug string, in service.SAMLProviderPatch) (service.SAMLProviderView, error)
	Get(ctx context.Context, actor service.Actor, slug string) (service.SAMLProviderView, error)
	List(ctx context.Context, actor service.Actor) ([]service.SAMLProviderView, error)
	Delete(ctx context.Context, actor service.Actor, slug string) error
	RefreshMetadata(ctx context.Context, actor service.Actor, slug string, in service.SAMLMetadataRefreshInput) (service.SAMLProviderMutationResult, error)
	ListSPKeys(ctx context.Context, actor service.Actor) ([]service.SAMLSPKeyView, error)
	RotateSPKey(ctx context.Context, actor service.Actor) (service.SAMLSPKeyView, error)
	RetireSPKey(ctx context.Context, actor service.Actor, fingerprint string) error
	CompromiseRetireSPKey(ctx context.Context, actor service.Actor, fingerprint string) (service.SAMLSPKeyView, error)
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
	Get(ctx context.Context, actor service.Actor, org domain.OrgID) (service.Org, error)
	List(ctx context.Context, actor service.Actor) ([]service.Org, error)
	ListMine(ctx context.Context, actor service.Actor) ([]service.MyOrg, error)
	Rename(ctx context.Context, actor service.Actor, org domain.OrgID, name string) (service.Org, error)
	Delete(ctx context.Context, actor service.Actor, org domain.OrgID) error
}

// API implements the generated strict server.
type API struct {
	Auth          AuthService
	SAMLAuth      SAMLAuthService
	Orgs          OrgService
	Projects      ProjectService
	Environments  EnvironmentService
	Folders       FolderService
	Keys          KeyService
	Values        ValueService
	Reveal        RevealService
	KeyGroups     KeyGroupService
	Grants        GrantService
	Identities    IdentityService
	Settings      SettingsService
	Providers     ProviderService
	SAMLProviders SAMLProviderService
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
	artifact := service.ArtifactCLI
	if req.Body.Artifact != nil {
		artifact = service.Artifact(*req.Body.Artifact)
	}
	result, err := a.Auth.LocalLogin(ctx, req.Body.Username, req.Body.Password, artifact)
	if err != nil {
		return nil, err
	}
	return sessionResponse(result), nil
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
	return nil, err
}

func (a *API) Whoami(ctx context.Context, _ apigen.WhoamiRequestObject) (apigen.WhoamiResponseObject, error) {
	id, err := a.Auth.Identity(ctx, bearer(ctx))
	if err != nil {
		return nil, err
	}
	return apigen.Whoami200JSONResponse{
		Session: apigen.Session{
			Id:                id.SessionID,
			Artifact:          id.Artifact.String(),
			CreatedAt:         id.CreatedAt,
			IdleExpiresAt:     id.IdleExpiresAt,
			AbsoluteExpiresAt: id.AbsoluteExpiresAt,
			Assurance:         assuranceOf(id.Assurance),
		},
		Principal: apigen.Principal{Id: string(id.Principal), Kind: apigen.Human},
	}, nil
}

// logoutResponse clears the browser cookies alongside the 204. The row is
// already gone — that is what revokes — but leaving the cookies would make
// every subsequent request present a value that can only be refused, and the
// SPA would look logged in until it asked.
type logoutResponse struct{ cookies []*http.Cookie }

func (r logoutResponse) VisitLogoutResponse(w http.ResponseWriter) error {
	return writeJSONWithCookies(w, r.cookies, http.StatusNoContent, nil)
}

func (a *API) Logout(ctx context.Context, _ apigen.LogoutRequestObject) (apigen.LogoutResponseObject, error) {
	if err := a.Auth.Logout(ctx, bearer(ctx)); err != nil {
		return nil, err
	}
	if r := requestFrom(ctx); r != nil {
		if c, cerr := r.Cookie(browserSessionCookie); cerr == nil && c.Value != "" {
			return logoutResponse{cookies: expiredBrowserCookies()}, nil
		}
	}
	return apigen.Logout204Response{}, nil
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
		return nil, err
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
		return nil, err
	}
	return sessionResponse(result), nil
}

func (a *API) StepUpTotp(ctx context.Context, req apigen.StepUpTotpRequestObject) (apigen.StepUpTotpResponseObject, error) {
	result, err := a.Auth.StepUpTOTP(ctx, bearer(ctx), req.Body.Code)
	if err != nil {
		if factorPrecondition(err) {
			return apigen.StepUpTotp400JSONResponse{
				BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, "")),
			}, nil
		}
		return nil, err
	}
	return sessionResponse(result), nil
}

func (a *API) RemoveTotp(ctx context.Context, req apigen.RemoveTotpRequestObject) (apigen.RemoveTotpResponseObject, error) {
	result, err := a.Auth.RemoveTOTP(ctx, bearer(ctx), req.Body.Password)
	if err != nil {
		if factorPrecondition(err) {
			return apigen.RemoveTotp400JSONResponse{
				BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, "")),
			}, nil
		}
		return nil, err
	}
	return sessionResponse(result), nil
}

func (a *API) RegenerateRecoveryCodes(ctx context.Context, req apigen.RegenerateRecoveryCodesRequestObject) (apigen.RegenerateRecoveryCodesResponseObject, error) {
	codes, result, err := a.Auth.GenerateRecoveryCodes(ctx, bearer(ctx), req.Body.Proof)
	if err != nil {
		if factorPrecondition(err) {
			return apigen.RegenerateRecoveryCodes400JSONResponse{
				BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, "")),
			}, nil
		}
		return nil, err
	}
	resp := recoveryCodesResponse{body: apigen.RecoveryCodesResult{
		RecoveryCodes: codes,
		Login:         loginResultOf(result),
	}}
	if result.Artifact == service.ArtifactBrowser && result.SessionToken != "" {
		resp.cookies = browserCookiesFor(result.SessionToken, result.CSRFToken)
	}
	return resp, nil
}

func (a *API) BeginRecovery(ctx context.Context, req apigen.BeginRecoveryRequestObject) (apigen.BeginRecoveryResponseObject, error) {
	result, err := a.Auth.ConsumeRecoveryCode(ctx, req.Body.Username, req.Body.Code)
	if err != nil {
		// The passkey-only floor refusal (A1): consuming the last code on a
		// passwordless account is refused loudly. Only a caller holding a VALID
		// code reaches it, so naming the structural state reveals nothing an
		// enumerator could not already learn — and the refusal is non-destructive.
		if errors.Is(err, service.ErrPasskeyOnlyViolation) {
			return apigen.BeginRecovery400JSONResponse{BadRequestJSONResponse: apigen.BadRequestJSONResponse(errorBody(apigen.ErrorCodeBadRequest, ""))}, nil
		}
		return nil, err
	}
	return apigen.BeginRecovery200JSONResponse{
		Authority: result.Authority,
		ExpiresAt: result.ExpiresAt,
	}, nil
}

// loginResultOf renders a freshly minted or rotated session for the wire. A
// browser-artifact token is delivered ONLY on the __Host-hikyo HttpOnly cookie
// and is never echoed into the script-readable body (B2); a CLI artifact has no
// cookie channel, so its token stays in the body.
func loginResultOf(r service.LoginResult) apigen.LoginResult {
	var token *string
	if r.Artifact != service.ArtifactBrowser {
		token = optional(r.SessionToken)
	}
	return apigen.LoginResult{
		SessionToken: token,
		Session: apigen.Session{
			Id:                r.SessionID,
			Artifact:          r.Artifact.String(),
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
		// Everything but the metadata leg above goes through the one uniform
		// writer, so a refusal class added later (conflict, for a duplicate name)
		// cannot fall through a switch and answer 500 by omission.
		return nil, err
	}
	return apigen.CreateOrg201JSONResponse(wireOrg(org)), nil
}

// ListMyOrgs is the navigation surface: the organisations the caller's own
// grants name. Distinct from ListOrgs, which is the operator's enumeration of
// every org and is MFA-mandatory — see the contract and service for why the
// sidebar must not go through it.
func (a *API) ListMyOrgs(ctx context.Context, _ apigen.ListMyOrgsRequestObject) (apigen.ListMyOrgsResponseObject, error) {
	orgs, err := a.Orgs.ListMine(ctx, service.Bearer(bearer(ctx)))
	if err != nil {
		if classify(err) == apigen.ErrorCodeUnauthenticated {
			return apigen.ListMyOrgs401JSONResponse{UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, ""))}, nil
		}
		return nil, err
	}
	items := make([]apigen.MyOrg, 0, len(orgs))
	for _, o := range orgs {
		items = append(items, apigen.MyOrg{Id: o.ID, Name: o.Name})
	}
	return apigen.ListMyOrgs200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) ListOrgs(ctx context.Context, _ apigen.ListOrgsRequestObject) (apigen.ListOrgsResponseObject, error) {
	orgs, err := a.Orgs.List(ctx, service.Bearer(bearer(ctx)))
	if err != nil {
		return nil, err
	}
	items := make([]apigen.Org, 0, len(orgs))
	for _, o := range orgs {
		items = append(items, wireOrg(o))
	}
	return apigen.ListOrgs200JSONResponse{Items: items, Count: len(items)}, nil
}

// GetOrg reads one organisation. It is tenant-scoped at org depth (#48), so
// there is no 403 leg: a caller who may not reach the org gets the same 404 as
// one asking after an org that never existed. The refusal is rendered by the
// uniform writer through the strict server's error leg, like the rest of the
// hierarchy surface — see internal/server/hierarchy.go.
func (a *API) GetOrg(ctx context.Context, req apigen.GetOrgRequestObject) (apigen.GetOrgResponseObject, error) {
	org, err := a.Orgs.Get(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org))
	if err != nil {
		return nil, err
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
		a.requireCSRF,
		a.validateAgainstContract,
	}
}

// requestKey carries the raw request so the OIDC handlers can read cookies (the
// browser-binding cookie and the __Host-hikyo session cookie), which the strict
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
const browserSessionCookie = "__Host-hikyo"

// oidcBindingCookiePrefix is the per-transaction browser-binding cookie name
// prefix (A16): the suffix is derived from the state so concurrent tabs do not
// clobber each other's binding.
const oidcBindingCookiePrefix = "__Host-hikyo-oidc-tx-"

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
