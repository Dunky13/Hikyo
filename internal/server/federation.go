package server

import (
	"context"
	"fmt"
	"time"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/jwkssource"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

// The OIDC federation transport (#62): instance-scoped issuer configuration and
// project-scoped `(issuer, subject)` bindings.
//
// Three rules this file exists to keep visible.
//
// There is NO route that edits a binding, and the generated types cannot express
// one: bindings are immutable, so the only mutation is a replacement mint naming
// the predecessor it supersedes.
//
// There is NO route that returns an issuer's static JWKS document. The read
// shape has no member for it, so a get or list handler physically cannot echo
// configuration back.
//
// The scope a request addresses IS the path, never a body member — the same rule
// the grant and identity transports keep, for the same reason: a body-supplied
// scope would let a caller authorized for one project bind another's identities.

// FederationService is the domain surface this transport exposes.
type FederationService interface {
	CreateIssuer(ctx context.Context, actor service.Actor, req service.IssuerRequest) (service.IssuerView, error)
	UpdateIssuer(ctx context.Context, actor service.Actor, id string, source jwkssource.KeySource, refused []string) (service.IssuerView, error)
	ListIssuers(ctx context.Context, actor service.Actor) ([]service.IssuerView, error)
	DeleteIssuer(ctx context.Context, actor service.Actor, id string) error
	CreateBinding(ctx context.Context, actor service.Actor, scope domain.Scope, saID string, req service.BindingRequest) (service.BindingView, error)
}

func (a *API) ListFederationIssuers(ctx context.Context, _ apigen.ListFederationIssuersRequestObject) (apigen.ListFederationIssuersResponseObject, error) {
	issuers, err := a.Federation.ListIssuers(ctx, service.Bearer(bearer(ctx)))
	if err != nil {
		return nil, err
	}
	items := make([]apigen.FederationIssuer, 0, len(issuers))
	for _, iss := range issuers {
		items = append(items, wireIssuer(iss))
	}
	return apigen.ListFederationIssuers200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) CreateFederationIssuer(ctx context.Context, req apigen.CreateFederationIssuerRequestObject) (apigen.CreateFederationIssuerResponseObject, error) {
	source, err := requestKeySource(req.Body.JwksMode, req.Body.StaticJwks)
	if err != nil {
		return nil, err
	}
	want := service.IssuerRequest{
		Issuer:           req.Body.Issuer,
		Type:             domain.IssuerType(req.Body.IssuerType),
		KeySource:        source,
		RefusedAudiences: req.Body.RefusedAudiences,
	}
	iss, err := a.Federation.CreateIssuer(ctx, service.Bearer(bearer(ctx)), want)
	if err != nil {
		return nil, err
	}
	return apigen.CreateFederationIssuer201JSONResponse(wireIssuer(iss)), nil
}

func (a *API) UpdateFederationIssuer(ctx context.Context, req apigen.UpdateFederationIssuerRequestObject) (apigen.UpdateFederationIssuerResponseObject, error) {
	source, err := requestKeySource(req.Body.JwksMode, req.Body.StaticJwks)
	if err != nil {
		return nil, err
	}
	iss, err := a.Federation.UpdateIssuer(ctx, service.Bearer(bearer(ctx)), req.Issuer,
		source, req.Body.RefusedAudiences)
	if err != nil {
		return nil, err
	}
	return apigen.UpdateFederationIssuer200JSONResponse(wireIssuer(iss)), nil
}

func (a *API) DeleteFederationIssuer(ctx context.Context, req apigen.DeleteFederationIssuerRequestObject) (apigen.DeleteFederationIssuerResponseObject, error) {
	if err := a.Federation.DeleteIssuer(ctx, service.Bearer(bearer(ctx)), req.Issuer); err != nil {
		return nil, err
	}
	return apigen.DeleteFederationIssuer204Response{}, nil
}

func (a *API) CreateFederatedBinding(ctx context.Context, req apigen.CreateFederatedBindingRequestObject) (apigen.CreateFederatedBindingResponseObject, error) {
	want := service.BindingRequest{
		Issuer:         req.Body.Issuer,
		Subject:        req.Body.Subject,
		Audience:       req.Body.Audience,
		RequiredClaims: domainClaimPins(req.Body.RequiredClaims),
	}
	if req.Body.Indefinite != nil {
		want.Indefinite = *req.Body.Indefinite
	}
	if req.Body.LifetimeSeconds != nil {
		want.Lifetime = time.Duration(*req.Body.LifetimeSeconds) * time.Second
	}
	if req.Body.Replaces != nil {
		want.Replaces = *req.Body.Replaces
	}
	view, err := a.Federation.CreateBinding(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.ServiceAccount, want)
	if err != nil {
		return nil, err
	}
	return apigen.CreateFederatedBinding201JSONResponse(wireBinding(view)), nil
}

func wireIssuer(iss service.IssuerView) apigen.FederationIssuer {
	out := apigen.FederationIssuer{
		Id: iss.ID, Issuer: iss.Issuer,
		IssuerType:       apigen.IssuerType(iss.Type),
		JwksMode:         apigen.JWKSMode(iss.KeySource.Mode()),
		RefusedAudiences: iss.RefusedAudiences,
		CreatedAt:        iss.CreatedAt, CreatedBy: string(iss.CreatedBy),
		LiveBindings: int(iss.Bindings),
	}
	out.UpdatedAt = optionalTime(iss.UpdatedAt)
	out.UpdatedBy = optional(string(iss.UpdatedBy))
	return out
}

func requestKeySource(mode apigen.JWKSMode, staticJWKS *string) (jwkssource.KeySource, error) {
	source, err := jwkssource.ParseKeySource(domain.JWKSMode(mode), staticJWKS)
	if err != nil {
		return jwkssource.KeySource{}, fmt.Errorf("%w: %v", service.ErrIssuerValue, err)
	}
	return source, nil
}

// wireBinding renders the binding as a credential row plus the mint's own
// outcome. It goes through wireCredential deliberately: a binding IS a
// credential, and rendering it through a second path would be a second place for
// the never-return-a-value rule to be forgotten.
func wireBinding(b service.BindingView) apigen.FederatedBinding {
	cred := apigen.MachineCredential{
		Id:        b.CredentialID,
		Kind:      apigen.CredentialKind(domain.CredentialOIDCFederation),
		Lifetime:  apigen.CredentialLifetime(b.Lifetime),
		CreatedAt: b.CreatedAt, CreatedBy: string(b.CreatedBy),
		ExpiringSoon: b.ExpiringSoon,
	}
	cred.ExpiresAt = optionalTime(b.ExpiresAt)
	cred.RevokedAt = optionalTime(b.RevokedAt)
	cred.ReactivatedAt = optionalTime(b.ReactivatedAt)
	cred.Issuer = optional(b.Issuer)
	cred.Subject = optional(b.Subject)
	cred.Audience = optional(b.Audience)
	if pins := wireClaimPins(b.RequiredClaims); len(pins) > 0 {
		cred.RequiredClaims = &pins
	}
	out := apigen.FederatedBinding{
		Credential: cred, IssuerId: b.IssuerID, Clamped: b.Clamped,
	}
	out.ReplacedId = optional(b.ReplacedID)
	return out
}

// domainClaimPins and wireClaimPins carry the DISCRIMINATED scalar across the
// boundary without collapsing it. Exactly one member is set on each side, and
// nothing here folds a string onto a number: `repository_id: 123` and
// `repository_id: "123"` stay two different pins all the way down.
func domainClaimPins(pins []apigen.FederatedClaimPin) []service.ClaimPin {
	out := make([]service.ClaimPin, 0, len(pins))
	for _, p := range pins {
		out = append(out, service.ClaimPin{
			Claim: p.Claim, String: p.StringValue, Number: p.NumberValue, Boolean: p.BoolValue,
		})
	}
	return out
}

func wireClaimPins(pins []service.ClaimPin) []apigen.FederatedClaimPin {
	out := make([]apigen.FederatedClaimPin, 0, len(pins))
	for _, p := range pins {
		out = append(out, apigen.FederatedClaimPin{
			Claim: p.Claim, StringValue: p.String, NumberValue: p.Number, BoolValue: p.Boolean,
		})
	}
	return out
}
