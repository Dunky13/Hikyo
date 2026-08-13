package server

import (
	"context"
	"time"

	"github.com/Dunky13/hikyo/api/apigen"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/service"
)

// The machine-identity transport (#61): service accounts, their credentials
// and the instance lifetime controls.
//
// Two rules this file exists to keep visible.
//
// There is NO route that returns a credential value after mint, and the
// generated types cannot express one: MachineCredential has no value member,
// so a list or get handler physically cannot leak it. The value appears in
// exactly one response type, the mint result.
//
// The scope a request addresses IS the path, never a body member — the same
// rule the grant transport keeps, for the same reason: a body-supplied scope
// would let a caller authorized for one project administer another's
// identities.

// IdentityService is the domain surface this transport exposes.
type IdentityService interface {
	CreateServiceAccount(ctx context.Context, actor service.Actor, scope domain.Scope, name string, kind domain.PrincipalClass) (service.ServiceAccountView, error)
	ListServiceAccounts(ctx context.Context, actor service.Actor, scope domain.Scope) ([]service.ServiceAccountView, error)
	DeleteServiceAccount(ctx context.Context, actor service.Actor, scope domain.Scope, id string) error
	MintCredential(ctx context.Context, actor service.Actor, scope domain.Scope, saID string, req service.MintRequest) (service.MintResult, error)
	ListCredentials(ctx context.Context, actor service.Actor, scope domain.Scope, saID string) ([]service.CredentialView, error)
	RevokeCredential(ctx context.Context, actor service.Actor, scope domain.Scope, saID, credentialID string) error
	Policy(ctx context.Context, actor service.Actor) (service.PolicyView, error)
	SetPolicy(ctx context.Context, actor service.Actor, change service.PolicyChange) (service.PolicyResult, error)
}

func (a *API) ListServiceAccounts(ctx context.Context, req apigen.ListServiceAccountsRequestObject) (apigen.ListServiceAccountsResponseObject, error) {
	accounts, err := a.Identities.ListServiceAccounts(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project))
	if err != nil {
		return nil, err
	}
	items := make([]apigen.ServiceAccount, 0, len(accounts))
	for _, sa := range accounts {
		items = append(items, wireServiceAccount(sa))
	}
	return apigen.ListServiceAccounts200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) CreateServiceAccount(ctx context.Context, req apigen.CreateServiceAccountRequestObject) (apigen.CreateServiceAccountResponseObject, error) {
	sa, err := a.Identities.CreateServiceAccount(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.Body.Name, domain.PrincipalClass(req.Body.Kind))
	if err != nil {
		return nil, err
	}
	// 201, like the four hierarchy creates it is shaped exactly like. The
	// mint below stays 200: it is an action returning a display-once secret,
	// the same shape as recovery-code regeneration and SP-key rotation.
	return apigen.CreateServiceAccount201JSONResponse(wireServiceAccount(sa)), nil
}

func (a *API) DeleteServiceAccount(ctx context.Context, req apigen.DeleteServiceAccountRequestObject) (apigen.DeleteServiceAccountResponseObject, error) {
	if err := a.Identities.DeleteServiceAccount(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.ServiceAccount); err != nil {
		return nil, err
	}
	return apigen.DeleteServiceAccount204Response{}, nil
}

func (a *API) ListMachineCredentials(ctx context.Context, req apigen.ListMachineCredentialsRequestObject) (apigen.ListMachineCredentialsResponseObject, error) {
	creds, err := a.Identities.ListCredentials(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.ServiceAccount)
	if err != nil {
		return nil, err
	}
	items := make([]apigen.MachineCredential, 0, len(creds))
	for _, c := range creds {
		items = append(items, wireCredential(c))
	}
	return apigen.ListMachineCredentials200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) MintMachineCredential(ctx context.Context, req apigen.MintMachineCredentialRequestObject) (apigen.MintMachineCredentialResponseObject, error) {
	want := service.MintRequest{}
	if req.Body.Indefinite != nil {
		want.Indefinite = *req.Body.Indefinite
	}
	if req.Body.LifetimeSeconds != nil {
		want.Lifetime = time.Duration(*req.Body.LifetimeSeconds) * time.Second
	}
	res, err := a.Identities.MintCredential(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.ServiceAccount, want)
	if err != nil {
		return nil, err
	}
	return apigen.MintMachineCredential200JSONResponse{
		Value: res.Value, Credential: wireCredential(res.Credential), Clamped: res.Clamped,
	}, nil
}

func (a *API) RevokeMachineCredential(ctx context.Context, req apigen.RevokeMachineCredentialRequestObject) (apigen.RevokeMachineCredentialResponseObject, error) {
	if err := a.Identities.RevokeCredential(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.ServiceAccount, req.Credential); err != nil {
		return nil, err
	}
	return apigen.RevokeMachineCredential204Response{}, nil
}

func (a *API) GetCredentialPolicy(ctx context.Context, _ apigen.GetCredentialPolicyRequestObject) (apigen.GetCredentialPolicyResponseObject, error) {
	p, err := a.Identities.Policy(ctx, service.Bearer(bearer(ctx)))
	if err != nil {
		return nil, err
	}
	return apigen.GetCredentialPolicy200JSONResponse(wirePolicy(p)), nil
}

func (a *API) SetCredentialPolicy(ctx context.Context, req apigen.SetCredentialPolicyRequestObject) (apigen.SetCredentialPolicyResponseObject, error) {
	change := service.PolicyChange{
		MaxFiniteLifetime:  time.Duration(req.Body.MaxFiniteLifetimeSeconds) * time.Second,
		AllowIndefinite:    req.Body.AllowIndefinite,
		MaxLiveCredentials: int64(req.Body.MaxLiveCredentials),
	}
	if req.Body.Confirm != nil {
		change.Confirm = *req.Body.Confirm
	}
	// An unconfirmed tightening is not an error: it is a PREVIEW, and the
	// enumeration is its whole content. The uniform error writer has no room
	// for a body beyond the fixed message per code, so refusing here would
	// enumerate the affected credentials to nobody — which is the one thing
	// the ADR requires this path to do.
	res, err := a.Identities.SetPolicy(ctx, service.Bearer(bearer(ctx)), change)
	if err != nil {
		return nil, err
	}
	return apigen.SetCredentialPolicy200JSONResponse(wirePolicyResult(res)), nil
}

func wireServiceAccount(sa service.ServiceAccountView) apigen.ServiceAccount {
	return apigen.ServiceAccount{
		Id: sa.ID, PrincipalId: string(sa.Principal), Name: sa.Name,
		Kind:      apigen.ServiceAccountKind(sa.Kind),
		CreatedAt: sa.CreatedAt, CreatedBy: string(sa.CreatedBy),
		LiveCredentials: int(sa.LiveCredentials),
	}
}

// wireCredential renders metadata and nothing else. There is no branch here
// that could add a value: the generated type has no member for one.
//
// The binding members ride along for an `oidc-federation` row, which is what
// the schema has always said this row carries in place of a prefix hint: a
// binding IS a credential row, listed through this route, and an operator who
// cannot see the byte-exact `(issuer, subject)` pair cannot audit it. Every one
// of them is the zero value for a bearer credential, so `optional` renders them
// absent rather than empty.
func wireCredential(c service.CredentialView) apigen.MachineCredential {
	out := apigen.MachineCredential{
		Id: c.ID, Kind: apigen.CredentialKind(c.Kind),
		Lifetime:  apigen.CredentialLifetime(c.Lifetime),
		CreatedAt: c.CreatedAt, CreatedBy: string(c.CreatedBy),
		ExpiringSoon: c.ExpiringSoon,
	}
	out.PrefixHint = optional(c.PrefixHint)
	out.ExpiresAt = optionalTime(c.ExpiresAt)
	out.RevokedAt = optionalTime(c.RevokedAt)
	out.LastUsedAt = optionalTime(c.LastUsedAt)
	out.Issuer = optional(c.Issuer)
	out.Subject = optional(c.Subject)
	out.Audience = optional(c.Audience)
	out.ReactivatedAt = optionalTime(c.ReactivatedAt)
	if pins := wireClaimPins(c.RequiredClaims); len(pins) > 0 {
		out.RequiredClaims = &pins
	}
	return out
}

func wirePolicy(p service.PolicyView) apigen.CredentialPolicy {
	out := apigen.CredentialPolicy{
		MaxFiniteLifetimeSeconds: int(p.MaxFiniteLifetime / time.Second),
		AllowIndefinite:          p.AllowIndefinite,
		MaxLiveCredentials:       int(p.MaxLiveCredentials),
	}
	out.UpdatedAt = optionalTime(p.UpdatedAt)
	out.UpdatedBy = optional(string(p.UpdatedBy))
	return out
}

func wirePolicyResult(r service.PolicyResult) apigen.CredentialPolicyResult {
	affected := make([]apigen.AffectedCredential, 0, len(r.Affected))
	for _, a := range r.Affected {
		row := apigen.AffectedCredential{
			Id: a.ID, ServiceAccountId: a.ServiceAccountID,
			Reason: apigen.AffectedCredentialReason(a.Reason),
		}
		row.ExpiresAt = optionalTime(a.ExpiresAt)
		affected = append(affected, row)
	}
	return apigen.CredentialPolicyResult{
		Applied: r.Applied, Policy: wirePolicy(r.Policy),
		Affected: affected, ClampedCount: int(r.Clamped),
	}
}

// optionalTime renders an absent instant as JSON null rather than the zero
// time. "Never used" and "used at the beginning of the epoch" are different
// facts, and only one of them is ever true.
func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
