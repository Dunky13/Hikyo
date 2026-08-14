package server

import (
	"context"
	"time"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

// The SCIM ADMINISTRATION transport: ordinary Hikyo domain surface, ordinary
// Hikyo error envelope, human sessions only. It is a separate file from the
// wire for the same reason it is a separate interface — two authorization
// languages, and mixing them in one file is how a handler ends up calling the
// wrong one.

// SCIMAdminService is the administration surface this transport needs.
type SCIMAdminService interface {
	CreateBinding(ctx context.Context, actor service.Actor, org domain.OrgID, in service.SCIMBindingInput) (service.SCIMBindingView, error)
	ListBindings(ctx context.Context, actor service.Actor, org domain.OrgID) ([]service.SCIMBindingView, error)
	GetBinding(ctx context.Context, actor service.Actor, org domain.OrgID, id string) (service.SCIMBindingView, error)
	DeleteBinding(ctx context.Context, actor service.Actor, org domain.OrgID, id string) error

	CreateMapping(ctx context.Context, actor service.Actor, org domain.OrgID, binding string, spec service.SCIMMappingSpec) (service.SCIMMappingResult, error)
	UpdateMapping(ctx context.Context, actor service.Actor, org domain.OrgID, binding string, spec service.SCIMMappingSpec) (service.SCIMMappingResult, error)
	DeleteMapping(ctx context.Context, actor service.Actor, org domain.OrgID, binding string, spec service.SCIMMappingSpec) (service.SCIMMappingResult, error)
	ListMappings(ctx context.Context, actor service.Actor, org domain.OrgID, binding string) ([]service.SCIMMappingView, error)

	MintCredential(ctx context.Context, actor service.Actor, org domain.OrgID, binding string, indefinite bool, proof string) (service.SCIMMintResult, error)
	ListCredentials(ctx context.Context, actor service.Actor, org domain.OrgID, binding string) ([]service.SCIMCredentialView, error)
	GetCredential(ctx context.Context, actor service.Actor, org domain.OrgID, binding, id string) (service.SCIMCredentialView, error)
	RevokeCredential(ctx context.Context, actor service.Actor, org domain.OrgID, binding, id string) error

	DirectoryUsers(ctx context.Context, actor service.Actor, org domain.OrgID, binding string) ([]service.SCIMDirectoryUser, error)
	DirectoryGroups(ctx context.Context, actor service.Actor, org domain.OrgID, binding string) ([]service.SCIMDirectoryGroup, error)
}

func (a *API) ListScimBindings(ctx context.Context, req apigen.ListScimBindingsRequestObject) (apigen.ListScimBindingsResponseObject, error) {
	views, err := a.SCIM.ListBindings(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org))
	if err != nil {
		return nil, err
	}
	items := make([]apigen.ScimBinding, 0, len(views))
	for _, v := range views {
		items = append(items, wireSCIMBinding(v))
	}
	return apigen.ListScimBindings200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) CreateScimBinding(ctx context.Context, req apigen.CreateScimBindingRequestObject) (apigen.CreateScimBindingResponseObject, error) {
	if req.Body == nil {
		return nil, domain.ErrInvalid
	}
	in := service.SCIMBindingInput{
		ProviderKind:  domain.ProviderKind(req.Body.ProviderKind),
		ProviderSlug:  req.Body.ProviderSlug,
		SubjectSource: req.Body.SubjectSource,
	}
	in.NameIDFormat = deref(req.Body.NameidFormat)
	in.NameIDQualifier = deref(req.Body.NameidQualifier)
	in.NameIDQualifierPresent = derefBool(req.Body.NameidQualifierPresent)
	in.NameIDSPQualifier = deref(req.Body.NameidSpQualifier)
	in.NameIDSPQualifierPresent = derefBool(req.Body.NameidSpQualifierPresent)
	view, err := a.SCIM.CreateBinding(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), in)
	if err != nil {
		return nil, err
	}
	return apigen.CreateScimBinding200JSONResponse(wireSCIMBinding(view)), nil
}

func (a *API) GetScimBinding(ctx context.Context, req apigen.GetScimBindingRequestObject) (apigen.GetScimBindingResponseObject, error) {
	view, err := a.SCIM.GetBinding(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), req.Binding)
	if err != nil {
		return nil, err
	}
	return apigen.GetScimBinding200JSONResponse(wireSCIMBinding(view)), nil
}

func (a *API) DeleteScimBinding(ctx context.Context, req apigen.DeleteScimBindingRequestObject) (apigen.DeleteScimBindingResponseObject, error) {
	if err := a.SCIM.DeleteBinding(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), req.Binding); err != nil {
		return nil, err
	}
	return apigen.DeleteScimBinding204Response{}, nil
}

func (a *API) ListScimMappings(ctx context.Context, req apigen.ListScimMappingsRequestObject) (apigen.ListScimMappingsResponseObject, error) {
	views, err := a.SCIM.ListMappings(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), req.Binding)
	if err != nil {
		return nil, err
	}
	items := make([]apigen.ScimMapping, 0, len(views))
	for _, v := range views {
		items = append(items, wireSCIMMapping(v))
	}
	return apigen.ListScimMappings200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) CreateScimMapping(ctx context.Context, req apigen.CreateScimMappingRequestObject) (apigen.CreateScimMappingResponseObject, error) {
	if req.Body == nil {
		return nil, domain.ErrInvalid
	}
	res, err := a.SCIM.CreateMapping(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), req.Binding,
		mappingSpec(req.Body.GroupId, req.Body.Template, req.Body.ProjectId, req.Body.EnvironmentId))
	if err != nil {
		return nil, err
	}
	return apigen.CreateScimMapping200JSONResponse(wireSCIMMappingResult(res)), nil
}

func (a *API) UpdateScimMapping(ctx context.Context, req apigen.UpdateScimMappingRequestObject) (apigen.UpdateScimMappingResponseObject, error) {
	if req.Body == nil {
		return nil, domain.ErrInvalid
	}
	res, err := a.SCIM.UpdateMapping(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), req.Binding,
		mappingSpec(req.Body.GroupId, req.Body.Template, req.Body.ProjectId, req.Body.EnvironmentId))
	if err != nil {
		return nil, err
	}
	return apigen.UpdateScimMapping200JSONResponse(wireSCIMMappingResult(res)), nil
}

func (a *API) DeleteScimMapping(ctx context.Context, req apigen.DeleteScimMappingRequestObject) (apigen.DeleteScimMappingResponseObject, error) {
	spec := service.SCIMMappingSpec{
		GroupID:   string(req.Params.Group),
		ProjectID: derefID(req.Params.Project),
		EnvID:     derefID(req.Params.Environment),
	}
	res, err := a.SCIM.DeleteMapping(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), req.Binding, spec)
	if err != nil {
		return nil, err
	}
	return apigen.DeleteScimMapping200JSONResponse(wireSCIMMappingResult(res)), nil
}

func (a *API) ListScimCredentials(ctx context.Context, req apigen.ListScimCredentialsRequestObject) (apigen.ListScimCredentialsResponseObject, error) {
	views, err := a.SCIM.ListCredentials(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), req.Binding)
	if err != nil {
		return nil, err
	}
	items := make([]apigen.ScimCredential, 0, len(views))
	for _, v := range views {
		items = append(items, wireSCIMCredential(v))
	}
	return apigen.ListScimCredentials200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) MintScimCredential(ctx context.Context, req apigen.MintScimCredentialRequestObject) (apigen.MintScimCredentialResponseObject, error) {
	indefinite, proof := false, ""
	if req.Body != nil {
		indefinite = derefBool(req.Body.Indefinite)
		proof = deref(req.Body.Proof)
	}
	res, err := a.SCIM.MintCredential(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), req.Binding, indefinite, proof)
	if err != nil {
		return nil, err
	}
	return apigen.MintScimCredential200JSONResponse{
		Credential: wireSCIMCredential(res.Credential),
		Token:      res.Token,
		Rotated:    res.Rotated,
	}, nil
}

func (a *API) GetScimCredential(ctx context.Context, req apigen.GetScimCredentialRequestObject) (apigen.GetScimCredentialResponseObject, error) {
	view, err := a.SCIM.GetCredential(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), req.Binding, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.GetScimCredential200JSONResponse(wireSCIMCredential(view)), nil
}

func (a *API) RevokeScimCredential(ctx context.Context, req apigen.RevokeScimCredentialRequestObject) (apigen.RevokeScimCredentialResponseObject, error) {
	if err := a.SCIM.RevokeCredential(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), req.Binding, req.Id); err != nil {
		return nil, err
	}
	return apigen.RevokeScimCredential204Response{}, nil
}

func (a *API) ListScimDirectoryUsers(ctx context.Context, req apigen.ListScimDirectoryUsersRequestObject) (apigen.ListScimDirectoryUsersResponseObject, error) {
	views, err := a.SCIM.DirectoryUsers(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), req.Binding)
	if err != nil {
		return nil, err
	}
	items := make([]apigen.ScimDirectoryUser, 0, len(views))
	for _, v := range views {
		groups := make([]apigen.ID, 0, len(v.Groups))
		for _, g := range v.Groups {
			groups = append(groups, apigen.ID(g))
		}
		items = append(items, apigen.ScimDirectoryUser{
			Id: apigen.ID(v.ID), UserName: v.UserName,
			ExternalId: optString(v.ExternalID), AccountId: apigen.ID(v.AccountID),
			Active: v.Active, Groups: groups,
			CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt,
			Attention: wireSCIMAttention(v.Attention),
		})
	}
	return apigen.ListScimDirectoryUsers200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) ListScimDirectoryGroups(ctx context.Context, req apigen.ListScimDirectoryGroupsRequestObject) (apigen.ListScimDirectoryGroupsResponseObject, error) {
	views, err := a.SCIM.DirectoryGroups(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), req.Binding)
	if err != nil {
		return nil, err
	}
	items := make([]apigen.ScimDirectoryGroup, 0, len(views))
	for _, v := range views {
		items = append(items, apigen.ScimDirectoryGroup{
			Id: apigen.ID(v.ID), DisplayName: v.DisplayName,
			ExternalId: optString(v.ExternalID), MemberCount: v.MemberCount,
			CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt,
		})
	}
	return apigen.ListScimDirectoryGroups200JSONResponse{Items: items, Count: len(items)}, nil
}

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

func mappingSpec(group apigen.ID, template string, project, env *string) service.SCIMMappingSpec {
	return service.SCIMMappingSpec{
		GroupID:   string(group),
		Template:  domain.Template(template),
		ProjectID: deref(project),
		EnvID:     deref(env),
	}
}

func wireSCIMBinding(v service.SCIMBindingView) apigen.ScimBinding {
	out := apigen.ScimBinding{
		Id: apigen.ID(v.ID), OrgId: apigen.ID(v.OrgID),
		ProviderKind:          apigen.ScimBindingProviderKind(v.ProviderKind),
		ProviderSlug:          v.ProviderSlug,
		ProviderIssuer:        v.ProviderIssuer,
		SubjectSource:         v.SubjectSource,
		NameidFormat:          optString(v.NameIDFormat),
		ConnectionPrincipalId: apigen.ID(v.ConnectionPrincipalID),
		// The WHOLE NameID profile, values and presence bits. It is immutable
		// after creation (§5.1) and it is an input to the injective subject
		// encoder, so a surface that cannot round-trip it cannot show an
		// administrator what identity this binding actually derives — and an
		// absent qualifier is a different encoder input from an empty one,
		// which is why presence rides separately from value.
		NameidQualifier:          qualifierValue(v.NameIDQualifier, v.NameIDQualifierPresent),
		NameidQualifierPresent:   optBool(v.NameIDQualifierPresent),
		NameidSpQualifier:        qualifierValue(v.NameIDSPQualifier, v.NameIDSPQualifierPresent),
		NameidSpQualifierPresent: optBool(v.NameIDSPQualifierPresent),
		CreatedAt:                v.CreatedAt,
		Attention:                wireSCIMAttention(v.Attention),
	}
	if !v.LastContactAt.IsZero() {
		t := v.LastContactAt
		out.LastContactAt = &t
	}
	return out
}

func wireSCIMAttention(in []service.SCIMAttentionView) []apigen.ScimAttention {
	out := make([]apigen.ScimAttention, 0, len(in))
	for _, a := range in {
		out = append(out, apigen.ScimAttention{
			State:       apigen.ScimAttentionState(a.State),
			SubjectRef:  a.SubjectRef,
			Cause:       a.Cause,
			EnteredAt:   a.EnteredAt,
			Remediation: a.Remediation,
		})
	}
	return out
}

func wireSCIMMapping(v service.SCIMMappingView) apigen.ScimMapping {
	caps := make([]string, 0, len(v.Capabilities))
	caps = append(caps, v.Capabilities...)
	return apigen.ScimMapping{
		Id: apigen.ID(v.ID), BindingId: apigen.ID(v.BindingID), GroupId: apigen.ID(v.GroupID),
		Template: v.Template, ProjectId: optString(v.ProjectID), EnvironmentId: optString(v.EnvID),
		Inert: v.Inert, CreatedAt: v.CreatedAt, Capabilities: caps,
	}
}

func wireSCIMMappingResult(res service.SCIMMappingResult) apigen.ScimMappingResult {
	warnings := make([]apigen.ScimBlastWarning, 0, len(res.Warnings))
	for _, w := range res.Warnings {
		warnings = append(warnings, apigen.ScimBlastWarning{
			Code:     apigen.ScimBlastWarningCode(w.Code),
			Severity: apigen.ScimBlastWarningSeverity(w.Severity),
			Message:  w.Message,
		})
	}
	return apigen.ScimMappingResult{
		Mapping:         wireSCIMMapping(res.Mapping),
		Warnings:        warnings,
		MembersAffected: res.MembersAffected,
		GrantsCreated:   res.GrantsCreated,
		OriginsReleased: res.OriginsReleased,
	}
}

func wireSCIMCredential(v service.SCIMCredentialView) apigen.ScimCredential {
	out := apigen.ScimCredential{
		Id: apigen.ID(v.ID), BindingId: apigen.ID(v.BindingID),
		CreatedAt: v.CreatedAt, Live: v.Live,
	}
	out.ExpiresAt = optTime(v.ExpiresAt)
	out.RevokedAt = optTime(v.RevokedAt)
	out.LastUsedAt = optTime(v.LastUsedAt)
	return out
}

// optString and optTime render "absent" for a zero value. The contract makes
// these members optional rather than nullable, so an unset one is simply not
// there — an empty string would say the identity provider sent one.
// qualifierValue renders a NameID qualifier. Unlike optString it emits an
// EMPTY value when the presence bit is set, because "present and empty" and
// "absent" are different inputs to the injective subject encoder and collapsing
// them is the round-trip failure this exists to prevent.
func qualifierValue(s string, present bool) *string {
	if !present && s == "" {
		return nil
	}
	return &s
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// optBool renders a false flag as absent: the contract makes these optional,
// and "the assertion carries no qualifier" is the absence of the member.
func optBool(b bool) *bool {
	if !b {
		return nil
	}
	return &b
}

func derefID(p *apigen.ID) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
