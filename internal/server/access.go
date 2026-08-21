package server

import (
	"context"
	"time"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

// The access transport (#55): grants, role templates, membership inspection
// and the two `project-settings` knobs.
//
// The grant's scope IS the addressed path, never a body field. A
// body-supplied scope would let a caller authorized at one depth write a
// grant at another — the whole authorization formula defeated by a JSON
// member — so the scope is built from the path parameters only, exactly as
// the hierarchy transport does, and the chokepoint refuses a depth mismatch.
//
// Like every other handler here these return a bare domain error on refusal
// and let the uniform writer decide the status: an unauthorized grant read
// answers byte-identically to a nonexistent org.

// GrantService is the domain surface this transport exposes.
type GrantService interface {
	Create(ctx context.Context, actor service.Actor, spec service.GrantSpec) (service.GrantResult, error)
	Revoke(ctx context.Context, actor service.Actor, spec service.GrantSpec) error
	List(ctx context.Context, actor service.Actor, scope domain.Scope) ([]service.Membership, error)
	ApplyTemplate(ctx context.Context, actor service.Actor, template domain.Template, principal domain.PrincipalID, scope domain.Scope) ([]service.GrantResult, error)
}

// SettingsService is the `project-settings` surface.
type SettingsService interface {
	GetMachineReveal(ctx context.Context, actor service.Actor, scope domain.Scope) (service.MachineRevealSettings, error)
	SetMachineReveal(ctx context.Context, actor service.Actor, scope domain.Scope, enabled bool) (service.MachineRevealSettings, error)
	GetEnvironment(ctx context.Context, actor service.Actor, scope domain.Scope) (service.EnvironmentSettings, error)
	SetEnvironment(ctx context.Context, actor service.Actor, scope domain.Scope, want service.EnvironmentSettings) (service.EnvironmentSettings, error)
}

// RetentionSettingsService is the org cap and project override surface.
type RetentionSettingsService interface {
	GetOrg(ctx context.Context, actor service.Actor, orgID domain.OrgID) (service.RetentionPolicy, error)
	SetOrg(ctx context.Context, actor service.Actor, orgID domain.OrgID, want service.RetentionPolicy) (service.RetentionPolicy, error)
	GetProject(ctx context.Context, actor service.Actor, scope domain.Scope) (service.ProjectRetention, error)
	SetProject(ctx context.Context, actor service.Actor, scope domain.Scope, want *service.RetentionPolicy) (service.ProjectRetention, error)
	GetHealth(ctx context.Context, actor service.Actor) (service.PruneHealth, error)
}

// grantSpec builds the service request from a path scope and a body. There is
// one of these rather than four inlined literals so the "scope comes from the
// path" rule has a single site to be reviewed at.
func grantSpec(scope domain.Scope, principal, capability string) service.GrantSpec {
	return service.GrantSpec{
		Target:     domain.PrincipalID(principal),
		Capability: domain.Capability(capability),
		Scope:      scope,
	}
}

func wireGrantResult(r service.GrantResult, capability domain.Capability) apigen.GrantResult {
	return apigen.GrantResult{
		GrantId: r.GrantID, Capability: string(capability),
		Created: r.Created, OriginAdded: r.OriginAdded,
	}
}

func wireGrantResults(results []service.GrantResult, caps []domain.Capability) apigen.GrantResultList {
	items := make([]apigen.GrantResult, 0, len(results))
	for i, r := range results {
		items = append(items, wireGrantResult(r, caps[i]))
	}
	return apigen.GrantResultList{Items: items, Count: len(items)}
}

func wireGrantScope(s domain.Scope) apigen.GrantScope {
	out := apigen.GrantScope{}
	if s.Org != "" {
		org := string(s.Org)
		out.OrgId = &org
	}
	if s.Project != "" {
		project := string(s.Project)
		out.ProjectId = &project
	}
	if s.Env != "" {
		env := string(s.Env)
		out.EnvironmentId = &env
	}
	return out
}

func wireMemberships(lines []service.Membership) apigen.GrantList {
	items := make([]apigen.Grant, 0, len(lines))
	for _, l := range lines {
		origins := make([]apigen.GrantOrigin, 0, len(l.Origins))
		for _, o := range l.Origins {
			origins = append(origins, apigen.GrantOrigin{
				Kind: apigen.GrantOriginKind(o.Kind), Subject: o.Subject,
			})
		}
		items = append(items, apigen.Grant{
			Id: l.GrantID, PrincipalId: string(l.Principal),
			Capability: string(l.Capability), Scope: wireGrantScope(l.Scope),
			Origins: origins, CreatedAt: l.CreatedAt,
		})
	}
	return apigen.GrantList{Items: items, Count: len(items)}
}

// applyTemplate is the shared body of the four template handlers: they differ
// only in the scope their path addresses.
func (a *API) applyTemplate(ctx context.Context, scope domain.Scope, principal, template string) (apigen.GrantResultList, error) {
	tmpl := domain.Template(template)
	level, err := scope.Level()
	if err != nil {
		return apigen.GrantResultList{}, err
	}
	// Expanding here as well as in the service is not a duplicate rule: the
	// service's expansion is what is WRITTEN, this one only names the
	// capabilities for the response. A disagreement between the two is a
	// length mismatch, refused below rather than zipped into a response that
	// labels each result with the wrong capability.
	caps, err := domain.ExpandTemplate(tmpl, level)
	if err != nil {
		return apigen.GrantResultList{}, domain.ErrInvalid
	}
	results, err := a.Grants.ApplyTemplate(ctx, service.Bearer(bearer(ctx)), tmpl, domain.PrincipalID(principal), scope)
	if err != nil {
		return apigen.GrantResultList{}, err
	}
	if len(results) != len(caps) {
		return apigen.GrantResultList{}, domain.ErrInvalid
	}
	return wireGrantResults(results, caps), nil
}

// ---------------------------------------------------------------------------
// Instance scope
// ---------------------------------------------------------------------------

func (a *API) ListInstanceGrants(ctx context.Context, _ apigen.ListInstanceGrantsRequestObject) (apigen.ListInstanceGrantsResponseObject, error) {
	lines, err := a.Grants.List(ctx, service.Bearer(bearer(ctx)), domain.Scope{})
	if err != nil {
		return nil, err
	}
	return apigen.ListInstanceGrants200JSONResponse(wireMemberships(lines)), nil
}

func (a *API) CreateInstanceGrant(ctx context.Context, req apigen.CreateInstanceGrantRequestObject) (apigen.CreateInstanceGrantResponseObject, error) {
	spec := grantSpec(domain.Scope{}, req.Body.Principal, req.Body.Capability)
	res, err := a.Grants.Create(ctx, service.Bearer(bearer(ctx)), spec)
	if err != nil {
		return nil, err
	}
	return apigen.CreateInstanceGrant200JSONResponse(wireGrantResult(res, spec.Capability)), nil
}

func (a *API) RevokeInstanceGrant(ctx context.Context, req apigen.RevokeInstanceGrantRequestObject) (apigen.RevokeInstanceGrantResponseObject, error) {
	spec := grantSpec(domain.Scope{}, req.Params.Principal, req.Params.Capability)
	if err := a.Grants.Revoke(ctx, service.Bearer(bearer(ctx)), spec); err != nil {
		return nil, err
	}
	return apigen.RevokeInstanceGrant204Response{}, nil
}

func (a *API) ApplyInstanceTemplate(ctx context.Context, req apigen.ApplyInstanceTemplateRequestObject) (apigen.ApplyInstanceTemplateResponseObject, error) {
	out, err := a.applyTemplate(ctx, domain.Scope{}, req.Body.Principal, string(req.Body.Template))
	if err != nil {
		return nil, err
	}
	return apigen.ApplyInstanceTemplate200JSONResponse(out), nil
}

// ---------------------------------------------------------------------------
// Organisation scope
// ---------------------------------------------------------------------------

func (a *API) ListOrgGrants(ctx context.Context, req apigen.ListOrgGrantsRequestObject) (apigen.ListOrgGrantsResponseObject, error) {
	lines, err := a.Grants.List(ctx, service.Bearer(bearer(ctx)), domain.Scope{Org: domain.OrgID(req.Org)})
	if err != nil {
		return nil, err
	}
	return apigen.ListOrgGrants200JSONResponse(wireMemberships(lines)), nil
}

func (a *API) CreateOrgGrant(ctx context.Context, req apigen.CreateOrgGrantRequestObject) (apigen.CreateOrgGrantResponseObject, error) {
	spec := grantSpec(domain.Scope{Org: domain.OrgID(req.Org)}, req.Body.Principal, req.Body.Capability)
	res, err := a.Grants.Create(ctx, service.Bearer(bearer(ctx)), spec)
	if err != nil {
		return nil, err
	}
	return apigen.CreateOrgGrant200JSONResponse(wireGrantResult(res, spec.Capability)), nil
}

func (a *API) RevokeOrgGrant(ctx context.Context, req apigen.RevokeOrgGrantRequestObject) (apigen.RevokeOrgGrantResponseObject, error) {
	spec := grantSpec(domain.Scope{Org: domain.OrgID(req.Org)}, req.Params.Principal, req.Params.Capability)
	if err := a.Grants.Revoke(ctx, service.Bearer(bearer(ctx)), spec); err != nil {
		return nil, err
	}
	return apigen.RevokeOrgGrant204Response{}, nil
}

func (a *API) ApplyOrgTemplate(ctx context.Context, req apigen.ApplyOrgTemplateRequestObject) (apigen.ApplyOrgTemplateResponseObject, error) {
	out, err := a.applyTemplate(ctx, domain.Scope{Org: domain.OrgID(req.Org)}, req.Body.Principal, string(req.Body.Template))
	if err != nil {
		return nil, err
	}
	return apigen.ApplyOrgTemplate200JSONResponse(out), nil
}

// ---------------------------------------------------------------------------
// Project scope
// ---------------------------------------------------------------------------

func (a *API) ListProjectGrants(ctx context.Context, req apigen.ListProjectGrantsRequestObject) (apigen.ListProjectGrantsResponseObject, error) {
	lines, err := a.Grants.List(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project))
	if err != nil {
		return nil, err
	}
	return apigen.ListProjectGrants200JSONResponse(wireMemberships(lines)), nil
}

func (a *API) CreateProjectGrant(ctx context.Context, req apigen.CreateProjectGrantRequestObject) (apigen.CreateProjectGrantResponseObject, error) {
	spec := grantSpec(projectScope(req.Org, req.Project), req.Body.Principal, req.Body.Capability)
	res, err := a.Grants.Create(ctx, service.Bearer(bearer(ctx)), spec)
	if err != nil {
		return nil, err
	}
	return apigen.CreateProjectGrant200JSONResponse(wireGrantResult(res, spec.Capability)), nil
}

func (a *API) RevokeProjectGrant(ctx context.Context, req apigen.RevokeProjectGrantRequestObject) (apigen.RevokeProjectGrantResponseObject, error) {
	spec := grantSpec(projectScope(req.Org, req.Project), req.Params.Principal, req.Params.Capability)
	if err := a.Grants.Revoke(ctx, service.Bearer(bearer(ctx)), spec); err != nil {
		return nil, err
	}
	return apigen.RevokeProjectGrant204Response{}, nil
}

func (a *API) ApplyProjectTemplate(ctx context.Context, req apigen.ApplyProjectTemplateRequestObject) (apigen.ApplyProjectTemplateResponseObject, error) {
	out, err := a.applyTemplate(ctx, projectScope(req.Org, req.Project), req.Body.Principal, string(req.Body.Template))
	if err != nil {
		return nil, err
	}
	return apigen.ApplyProjectTemplate200JSONResponse(out), nil
}

// ---------------------------------------------------------------------------
// Environment scope
// ---------------------------------------------------------------------------

func (a *API) CreateEnvGrant(ctx context.Context, req apigen.CreateEnvGrantRequestObject) (apigen.CreateEnvGrantResponseObject, error) {
	spec := grantSpec(envScope(req.Org, req.Project, req.Environment), req.Body.Principal, req.Body.Capability)
	res, err := a.Grants.Create(ctx, service.Bearer(bearer(ctx)), spec)
	if err != nil {
		return nil, err
	}
	return apigen.CreateEnvGrant200JSONResponse(wireGrantResult(res, spec.Capability)), nil
}

func (a *API) RevokeEnvGrant(ctx context.Context, req apigen.RevokeEnvGrantRequestObject) (apigen.RevokeEnvGrantResponseObject, error) {
	spec := grantSpec(envScope(req.Org, req.Project, req.Environment), req.Params.Principal, req.Params.Capability)
	if err := a.Grants.Revoke(ctx, service.Bearer(bearer(ctx)), spec); err != nil {
		return nil, err
	}
	return apigen.RevokeEnvGrant204Response{}, nil
}

func (a *API) ApplyEnvTemplate(ctx context.Context, req apigen.ApplyEnvTemplateRequestObject) (apigen.ApplyEnvTemplateResponseObject, error) {
	out, err := a.applyTemplate(ctx, envScope(req.Org, req.Project, req.Environment), req.Body.Principal, string(req.Body.Template))
	if err != nil {
		return nil, err
	}
	return apigen.ApplyEnvTemplate200JSONResponse(out), nil
}

// ---------------------------------------------------------------------------
// project-settings
// ---------------------------------------------------------------------------

func wireSettings(s service.EnvironmentSettings) apigen.EnvironmentSettings {
	out := apigen.EnvironmentSettings{Protected: s.Protected}
	if s.HasWindow {
		// Seconds, not a duration string: the wire carries the same unit the
		// column does, and 0 is a legal value that must stay distinct from
		// "inherits the instance default" (which is the absent member).
		seconds := int(s.Window.Seconds())
		out.ReauthWindowSeconds = &seconds
	}
	return out
}

func (a *API) GetEnvironmentSettings(ctx context.Context, req apigen.GetEnvironmentSettingsRequestObject) (apigen.GetEnvironmentSettingsResponseObject, error) {
	got, err := a.Settings.GetEnvironment(ctx, service.Bearer(bearer(ctx)), envScope(req.Org, req.Project, req.Environment))
	if err != nil {
		return nil, err
	}
	return apigen.GetEnvironmentSettings200JSONResponse(wireSettings(got)), nil
}

func (a *API) SetEnvironmentSettings(ctx context.Context, req apigen.SetEnvironmentSettingsRequestObject) (apigen.SetEnvironmentSettingsResponseObject, error) {
	want := service.EnvironmentSettings{Protected: req.Body.Protected}
	if req.Body.ReauthWindowSeconds != nil {
		want.HasWindow = true
		want.Window = time.Duration(*req.Body.ReauthWindowSeconds) * time.Second
	}
	got, err := a.Settings.SetEnvironment(ctx, service.Bearer(bearer(ctx)), envScope(req.Org, req.Project, req.Environment), want)
	if err != nil {
		return nil, err
	}
	return apigen.SetEnvironmentSettings200JSONResponse(wireSettings(got)), nil
}

func wireOrgRetention(policy service.RetentionPolicy) apigen.RetentionPolicy {
	out := apigen.RetentionPolicy{Mode: apigen.RetentionPolicyModeKeepIfEither}
	if policy.Unlimited {
		out.Mode = apigen.RetentionPolicyModeUnlimited
		return out
	}
	age, count := int(policy.MaxAge/time.Second), int(policy.LastRevisions)
	out.MaxAgeSeconds, out.LastRevisions = &age, &count
	return out
}

func wireProjectRetention(retention service.ProjectRetention) apigen.ProjectRetentionPolicy {
	org := wireOrgRetention(retention.Policy)
	out := apigen.ProjectRetentionPolicy{
		Inherited: retention.Inherited,
		Mode:      apigen.ProjectRetentionPolicyMode(org.Mode),
	}
	out.MaxAgeSeconds, out.LastRevisions = org.MaxAgeSeconds, org.LastRevisions
	return out
}

func parseOrgRetention(in apigen.RetentionPolicy) (service.RetentionPolicy, error) {
	if in.Mode == apigen.RetentionPolicyModeUnlimited {
		if in.MaxAgeSeconds != nil || in.LastRevisions != nil {
			return service.RetentionPolicy{}, domain.ErrInvalid
		}
		return service.RetentionPolicy{Unlimited: true}, nil
	}
	if in.Mode != apigen.RetentionPolicyModeKeepIfEither || in.MaxAgeSeconds == nil || in.LastRevisions == nil {
		return service.RetentionPolicy{}, domain.ErrInvalid
	}
	const maxDurationSeconds = int64((1<<63 - 1) / int64(time.Second))
	if int64(*in.MaxAgeSeconds) > maxDurationSeconds {
		return service.RetentionPolicy{}, domain.ErrInvalid
	}
	return service.RetentionPolicy{
		MaxAge:        time.Duration(*in.MaxAgeSeconds) * time.Second,
		LastRevisions: int64(*in.LastRevisions),
	}, nil
}

func parseProjectRetention(in apigen.SetProjectRetentionRequest) (*service.RetentionPolicy, error) {
	if in.Inherited {
		if in.MaxAgeSeconds != nil || in.LastRevisions != nil {
			return nil, domain.ErrInvalid
		}
		return nil, nil
	}
	policy, err := parseOrgRetention(apigen.RetentionPolicy{
		Mode:          apigen.RetentionPolicyModeKeepIfEither,
		MaxAgeSeconds: in.MaxAgeSeconds, LastRevisions: in.LastRevisions,
	})
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

func (a *API) GetOrgRetention(ctx context.Context, req apigen.GetOrgRetentionRequestObject) (apigen.GetOrgRetentionResponseObject, error) {
	got, err := a.Retention.GetOrg(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org))
	if err != nil {
		return nil, err
	}
	return apigen.GetOrgRetention200JSONResponse(wireOrgRetention(got)), nil
}

func (a *API) SetOrgRetention(ctx context.Context, req apigen.SetOrgRetentionRequestObject) (apigen.SetOrgRetentionResponseObject, error) {
	want, err := parseOrgRetention(*req.Body)
	if err != nil {
		return nil, err
	}
	got, err := a.Retention.SetOrg(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), want)
	if err != nil {
		return nil, err
	}
	return apigen.SetOrgRetention200JSONResponse(wireOrgRetention(got)), nil
}

func (a *API) GetProjectRetention(ctx context.Context, req apigen.GetProjectRetentionRequestObject) (apigen.GetProjectRetentionResponseObject, error) {
	got, err := a.Retention.GetProject(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project))
	if err != nil {
		return nil, err
	}
	return apigen.GetProjectRetention200JSONResponse(wireProjectRetention(got)), nil
}

func (a *API) SetProjectRetention(ctx context.Context, req apigen.SetProjectRetentionRequestObject) (apigen.SetProjectRetentionResponseObject, error) {
	want, err := parseProjectRetention(*req.Body)
	if err != nil {
		return nil, err
	}
	got, err := a.Retention.SetProject(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), want)
	if err != nil {
		return nil, err
	}
	return apigen.SetProjectRetention200JSONResponse(wireProjectRetention(got)), nil
}

func (a *API) GetRetentionHealth(ctx context.Context, _ apigen.GetRetentionHealthRequestObject) (apigen.GetRetentionHealthResponseObject, error) {
	health, err := a.Retention.GetHealth(ctx, service.Bearer(bearer(ctx)))
	if err != nil {
		return nil, err
	}
	var last *time.Time
	if health.Recorded {
		at := health.LastSuccess
		last = &at
	}
	return apigen.GetRetentionHealth200JSONResponse{
		LastPruneSuccess:  last,
		Stale:             health.Stale,
		StaleAfterSeconds: apigen.RetentionHealthStaleAfterSeconds(service.PruneStaleAfter / time.Second),
		PeakProjectBytes:  int(health.PeakProjectBytes),
		StorageWarn:       health.StorageWarn,
	}, nil
}

func (a *API) GetMachineReveal(ctx context.Context, req apigen.GetMachineRevealRequestObject) (apigen.GetMachineRevealResponseObject, error) {
	got, err := a.Settings.GetMachineReveal(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project))
	if err != nil {
		return nil, err
	}
	return apigen.GetMachineReveal200JSONResponse{Enabled: got.Enabled}, nil
}

func (a *API) SetMachineReveal(ctx context.Context, req apigen.SetMachineRevealRequestObject) (apigen.SetMachineRevealResponseObject, error) {
	got, err := a.Settings.SetMachineReveal(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), req.Body.Enabled)
	if err != nil {
		return nil, err
	}
	return apigen.SetMachineReveal200JSONResponse{Enabled: got.Enabled}, nil
}
