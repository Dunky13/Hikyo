package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Dunky13/hikyo/api/apigen"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/scimproto"
	"github.com/Dunky13/hikyo/internal/service"
)

// The SCIM wire transport (#73 §8). It owns exactly three things — decoding
// the protocol, rendering the protocol, and mapping refusals onto the RFC 7644
// error shapes — and no policy whatsoever. Every decision about what is
// allowed lives in `internal/scimproto` (the closed matrix, the closed filter
// grammar) or in the service (authorization, the transitions).
//
// Refusals here are NEVER the Hikyo error envelope: an identity provider
// speaks SCIM, and answering it in a second error dialect is how a refusal
// becomes an unhandled exception in somebody else's connector.

// SCIMWireService is the provisioning surface this transport needs.
type SCIMWireService interface {
	CreateUser(ctx context.Context, actor service.Actor, org domain.OrgID, binding string, in service.SCIMUserInput) (service.SCIMUserResource, error)
	GetUser(ctx context.Context, actor service.Actor, org domain.OrgID, binding, id string) (service.SCIMUserResource, error)
	ListUsers(ctx context.Context, actor service.Actor, org domain.OrgID, binding string, filter scimproto.Filter, page scimproto.Page) ([]service.SCIMUserResource, int, error)
	ReplaceUser(ctx context.Context, actor service.Actor, org domain.OrgID, binding, id string, in service.SCIMUserInput) (service.SCIMUserResource, error)
	PatchUser(ctx context.Context, actor service.Actor, org domain.OrgID, binding, id string, in service.SCIMUserInput) (service.SCIMUserResource, error)
	DeleteUser(ctx context.Context, actor service.Actor, org domain.OrgID, binding, id string) error

	CreateGroup(ctx context.Context, actor service.Actor, org domain.OrgID, binding string, in service.SCIMGroupInput) (service.SCIMGroupResource, error)
	GetGroup(ctx context.Context, actor service.Actor, org domain.OrgID, binding, id string) (service.SCIMGroupResource, error)
	ListGroups(ctx context.Context, actor service.Actor, org domain.OrgID, binding string, filter scimproto.Filter, page scimproto.Page) ([]service.SCIMGroupResource, int, error)
	ReplaceGroup(ctx context.Context, actor service.Actor, org domain.OrgID, binding, id string, in service.SCIMGroupInput) (service.SCIMGroupResource, error)
	PatchGroup(ctx context.Context, actor service.Actor, org domain.OrgID, binding, id string, in service.SCIMGroupInput) (service.SCIMGroupResource, error)
	DeleteGroup(ctx context.Context, actor service.Actor, org domain.OrgID, binding, id string) error

	Discovery(ctx context.Context, actor service.Actor, org domain.OrgID, binding string) error
	Authenticate(ctx context.Context, actor service.Actor, org domain.OrgID, binding string) error
	Unsupported(ctx context.Context, actor service.Actor, org domain.OrgID, binding, what string) error

	// PageBound is the server's `count` ceiling — an ops-spec bound the
	// transport must clamp against before it reaches the service.
	PageBound() int
}

// scimActor builds the wire's authenticating actor: the presented credential
// AND the binding the request addressed. Both travel together because the
// credential must match the binding IN THE PATH — there is no ambient routing
// by credential, and a mismatch is an authentication failure.
func scimActor(ctx context.Context, binding string) service.Actor {
	return service.SCIMCredentialActor(bearer(ctx), binding)
}

// afterAuth re-ranks a PARSE failure against authentication. A malformed body
// from an unknown, revoked or wrong-binding credential must answer 401: a 400
// tells an unauthenticated caller that the binding it guessed exists, and §8
// makes the credential-versus-binding mismatch an authentication failure
// "never a SCIM 400".
func (a *API) afterAuth(ctx context.Context, org, binding string, parseErr *scimproto.Error) error {
	if err := a.SCIMWire.Authenticate(ctx, scimActor(ctx, binding), domain.OrgID(org), binding); err != nil {
		return err
	}
	return parseErr
}

// scimError maps a refusal onto its RFC 7644 shape. The closed mapping (§8)
// lives here in ONE switch, so a new refusal cannot quietly acquire a
// different status than the ADR assigns it.
func scimError(err error) *scimproto.Error {
	if e, ok := scimproto.AsError(err); ok {
		return e
	}
	switch {
	case errors.Is(err, domain.ErrUnauthenticated):
		return scimproto.Unauthorized()
	case errors.Is(err, service.ErrSCIMUniqueness):
		return scimproto.Conflict("This value is already taken in this binding.")
	case errors.Is(err, service.ErrSCIMSubjectWriteOnce):
		return scimproto.ErrMutability(
			"The subject is write-once per resource. Deprovision and recreate instead.")
	case errors.Is(err, service.ErrSCIMUnknownMember):
		return scimproto.ErrInvalidValue(
			"A member reference names no user provisioned by this binding.")
	case errors.Is(err, service.ErrSCIMNestedGroup):
		return scimproto.ErrInvalidValue("Nested group members are not supported.")
	case errors.Is(err, service.ErrSCIMNoTarget):
		// §8's closed mapping: "PATCH path resolving to nothing -> `noTarget`",
		// which RFC 7644 §3.5.2 makes a 400. The sentinel wraps ErrNotFound (it
		// IS a missing member), so without this case it fell through to a bare
		// 404 and the identity provider was told the GROUP was gone rather than
		// that its filter matched nothing — a different remediation entirely.
		// This case must stay ABOVE the ErrNotFound arm.
		return scimproto.ErrNoTarget("The members filter names no member of this group.")
	case errors.Is(err, service.ErrSCIMUserNameRequired):
		return scimproto.ErrInvalidValue("userName is required.")
	case errors.Is(err, service.ErrSCIMPasswordRefused):
		return scimproto.ErrInvalidValue(
			"The password attribute is not supported: provisioning never establishes credentials.")
	case errors.Is(err, service.ErrSCIMSubjectMissing):
		return scimproto.ErrInvalidValue(
			"This resource carries no value at the binding's subject source.")
	case errors.Is(err, service.ErrSCIMProviderUnavailable):
		// The provider is disabled or removed, so the whole wire surface fails
		// closed (§1). It answers 404 — the same shape as a binding that is not
		// there — and that collapse is DELIBERATE, not an anti-probe argument:
		// this error is only reachable after the credential authenticated FOR
		// THIS BINDING, so the caller already knows the binding exists and
		// there is no oracle left to close.
		//
		// What is traded away is that the wire refusal is not NAMED, which the
		// ADR asks for. It is named where a human can act on it — the service
		// sentinel, and the `provider_unavailable` attention state with its
		// remediation on the administration surface — and the identity
		// provider's remediation is identical either way: retry later, while
		// an administrator repairs the provider. A distinct status would mean
		// declaring a new response on every wire operation to say something no
		// connector would do anything different about. Recorded as a deviation
		// in the handoff.
		return scimproto.NotFound()
	case errors.Is(err, domain.ErrNotFound):
		return scimproto.NotFound()
	case errors.Is(err, domain.ErrConflict):
		return scimproto.Conflict("The current state refuses this request.")
	case errors.Is(err, domain.ErrInvalid):
		return scimproto.ErrInvalidValue("The request is not valid for this resource.")
	default:
		return &scimproto.Error{Status: http.StatusInternalServerError, Detail: "Internal error."}
	}
}

// scimBody is one rendered SCIM response body.
type scimBody = apigen.ScimResource

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

// scimRequestBody picks whichever content type the identity provider used.
// Real connectors send both `application/scim+json` and plain JSON, and the
// RFC does not make either wrong.
func scimRequestBody(scim, plain *apigen.ScimResource) (map[string]any, *scimproto.Error) {
	switch {
	case scim != nil:
		return map[string]any(*scim), nil
	case plain != nil:
		return map[string]any(*plain), nil
	default:
		return nil, scimproto.ErrInvalidValue("The request body is required.")
	}
}

// rawJSON re-serialises the decoded body so scimproto can parse it under the
// SAME decoder the trust boundary uses. The round trip costs one marshal and
// buys one parser: the `password` refusal, the bounds and the UTF-8 check all
// live in scimproto and are not duplicated here.
func rawJSON(body map[string]any) ([]byte, *scimproto.Error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, scimproto.ErrInvalidValue("The request body is not serialisable JSON.")
	}
	return raw, nil
}

// scimUserInput decodes a User resource into the service's desired-state
// input. `groups` is dropped on the floor: RFC 7643 makes it read-only, and
// membership is authored exclusively through Group operations. The identity
// material is NOT read here — the whole resource travels to the service, which
// reads it at the attribute path the binding declares.
func scimUserInput(body map[string]any) (service.SCIMUserInput, *scimproto.Error) {
	raw, e := rawJSON(body)
	if e != nil {
		return service.SCIMUserInput{}, e
	}
	u, e := scimproto.DecodeUser(raw)
	if e != nil {
		return service.SCIMUserInput{}, e
	}
	in := service.SCIMUserInput{UserName: u.UserName, ExternalID: u.ExternalID}
	if v, ok := body["active"]; ok {
		active, e := scimproto.NormalizeActive(v)
		if e != nil {
			return service.SCIMUserInput{}, e
		}
		in.Active = &active
	}
	in.Resource = body
	in.Attributes = scimDisplayAttributes(body)
	return in, nil
}

// scimDisplayAttributes keeps everything this server does not interpret, as
// delivery/display metadata: never matched, never a linking key, never
// verified authority — stored for the org's directory view and round-tripped.
func scimDisplayAttributes(body map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range body {
		switch k {
		case "id", "schemas", "meta", "userName", "externalId", "active", "groups",
			"members", "displayName", "password":
			continue
		}
		out[k] = v
	}
	return out
}

// scimGroupInput decodes a Group resource, applying §6's two named member
// refusals before anything reaches the service.
func scimGroupInput(body map[string]any) (service.SCIMGroupInput, *scimproto.Error) {
	raw, e := rawJSON(body)
	if e != nil {
		return service.SCIMGroupInput{}, e
	}
	g, e := scimproto.DecodeGroup(raw)
	if e != nil {
		return service.SCIMGroupInput{}, e
	}
	if e := scimproto.CheckMembers(g.Members); e != nil {
		return service.SCIMGroupInput{}, e
	}
	in := service.SCIMGroupInput{DisplayName: g.DisplayName, ExternalID: g.ExternalID}
	if _, present := body["members"]; present {
		in.MembersPresent = true
		for _, m := range g.Members {
			in.Members = append(in.Members, m.Value)
		}
	}
	return in, nil
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

func renderSCIMUser(u service.SCIMUserResource) scimBody {
	// The declared schema set is the CORE one plus every extension the stored
	// attributes actually carry. Hard-coding the core schema alone while
	// round-tripping enterprise/custom attributes emits a resource no conformant
	// client can interpret — and breaks extension-path subject sources, whose
	// whole value lives under such a URI.
	out := scimBody{
		"schemas":  scimproto.SchemasFor(u.Attributes),
		"id":       u.ID,
		"userName": u.UserName,
		"active":   u.Active,
		"meta": map[string]any{
			"resourceType": "User",
			"created":      u.CreatedAt.UTC().Format(scimTimeFormat),
			"lastModified": u.UpdatedAt.UTC().Format(scimTimeFormat),
		},
	}
	if u.ExternalID != "" {
		out["externalId"] = u.ExternalID
	}
	// `groups` is response-only, and always present (possibly empty) so a
	// connector reading it never has to distinguish absent from empty.
	groups := make([]any, 0, len(u.Groups))
	for _, g := range u.Groups {
		groups = append(groups, map[string]any{"value": g, "type": "direct"})
	}
	out["groups"] = groups
	for k, v := range u.Attributes {
		if _, taken := out[k]; !taken {
			out[k] = v
		}
	}
	return out
}

func renderSCIMGroup(g service.SCIMGroupResource) scimBody {
	members := make([]any, 0, len(g.Members))
	for _, m := range g.Members {
		members = append(members, map[string]any{"value": m, "type": "User"})
	}
	out := scimBody{
		"schemas":     []string{scimproto.SchemaGroup},
		"id":          g.ID,
		"displayName": g.DisplayName,
		"members":     members,
		"meta": map[string]any{
			"resourceType": "Group",
			"created":      g.CreatedAt.UTC().Format(scimTimeFormat),
			"lastModified": g.UpdatedAt.UTC().Format(scimTimeFormat),
		},
	}
	if g.ExternalID != "" {
		out["externalId"] = g.ExternalID
	}
	return out
}

// scimTimeFormat is RFC 3339 with second precision, which is what RFC 7643's
// `meta` timestamps are and what every connector parses.
const scimTimeFormat = "2006-01-02T15:04:05Z"

// scimListParams turns the query into a validated filter and page. `sortBy`
// is refused HERE with 501: sorting is advertised absent, and answering an
// unsorted list to a request that asked for one is the half-implementation the
// ADR forbids by name.
// startIndex and count arrive as STRINGS. The contract deliberately declares
// no numeric type or bound on them: contract validation runs before the
// provisioning credential is authenticated, so a `minimum: 1` made
// `startIndex=0` an unauthenticated Hikyo 400 rather than the uniform 401 — and
// contradicted RFC 7644 §3.4.2.4, which reads a value below 1 AS 1. Parsing,
// clamping and every named refusal live here instead, after `afterAuth` has
// ranked authentication first.
func (a *API) scimListParams(filter *string, startIndex, count *string, sortBy, sortOrder *string, res scimproto.Resource) (scimproto.Filter, scimproto.Page, *scimproto.Error) {
	// EITHER sorting parameter. Refusing only `sortBy` let `sortOrder` be
	// silently ignored, which is the half-implementation the ADR forbids by
	// name rather than the authenticated 501 it requires.
	for _, p := range []*string{sortBy, sortOrder} {
		if p != nil && *p != "" {
			return scimproto.Filter{}, scimproto.Page{}, scimproto.NotImplemented("Sorting")
		}
	}
	raw := ""
	if filter != nil {
		raw = *filter
	}
	f, e := scimproto.ParseFilter(raw, res)
	if e != nil {
		return scimproto.Filter{}, scimproto.Page{}, e
	}
	start, cnt := "", ""
	if startIndex != nil {
		start = *startIndex
	}
	if count != nil {
		cnt = *count
	}
	p, e := scimproto.ParsePage(start, cnt, a.SCIMWire.PageBound())
	if e != nil {
		return scimproto.Filter{}, scimproto.Page{}, e
	}
	return f, p, nil
}
