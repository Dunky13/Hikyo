package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Dunky13/hikyo/api/apigen"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/scimproto"
	"github.com/Dunky13/hikyo/internal/service"
)

// The SCIM wire handlers. Each does the same four things — decode, call the
// service, render, map the refusal — and the repetition is the generated
// interface's, not a choice: every operation has its own response type.
//
// Refusals all route through scimRefusal, ONE exhaustive status-to-response
// mapping. The earlier hand-rolled per-operation switches disagreed with each
// other: some default branches wrapped a mapped 400 or 500 body inside an HTTP
// 404, and some 500s emitted the Hikyo envelope among SCIM bodies. An identity
// provider that met two error dialects on one mount would have to parse both.

// scimRefusal renders a refusal as the operation's own response type for the
// mapped status. A status the operation does not declare cannot be rendered as
// itself, so it falls back to the 500 every operation declares — with the body
// corrected to match, because a body whose `status` member disagreed with the
// HTTP status is exactly the disagreement this function exists to remove.
func scimRefusal[T any](err error, pick map[int]func(scimBody) T) T {
	e := scimError(err)
	body := e.Body()
	if f, ok := pick[e.Status]; ok {
		return f(body)
	}
	body["status"] = "500"
	body["detail"] = "Internal error."
	return pick[http.StatusInternalServerError](body)
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

func (a *API) ScimServiceProviderConfig(ctx context.Context, req apigen.ScimServiceProviderConfigRequestObject) (apigen.ScimServiceProviderConfigResponseObject, error) {
	if _, err := a.SCIMWire.Discovery(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding); err != nil {
		return scimServiceProviderConfigRefusal(err), nil
	}
	return apigen.ScimServiceProviderConfig200ApplicationScimPlusJSONResponse(
		scimproto.ServiceProviderConfig(a.SCIMWire.PageBound())), nil
}

// The two documents that describe SCHEMAS are per-binding: they render the
// extensions THIS binding declared, which is the same closed set ingest
// enforces and a rendered resource may name.
func (a *API) ScimResourceTypes(ctx context.Context, req apigen.ScimResourceTypesRequestObject) (apigen.ScimResourceTypesResponseObject, error) {
	declared, err := a.SCIMWire.Discovery(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding)
	if err != nil {
		return scimResourceTypesRefusal(err), nil
	}
	return apigen.ScimResourceTypes200ApplicationScimPlusJSONResponse(scimproto.ResourceTypes(declared)), nil
}

func (a *API) ScimSchemas(ctx context.Context, req apigen.ScimSchemasRequestObject) (apigen.ScimSchemasResponseObject, error) {
	declared, err := a.SCIMWire.Discovery(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding)
	if err != nil {
		return scimSchemasRefusal(err), nil
	}
	return apigen.ScimSchemas200ApplicationScimPlusJSONResponse(scimproto.Schemas(declared)), nil
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

func (a *API) ScimListUsers(ctx context.Context, req apigen.ScimListUsersRequestObject) (apigen.ScimListUsersResponseObject, error) {
	filter, page, e := a.scimListParams(
		strPtr(req.Params.Filter), strPtr(req.Params.StartIndex), strPtr(req.Params.Count),
		strPtr(req.Params.SortBy), strPtr(req.Params.SortOrder), scimproto.ResourceUser)
	if e != nil {
		return scimListUsersRefusal(a.afterAuth(ctx, req.Org, req.Binding, e)), nil
	}
	users, total, err := a.SCIMWire.ListUsers(ctx, scimActor(ctx, req.Binding),
		domain.OrgID(req.Org), req.Binding, filter, page)
	if err != nil {
		return scimListUsersRefusal(err), nil
	}
	resources := make([]any, 0, len(users))
	for _, u := range users {
		resources = append(resources, map[string]any(renderSCIMUser(u)))
	}
	return apigen.ScimListUsers200ApplicationScimPlusJSONResponse(
		scimproto.ListResponse(total, page, resources)), nil
}

func (a *API) ScimCreateUser(ctx context.Context, req apigen.ScimCreateUserRequestObject) (apigen.ScimCreateUserResponseObject, error) {
	body, e := scimRequestBody(req.ApplicationScimPlusJSONBody, req.JSONBody)
	if e != nil {
		return scimCreateUserRefusal(a.afterAuth(ctx, req.Org, req.Binding, e)), nil
	}
	in, e := scimUserInput(body)
	if e != nil {
		return scimCreateUserRefusal(a.afterAuth(ctx, req.Org, req.Binding, e)), nil
	}
	u, err := a.SCIMWire.CreateUser(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding, in)
	if err != nil {
		return scimCreateUserRefusal(err), nil
	}
	return apigen.ScimCreateUser201ApplicationScimPlusJSONResponse(renderSCIMUser(u)), nil
}

func (a *API) ScimGetUser(ctx context.Context, req apigen.ScimGetUserRequestObject) (apigen.ScimGetUserResponseObject, error) {
	u, err := a.SCIMWire.GetUser(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding, req.Id)
	if err != nil {
		return scimGetUserRefusal(err), nil
	}
	return apigen.ScimGetUser200ApplicationScimPlusJSONResponse(renderSCIMUser(u)), nil
}

func (a *API) ScimReplaceUser(ctx context.Context, req apigen.ScimReplaceUserRequestObject) (apigen.ScimReplaceUserResponseObject, error) {
	body, e := scimRequestBody(req.ApplicationScimPlusJSONBody, req.JSONBody)
	if e != nil {
		return scimReplaceUserRefusal(a.afterAuth(ctx, req.Org, req.Binding, e)), nil
	}
	in, e := scimUserInput(body)
	if e != nil {
		return scimReplaceUserRefusal(a.afterAuth(ctx, req.Org, req.Binding, e)), nil
	}
	// RFC replacement: an omitted `active` defaults TRUE, which reactivates.
	if in.Active == nil {
		on := true
		in.Active = &on
	}
	u, err := a.SCIMWire.ReplaceUser(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding, req.Id, in)
	if err != nil {
		return scimReplaceUserRefusal(err), nil
	}
	return apigen.ScimReplaceUser200ApplicationScimPlusJSONResponse(renderSCIMUser(u)), nil
}

func (a *API) ScimPatchUser(ctx context.Context, req apigen.ScimPatchUserRequestObject) (apigen.ScimPatchUserResponseObject, error) {
	body, e := scimRequestBody(req.ApplicationScimPlusJSONBody, req.JSONBody)
	if e != nil {
		return scimPatchUserRefusal(a.afterAuth(ctx, req.Org, req.Binding, e)), nil
	}
	in, e := scimPatchUserInput(body)
	if e != nil {
		return scimPatchUserRefusal(a.afterAuth(ctx, req.Org, req.Binding, e)), nil
	}
	u, err := a.SCIMWire.PatchUser(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding, req.Id, in)
	if err != nil {
		return scimPatchUserRefusal(err), nil
	}
	return apigen.ScimPatchUser200ApplicationScimPlusJSONResponse(renderSCIMUser(u)), nil
}

func (a *API) ScimDeleteUser(ctx context.Context, req apigen.ScimDeleteUserRequestObject) (apigen.ScimDeleteUserResponseObject, error) {
	if err := a.SCIMWire.DeleteUser(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding, req.Id); err != nil {
		return scimDeleteUserRefusal(err), nil
	}
	return apigen.ScimDeleteUser204Response{}, nil
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

func (a *API) ScimListGroups(ctx context.Context, req apigen.ScimListGroupsRequestObject) (apigen.ScimListGroupsResponseObject, error) {
	filter, page, e := a.scimListParams(
		strPtr(req.Params.Filter), strPtr(req.Params.StartIndex), strPtr(req.Params.Count),
		strPtr(req.Params.SortBy), strPtr(req.Params.SortOrder), scimproto.ResourceGroup)
	if e != nil {
		return scimListGroupsRefusal(a.afterAuth(ctx, req.Org, req.Binding, e)), nil
	}
	groups, total, err := a.SCIMWire.ListGroups(ctx, scimActor(ctx, req.Binding),
		domain.OrgID(req.Org), req.Binding, filter, page)
	if err != nil {
		return scimListGroupsRefusal(err), nil
	}
	resources := make([]any, 0, len(groups))
	for _, g := range groups {
		resources = append(resources, map[string]any(renderSCIMGroup(g)))
	}
	return apigen.ScimListGroups200ApplicationScimPlusJSONResponse(
		scimproto.ListResponse(total, page, resources)), nil
}

func (a *API) ScimCreateGroup(ctx context.Context, req apigen.ScimCreateGroupRequestObject) (apigen.ScimCreateGroupResponseObject, error) {
	body, e := scimRequestBody(req.ApplicationScimPlusJSONBody, req.JSONBody)
	if e != nil {
		return scimCreateGroupRefusal(a.afterAuth(ctx, req.Org, req.Binding, e)), nil
	}
	in, e := scimGroupInput(body)
	if e != nil {
		return scimCreateGroupRefusal(a.afterAuth(ctx, req.Org, req.Binding, e)), nil
	}
	g, err := a.SCIMWire.CreateGroup(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding, in)
	if err != nil {
		return scimCreateGroupRefusal(err), nil
	}
	return apigen.ScimCreateGroup201ApplicationScimPlusJSONResponse(renderSCIMGroup(g)), nil
}

func (a *API) ScimGetGroup(ctx context.Context, req apigen.ScimGetGroupRequestObject) (apigen.ScimGetGroupResponseObject, error) {
	g, err := a.SCIMWire.GetGroup(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding, req.Id)
	if err != nil {
		return scimGetGroupRefusal(err), nil
	}
	return apigen.ScimGetGroup200ApplicationScimPlusJSONResponse(renderSCIMGroup(g)), nil
}

func (a *API) ScimReplaceGroup(ctx context.Context, req apigen.ScimReplaceGroupRequestObject) (apigen.ScimReplaceGroupResponseObject, error) {
	body, e := scimRequestBody(req.ApplicationScimPlusJSONBody, req.JSONBody)
	if e != nil {
		return scimReplaceGroupRefusal(a.afterAuth(ctx, req.Org, req.Binding, e)), nil
	}
	in, e := scimGroupInput(body)
	if e != nil {
		return scimReplaceGroupRefusal(a.afterAuth(ctx, req.Org, req.Binding, e)), nil
	}
	g, err := a.SCIMWire.ReplaceGroup(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding, req.Id, in)
	if err != nil {
		return scimReplaceGroupRefusal(err), nil
	}
	return apigen.ScimReplaceGroup200ApplicationScimPlusJSONResponse(renderSCIMGroup(g)), nil
}

func (a *API) ScimPatchGroup(ctx context.Context, req apigen.ScimPatchGroupRequestObject) (apigen.ScimPatchGroupResponseObject, error) {
	body, e := scimRequestBody(req.ApplicationScimPlusJSONBody, req.JSONBody)
	if e != nil {
		return scimPatchGroupRefusal(a.afterAuth(ctx, req.Org, req.Binding, e)), nil
	}
	in, e := scimPatchGroupInput(body)
	if e != nil {
		return scimPatchGroupRefusal(a.afterAuth(ctx, req.Org, req.Binding, e)), nil
	}
	g, err := a.SCIMWire.PatchGroup(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding, req.Id, in)
	if err != nil {
		return scimPatchGroupRefusal(err), nil
	}
	return apigen.ScimPatchGroup200ApplicationScimPlusJSONResponse(renderSCIMGroup(g)), nil
}

func (a *API) ScimDeleteGroup(ctx context.Context, req apigen.ScimDeleteGroupRequestObject) (apigen.ScimDeleteGroupResponseObject, error) {
	if err := a.SCIMWire.DeleteGroup(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding, req.Id); err != nil {
		return scimDeleteGroupRefusal(err), nil
	}
	return apigen.ScimDeleteGroup204Response{}, nil
}

// ---------------------------------------------------------------------------
// The four named 501 refusals
//
// They are routes rather than 404s because the ADR requires each to be refused
// with the RFC 7644 error shape, and they AUTHENTICATE like every other wire
// operation so an unauthenticated caller gets the uniform refusal rather than a
// 501 that would confirm the binding exists.
// ---------------------------------------------------------------------------

func (a *API) ScimBulk(ctx context.Context, req apigen.ScimBulkRequestObject) (apigen.ScimBulkResponseObject, error) {
	if err := a.SCIMWire.Unsupported(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding, "Bulk"); err != nil {
		return scimBulkRefusal(err), nil
	}
	return scimBulkRefusal(scimproto.NotImplemented("Bulk")), nil
}

func (a *API) ScimMe(ctx context.Context, req apigen.ScimMeRequestObject) (apigen.ScimMeResponseObject, error) {
	if err := a.SCIMWire.Unsupported(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding, "/Me"); err != nil {
		return scimMeRefusal(err), nil
	}
	return scimMeRefusal(scimproto.NotImplemented("/Me")), nil
}

func (a *API) ScimSearchUsers(ctx context.Context, req apigen.ScimSearchUsersRequestObject) (apigen.ScimSearchUsersResponseObject, error) {
	if err := a.SCIMWire.Unsupported(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding, ".search"); err != nil {
		return scimSearchUsersRefusal(err), nil
	}
	return scimSearchUsersRefusal(scimproto.NotImplemented("The .search POST query")), nil
}

func (a *API) ScimSearchGroups(ctx context.Context, req apigen.ScimSearchGroupsRequestObject) (apigen.ScimSearchGroupsResponseObject, error) {
	if err := a.SCIMWire.Unsupported(ctx, scimActor(ctx, req.Binding), domain.OrgID(req.Org), req.Binding, ".search"); err != nil {
		return scimSearchGroupsRefusal(err), nil
	}
	return scimSearchGroupsRefusal(scimproto.NotImplemented("The .search POST query")), nil
}

// ---------------------------------------------------------------------------
// PATCH decoding
// ---------------------------------------------------------------------------

// scimPatchUserInput validates a PatchOp message against the closed matrix and
// applies the accepted cells IN ORDER against one accumulating desired state.
//
// Validation runs over EVERY operation first (inside ParsePatch), so whole-
// request atomicity holds: one invalid operation fails the request with nothing
// applied. Folding by CATEGORY — collecting every `active` op and taking the
// last — lost the sequence, so `replace active=false` then `replace active=true`
// and the reverse produced the same final authorization state.
func scimPatchUserInput(body map[string]any) (service.SCIMUserInput, *scimproto.Error) {
	raw, e := rawJSON(body)
	if e != nil {
		return service.SCIMUserInput{}, e
	}
	ops, e := scimproto.ParsePatch(raw, scimproto.ResourceUser)
	if e != nil {
		return service.SCIMUserInput{}, e
	}
	merged := map[string]any{}
	var active *bool
	cleared := false
	for _, op := range ops {
		switch op.Kind {
		case scimproto.PathNone:
			values, e := decodeObjectValue(op.Value)
			if e != nil {
				return service.SCIMUserInput{}, e
			}
			for k, v := range values {
				if strings.EqualFold(k, "active") {
					on, e := scimproto.NormalizeActive(v)
					if e != nil {
						return service.SCIMUserInput{}, e
					}
					active = &on
					continue
				}
				merged[k] = v
			}
		case scimproto.PathActive:
			var v any
			if e := decodeInto(op.Value, &v); e != nil {
				return service.SCIMUserInput{}, e
			}
			on, e := scimproto.NormalizeActive(v)
			if e != nil {
				return service.SCIMUserInput{}, e
			}
			active = &on
		case scimproto.PathPlain:
			if op.Op == "remove" {
				// Explicit CLEARING, distinct from omission: the service must
				// be able to tell "the identity provider removed this" from
				// "the identity provider did not mention it".
				merged[op.Attr] = nil
				if strings.EqualFold(op.Attr, "externalId") {
					// `externalId` is a first-class column rather than display
					// metadata, so its explicit removal needs its own presence
					// bit — otherwise it arrives as `ExternalID == ""`, which is
					// exactly what omission looks like.
					cleared = true
				}
				continue
			}
			var v any
			if e := decodeInto(op.Value, &v); e != nil {
				return service.SCIMUserInput{}, e
			}
			merged[op.Attr] = v
		}
	}
	in := service.SCIMUserInput{Active: active, Patch: true, ExternalIDCleared: cleared}
	if len(merged) > 0 {
		folded, e := scimUserInput(merged)
		if e != nil {
			return service.SCIMUserInput{}, e
		}
		in.UserName, in.ExternalID = folded.UserName, folded.ExternalID
		in.Attributes, in.Resource = folded.Attributes, folded.Resource
	}
	return in, nil
}

// scimPatchGroupInput does the same for a Group, resolving the member cells
// into an ORDERED script the service folds over the stored set. The PATHLESS
// cell can carry `members` too — dropping it there silently discarded
// membership changes, and a removal that never happened leaves grants standing.
//
// Order is preserved for exactly the reason the User path preserves it: a PATCH
// is a sequence. Bucketing membership operations into "adds" and "removes" made
// `add X` then `remove members[value eq X]` and its reverse produce the same
// final membership — and therefore the same final AUTHORIZATION — which is a
// wrong answer to one of the two requests.
func scimPatchGroupInput(body map[string]any) (service.SCIMGroupInput, *scimproto.Error) {
	raw, e := rawJSON(body)
	if e != nil {
		return service.SCIMGroupInput{}, e
	}
	ops, e := scimproto.ParsePatch(raw, scimproto.ResourceGroup)
	if e != nil {
		return service.SCIMGroupInput{}, e
	}
	in := service.SCIMGroupInput{Patch: true}
	merged := map[string]any{}
	for _, op := range ops {
		switch op.Kind {
		case scimproto.PathNone:
			values, e := decodeObjectValue(op.Value)
			if e != nil {
				return service.SCIMGroupInput{}, e
			}
			for k, v := range values {
				if !strings.EqualFold(k, "members") {
					merged[k] = v
					continue
				}
				refs, e := memberRefsFrom(v)
				if e != nil {
					return service.SCIMGroupInput{}, e
				}
				// A pathless value object naming `members` states a desired SET,
				// exactly like `replace` on the `members` path.
				in.MemberOps = append(in.MemberOps,
					service.SCIMMemberOp{Kind: service.SCIMMemberReplace, Members: refs})
			}
		case scimproto.PathPlain:
			if op.Op == "remove" {
				merged[op.Attr] = nil
				if strings.EqualFold(op.Attr, "externalId") {
					in.ExternalIDCleared = true
				}
				continue
			}
			var v any
			if e := decodeInto(op.Value, &v); e != nil {
				return service.SCIMGroupInput{}, e
			}
			merged[op.Attr] = v
		case scimproto.PathMembers:
			if op.Op == "remove" {
				in.MemberOps = append(in.MemberOps, service.SCIMMemberOp{Kind: service.SCIMMemberClear})
				continue
			}
			refs, e := decodeMemberRefs(op.Value)
			if e != nil {
				return service.SCIMGroupInput{}, e
			}
			kind := service.SCIMMemberAdd
			if op.Op == "replace" {
				kind = service.SCIMMemberReplace
			}
			in.MemberOps = append(in.MemberOps, service.SCIMMemberOp{Kind: kind, Members: refs})
		case scimproto.PathMemberValue:
			in.MemberOps = append(in.MemberOps,
				service.SCIMMemberOp{Kind: service.SCIMMemberRemoveOne, Value: op.MemberValue})
		}
	}
	if len(merged) > 0 {
		folded, e := scimGroupInput(merged)
		if e != nil {
			return service.SCIMGroupInput{}, e
		}
		in.DisplayName, in.ExternalID = folded.DisplayName, folded.ExternalID
	}
	return in, nil
}

// memberRefsFrom decodes a member array that arrived inside a pathless value
// object, applying §6's two named refusals like any other member list.
func memberRefsFrom(v any) ([]string, *scimproto.Error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, scimproto.ErrInvalidValue("The members value has the wrong shape.")
	}
	return decodeMemberRefs(raw)
}

func decodeObjectValue(raw []byte) (map[string]any, *scimproto.Error) {
	var out map[string]any
	if e := decodeInto(raw, &out); e != nil {
		return nil, e
	}
	return out, nil
}

func decodeMemberRefs(raw []byte) ([]string, *scimproto.Error) {
	var refs []scimproto.Member
	if e := decodeInto(raw, &refs); e != nil {
		return nil, e
	}
	if e := scimproto.CheckMembers(refs); e != nil {
		return nil, e
	}
	out := make([]string, 0, len(refs))
	for _, m := range refs {
		out = append(out, m.Value)
	}
	return out, nil
}

// decodeInto parses a PATCH operation's `value` under the same discipline the
// rest of the boundary uses: a decode failure is `invalidValue`, never a
// silently-zero field.
func decodeInto(raw []byte, into any) *scimproto.Error {
	if len(raw) == 0 {
		return scimproto.ErrInvalidValue("The operation carries no value.")
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return scimproto.ErrInvalidValue("The operation value has the wrong shape.")
	}
	return nil
}

func strPtr[T ~string](p *T) *string {
	if p == nil {
		return nil
	}
	v := string(*p)
	return &v
}

// ---------------------------------------------------------------------------
// Refusal mapping, one exhaustive table per operation
// ---------------------------------------------------------------------------

func scimServiceProviderConfigRefusal(err error) apigen.ScimServiceProviderConfigResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimServiceProviderConfigResponseObject{
		401: func(b scimBody) apigen.ScimServiceProviderConfigResponseObject {
			return apigen.ScimServiceProviderConfig401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimServiceProviderConfigResponseObject {
			return apigen.ScimServiceProviderConfig404ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimServiceProviderConfigResponseObject {
			return apigen.ScimServiceProviderConfig500ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimResourceTypesRefusal(err error) apigen.ScimResourceTypesResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimResourceTypesResponseObject{
		401: func(b scimBody) apigen.ScimResourceTypesResponseObject {
			return apigen.ScimResourceTypes401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimResourceTypesResponseObject {
			return apigen.ScimResourceTypes404ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimResourceTypesResponseObject {
			return apigen.ScimResourceTypes500ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimSchemasRefusal(err error) apigen.ScimSchemasResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimSchemasResponseObject{
		401: func(b scimBody) apigen.ScimSchemasResponseObject {
			return apigen.ScimSchemas401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimSchemasResponseObject {
			return apigen.ScimSchemas404ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimSchemasResponseObject {
			return apigen.ScimSchemas500ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimListUsersRefusal(err error) apigen.ScimListUsersResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimListUsersResponseObject{
		400: func(b scimBody) apigen.ScimListUsersResponseObject {
			return apigen.ScimListUsers400ApplicationScimPlusJSONResponse(b)
		},
		401: func(b scimBody) apigen.ScimListUsersResponseObject {
			return apigen.ScimListUsers401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimListUsersResponseObject {
			return apigen.ScimListUsers404ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimListUsersResponseObject {
			return apigen.ScimListUsers500ApplicationScimPlusJSONResponse(b)
		},
		501: func(b scimBody) apigen.ScimListUsersResponseObject {
			return apigen.ScimListUsers501ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimCreateUserRefusal(err error) apigen.ScimCreateUserResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimCreateUserResponseObject{
		400: func(b scimBody) apigen.ScimCreateUserResponseObject {
			return apigen.ScimCreateUser400ApplicationScimPlusJSONResponse(b)
		},
		401: func(b scimBody) apigen.ScimCreateUserResponseObject {
			return apigen.ScimCreateUser401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimCreateUserResponseObject {
			return apigen.ScimCreateUser404ApplicationScimPlusJSONResponse(b)
		},
		409: func(b scimBody) apigen.ScimCreateUserResponseObject {
			return apigen.ScimCreateUser409ApplicationScimPlusJSONResponse(b)
		},
		413: func(b scimBody) apigen.ScimCreateUserResponseObject {
			return apigen.ScimCreateUser413ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimCreateUserResponseObject {
			return apigen.ScimCreateUser500ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimGetUserRefusal(err error) apigen.ScimGetUserResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimGetUserResponseObject{
		401: func(b scimBody) apigen.ScimGetUserResponseObject {
			return apigen.ScimGetUser401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimGetUserResponseObject {
			return apigen.ScimGetUser404ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimGetUserResponseObject {
			return apigen.ScimGetUser500ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimReplaceUserRefusal(err error) apigen.ScimReplaceUserResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimReplaceUserResponseObject{
		400: func(b scimBody) apigen.ScimReplaceUserResponseObject {
			return apigen.ScimReplaceUser400ApplicationScimPlusJSONResponse(b)
		},
		401: func(b scimBody) apigen.ScimReplaceUserResponseObject {
			return apigen.ScimReplaceUser401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimReplaceUserResponseObject {
			return apigen.ScimReplaceUser404ApplicationScimPlusJSONResponse(b)
		},
		409: func(b scimBody) apigen.ScimReplaceUserResponseObject {
			return apigen.ScimReplaceUser409ApplicationScimPlusJSONResponse(b)
		},
		413: func(b scimBody) apigen.ScimReplaceUserResponseObject {
			return apigen.ScimReplaceUser413ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimReplaceUserResponseObject {
			return apigen.ScimReplaceUser500ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimPatchUserRefusal(err error) apigen.ScimPatchUserResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimPatchUserResponseObject{
		400: func(b scimBody) apigen.ScimPatchUserResponseObject {
			return apigen.ScimPatchUser400ApplicationScimPlusJSONResponse(b)
		},
		401: func(b scimBody) apigen.ScimPatchUserResponseObject {
			return apigen.ScimPatchUser401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimPatchUserResponseObject {
			return apigen.ScimPatchUser404ApplicationScimPlusJSONResponse(b)
		},
		409: func(b scimBody) apigen.ScimPatchUserResponseObject {
			return apigen.ScimPatchUser409ApplicationScimPlusJSONResponse(b)
		},
		413: func(b scimBody) apigen.ScimPatchUserResponseObject {
			return apigen.ScimPatchUser413ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimPatchUserResponseObject {
			return apigen.ScimPatchUser500ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimDeleteUserRefusal(err error) apigen.ScimDeleteUserResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimDeleteUserResponseObject{
		401: func(b scimBody) apigen.ScimDeleteUserResponseObject {
			return apigen.ScimDeleteUser401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimDeleteUserResponseObject {
			return apigen.ScimDeleteUser404ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimDeleteUserResponseObject {
			return apigen.ScimDeleteUser500ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimListGroupsRefusal(err error) apigen.ScimListGroupsResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimListGroupsResponseObject{
		400: func(b scimBody) apigen.ScimListGroupsResponseObject {
			return apigen.ScimListGroups400ApplicationScimPlusJSONResponse(b)
		},
		401: func(b scimBody) apigen.ScimListGroupsResponseObject {
			return apigen.ScimListGroups401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimListGroupsResponseObject {
			return apigen.ScimListGroups404ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimListGroupsResponseObject {
			return apigen.ScimListGroups500ApplicationScimPlusJSONResponse(b)
		},
		501: func(b scimBody) apigen.ScimListGroupsResponseObject {
			return apigen.ScimListGroups501ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimCreateGroupRefusal(err error) apigen.ScimCreateGroupResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimCreateGroupResponseObject{
		400: func(b scimBody) apigen.ScimCreateGroupResponseObject {
			return apigen.ScimCreateGroup400ApplicationScimPlusJSONResponse(b)
		},
		401: func(b scimBody) apigen.ScimCreateGroupResponseObject {
			return apigen.ScimCreateGroup401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimCreateGroupResponseObject {
			return apigen.ScimCreateGroup404ApplicationScimPlusJSONResponse(b)
		},
		409: func(b scimBody) apigen.ScimCreateGroupResponseObject {
			return apigen.ScimCreateGroup409ApplicationScimPlusJSONResponse(b)
		},
		413: func(b scimBody) apigen.ScimCreateGroupResponseObject {
			return apigen.ScimCreateGroup413ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimCreateGroupResponseObject {
			return apigen.ScimCreateGroup500ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimGetGroupRefusal(err error) apigen.ScimGetGroupResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimGetGroupResponseObject{
		401: func(b scimBody) apigen.ScimGetGroupResponseObject {
			return apigen.ScimGetGroup401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimGetGroupResponseObject {
			return apigen.ScimGetGroup404ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimGetGroupResponseObject {
			return apigen.ScimGetGroup500ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimReplaceGroupRefusal(err error) apigen.ScimReplaceGroupResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimReplaceGroupResponseObject{
		400: func(b scimBody) apigen.ScimReplaceGroupResponseObject {
			return apigen.ScimReplaceGroup400ApplicationScimPlusJSONResponse(b)
		},
		401: func(b scimBody) apigen.ScimReplaceGroupResponseObject {
			return apigen.ScimReplaceGroup401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimReplaceGroupResponseObject {
			return apigen.ScimReplaceGroup404ApplicationScimPlusJSONResponse(b)
		},
		409: func(b scimBody) apigen.ScimReplaceGroupResponseObject {
			return apigen.ScimReplaceGroup409ApplicationScimPlusJSONResponse(b)
		},
		413: func(b scimBody) apigen.ScimReplaceGroupResponseObject {
			return apigen.ScimReplaceGroup413ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimReplaceGroupResponseObject {
			return apigen.ScimReplaceGroup500ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimPatchGroupRefusal(err error) apigen.ScimPatchGroupResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimPatchGroupResponseObject{
		400: func(b scimBody) apigen.ScimPatchGroupResponseObject {
			return apigen.ScimPatchGroup400ApplicationScimPlusJSONResponse(b)
		},
		401: func(b scimBody) apigen.ScimPatchGroupResponseObject {
			return apigen.ScimPatchGroup401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimPatchGroupResponseObject {
			return apigen.ScimPatchGroup404ApplicationScimPlusJSONResponse(b)
		},
		409: func(b scimBody) apigen.ScimPatchGroupResponseObject {
			return apigen.ScimPatchGroup409ApplicationScimPlusJSONResponse(b)
		},
		413: func(b scimBody) apigen.ScimPatchGroupResponseObject {
			return apigen.ScimPatchGroup413ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimPatchGroupResponseObject {
			return apigen.ScimPatchGroup500ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimDeleteGroupRefusal(err error) apigen.ScimDeleteGroupResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimDeleteGroupResponseObject{
		401: func(b scimBody) apigen.ScimDeleteGroupResponseObject {
			return apigen.ScimDeleteGroup401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimDeleteGroupResponseObject {
			return apigen.ScimDeleteGroup404ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimDeleteGroupResponseObject {
			return apigen.ScimDeleteGroup500ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimBulkRefusal(err error) apigen.ScimBulkResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimBulkResponseObject{
		401: func(b scimBody) apigen.ScimBulkResponseObject {
			return apigen.ScimBulk401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimBulkResponseObject {
			return apigen.ScimBulk404ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimBulkResponseObject {
			return apigen.ScimBulk500ApplicationScimPlusJSONResponse(b)
		},
		501: func(b scimBody) apigen.ScimBulkResponseObject {
			return apigen.ScimBulk501ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimMeRefusal(err error) apigen.ScimMeResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimMeResponseObject{
		401: func(b scimBody) apigen.ScimMeResponseObject {
			return apigen.ScimMe401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimMeResponseObject {
			return apigen.ScimMe404ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimMeResponseObject {
			return apigen.ScimMe500ApplicationScimPlusJSONResponse(b)
		},
		501: func(b scimBody) apigen.ScimMeResponseObject {
			return apigen.ScimMe501ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimSearchUsersRefusal(err error) apigen.ScimSearchUsersResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimSearchUsersResponseObject{
		401: func(b scimBody) apigen.ScimSearchUsersResponseObject {
			return apigen.ScimSearchUsers401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimSearchUsersResponseObject {
			return apigen.ScimSearchUsers404ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimSearchUsersResponseObject {
			return apigen.ScimSearchUsers500ApplicationScimPlusJSONResponse(b)
		},
		501: func(b scimBody) apigen.ScimSearchUsersResponseObject {
			return apigen.ScimSearchUsers501ApplicationScimPlusJSONResponse(b)
		},
	})
}

func scimSearchGroupsRefusal(err error) apigen.ScimSearchGroupsResponseObject {
	return scimRefusal(err, map[int]func(scimBody) apigen.ScimSearchGroupsResponseObject{
		401: func(b scimBody) apigen.ScimSearchGroupsResponseObject {
			return apigen.ScimSearchGroups401ApplicationScimPlusJSONResponse(b)
		},
		404: func(b scimBody) apigen.ScimSearchGroupsResponseObject {
			return apigen.ScimSearchGroups404ApplicationScimPlusJSONResponse(b)
		},
		500: func(b scimBody) apigen.ScimSearchGroupsResponseObject {
			return apigen.ScimSearchGroups500ApplicationScimPlusJSONResponse(b)
		},
		501: func(b scimBody) apigen.ScimSearchGroupsResponseObject {
			return apigen.ScimSearchGroups501ApplicationScimPlusJSONResponse(b)
		},
	})
}
