package server

import (
	"context"
	"encoding/json"

	"github.com/Dunky13/wenv/api/apigen"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/schema"
	"github.com/Dunky13/wenv/internal/service"
)

// The key-catalogue transport (#49). Same discipline as the hierarchy
// handlers: every refusal is a bare domain error routed through the one
// uniform writer, so "fixed message per code" lives in a single place and no
// handler can answer 500 by falling through a switch.
//
// This file TRANSLATES and does not decide. The one exception is stated
// where it happens: an ordinary metadata update carrying a `classification`
// member is refused here, because the refusal is about the SHAPE of the
// request — the field exists in the contract only so the refusal can name the
// ceremony instead of reading as an unknown member — and answering it here
// costs no read and cannot become a way to probe the current classification.

// KeyService and KeyGroupService are the domain surfaces this transport
// exposes. Scopes are addressed as domain.Scope, the same shape authorize()
// takes, so a wrong-depth address is refused at the chokepoint.
type KeyService interface {
	Create(ctx context.Context, actor service.Actor, scope domain.Scope, spec service.KeySpec) (service.Key, error)
	Get(ctx context.Context, actor service.Actor, scope domain.Scope, id string) (service.Key, error)
	List(ctx context.Context, actor service.Actor, scope domain.Scope) ([]service.Key, int64, error)
	Rename(ctx context.Context, actor service.Actor, scope domain.Scope, id, name string) (service.Key, error)
	UpdateMetadata(ctx context.Context, actor service.Actor, scope domain.Scope, id string, m service.KeyMetadataUpdate) (service.Key, error)
	UpdateDeclaration(ctx context.Context, actor service.Actor, scope domain.Scope, id string, u service.KeyDeclarationUpdate) (service.Key, error)
	Reclassify(ctx context.Context, actor service.Actor, scope domain.Scope, id, classification string) (service.Key, error)
	SetGroup(ctx context.Context, actor service.Actor, scope domain.Scope, id, groupID string) (service.Key, error)
	Delete(ctx context.Context, actor service.Actor, scope domain.Scope, id string) error
}

type KeyGroupService interface {
	Create(ctx context.Context, actor service.Actor, scope domain.Scope, name string) (service.KeyGroupView, error)
	Get(ctx context.Context, actor service.Actor, scope domain.Scope, id string) (service.KeyGroupView, error)
	List(ctx context.Context, actor service.Actor, scope domain.Scope) ([]service.KeyGroupView, error)
	Rename(ctx context.Context, actor service.Actor, scope domain.Scope, id, name string) (service.KeyGroupView, error)
	Delete(ctx context.Context, actor service.Actor, scope domain.Scope, id string) error
}

func (a *API) ListKeys(ctx context.Context, req apigen.ListKeysRequestObject) (apigen.ListKeysResponseObject, error) {
	keys, revision, err := a.Keys.List(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project))
	if err != nil {
		return nil, err
	}
	items := make([]apigen.Key, 0, len(keys))
	for _, key := range keys {
		items = append(items, wireKey(key))
	}
	return apigen.ListKeys200JSONResponse{Items: items, Count: len(items), SchemaRevision: revision}, nil
}

func (a *API) CreateKey(ctx context.Context, req apigen.CreateKeyRequestObject) (apigen.CreateKeyResponseObject, error) {
	declaration, err := domainDeclaration(req.Body.Declaration)
	if err != nil {
		return nil, err
	}
	spec := service.KeySpec{
		Name:            req.Body.Name,
		Classification:  string(req.Body.Classification),
		FolderPath:      deref(req.Body.FolderPath),
		Description:     deref(req.Body.Description),
		Deprecated:      derefBool(req.Body.Deprecated),
		DeprecationNote: deref(req.Body.DeprecationNote),
		Declaration:     declaration,
		Presence:        domainPresence(req.Body.Presence),
		GroupID:         deref(req.Body.GroupId),
	}
	key, err := a.Keys.Create(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), spec)
	if err != nil {
		return nil, err
	}
	return apigen.CreateKey201JSONResponse(wireKey(key)), nil
}

func (a *API) GetKey(ctx context.Context, req apigen.GetKeyRequestObject) (apigen.GetKeyResponseObject, error) {
	key, err := a.Keys.Get(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), req.Key)
	if err != nil {
		return nil, err
	}
	return apigen.GetKey200JSONResponse(wireKey(key)), nil
}

// UpdateKeyMetadata writes the four non-semantic fields — and refuses a body
// that carries `classification` at all, equal to the current value or not.
// Refusing the FIELD rather than the CHANGE is deliberate: it needs no read,
// and it keeps a caller from discovering the current classification by
// observing which values are accepted.
func (a *API) UpdateKeyMetadata(ctx context.Context, req apigen.UpdateKeyMetadataRequestObject) (apigen.UpdateKeyMetadataResponseObject, error) {
	if req.Body.Classification != nil {
		return nil, service.ErrClassificationInUpdate
	}
	// The pointers pass through UNTOUCHED: this is a PATCH, absent means
	// "leave it alone", and collapsing an absent member onto a zero value here
	// is how one request that set only `--description` would clear the folder
	// path, the deprecation flag and the note.
	key, err := a.Keys.UpdateMetadata(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.Key, service.KeyMetadataUpdate{
			FolderPath:      req.Body.FolderPath,
			Description:     req.Body.Description,
			Deprecated:      req.Body.Deprecated,
			DeprecationNote: req.Body.DeprecationNote,
		})
	if err != nil {
		return nil, err
	}
	return apigen.UpdateKeyMetadata200JSONResponse(wireKey(key)), nil
}

func (a *API) RenameKey(ctx context.Context, req apigen.RenameKeyRequestObject) (apigen.RenameKeyResponseObject, error) {
	key, err := a.Keys.Rename(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.Key, req.Body.Name)
	if err != nil {
		return nil, err
	}
	return apigen.RenameKey200JSONResponse(wireKey(key)), nil
}

func (a *API) UpdateKeyDeclaration(ctx context.Context, req apigen.UpdateKeyDeclarationRequestObject) (apigen.UpdateKeyDeclarationResponseObject, error) {
	declaration, err := domainDeclaration(req.Body.Declaration)
	if err != nil {
		return nil, err
	}
	presence := domainPresence(&req.Body.Presence)
	key, err := a.Keys.UpdateDeclaration(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.Key,
		service.KeyDeclarationUpdate{Declaration: declaration, Presence: presence})
	if err != nil {
		return nil, err
	}
	return apigen.UpdateKeyDeclaration200JSONResponse(wireKey(key)), nil
}

func (a *API) ReclassifyKey(ctx context.Context, req apigen.ReclassifyKeyRequestObject) (apigen.ReclassifyKeyResponseObject, error) {
	key, err := a.Keys.Reclassify(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.Key, string(req.Body.Classification))
	if err != nil {
		return nil, err
	}
	return apigen.ReclassifyKey200JSONResponse(wireKey(key)), nil
}

func (a *API) SetKeyGroup(ctx context.Context, req apigen.SetKeyGroupRequestObject) (apigen.SetKeyGroupResponseObject, error) {
	key, err := a.Keys.SetGroup(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.Key, req.Body.GroupId)
	if err != nil {
		return nil, err
	}
	return apigen.SetKeyGroup200JSONResponse(wireKey(key)), nil
}

func (a *API) DeleteKey(ctx context.Context, req apigen.DeleteKeyRequestObject) (apigen.DeleteKeyResponseObject, error) {
	if err := a.Keys.Delete(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), req.Key); err != nil {
		return nil, err
	}
	return apigen.DeleteKey204Response{}, nil
}

func (a *API) ListKeyGroups(ctx context.Context, req apigen.ListKeyGroupsRequestObject) (apigen.ListKeyGroupsResponseObject, error) {
	groups, err := a.KeyGroups.List(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project))
	if err != nil {
		return nil, err
	}
	items := make([]apigen.KeyGroup, 0, len(groups))
	for _, group := range groups {
		items = append(items, wireKeyGroup(group))
	}
	return apigen.ListKeyGroups200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) CreateKeyGroup(ctx context.Context, req apigen.CreateKeyGroupRequestObject) (apigen.CreateKeyGroupResponseObject, error) {
	group, err := a.KeyGroups.Create(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), req.Body.Name)
	if err != nil {
		return nil, err
	}
	return apigen.CreateKeyGroup201JSONResponse(wireKeyGroup(group)), nil
}

func (a *API) GetKeyGroup(ctx context.Context, req apigen.GetKeyGroupRequestObject) (apigen.GetKeyGroupResponseObject, error) {
	group, err := a.KeyGroups.Get(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), req.Group)
	if err != nil {
		return nil, err
	}
	return apigen.GetKeyGroup200JSONResponse(wireKeyGroup(group)), nil
}

func (a *API) RenameKeyGroup(ctx context.Context, req apigen.RenameKeyGroupRequestObject) (apigen.RenameKeyGroupResponseObject, error) {
	group, err := a.KeyGroups.Rename(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.Group, req.Body.Name)
	if err != nil {
		return nil, err
	}
	return apigen.RenameKeyGroup200JSONResponse(wireKeyGroup(group)), nil
}

func (a *API) DeleteKeyGroup(ctx context.Context, req apigen.DeleteKeyGroupRequestObject) (apigen.DeleteKeyGroupResponseObject, error) {
	if err := a.KeyGroups.Delete(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), req.Group); err != nil {
		return nil, err
	}
	return apigen.DeleteKeyGroup204Response{}, nil
}

// ---------------------------------------------------------------------------
// Wire ↔ domain
// ---------------------------------------------------------------------------

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefBool(b *bool) bool { return b != nil && *b }

// domainDeclaration converts the contract's declaration into the schema
// package's. The JSON Schema rides as a STRING on the wire and becomes raw
// bytes here without a decode/re-encode round trip: the profile rejects
// duplicate object keys and bounds the document's BYTES, and a round trip
// through map[string]any would silently resolve duplicates last-wins and
// renormalize numbers — turning two checks the ADR fixes into no-ops.
func domainDeclaration(d apigen.KeyDeclaration) (schema.Declaration, error) {
	out := schema.Declaration{}
	if d.Rule != nil {
		rule, err := domainRule(*d.Rule)
		if err != nil {
			return out, err
		}
		out.Rule = &rule
	}
	if d.AnyOf != nil {
		for _, alt := range *d.AnyOf {
			rule, err := domainRule(alt)
			if err != nil {
				return out, err
			}
			out.AnyOf = append(out.AnyOf, rule)
		}
	}
	return out, nil
}

func domainRule(r apigen.KeyRule) (schema.Rule, error) {
	out := schema.Rule{
		Type:       schema.Type(r.Type),
		MinLength:  r.MinLength,
		MaxLength:  r.MaxLength,
		Pattern:    deref(r.Pattern),
		AllowEmpty: derefBool(r.AllowEmpty),
		Min:        r.Min,
		Max:        r.Max,
	}
	if r.Members != nil {
		out.Members = *r.Members
	}
	if r.Schemes != nil {
		out.Schemes = *r.Schemes
	}
	if r.JsonSchema != nil {
		out.JSONSchema = json.RawMessage(*r.JsonSchema)
	}
	return out, nil
}

func domainPresence(p *apigen.KeyPresenceRules) schema.PresenceRules {
	if p == nil {
		// Absent presence is `none` on both sides — the declared default, not
		// a silent one: a key that is neither required nor forbidden anywhere
		// is the ordinary case, and spelling it out here keeps the zero value
		// from meaning "unset mode", which the store's CHECK would refuse.
		return schema.DefaultPresenceRules()
	}
	return schema.PresenceRules{
		Required:  domainPresenceRule(p.RequiredIn),
		Forbidden: domainPresenceRule(p.ForbiddenIn),
	}
}

func domainPresenceRule(p apigen.KeyPresence) schema.Presence {
	out := schema.Presence{Mode: schema.PresenceMode(p.Mode)}
	if p.EnvironmentIds != nil {
		out.Environments = *p.EnvironmentIds
	}
	return out
}

func wireKey(key service.Key) apigen.Key {
	return apigen.Key{
		Id:              key.ID,
		OrgId:           key.OrgID,
		ProjectId:       key.ProjectID,
		Name:            key.Name,
		FolderPath:      key.FolderPath,
		Classification:  apigen.KeyClassification(key.Classification),
		Description:     key.Description,
		Deprecated:      key.Deprecated,
		DeprecationNote: key.DeprecationNote,
		Declaration:     wireDeclaration(key.Declaration),
		Presence:        wirePresence(key.Presence),
		GroupId:         key.GroupID,
		CreatedAt:       key.CreatedAt,
	}
}

func wireDeclaration(d schema.Declaration) apigen.KeyDeclaration {
	out := apigen.KeyDeclaration{}
	if d.Rule != nil {
		rule := wireRule(*d.Rule)
		out.Rule = &rule
	}
	if len(d.AnyOf) > 0 {
		alts := make([]apigen.KeyRule, 0, len(d.AnyOf))
		for _, alt := range d.AnyOf {
			alts = append(alts, wireRule(alt))
		}
		out.AnyOf = &alts
	}
	return out
}

func wireRule(r schema.Rule) apigen.KeyRule {
	out := apigen.KeyRule{
		Type:      apigen.KeyRuleType(r.Type),
		MinLength: r.MinLength,
		MaxLength: r.MaxLength,
		Min:       r.Min,
		Max:       r.Max,
	}
	if r.Pattern != "" {
		out.Pattern = &r.Pattern
	}
	if r.AllowEmpty {
		allow := true
		out.AllowEmpty = &allow
	}
	if len(r.Members) > 0 {
		members := r.Members
		out.Members = &members
	}
	if len(r.Schemes) > 0 {
		schemes := r.Schemes
		out.Schemes = &schemes
	}
	if len(r.JSONSchema) > 0 {
		document := string(r.JSONSchema)
		out.JsonSchema = &document
	}
	return out
}

func wirePresence(p schema.PresenceRules) apigen.KeyPresenceRules {
	return apigen.KeyPresenceRules{
		RequiredIn:  wirePresenceRule(p.Required),
		ForbiddenIn: wirePresenceRule(p.Forbidden),
	}
}

func wirePresenceRule(p schema.Presence) apigen.KeyPresence {
	out := apigen.KeyPresence{Mode: apigen.KeyPresenceMode(p.Mode)}
	if len(p.Environments) > 0 {
		ids := p.Environments
		out.EnvironmentIds = &ids
	}
	return out
}

func wireKeyGroup(group service.KeyGroupView) apigen.KeyGroup {
	members := group.Members
	if members == nil {
		members = []string{}
	}
	return apigen.KeyGroup{
		Id:        group.ID,
		OrgId:     group.OrgID,
		ProjectId: group.ProjectID,
		Name:      group.Name,
		Members:   members,
		Inert:     group.Inert,
		CreatedAt: group.CreatedAt,
	}
}
