package service

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// Mapping-table administration (#73 §3, §4).
//
// The blast-radius moment MOVES here. The locked rule demands the org-scope
// blast warning "at grant time", when a human is present — under SCIM no human
// attends the sync, so the warning fires at mapping-row CREATION AND WIDENING,
// in the same transaction that creates the origins. The warning still precedes
// every grant's existence, because the response carrying it and the grants it
// describes commit together.

// SCIMMappingSpec addresses or declares one mapping row.
type SCIMMappingSpec struct {
	GroupID  string
	Template domain.Template
	// Scope inside the binding's org. Both empty is org scope, which is the
	// widest a binding can reach and therefore the one that must be asked for
	// explicitly rather than defaulted into.
	ProjectID string
	EnvID     string
}

// SCIMMappingView is one mapping row as the surface renders it.
type SCIMMappingView struct {
	ID        string
	BindingID string
	GroupID   string
	Template  string
	ProjectID string
	EnvID     string
	Inert     bool
	CreatedAt time.Time
	// Capabilities is what this row expands into — the ADR's "expansion at sync
	// time is expansion at grant time", made visible so a reader does not have
	// to know the template table by heart.
	Capabilities []string
}

// SCIMBlastWarning is server-authored consequence language for a mapping row
// (§3). It is authored HERE and not in a client because the rule the ADR
// locked is about what the human is told, and a client that renders its own
// wording is a second, unreviewed policy.
type SCIMBlastWarning struct {
	Code     string
	Severity string
	Message  string
}

// Closed warning codes. Adding one is a deliberate change to what the surface
// promises to say, which is why they are an enumeration and not free text at
// the call site.
const (
	SCIMWarnOrgScope         = "org_scope"
	SCIMWarnRevealExpanding  = "reveal_expanding"
	SCIMWarnProductionEnv    = "production_environment"
	SCIMWarnPopulatedGroup   = "populated_group"
	SCIMWarnSeverityWarning  = "warning"
	SCIMWarnSeverityCritical = "critical"
)

// SCIMMappingResult is what a create or widen actually did, warnings included.
type SCIMMappingResult struct {
	Mapping SCIMMappingView
	// Warnings is never nil on a create or widen: the consequence language is
	// part of the response, not an optional decoration a client may drop.
	Warnings []SCIMBlastWarning
	// MembersAffected and GrantsCreated report the immediate blast: a mapping
	// row applies to the group's CURRENT members in the authoring transaction,
	// so there is no "waits for the next push" gap to hide behind.
	MembersAffected int
	GrantsCreated   int
	OriginsReleased int
}

// blastWarnings is the consequence language for one prospective mapping row.
// It fires on an org-scoped row, on any row expanding to `reveal` or
// `reveal-history`, and on a row aimed at an already-populated group.
func blastWarnings(scope domain.Scope, caps []domain.Capability, members int) []SCIMBlastWarning {
	out := []SCIMBlastWarning{}
	if scope.Project == "" {
		out = append(out, SCIMBlastWarning{
			Code:     SCIMWarnOrgScope,
			Severity: SCIMWarnSeverityWarning,
			Message: "This row grants at ORG scope: everyone in the mapped group gets it on every project " +
				"and every environment in this organisation, including ones created later. " +
				"A project- or environment-scoped row is almost always what you want instead.",
		})
	}
	if slices.Contains(caps, domain.CapReveal) || slices.Contains(caps, domain.CapRevealHistory) {
		out = append(out, SCIMBlastWarning{
			Code:     SCIMWarnRevealExpanding,
			Severity: SCIMWarnSeverityCritical,
			Message: "This row expands to secret disclosure (reveal / reveal-history). Every current and " +
				"future member of the mapped group will be able to read plaintext secret values in scope, " +
				"and the identity provider — not this surface — decides who is a member.",
		})
	}
	if scope.Env != "" {
		out = append(out, SCIMBlastWarning{
			Code:     SCIMWarnProductionEnv,
			Severity: SCIMWarnSeverityWarning,
			Message: "This row targets one named environment. Confirm it is the environment you meant: " +
				"nothing here preselects one for you, least of all a production environment.",
		})
	}
	if members > 0 {
		out = append(out, SCIMBlastWarning{
			Code:     SCIMWarnPopulatedGroup,
			Severity: SCIMWarnSeverityWarning,
			Message: fmt.Sprintf(
				"The mapped group already has %d member(s). They are granted immediately, in this same "+
					"transaction — there is no waiting for the next provisioning push.", members),
		})
	}
	return out
}

// CreateMapping adds a mapping row and applies it IMMEDIATELY to the group's
// current members, in the authoring transaction (§3).
func (s *SCIM) CreateMapping(ctx context.Context, actor Actor, org domain.OrgID, bindingID string, spec SCIMMappingSpec) (SCIMMappingResult, error) {
	var out SCIMMappingResult
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		scope := domain.Scope{Org: org}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpSCIMMappingCreate, scope)
		if err != nil {
			return err
		}
		// §9: per-binding writes SERIALIZE. The wire takes this lock through
		// its contact UPDATE; an ADMINISTRATION mutation has no such update,
		// so it takes the row lock explicitly and holds it to commit. Mapping
		// authoring reconciles origins in its own transaction, which is the
		// same origin arithmetic a push performs and needs the same
		// serialization — so both legs mark the SAME phase pair, and a fixture
		// asserting strict alternation covers admin-versus-wire races too.
		unlock, err := lockBindingRow(ctx, r, p, bindingID)
		if err != nil {
			return err
		}
		defer unlock()
		c, err := s.loadBinding(ctx, r, az, p, bindingID, false)
		if err != nil {
			return err
		}
		if err := checkMappingScope(c.binding, spec.Template, spec.ProjectID, spec.EnvID); err != nil {
			return err
		}
		if err := s.resolveMappingScope(ctx, r, az, p, c.binding, spec.ProjectID, spec.EnvID); err != nil {
			return err
		}
		// The row references the binding's group resource BY ITS SERVER-MINTED
		// ID (§3), so a row naming an id this server never minted is refused
		// rather than stored as something that can never match.
		if _, err := r.SCIM().Group(ctx, p, bindingID, spec.GroupID); err != nil {
			return err
		}

		now := s.now()
		id, err := newID("scm")
		if err != nil {
			return err
		}
		if err := r.SCIM().CreateMapping(ctx, p, store.NewSCIMMapping{
			ID: id, BindingID: bindingID, GroupID: spec.GroupID,
			Template:       string(spec.Template),
			ScopeProjectID: spec.ProjectID, ScopeEnvID: spec.EnvID,
			CreatedAt: now,
		}); err != nil {
			return err
		}
		row, err := r.SCIM().Mapping(ctx, p, id)
		if err != nil {
			return err
		}

		events, created, members, err := s.applyRowToMembers(ctx, r, az, c, row, now)
		if err != nil {
			return err
		}
		caps, err := domain.ExpandTemplate(spec.Template, mustLevel(mappingScope(c.binding, row)))
		if err != nil {
			return err
		}
		out = SCIMMappingResult{
			Mapping:         mappingView(row, caps),
			Warnings:        blastWarnings(mappingScope(c.binding, row), caps, members),
			MembersAffected: members,
			GrantsCreated:   created,
		}
		events = append(events, mappingEvent(audit.EventSCIMMappingCreated, c, row, caller.Principal))
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelOrg, events...)
	})
	return out, err
}

// UpdateMapping retargets one addressed row's template in place. The row KEEPS
// its id, which is what makes narrowing precise: origins key on the row, so a
// delete-and-recreate would release every origin it holds and immediately
// recreate most of them — momentarily revoking capabilities that never stopped
// being granted, and logging their holders out for a bookkeeping change.
//
// Widening creates the newly covered origins here and now; narrowing releases
// the no-longer-covered part under §2.4, in the same authoring transaction and
// with no IdP round-trip (§4).
func (s *SCIM) UpdateMapping(ctx context.Context, actor Actor, org domain.OrgID, bindingID string, spec SCIMMappingSpec) (SCIMMappingResult, error) {
	var out SCIMMappingResult
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		scope := domain.Scope{Org: org}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpSCIMMappingUpdate, scope)
		if err != nil {
			return err
		}
		// §9: per-binding writes SERIALIZE. The wire takes this lock through
		// its contact UPDATE; an ADMINISTRATION mutation has no such update,
		// so it takes the row lock explicitly and holds it to commit. Mapping
		// authoring reconciles origins in its own transaction, which is the
		// same origin arithmetic a push performs and needs the same
		// serialization — so both legs mark the SAME phase pair, and a fixture
		// asserting strict alternation covers admin-versus-wire races too.
		unlock, err := lockBindingRow(ctx, r, p, bindingID)
		if err != nil {
			return err
		}
		defer unlock()
		c, err := s.loadBinding(ctx, r, az, p, bindingID, false)
		if err != nil {
			return err
		}
		if err := checkMappingScope(c.binding, spec.Template, spec.ProjectID, spec.EnvID); err != nil {
			return err
		}
		if err := s.resolveMappingScope(ctx, r, az, p, c.binding, spec.ProjectID, spec.EnvID); err != nil {
			return err
		}
		row, err := s.addressedMapping(ctx, r, p, bindingID, spec)
		if err != nil {
			return err
		}
		level := mustLevel(mappingScope(c.binding, row))
		before, err := domain.ExpandTemplate(domain.Template(row.Template), level)
		if err != nil {
			return err
		}
		after, err := domain.ExpandTemplate(spec.Template, level)
		if err != nil {
			return err
		}
		now := s.now()
		if err := r.SCIM().UpdateMappingTemplate(ctx, p, row.ID, string(spec.Template)); err != nil {
			return err
		}
		row.Template = string(spec.Template)

		var events []grantEventInput
		released := 0
		// Narrowing first: release what the row no longer covers, before the
		// widening half re-reads the members' rows.
		dropped := missing(before, after)
		if len(dropped) > 0 {
			evs, count, err := s.releaseRowCapabilities(ctx, r, az, c, row, dropped, now)
			if err != nil {
				return err
			}
			events = append(events, evs...)
			released = count
		}
		grantEvents, created, members, err := s.applyRowToMembers(ctx, r, az, c, row, now)
		if err != nil {
			return err
		}
		events = append(events, grantEvents...)

		out = SCIMMappingResult{
			Mapping:         mappingView(row, after),
			Warnings:        blastWarnings(mappingScope(c.binding, row), after, members),
			MembersAffected: members,
			GrantsCreated:   created,
			OriginsReleased: released,
		}
		events = append(events, mappingEvent(audit.EventSCIMMappingUpdated, c, row, caller.Principal))
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelOrg, events...)
	})
	return out, err
}

// DeleteMapping removes one addressed row and releases every origin keyed on
// it, in the authoring transaction (§4): "the org admin is never stuck behind
// an IdP they don't control".
func (s *SCIM) DeleteMapping(ctx context.Context, actor Actor, org domain.OrgID, bindingID string, spec SCIMMappingSpec) (SCIMMappingResult, error) {
	var out SCIMMappingResult
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		scope := domain.Scope{Org: org}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpSCIMMappingDelete, scope)
		if err != nil {
			return err
		}
		// §9: per-binding writes SERIALIZE. The wire takes this lock through
		// its contact UPDATE; an ADMINISTRATION mutation has no such update,
		// so it takes the row lock explicitly and holds it to commit. Mapping
		// authoring reconciles origins in its own transaction, which is the
		// same origin arithmetic a push performs and needs the same
		// serialization — so both legs mark the SAME phase pair, and a fixture
		// asserting strict alternation covers admin-versus-wire races too.
		unlock, err := lockBindingRow(ctx, r, p, bindingID)
		if err != nil {
			return err
		}
		defer unlock()
		c, err := s.loadBinding(ctx, r, az, p, bindingID, false)
		if err != nil {
			return err
		}
		row, err := s.addressedMapping(ctx, r, p, bindingID, spec)
		if err != nil {
			return err
		}
		now := s.now()
		events, released, err := s.releaseRow(ctx, r, az, c, row, domain.CauseMappingDelete, now)
		if err != nil {
			return err
		}
		if err := r.SCIM().DeleteMapping(ctx, p, row.ID); err != nil {
			return err
		}
		// The row is gone, so any `inert_mapping` attention it raised is too.
		// The exit cause is the ACT that cleared it — the mapping was deleted —
		// not the older act that made it inert. Recording `group_deleted` here
		// put a false explanation in the trail: the audited exit says why the
		// state ended, and this state ended because an administrator deleted
		// the row.
		cleared, err := s.clearAttention(ctx, r, c, domain.AttentionInertMapping, row.ID, domain.CauseMappingDelete)
		if err != nil {
			return err
		}
		events = append(events, cleared...)
		out = SCIMMappingResult{Mapping: mappingView(row, nil), OriginsReleased: released, Warnings: []SCIMBlastWarning{}}
		events = append(events, mappingEvent(audit.EventSCIMMappingDeleted, c, row, caller.Principal))
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelOrg, events...)
	})
	return out, err
}

// ListMappings returns the binding's mapping table.
func (s *SCIM) ListMappings(ctx context.Context, actor Actor, org domain.OrgID, bindingID string) ([]SCIMMappingView, error) {
	var out []SCIMMappingView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		scope := domain.Scope{Org: org}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpSCIMMappingList, scope)
		if err != nil {
			return err
		}
		c, err := s.loadBinding(ctx, r, az, p, bindingID, false)
		if err != nil {
			return err
		}
		rows, err := r.SCIM().Mappings(ctx, p, bindingID)
		if err != nil {
			return err
		}
		for _, row := range rows {
			caps, err := domain.ExpandTemplate(domain.Template(row.Template), mustLevel(mappingScope(c.binding, row)))
			if err != nil {
				return err
			}
			out = append(out, mappingView(row, caps))
		}
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelOrg,
			adminReadEvent(string(org), bindingID, "mapping", len(out)))
	})
	return out, err
}

// addressedMapping resolves the row a caller addressed by (group, scope). The
// spellings document addresses a row by group alone, which cannot pick one row
// among several when a group is mapped at more than one scope — see the
// progress note. The scope is therefore part of the address, and the template
// is not: the template is what an update CHANGES.
func (s *SCIM) addressedMapping(
	ctx context.Context, r store.Repos, p authz.Proof, bindingID string, spec SCIMMappingSpec,
) (store.SCIMMapping, error) {
	rows, err := r.SCIM().MappingsForGroup(ctx, p, bindingID, spec.GroupID)
	if err != nil {
		return store.SCIMMapping{}, err
	}
	var hits []store.SCIMMapping
	for _, row := range rows {
		if row.ScopeProjectID == spec.ProjectID && row.ScopeEnvID == spec.EnvID {
			hits = append(hits, row)
		}
	}
	switch len(hits) {
	case 0:
		return store.SCIMMapping{}, domain.ErrNotFound
	case 1:
		return hits[0], nil
	default:
		// Two rows for one group at one scope differing only by template. The
		// caller must name which, and the surface must not pick.
		return store.SCIMMapping{}, fmt.Errorf(
			"%w: service: this group has %d mapping rows at that scope; name the template to address one",
			domain.ErrConflict, len(hits))
	}
}

// applyRowToMembers creates the row's origins for every CURRENT member of its
// group. This is what makes "mapping create/widen applies immediately" true.
func (s *SCIM) applyRowToMembers(
	ctx context.Context, r store.Repos, az *authz.TxAuthorizer,
	c scimContext, row store.SCIMMapping, now time.Time,
) ([]grantEventInput, int, int, error) {
	members, err := r.SCIM().GroupMembers(ctx, c.proof, c.binding.ID, row.GroupID)
	if err != nil {
		return nil, 0, 0, err
	}
	var events []grantEventInput
	created, affected := 0, 0
	for _, m := range members {
		user, err := r.SCIM().User(ctx, c.proof, c.binding.ID, m.UserID)
		if err != nil {
			return nil, 0, 0, err
		}
		// An inactive user holds no origins (§5.4's `active: true -> false` row
		// released them), and a mapping row must not resurrect them behind the
		// IdP's back.
		if !user.Active {
			continue
		}
		principal, err := principalForAccount(ctx, az, user.AccountID)
		if err != nil {
			return nil, 0, 0, err
		}
		evs, n, err := s.applyMappings(ctx, r, az, c, principal, []store.SCIMMapping{row}, now)
		if err != nil {
			return nil, 0, 0, err
		}
		events = append(events, evs...)
		created += n
		affected++
	}
	return events, created, affected, nil
}

// releaseRow releases every origin keyed on one mapping row, for every member
// of its group, under §2.4.
func (s *SCIM) releaseRow(
	ctx context.Context, r store.Repos, az *authz.TxAuthorizer,
	c scimContext, row store.SCIMMapping, cause domain.SCIMCause, now time.Time,
) ([]grantEventInput, int, error) {
	members, err := r.SCIM().GroupMembers(ctx, c.proof, c.binding.ID, row.GroupID)
	if err != nil {
		return nil, 0, err
	}
	var events []grantEventInput
	released := 0
	for _, m := range members {
		user, err := r.SCIM().User(ctx, c.proof, c.binding.ID, m.UserID)
		if err != nil {
			return nil, 0, err
		}
		principal, err := principalForAccount(ctx, az, user.AccountID)
		if err != nil {
			return nil, 0, err
		}
		outcome, evs, err := releaseSCIMOrigins(ctx, az, now, releaseArgs{
			binding: c.binding.ID, org: domain.OrgID(c.binding.OrgID), principal: principal,
			match: matchMappingRows(c.binding.ID, map[string]bool{row.ID: true}), cause: cause,
		})
		if err != nil {
			return nil, 0, err
		}
		events = append(events, evs...)
		released += outcome.Released
		if outcome.AuthorityChanged() {
			if err := advanceAndSweep(ctx, az, principal); err != nil {
				return nil, 0, err
			}
		}
		for _, grantID := range outcome.Retained {
			ev, err := s.enterAttention(ctx, r, c, domain.AttentionLockoutRetention, grantID, cause, now)
			if err != nil {
				return nil, 0, err
			}
			events = append(events, ev...)
		}
	}
	return events, released, nil
}

// releaseRowCapabilities is the NARROWING half: release only the origins the
// row no longer covers, leaving the ones it still does. It reuses the same
// algorithm with a grant filter rather than a second release path, because two
// release paths is how a lockout conversion goes missing from one of them.
func (s *SCIM) releaseRowCapabilities(
	ctx context.Context, r store.Repos, az *authz.TxAuthorizer,
	c scimContext, row store.SCIMMapping, dropped []domain.Capability, now time.Time,
) ([]grantEventInput, int, error) {
	members, err := r.SCIM().GroupMembers(ctx, c.proof, c.binding.ID, row.GroupID)
	if err != nil {
		return nil, 0, err
	}
	drop := map[domain.Capability]bool{}
	for _, capability := range dropped {
		drop[capability] = true
	}
	var events []grantEventInput
	released := 0
	for _, m := range members {
		user, err := r.SCIM().User(ctx, c.proof, c.binding.ID, m.UserID)
		if err != nil {
			return nil, 0, err
		}
		principal, err := principalForAccount(ctx, az, user.AccountID)
		if err != nil {
			return nil, 0, err
		}
		outcome, evs, err := releaseSCIMOrigins(ctx, az, now, releaseArgs{
			binding: c.binding.ID, org: domain.OrgID(c.binding.OrgID), principal: principal,
			match: matchMappingRows(c.binding.ID, map[string]bool{row.ID: true}),
			grant: func(g domain.Grant) bool { return drop[g.Capability] },
			cause: domain.CauseMappingDelete,
		})
		if err != nil {
			return nil, 0, err
		}
		events = append(events, evs...)
		released += outcome.Released
		if outcome.AuthorityChanged() {
			if err := advanceAndSweep(ctx, az, principal); err != nil {
				return nil, 0, err
			}
		}
		for _, grantID := range outcome.Retained {
			ev, err := s.enterAttention(ctx, r, c,
				domain.AttentionLockoutRetention, grantID, domain.CauseMappingDelete, now)
			if err != nil {
				return nil, 0, err
			}
			events = append(events, ev...)
		}
	}
	return events, released, nil
}

// The mapping row's own id is the event OBJECT, and what the authoring
// transaction granted or released is the `grant.*` events it emits beside this
// one — §10's field list for `scim.mapping_*` is exactly the five below.
func mappingEvent(typ audit.EventType, c scimContext, row store.SCIMMapping, actor domain.PrincipalID) grantEventInput {
	return grantEventInput{
		typ:    typ,
		object: audit.Object{Type: "scim-mapping", ID: row.ID},
		payload: audit.Payload{
			"binding":  c.binding.ID,
			"group_id": row.GroupID,
			"template": row.Template,
			"scope":    scopeObject(mappingScope(c.binding, row)),
			"actor":    string(actor),
		},
	}
}

func mappingView(row store.SCIMMapping, caps []domain.Capability) SCIMMappingView {
	out := SCIMMappingView{
		ID: row.ID, BindingID: row.BindingID, GroupID: row.GroupID,
		Template: row.Template, ProjectID: row.ScopeProjectID, EnvID: row.ScopeEnvID,
		Inert: row.Inert, CreatedAt: row.CreatedAt,
	}
	for _, c := range caps {
		out.Capabilities = append(out.Capabilities, string(c))
	}
	return out
}

// missing returns the capabilities in `before` that `after` does not cover —
// the "no-longer-covered part" §5.4 names.
func missing(before, after []domain.Capability) []domain.Capability {
	keep := map[domain.Capability]bool{}
	for _, c := range after {
		keep[c] = true
	}
	var out []domain.Capability
	for _, c := range before {
		if !keep[c] {
			out = append(out, c)
		}
	}
	return out
}

// mustLevel is the level of a scope this package built itself. A gap here is a
// defect in mappingScope, not a caller error, so it collapses to org depth
// rather than propagating an error through every render path.
func mustLevel(s domain.Scope) domain.Level {
	l, err := s.Level()
	if err != nil {
		return domain.LevelOrg
	}
	return l
}
