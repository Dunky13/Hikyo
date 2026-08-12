package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/scimproto"
	"github.com/Dunky13/hikyo/internal/store"
)

// The Group half of the wire (#73 §6). Groups are binding-scoped resources
// with a server-minted id; MEMBERS are references to this binding's provisioned
// users, and a reference resolving to no such user is refused by name — the IdP
// can only reference ids this server minted. Group-typed members are refused by
// name too: v1 is flat, and Okta and Entra provision direct user members.
//
// The User resource's `groups` attribute is response-only per RFC 7643;
// membership is authored EXCLUSIVELY through these operations, which is why
// nothing in the User path writes a membership row.

// SCIMGroupResource is one provisioned group as the wire renders it.
type SCIMGroupResource struct {
	ID          string
	ExternalID  string
	DisplayName string
	Members     []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// SCIMGroupInput is a create or a full replacement.
type SCIMGroupInput struct {
	DisplayName string
	ExternalID  string
	// Members is the desired member set. On PUT it REPLACES; on PATCH the
	// caller has already resolved the accepted matrix cell into a desired set.
	Members []string
	// MembersPresent distinguishes "no members named" from "an empty member
	// set", which are different desired states: the first leaves membership
	// alone on a PATCH, the second clears it.
	MembersPresent bool
	// ExternalIDCleared marks an EXPLICIT `remove externalId`, which omission
	// does not. Same reason as the User field: without presence state the
	// removal became a silent no-op.
	ExternalIDCleared bool
	// MemberOps is the ORDERED PATCH membership script. A PATCH is a sequence,
	// not a set of buckets: `add X` then `remove members[value eq X]` and the
	// same two operations reversed are different requests with different final
	// states, and collapsing them into "adds" and "removes" produced the same
	// answer for both. Only this side can see the stored set, so the script is
	// folded here, in order, into the single desired set `setMembers`
	// reconciles against.
	MemberOps []SCIMMemberOp
	// Patch marks a partial update, so a PATCH that never mentions displayName
	// leaves it alone while a PUT clears it.
	Patch bool
}

// SCIMMemberOp is one membership operation of a PATCH, in the order the
// identity provider sent it.
type SCIMMemberOp struct {
	// Kind is the accepted matrix cell: `add` (union), `replace` (whole set),
	// `clear` (remove on `members`), or `remove-one` (`members[value eq "…"]`).
	Kind SCIMMemberOpKind
	// Members is the operand of `add` and `replace`.
	Members []string
	// Value is the reference `remove-one` names.
	Value string
}

// SCIMMemberOpKind is the closed set of membership operations the §8 matrix
// admits on a Group.
type SCIMMemberOpKind string

const (
	SCIMMemberAdd       SCIMMemberOpKind = "add"
	SCIMMemberReplace   SCIMMemberOpKind = "replace"
	SCIMMemberClear     SCIMMemberOpKind = "clear"
	SCIMMemberRemoveOne SCIMMemberOpKind = "remove-one"
)

// ErrSCIMNoTarget refuses a filtered member removal naming somebody who is not
// a member. RFC 7644 calls that `noTarget`, and answering success would tell
// the identity provider a removal happened that did not.
var ErrSCIMNoTarget = fmt.Errorf(
	"%w: service: the members filter names no member of this group", domain.ErrNotFound)

// desiredMembers turns whatever the request expressed into the ONE desired set
// `setMembers` reconciles against. It refuses a removal that targets nothing.
//
// A PATCH script is folded IN ORDER over the stored set, so each operation sees
// what its predecessors did: `add X` then `remove members[value eq X]` ends
// without X, the reverse ends with X, and a `remove-one` naming a member an
// earlier operation in the SAME request added is a legitimate target rather
// than a `noTarget` refusal.
func (in SCIMGroupInput) desiredMembers(current []store.SCIMGroupMember) ([]string, error) {
	stored := make([]string, 0, len(current))
	for _, m := range current {
		stored = append(stored, m.UserID)
	}
	if len(in.MemberOps) == 0 {
		// PUT and create: the named set replaces wholesale, and an unnamed set
		// leaves the stored one alone.
		if !in.MembersPresent {
			return dedupe(stored), nil
		}
		return dedupe(in.Members), nil
	}
	set := dedupe(stored)
	for _, op := range in.MemberOps {
		switch op.Kind {
		case SCIMMemberReplace:
			set = dedupe(op.Members)
		case SCIMMemberClear:
			set = nil
		case SCIMMemberAdd:
			set = dedupe(append(append([]string{}, set...), op.Members...))
		case SCIMMemberRemoveOne:
			next := make([]string, 0, len(set))
			found := false
			for _, id := range set {
				if id == op.Value {
					found = true
					continue
				}
				next = append(next, id)
			}
			if !found {
				return nil, ErrSCIMNoTarget
			}
			set = next
		default:
			return nil, fmt.Errorf("service: unknown SCIM member operation %q", op.Kind)
		}
	}
	return set, nil
}

// dedupe keeps the first occurrence of each id, in order. An identity provider
// repeating a reference in one request must not make the second insertion a
// unique-key violation that rolls back the whole valid desired set — and it
// happens: connectors resend a full member list containing a duplicate.
func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, id := range in {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// touchesMembers reports whether the request said anything about membership at
// all. A PATCH that only renames must not reconcile the member set.
func (in SCIMGroupInput) touchesMembers() bool {
	return in.MembersPresent || len(in.MemberOps) > 0
}

// CreateGroup mints a group and applies any mapping rows already pointing at
// the id — normally none, because mapping rows reference the id minted HERE.
func (s *SCIM) CreateGroup(ctx context.Context, actor Actor, org domain.OrgID, bindingID string, in SCIMGroupInput) (SCIMGroupResource, error) {
	var out SCIMGroupResource
	err := s.wireTx(ctx, actor, org, bindingID, authz.OpSCIMGroupCreate,
		func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time) ([]grantEventInput, error) {
			if in.DisplayName == "" {
				return nil, fmt.Errorf("%w: service: displayName is required", domain.ErrInvalid)
			}
			// displayName is NOT unique, and this is the absence of a check
			// rather than a missing one. RFC 7643 does not make it unique, real
			// directories hold same-named groups in different organisational
			// units, and the ADR's closed uniqueness mapping names only
			// duplicate `userName` and a subject-source collision. A
			// `displayName eq` probe that matches two groups is answered with
			// two, which is what a ListResponse is for.
			id, err := newID("scg")
			if err != nil {
				return nil, err
			}
			if err := r.SCIM().CreateGroup(ctx, c.proof, store.NewSCIMGroup{
				ID: id, BindingID: bindingID, DisplayName: in.DisplayName,
				DisplayNameLower: fold(in.DisplayName), ExternalID: in.ExternalID,
				CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				return nil, err
			}
			events, added, _, err := s.setMembers(ctx, r, az, c, id, in.Members, now)
			if err != nil {
				return nil, err
			}
			out, err = s.renderGroup(ctx, r, c, bindingID, id)
			if err != nil {
				return nil, err
			}
			events = append(events, groupEvent(audit.EventSCIMGroupCreated, c, id, in.DisplayName))
			if len(added) > 0 {
				events = append(events, membershipEvent(c, id, added, nil))
			}
			return events, nil
		})
	return out, err
}

// ReplaceGroup is RFC replacement: omitted mutable attributes clear, and the
// member set is replaced wholesale.
func (s *SCIM) ReplaceGroup(ctx context.Context, actor Actor, org domain.OrgID, bindingID, id string, in SCIMGroupInput) (SCIMGroupResource, error) {
	in.MembersPresent = true
	return s.mutateGroup(ctx, actor, org, bindingID, id, authz.OpSCIMGroupReplace, in, true)
}

// PatchGroup applies the accepted matrix cells the transport already validated.
func (s *SCIM) PatchGroup(ctx context.Context, actor Actor, org domain.OrgID, bindingID, id string, in SCIMGroupInput) (SCIMGroupResource, error) {
	return s.mutateGroup(ctx, actor, org, bindingID, id, authz.OpSCIMGroupPatch, in, false)
}

func (s *SCIM) mutateGroup(
	ctx context.Context, actor Actor, org domain.OrgID, bindingID, id string,
	op authz.Operation, in SCIMGroupInput, replace bool,
) (SCIMGroupResource, error) {
	var out SCIMGroupResource
	err := s.wireTx(ctx, actor, org, bindingID, op,
		func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time) ([]grantEventInput, error) {
			row, err := r.SCIM().Group(ctx, c.proof, bindingID, id)
			if err != nil {
				return nil, err
			}
			next := row
			// dirty is "the stored row would actually differ", for the same
			// reason the User path carries one: a re-assertion that changes
			// nothing must not bump `UpdatedAt` or emit an update event.
			dirty := false
			if replace || in.DisplayName != "" {
				if in.DisplayName == "" {
					return nil, fmt.Errorf("%w: service: displayName is required", domain.ErrInvalid)
				}
				next.DisplayName, next.DisplayNameLower = in.DisplayName, fold(in.DisplayName)
			}
			if replace || in.ExternalID != "" || in.ExternalIDCleared {
				next.ExternalID = in.ExternalID
			}
			// Compared RAW: a case-only rename is a change the identity provider
			// made, and the folded column is a lookup key, not the value.
			if next.DisplayName != row.DisplayName || next.ExternalID != row.ExternalID {
				dirty = true
			}
			if dirty {
				if err := r.SCIM().UpdateGroup(ctx, c.proof, store.SCIMGroupUpdate{
					ID: id, BindingID: bindingID, DisplayName: next.DisplayName,
					DisplayNameLower: next.DisplayNameLower, ExternalID: next.ExternalID,
					UpdatedAt: now,
				}); err != nil {
					return nil, err
				}
			}
			var events []grantEventInput
			var added, removed []string
			if in.touchesMembers() {
				current, err := r.SCIM().GroupMembers(ctx, c.proof, c.binding.ID, id)
				if err != nil {
					return nil, err
				}
				desired, err := in.desiredMembers(current)
				if err != nil {
					return nil, err
				}
				evs, a, rm, err := s.setMembers(ctx, r, az, c, id, desired, now)
				if err != nil {
					return nil, err
				}
				events, added, removed = evs, a, rm
			}
			out, err = s.renderGroup(ctx, r, c, bindingID, id)
			if err != nil {
				return nil, err
			}
			// A rename changes displayName and NOTHING about grants: mapping
			// rows key on the id (§5.4's Group update row). A request that
			// changed neither the row nor its membership emits nothing.
			if dirty {
				events = append(events, groupEvent(audit.EventSCIMGroupUpdated, c, id, next.DisplayName))
			}
			if len(added) > 0 || len(removed) > 0 {
				events = append(events, membershipEvent(c, id, added, removed))
			}
			return events, nil
		})
	return out, err
}

// setMembers applies a DESIRED member set: create origins for exactly the
// users added, release exactly that group's origins for the users removed
// (§5.4's "create/release origins for exactly the affected users x that
// group's mapping rows"), and leave everyone else alone.
func (s *SCIM) setMembers(
	ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext,
	groupID string, desired []string, now time.Time,
) ([]grantEventInput, []string, []string, error) {
	// De-duplicated HERE rather than at each caller: `CreateGroup` passes the
	// decoded member list straight through, and a repeated reference made the
	// second insertion a unique-key violation that rolled back the whole valid
	// desired set. One guard at the reconciler covers create, PUT and PATCH.
	desired = dedupe(desired)
	current, err := r.SCIM().GroupMembers(ctx, c.proof, c.binding.ID, groupID)
	if err != nil {
		return nil, nil, nil, err
	}
	have := map[string]bool{}
	for _, m := range current {
		have[m.UserID] = true
	}
	want := map[string]bool{}
	for _, id := range desired {
		want[id] = true
	}

	mappings, err := r.SCIM().MappingsForGroup(ctx, c.proof, c.binding.ID, groupID)
	if err != nil {
		return nil, nil, nil, err
	}

	var events []grantEventInput
	var added, removed []string
	for _, id := range desired {
		if have[id] {
			continue
		}
		// A member reference resolving to no user THIS BINDING provisioned is
		// refused by name: the IdP can only reference ids this server minted.
		user, err := r.SCIM().User(ctx, c.proof, c.binding.ID, id)
		if errors.Is(err, domain.ErrNotFound) {
			return nil, nil, nil, ErrSCIMUnknownMember
		}
		if err != nil {
			return nil, nil, nil, err
		}
		memberID, err := newID("sgm")
		if err != nil {
			return nil, nil, nil, err
		}
		if err := r.SCIM().AddGroupMember(ctx, c.proof, store.SCIMGroupMember{
			ID: memberID, BindingID: c.binding.ID, GroupID: groupID, UserID: id, CreatedAt: now,
		}); err != nil {
			return nil, nil, nil, err
		}
		added = append(added, user.AccountID)
		if !user.Active {
			continue // an inactive user holds no origins; membership is recorded, not granted
		}
		principal, err := principalForAccount(ctx, az, user.AccountID)
		if err != nil {
			return nil, nil, nil, err
		}
		evs, _, err := s.applyMappings(ctx, r, az, c, principal, mappings, now)
		if err != nil {
			return nil, nil, nil, err
		}
		events = append(events, evs...)
	}
	for _, m := range current {
		if want[m.UserID] {
			continue
		}
		user, err := r.SCIM().User(ctx, c.proof, c.binding.ID, m.UserID)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := r.SCIM().RemoveGroupMember(ctx, c.proof, c.binding.ID, groupID, m.UserID); err != nil {
			return nil, nil, nil, err
		}
		removed = append(removed, user.AccountID)
		// One account can be attached to SEVERAL resources in this binding —
		// two identities the operator linked to one human — and each may be a
		// member of this group in its own right. Releasing the group's origins
		// for the PRINCIPAL when only one of them left would take away access
		// the identity provider is still asserting through the other. The check
		// runs AFTER the row is gone, so it asks about the membership that
		// actually survives.
		justified, err := s.groupStillJustifiedByPeer(ctx, r, c, groupID, user.AccountID)
		if err != nil {
			return nil, nil, nil, err
		}
		if justified {
			continue
		}
		principal, err := principalForAccount(ctx, az, user.AccountID)
		if err != nil {
			return nil, nil, nil, err
		}
		evs, _, err := s.releaseGroupOrigins(ctx, r, az, c, principal, groupID, domain.CauseMemberRemoved, now)
		if err != nil {
			return nil, nil, nil, err
		}
		events = append(events, evs...)
	}
	return events, added, removed, nil
}

// groupStillJustifiedByPeer reports whether any ACTIVE resource of the same
// account remains a member of this group. It is the membership-shaped twin of
// `originsJustifiedElsewhere`, which answers the same question for a whole
// deprovision.
//
// ponytail: linear in the group's surviving membership, one user read per
// member. Groups here are bounded by the page bound and the traffic is a
// connector's reconciliation cycle; if a directory ever holds groups where that
// matters, the answer is a single query joining scim_group_members to
// scim_users on account_id, not a cache.
func (s *SCIM) groupStillJustifiedByPeer(
	ctx context.Context, r store.Repos, c scimContext, groupID, accountID string,
) (bool, error) {
	survivors, err := r.SCIM().GroupMembers(ctx, c.proof, c.binding.ID, groupID)
	if err != nil {
		return false, err
	}
	for _, m := range survivors {
		peer, err := r.SCIM().User(ctx, c.proof, c.binding.ID, m.UserID)
		if err != nil {
			return false, err
		}
		if peer.AccountID == accountID && peer.Active {
			return true, nil
		}
	}
	return false, nil
}

// releaseGroupOrigins releases ONE group's origins for one principal.
// "Group removal releases only that group's origin; a row with a `manual`
// origin beside it survives, and vice versa" (§2).
func (s *SCIM) releaseGroupOrigins(
	ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext,
	principal domain.PrincipalID, groupID string, cause domain.SCIMCause, now time.Time,
) ([]grantEventInput, int, error) {
	outcome, events, err := releaseSCIMOrigins(ctx, az, now, releaseArgs{
		binding: c.binding.ID, org: domain.OrgID(c.binding.OrgID), principal: principal,
		match: matchGroup(c.binding.ID, groupID), cause: cause,
	})
	if err != nil {
		return nil, 0, err
	}
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
	return events, outcome.Released, nil
}

// DeleteGroup releases that group's origins for every member and flips every
// referencing mapping row to INERT with an attention state — the row is never
// silently removed, because a human has to decide whether it should point at a
// live group or go away (§5.4).
func (s *SCIM) DeleteGroup(ctx context.Context, actor Actor, org domain.OrgID, bindingID, id string) error {
	return s.wireTx(ctx, actor, org, bindingID, authz.OpSCIMGroupDelete,
		func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time) ([]grantEventInput, error) {
			row, err := r.SCIM().Group(ctx, c.proof, bindingID, id)
			if err != nil {
				return nil, err
			}
			members, err := r.SCIM().GroupMembers(ctx, c.proof, c.binding.ID, id)
			if err != nil {
				return nil, err
			}
			var events []grantEventInput
			var removed []string
			released := 0
			for _, m := range members {
				user, err := r.SCIM().User(ctx, c.proof, bindingID, m.UserID)
				if err != nil {
					return nil, err
				}
				principal, err := principalForAccount(ctx, az, user.AccountID)
				if err != nil {
					return nil, err
				}
				// The count comes from the outcome, not from a before/after row
				// total: a lockout conversion REPLACES the released origin with
				// a retention one, so the totals match and the release vanishes
				// from the audit evidence.
				evs, n, err := s.releaseGroupOrigins(ctx, r, az, c, principal, id, domain.CauseGroupDeleted, now)
				if err != nil {
					return nil, err
				}
				released += n
				events = append(events, evs...)
				removed = append(removed, user.AccountID)
			}
			if err := r.SCIM().ClearGroupMembers(ctx, c.proof, c.binding.ID, id); err != nil {
				return nil, err
			}
			// Referencing mapping rows flip to inert and raise attention. They
			// grant nothing while inert, and `desiredMappings` skips them.
			if _, err := r.SCIM().SetMappingInert(ctx, c.proof, bindingID, id, true); err != nil {
				return nil, err
			}
			rows, err := r.SCIM().MappingsForGroup(ctx, c.proof, bindingID, id)
			if err != nil {
				return nil, err
			}
			for _, m := range rows {
				ev, err := s.enterAttention(ctx, r, c,
					domain.AttentionInertMapping, m.ID, domain.CauseGroupDeleted, now)
				if err != nil {
					return nil, err
				}
				events = append(events, ev...)
			}
			if err := r.SCIM().DeleteGroup(ctx, c.proof, bindingID, id); err != nil {
				return nil, err
			}
			events = append(events, groupEvent(audit.EventSCIMGroupDeleted, c, id, row.DisplayName))
			if len(removed) > 0 {
				events = append(events, membershipEvent(c, id, nil, removed))
			}
			return events, nil
		})
}

// GetGroup returns one group with its member references.
func (s *SCIM) GetGroup(ctx context.Context, actor Actor, org domain.OrgID, bindingID, id string) (SCIMGroupResource, error) {
	var out SCIMGroupResource
	err := s.wireTx(ctx, actor, org, bindingID, authz.OpSCIMGroupGet,
		func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time) ([]grantEventInput, error) {
			var err error
			out, err = s.renderGroup(ctx, r, c, bindingID, id)
			if err != nil {
				return nil, err
			}
			return []grantEventInput{directoryReadEvent(bindingID, "group", string(scimproto.FilterNone), 1, 1)}, nil
		})
	return out, err
}

// ListGroups answers the two Group filters. `displayName eq` is the probe both
// Okta and Entra issue to discover a group before creating or updating it, so
// it is load-bearing rather than a convenience.
func (s *SCIM) ListGroups(ctx context.Context, actor Actor, org domain.OrgID, bindingID string, filter scimproto.Filter, page scimproto.Page) ([]SCIMGroupResource, int, error) {
	var out []SCIMGroupResource
	total := 0
	err := s.wireTx(ctx, actor, org, bindingID, authz.OpSCIMGroupList,
		func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time) ([]grantEventInput, error) {
			var rows []store.SCIMGroup
			switch filter.Shape {
			case scimproto.FilterNone:
				all, err := r.SCIM().Groups(ctx, c.proof, bindingID)
				if err != nil {
					return nil, err
				}
				rows = all
			case scimproto.FilterDisplayNameEq:
				matches, err := r.SCIM().GroupsByDisplayName(ctx, c.proof, bindingID, fold(filter.Value))
				if err != nil {
					return nil, err
				}
				rows = matches
			case scimproto.FilterExternalIDEq:
				matches, err := r.SCIM().GroupsByExternalID(ctx, c.proof, bindingID, filter.Value)
				if err != nil {
					return nil, err
				}
				rows = matches
			default:
				return nil, fmt.Errorf("%w: service: filter %q is not answerable on Groups", domain.ErrInvalid, filter.Shape)
			}
			total = len(rows)
			for _, row := range scimproto.Slice(rows, page) {
				view, err := s.renderGroup(ctx, r, c, bindingID, row.ID)
				if err != nil {
					return nil, err
				}
				out = append(out, view)
			}
			return []grantEventInput{
				directoryReadEvent(bindingID, "group", string(filter.Shape), page.StartIndex, len(out)),
			}, nil
		})
	return out, total, err
}

func (s *SCIM) renderGroup(ctx context.Context, r store.Repos, c scimContext, bindingID, id string) (SCIMGroupResource, error) {
	row, err := r.SCIM().Group(ctx, c.proof, bindingID, id)
	if err != nil {
		return SCIMGroupResource{}, err
	}
	members, err := r.SCIM().GroupMembers(ctx, c.proof, c.binding.ID, id)
	if err != nil {
		return SCIMGroupResource{}, err
	}
	out := SCIMGroupResource{
		ID: row.ID, ExternalID: row.ExternalID, DisplayName: row.DisplayName,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
	for _, m := range members {
		out.Members = append(out.Members, m.UserID)
	}
	return out, nil
}

// §10's field list for `scim.group_*` is "binding, group id, displayName". What
// a DELETE released and made inert is carried by the `grant.*` and
// `scim.attention_entered` events emitted beside it in the same transaction.
func groupEvent(typ audit.EventType, c scimContext, id, displayName string) grantEventInput {
	p := audit.Payload{
		"binding": c.binding.ID, "group_id": id,
		// IdP-supplied: sanitized, `ew_`-redacted and bounded here, at the one
		// point it enters the trail.
		"display_name": audit.SanitizeFreeText(displayName),
	}
	return grantEventInput{typ: typ, object: audit.Object{Type: "scim-group", ID: id}, payload: p}
}

func membershipEvent(c scimContext, id string, added, removed []string) grantEventInput {
	return grantEventInput{
		typ:    audit.EventSCIMGroupMembership,
		object: audit.Object{Type: "scim-group", ID: id},
		payload: audit.Payload{
			"binding": c.binding.ID, "group_id": id,
			// Bounded at 200 ids each, per §10's list bounds.
			"added_accounts":   sanitizedList(added, 200),
			"removed_accounts": sanitizedList(removed, 200),
		},
	}
}

// Discovery serves the three static documents. They run under the binding's
// authentication, admission and serialization, and they record contact — a
// probe IS the identity provider reaching this server — but they emit NOTHING.
// §10: the discovery endpoints "carry no tenant data; they are the one SCIM
// surface annotated `audited: none`-equivalent by explicit registry annotation
// on their probe class, not silence". The annotation is the name-pinned
// exemption entry (internal/isolation/testdata/audited_exemptions.json) for
// `scim-discovery.read` and for each of the three routes; a `directory_read`
// per probe would record the server's own manual being read, and would bury
// the reads that ARE tenant data under a connector's polling.
//
// Nor does it reconcile attention: a configuration fetch is not a
// re-assertion cycle, so it must not clear the post-restore state (§9.1's exit
// is re-mint PLUS a completed cycle) and must not lower a staleness warning
// that no directory traffic has earned.
func (s *SCIM) Discovery(ctx context.Context, actor Actor, org domain.OrgID, bindingID string) error {
	return s.wireTx(ctx, actor, org, bindingID, authz.OpSCIMDiscovery, nil)
}
