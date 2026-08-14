package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
)

// The §2.4 universal release algorithm (#73, scim-provisioning ADR).
//
// ONE algorithm governs every SCIM-side origin release, whatever triggered it —
// user deprovision or delete, group membership removal, group delete, mapping
// row delete or narrowing, binding delete: release the named `scim` origins;
// revoke rows whose last origin that was; advance the affected principals'
// session generations in the same transaction; emit the audit events.
//
// The one place it bends is the lockout interplay, and it bends by CONVERTING
// rather than refusing. The locked refusal — removing the last org
// `manage-members` holder is refused — binds HUMAN revocation unchanged. Here
// a refusal would wedge the IdP into infinite retry while the departed user
// kept all their access, so the `scim` origin is released (origin truth stays
// honest: the IdP did withdraw it) and a `lockout-retention(cause)` origin is
// minted on the same row in the same transaction.

// ErrSCIMOriginOnly refuses a HAND revocation of a grant whose only live
// origins are system-owned, naming the two real remediations (ADR §4).
//
// Before this ticket such a revoke fell through to ErrNoSuchGrant, which is a
// different statement: "you do not hold that" versus "you hold it, and this is
// not the lever that removes it". An administrator told the first would go
// looking for a grant that is right there on the membership line.
var ErrSCIMOriginOnly = fmt.Errorf(
	"%w: service: this grant is held by SCIM provisioning; remove the user from the group at the identity provider, or edit or delete the mapping row",
	domain.ErrConflict)

// ErrLockoutRetained refuses a hand revocation of a grant held only by a
// `lockout-retention` origin. The origin is system-owned: it is not
// hand-revocable and not IdP-addressable, and the cure is adding another
// `manage-members` holder to the org (ADR §2.4).
var ErrLockoutRetained = fmt.Errorf(
	"%w: service: this grant is retained because it is the org's last manage-members grant; grant manage-members to another principal and the retention releases itself",
	domain.ErrConflict)

// ErrStructuralGrant refuses a hand revocation of a provisioning connection's
// own `scim-provision` grant. It is released only by the binding-deletion state
// machine (§6), which retires the principal and the grant atomically.
var ErrStructuralGrant = fmt.Errorf(
	"%w: service: this grant is structural to a SCIM binding; delete the binding to retire it",
	domain.ErrConflict)

// releaseMatch decides which `scim` origins a release names. Every trigger in
// §5.4 is one of these predicates over the origin's `(binding, mapping row,
// group)` key, which is what makes them one algorithm rather than six.
type releaseMatch func(domain.SCIMOriginKey) bool

// matchBinding releases every origin the binding holds — binding delete (§6),
// and the whole-user releases that address a user's entire footprint in ONE
// binding (deprovision, delete).
func matchBinding(binding string) releaseMatch {
	return func(k domain.SCIMOriginKey) bool { return k.Binding == binding }
}

// matchGroup releases the origins of one group inside one binding — membership
// removal and group delete. "Group removal releases only that group's origin;
// a row with a `manual` origin beside it survives" (§2).
func matchGroup(binding, group string) releaseMatch {
	return func(k domain.SCIMOriginKey) bool { return k.Binding == binding && k.Group == group }
}

// matchMappingRows releases the origins keyed on a named set of mapping rows —
// mapping-row delete and the no-longer-covered part of a narrowing.
func matchMappingRows(binding string, rows map[string]bool) releaseMatch {
	return func(k domain.SCIMOriginKey) bool { return k.Binding == binding && rows[k.MappingRow] }
}

// releaseOutcome reports what one principal's release actually did, so the
// caller can build its own event truthfully and decide about the generation
// advance without a second read.
type releaseOutcome struct {
	// Released counts origins actually removed.
	Released int
	// RowsRevoked counts grant rows whose LAST origin this was.
	RowsRevoked int
	// Retained names the grants converted to `lockout-retention` instead of
	// being revoked.
	Retained []string
	// ManualRemains reports whether the principal still holds a grant in this
	// org on a MANUAL origin — the honest remainder the per-user attention flag
	// exists for (§5.3): "IdP deprovisioned this user; manual grants remain."
	//
	// Deliberately narrow. A row surviving on ANOTHER BINDING's `scim` origin
	// is not a manual grant and must not raise this flag: nothing about it
	// needs a human decision, and the second identity provider is still
	// asserting it. Whether that case deserves wording of its own is post-v1;
	// inventing a state for it here would widen the closed enumeration.
	ManualRemains bool
}

// AuthorityChanged reports whether effective policy actually moved. A release
// that only shed one of several origins took nothing away, so killing the
// holder's sessions for it would be a denial of service dressed as security —
// the same rule the human revoke path already applies.
func (o releaseOutcome) AuthorityChanged() bool { return o.RowsRevoked > 0 }

// releaseArgs carries one release. It is a struct rather than eight parameters
// because every caller sets all of them and a positional mistake between two
// string ids is invisible at the call site.
type releaseArgs struct {
	binding   string
	org       domain.OrgID
	principal domain.PrincipalID
	match     releaseMatch
	// grant, when set, narrows the release to grant rows it accepts. It exists
	// for the ONE trigger that is not "release everything this key holds":
	// narrowing a mapping row releases the no-longer-covered part (§5.4) while
	// leaving the part the row still covers. Expressing that as a filter keeps
	// it inside the one algorithm rather than beside it, which is where a
	// missing lockout conversion would hide.
	grant func(domain.Grant) bool
	cause domain.SCIMCause
}

// accepts reports whether a grant row is in scope for this release.
func (a releaseArgs) accepts(g domain.Grant) bool {
	return a.grant == nil || a.grant(g)
}

// releaseSCIMOrigins is the algorithm. It never advances a session generation
// itself: some callers must advance UNCONDITIONALLY (deprovision and delete,
// §5.3 — "even when no grant row changes, because the IdP has declared this
// human gone") and some only when authority moved. Folding the advance in here
// would force one of the two to be wrong.
func releaseSCIMOrigins(
	ctx context.Context, az *authz.TxAuthorizer, now time.Time, args releaseArgs,
) (releaseOutcome, []grantEventInput, error) {
	var out releaseOutcome
	var events []grantEventInput

	// Lock first, read second: the release is a read-then-write over the
	// target's grant rows, and every grant writer in the system takes this lock
	// as its first statement.
	if err := az.LockTargetPrincipal(ctx, args.principal); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return out, nil, nil // the principal went away; nothing holds anything
		}
		return out, nil, err
	}
	rows, err := az.GrantOriginsForPrincipal(ctx, args.principal)
	if err != nil {
		return out, nil, err
	}

	// Group the flat (row, origin) stream by row, preserving the read order so
	// the events come out deterministically.
	type rowState struct {
		grant   authz.GrantRow
		origins []authz.Origin
	}
	order := make([]string, 0, len(rows))
	byRow := map[string]*rowState{}
	for _, r := range rows {
		st, ok := byRow[r.ID]
		if !ok {
			st = &rowState{grant: r.GrantRow}
			byRow[r.ID] = st
			order = append(order, r.ID)
		}
		st.origins = append(st.origins, r.Origin)
	}

	for _, id := range order {
		st := byRow[id]
		if !args.accepts(st.grant.Grant) {
			continue
		}
		var doomed []authz.Origin
		survivors := 0
		for _, o := range st.origins {
			if o.Kind != domain.OriginSCIM {
				survivors++
				continue
			}
			key, ok := domain.ParseSCIMOriginSubject(o.Subject)
			if !ok {
				// A subject this package did not write. Fail loud rather than
				// guess: releasing the wrong origin removes somebody's access.
				return out, nil, fmt.Errorf(
					"service: grant %s carries an unparseable scim origin subject %q", id, o.Subject)
			}
			if args.match(key) {
				doomed = append(doomed, o)
				continue
			}
			survivors++
		}
		if len(doomed) == 0 {
			// Nothing of ours on this row. It is the honest remainder only if a
			// HUMAN put it there.
			if st.grant.Grant.Scope.Org == args.org && hasManualOrigin(st.origins) {
				out.ManualRemains = true
			}
			continue
		}

		// The lockout interplay, decided BEFORE the release so the conversion
		// and the release commit together.
		convert := false
		if survivors == 0 {
			cause, err := wouldLockOut(ctx, az, args.principal, st.grant.Grant)
			if err != nil {
				return out, nil, err
			}
			convert = cause
		}

		for _, o := range doomed {
			ok, err := az.ReleaseGrantOrigin(ctx, id, args.principal, o)
			if err != nil {
				return out, nil, err
			}
			if ok {
				out.Released++
			}
		}

		if convert {
			// Origin truth stays honest: the IdP DID withdraw it. The row
			// survives on a system-minted retention origin recording what
			// triggered the conversion, and the binding enters the attention
			// state naming the retained grant and principal.
			originID, err := newID("gor")
			if err != nil {
				return out, nil, err
			}
			retention := authz.Origin{
				Kind: domain.OriginLockoutRetention,
				Subject: domain.SCIMRetentionKey{
					Binding: args.binding, Cause: args.cause,
				}.Subject(),
			}
			if err := az.AddGrantOrigin(ctx, originID, id, args.principal, retention, now); err != nil {
				return out, nil, err
			}
			out.Retained = append(out.Retained, id)
			events = append(events,
				grantEventInput{
					typ:    audit.EventSCIMLockoutRetention,
					object: audit.Object{Type: "grant", ID: id},
					payload: audit.Payload{
						"binding":   args.binding,
						"principal": string(args.principal),
						"grant_id":  id,
						"cause":     string(args.cause),
					},
				},
				grantModifiedEvent(args, st.grant, doomed),
			)
			continue
		}

		remaining, err := az.GrantOriginCount(ctx, id)
		if err != nil {
			return out, nil, err
		}
		if remaining > 0 {
			out.ManualRemains = out.ManualRemains ||
				(st.grant.Grant.Scope.Org == args.org && hasManualOrigin(st.origins))
			events = append(events, grantModifiedEvent(args, st.grant, doomed))
			continue
		}
		if _, err := az.DeleteGrantRow(ctx, id, args.principal); err != nil {
			return out, nil, err
		}
		out.RowsRevoked++
		events = append(events, grantRevokedEvent(args, st.grant, doomed))
	}
	return out, events, nil
}

// wouldLockOut reports whether revoking this exact row would leave the org with
// no `manage-members` holder — the state the locked invariant refuses a human
// and this algorithm converts instead.
//
// Project-scope `manage-members` is not the invariant's subject, and neither is
// an instance grant: an org binding cannot touch instance grants, so the
// instance-scope invariant cannot arise here at all (§2.4).
func wouldLockOut(ctx context.Context, az *authz.TxAuthorizer, target domain.PrincipalID, g domain.Grant) (bool, error) {
	if g.Capability != domain.CapManageMembers {
		return false, nil
	}
	level, err := g.Scope.Level()
	if err != nil {
		return false, err
	}
	if level != domain.LevelOrg {
		return false, nil
	}
	remaining, err := remainingMemberManagers(ctx, az, target, g.Scope)
	if err != nil {
		return false, err
	}
	return remaining == 0, nil
}

func grantModifiedEvent(args releaseArgs, row authz.GrantRow, released []authz.Origin) grantEventInput {
	return grantEventInput{
		typ:     audit.EventGrantModified,
		object:  audit.Object{Type: "grant", ID: row.ID},
		payload: scimGrantPayload(args, row, released, false),
	}
}

func grantRevokedEvent(args releaseArgs, row authz.GrantRow, released []authz.Origin) grantEventInput {
	p := scimGrantPayload(args, row, released, true)
	p["origins_remaining"] = 0
	// The row died, so the generation advance and the session sweep happen —
	// either here, when authority moved, or unconditionally at the caller.
	p["sessions_revoked"] = true
	return grantEventInput{
		typ:     audit.EventGrantRevoked,
		object:  audit.Object{Type: "grant", ID: row.ID},
		payload: p,
	}
}

// scimGrantPayload renders the grant-lifecycle payload for a SCIM-side
// release, including the origin fields §10 adds to the `grant.*` category:
// which binding, which mapping row and which IdP group moved. That is what
// makes "why can they?" answerable from the trail and not only from the row.
func scimGrantPayload(args releaseArgs, row authz.GrantRow, released []authz.Origin, revoked bool) audit.Payload {
	p := audit.Payload{
		"target_principal": string(args.principal),
		"capability":       string(row.Grant.Capability),
		"scope":            renderScope(row.Grant.Scope),
		"origin_kind":      string(domain.OriginSCIM),
		"self_grant":       false,
		"unheld":           false,
		"target_class":     string(domain.ClassHuman),
		"origin_binding":   args.binding,
	}
	// One release can name several mapping rows on one grant (a user in two
	// mapped groups that both expand to the same capability). The event records
	// them sorted and de-duplicated so the trail is stable.
	rows, groups := map[string]bool{}, map[string]bool{}
	for _, o := range released {
		if key, ok := domain.ParseSCIMOriginSubject(o.Subject); ok {
			rows[key.MappingRow] = true
			groups[key.Group] = true
		}
	}
	p["origin_mapping_row"] = joinSorted(rows)
	p["origin_group"] = joinSorted(groups)
	_ = revoked
	return p
}

// hasManualOrigin reports whether a human put one of these origins there.
// Break-glass counts: it is a grant a human made under local host authority,
// and it is exactly as much of a remainder as an ordinary one.
func hasManualOrigin(origins []authz.Origin) bool {
	for _, o := range origins {
		if domain.IsMintableOrigin(o.Kind) {
			return true
		}
	}
	return false
}

func joinSorted(set map[string]bool) string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	joined := ""
	for i, s := range out {
		if i > 0 {
			joined += ","
		}
		joined += s
	}
	return joined
}

// cureLockoutRetentions is the deterministic-release half of §2.4: the moment a
// transaction leaves the org with another `manage-members` holder, that same
// transaction releases every `lockout-retention` origin whose cause is thereby
// cured.
//
// It runs at the END of any transaction that CREATED a `manage-members` grant —
// by a human through the ordinary grant surface, or by a sync — because that is
// the only event that can cure one. It walks every retention origin in the
// instance rather than only the addressed org, because an instance-scope
// `manage-members` grant cures every org at once and a per-org sweep would
// leave the rest standing while claiming to be deterministic.
// clearRetentionAttention lowers the `lockout_retention` state a cured
// retention raised. It is a CLOSURE rather than a (repos, proof) pair because
// break-glass has no principal and mints no proof at all: handing this function
// a nil proof would be the one forgeable value the proof model refuses by name,
// so a caller that cannot address the tenant's rows simply passes no closure.
type clearRetentionAttention func(ctx context.Context, binding, grantID string) ([]grantEventInput, error)

func cureLockoutRetentions(
	ctx context.Context, az *authz.TxAuthorizer, clear clearRetentionAttention,
	curingGrantID string, curing domain.Scope,
) ([]CureResult, []grantEventInput, error) {
	// Scope the sweep to what the curing grant can possibly cure. A project- or
	// environment-scoped `manage-members` row cures nothing — the census counts
	// org-or-above holders only — and sweeping every retention in the instance
	// for it would be tenant-triggerable O(instance) work AND a cross-tenant
	// timing signal.
	level, err := curing.Level()
	if err != nil {
		return nil, nil, err
	}
	if level == domain.LevelProject || level == domain.LevelEnv {
		return nil, nil, nil
	}
	// Bounded to the org an ORG-scope grant can actually cure. The unbounded
	// walk is reserved for an INSTANCE-scope grant, which genuinely cures every
	// org at once; running it for an org grant was tenant-triggerable
	// O(instance) work and a cross-tenant timing signal.
	held, err := az.LockoutRetentionsInOrg(ctx, curing.Org)
	if level == domain.LevelNone {
		held, err = az.LockoutRetentions(ctx)
	}
	if err != nil {
		return nil, nil, err
	}
	var cured []CureResult
	var events []grantEventInput
	for _, ret := range held {
		remaining, err := remainingMemberManagers(ctx, az, ret.Principal, ret.Grant.Scope)
		if err != nil {
			return nil, nil, err
		}
		if remaining == 0 {
			continue // still the last holder; the retention is still doing its job
		}
		if err := az.LockTargetPrincipal(ctx, ret.Principal); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				continue
			}
			return nil, nil, err
		}
		origin := authz.Origin{
			Kind: domain.OriginLockoutRetention,
			Subject: domain.SCIMRetentionKey{
				Binding: ret.Binding, Cause: ret.Cause,
			}.Subject(),
		}
		released, err := az.ReleaseGrantOrigin(ctx, ret.ID, ret.Principal, origin)
		if err != nil {
			return nil, nil, err
		}
		if !released {
			continue
		}
		count, err := az.GrantOriginCount(ctx, ret.ID)
		if err != nil {
			return nil, nil, err
		}
		// The retention was the row's last origin by construction — it was
		// minted because the release emptied the row — so the cure revokes it.
		// If something else has since joined the row, the row survives and the
		// cure is a modification, which is the truthful pair either way.
		// The origin arithmetic is visible on the grant category too (§10):
		// last-origin release is a revocation, a surviving row is a
		// modification. Emitting only the SCIM cure event would leave the
		// grant trail silent about a capability that just went away.
		lifecycle := grantEventInput{
			typ:    audit.EventGrantModified,
			object: audit.Object{Type: "grant", ID: ret.ID},
			payload: audit.Payload{
				"target_principal": string(ret.Principal),
				"capability":       string(ret.Grant.Capability),
				"scope":            renderScope(ret.Grant.Scope),
				"origin_kind":      string(domain.OriginLockoutRetention),
				"self_grant":       false,
				"unheld":           false,
				"target_class":     string(domain.ClassHuman),
				"origin_binding":   ret.Binding,
			},
		}
		if count == 0 {
			if _, err := az.DeleteGrantRow(ctx, ret.ID, ret.Principal); err != nil {
				return nil, nil, err
			}
			if err := az.AdvanceGeneration(ctx, ret.Principal); err != nil {
				return nil, nil, err
			}
			if err := az.RevokeAllSessionsFor(ctx, ret.Principal); err != nil {
				return nil, nil, err
			}
			lifecycle.typ = audit.EventGrantRevoked
			lifecycle.payload["origins_remaining"] = 0
			lifecycle.payload["sessions_revoked"] = true
		}
		cured = append(cured, CureResult{
			Binding: ret.Binding, Org: ret.Grant.Scope.Org, GrantID: ret.ID,
		})
		// §2.4's state, cleared in the SAME transaction that cured it and
		// through the AUDITED exit path — a `lockout_retention` warning
		// standing over a retention that no longer exists is a warning nobody
		// can act on, and every cure path reaches this line: the human grant
		// surface, the template path, break-glass and a sync alike.
		//
		// It runs under the caller's own proof, which addresses this org
		// because the sweep above is bounded to it. An INSTANCE-scope curing
		// grant is the one shape whose proof carries no chain and therefore
		// cannot address a tenant's rows; those bindings' rows are reconciled
		// by refreshBindingAttention on the next administration read, which is
		// the same audited exit path under the org admin's own proof.
		if level == domain.LevelOrg && clear != nil {
			evs, err := clear(ctx, ret.Binding, ret.ID)
			if err != nil {
				return nil, nil, err
			}
			events = append(events, evs...)
		}
		events = append(events, lifecycle, grantEventInput{
			typ:    audit.EventSCIMLockoutRetentionReleased,
			object: audit.Object{Type: "grant", ID: ret.ID},
			payload: audit.Payload{
				// Recovered from the origin itself: the retention outlives its
				// binding (§6 step 2), so no join could answer this and the
				// origin records it at conversion time instead.
				"binding":         ret.Binding,
				"principal":       string(ret.Principal),
				"grant_id":        ret.ID,
				"cause":           string(ret.Cause),
				"curing_grant_id": curingGrantID,
			},
		})
	}
	return cured, events, nil
}

// CureResult names one retention the cure released, so the caller can clear
// the binding's `lockout_retention` attention state through the AUDITED exit
// path rather than leaving it standing over a grant that is no longer retained.
type CureResult struct {
	Binding string
	Org     domain.OrgID
	GrantID string
}
