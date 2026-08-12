package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/tx"
)

// The SCIM ADMINISTRATION surface (#73): binding CRUD, mapping-table
// administration, credential mint/list/revoke, and the provisioned directory
// views. Domain surface with full UI<->CLI parity, every verb under
// `manage-members` held at ORG SCOPE EXACTLY (§1) — a mapping row causes grants
// the author need not hold, and unheld-capability granting is an org/instance
// power, so a project-scope member manager must not reach it through SCIM.

// SCIMBindingInput is a binding as the caller declares it. Everything in it is
// immutable after creation: the subject source and NameID profile by §5.1, the
// provider reference because a binding holds a READ-ONLY reference to it.
type SCIMBindingInput struct {
	ProviderKind domain.ProviderKind
	ProviderSlug string
	// SubjectSource is the SCIM attribute path carrying identity material.
	// `userName` is refused by name.
	SubjectSource string
	// The SAML NameID profile. Presence is carried separately from value
	// because the injective encoder distinguishes an absent qualifier from an
	// empty one, and collapsing them would make two SAML subjects collide.
	NameIDFormat             string
	NameIDQualifier          string
	NameIDQualifierPresent   bool
	NameIDSPQualifier        string
	NameIDSPQualifierPresent bool
}

// SCIMBindingView is one binding as the surface renders it, with the attention
// states that answer "what does SCIM think is wrong?" (§9).
type SCIMBindingView struct {
	ID                       string
	OrgID                    string
	ProviderKind             string
	ProviderSlug             string
	ProviderIssuer           string
	SubjectSource            string
	NameIDFormat             string
	NameIDQualifier          string
	NameIDQualifierPresent   bool
	NameIDSPQualifier        string
	NameIDSPQualifierPresent bool
	ConnectionPrincipalID    string
	LastContactAt            time.Time
	CreatedAt                time.Time
	Attention                []SCIMAttentionView
}

// SCIMAttentionView is one raised attention state with its cause.
type SCIMAttentionView struct {
	State      string
	SubjectRef string
	Cause      string
	EnteredAt  time.Time
	// Remediation is server-authored: the surface must name what to do, not
	// only what is wrong.
	Remediation string
}

// CreateBinding creates the per-org binding, its provisioning connection, and
// the connection's structural `scim-provision` grant — one transaction, because
// a connection without its grant is a principal that can do nothing and a grant
// without its connection is a row no origin holds.
func (s *SCIM) CreateBinding(ctx context.Context, actor Actor, org domain.OrgID, in SCIMBindingInput) (SCIMBindingView, error) {
	var out SCIMBindingView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		scope := domain.Scope{Org: org}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpSCIMBindingCreate, scope)
		if err != nil {
			return err
		}
		if !domain.IsProviderKind(in.ProviderKind) {
			return fmt.Errorf("%w: service: unknown provider kind %q", domain.ErrInvalid, in.ProviderKind)
		}
		if err := domain.CheckSubjectSource(in.SubjectSource); err != nil {
			return fmt.Errorf("%w: %s", ErrSCIMSubjectSource, err)
		}
		provider, err := s.referencedProvider(ctx, az, in)
		if err != nil {
			return err
		}

		now := s.now()
		bindingID, err := newID("scb")
		if err != nil {
			return err
		}
		principalID, err := newID("prn")
		if err != nil {
			return err
		}
		// The principal first: the binding row references it, and it carries
		// its class at INSERT so it is never briefly unclassified.
		if err := az.CreateProvisioningPrincipal(ctx, domain.PrincipalID(principalID), now); err != nil {
			return err
		}
		if err := r.SCIM().CreateBinding(ctx, p, store.NewSCIMBinding{
			ID:                       bindingID,
			ProviderKind:             string(in.ProviderKind),
			ProviderID:               provider.id,
			ProviderSlug:             in.ProviderSlug,
			ProviderIssuer:           provider.issuer,
			SubjectSource:            in.SubjectSource,
			NameIDFormat:             in.NameIDFormat,
			NameIDQualifier:          in.NameIDQualifier,
			NameIDQualifierPresent:   in.NameIDQualifierPresent,
			NameIDSPQualifier:        in.NameIDSPQualifier,
			NameIDSPQualifierPresent: in.NameIDSPQualifierPresent,
			ConnectionPrincipalID:    principalID,
			CreatedAt:                now,
		}); err != nil {
			// The uniqueness constraint arbitrates the concurrent-create race
			// (§1): one row wins, the loser fails closed with the named
			// conflict rather than being reconciled in application code.
			return err
		}
		grant, err := structuralGrant(ctx, az, domain.PrincipalID(principalID), scope, bindingID, now)
		if err != nil {
			return err
		}

		b, err := r.SCIM().Binding(ctx, p, bindingID)
		if err != nil {
			return err
		}
		c := scimContext{proof: p, binding: b}
		events := []grantEventInput{{
			typ:    audit.EventSCIMBindingCreated,
			object: audit.Object{Type: "scim-binding", ID: bindingID},
			payload: audit.Payload{
				"org":          string(org),
				"provider_ref": provider.id,
				"actor":        string(caller.Principal),
			},
		}, {
			typ:    audit.EventGrantCreated,
			object: audit.Object{Type: "grant", ID: grant.GrantID},
			payload: audit.Payload{
				"target_principal": principalID,
				"capability":       string(domain.CapSCIMProvision),
				"scope":            renderScope(scope),
				"origin_kind":      string(domain.OriginStructural),
				"self_grant":       false,
				"unheld":           false,
				"target_class":     string(domain.ClassProvisioning),
				"origin_binding":   bindingID,
			},
		}}
		// Both states reconciled at creation, in both directions: a binding
		// created against an already-disabled provider must say so immediately
		// rather than at the next list, and a brand-new binding is not stale
		// until the threshold elapses.
		attention, err := s.refreshBindingAttention(ctx, r, az, c, now)
		if err != nil {
			return err
		}
		events = append(events, attention...)
		// Render the states this transaction actually raised, not an empty
		// list: the create response is where an operator learns the binding is
		// waiting for its first push and has no credential yet.
		raised, err := r.SCIM().Attention(ctx, p, bindingID)
		if err != nil {
			return err
		}
		out = bindingView(b, raised)
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelOrg, events...)
	})
	return out, err
}

// referencedProvider resolves the provider a binding names and freezes its
// issuer into the binding. Creating a binding grants no authority over the
// provider — this is a read — but a binding pointing at a provider that is not
// there could never derive a subject the login path would compute.
//
// It returns the provider's ROW id too, which is what the audit trail records
// as `provider_ref`: a slug is a mutable address, and a provider recreated
// under the same slug would otherwise read as if nothing had changed.
func (s *SCIM) referencedProvider(ctx context.Context, az *authz.TxAuthorizer, in SCIMBindingInput) (providerFacts, error) {
	missing := fmt.Errorf("%w: service: no such identity provider", domain.ErrInvalid)
	switch in.ProviderKind {
	case domain.ProviderOIDC:
		p, err := az.ProviderBySlug(ctx, in.ProviderSlug)
		if errors.Is(err, domain.ErrNotFound) {
			return providerFacts{}, missing
		}
		if err != nil {
			return providerFacts{}, err
		}
		return providerFacts{id: p.ID, issuer: p.Issuer}, nil
	default:
		p, err := az.SAMLProviderBySlug(ctx, in.ProviderSlug)
		if errors.Is(err, domain.ErrNotFound) {
			return providerFacts{}, missing
		}
		if err != nil {
			return providerFacts{}, err
		}
		return providerFacts{
			id: p.ID, issuer: p.EntityID, allowEmailNameID: p.AllowEmailNameID,
		}, nil
	}
}

// structuralGrant writes the provisioning connection's own `scim-provision`
// grant, carrying the `structural(binding)` origin.
//
// It does NOT go through grantOne, and the reason is the point of §7: this
// grant has no GRANTOR whose authority could be evaluated. It is system-created
// with the binding and retired with it, and the ordinary grant API refuses
// `scim-provision` to every principal by name (ErrSystemCreatedOnly) precisely
// so this is the only path that can write it. What it does keep is every rule
// that is about the TARGET rather than the granter: the principal-row lock, the
// class, and the normative allowlist — asked here directly because
// checkPrincipalClass's job is to refuse this capability everywhere else.
func structuralGrant(
	ctx context.Context, az *authz.TxAuthorizer, target domain.PrincipalID,
	scope domain.Scope, bindingID string, now time.Time,
) (GrantResult, error) {
	if err := az.LockTargetPrincipal(ctx, target); err != nil {
		return GrantResult{}, err
	}
	class, err := az.PrincipalClass(ctx, target)
	if err != nil {
		return GrantResult{}, err
	}
	if class != domain.ClassProvisioning {
		return GrantResult{}, fmt.Errorf("%w: service: only a provisioning connection may hold %q",
			ErrMachineCapability, domain.CapSCIMProvision)
	}
	if !domain.MachineMayHold(class, domain.CapSCIMProvision) {
		return GrantResult{}, fmt.Errorf("%w: class %q may not hold %q",
			ErrMachineCapability, class, domain.CapSCIMProvision)
	}
	if err := checkMachineScope(class, scope); err != nil {
		return GrantResult{}, err
	}
	return writeGrantRow(ctx, az, GrantSpec{
		Target: target, Capability: domain.CapSCIMProvision, Scope: scope,
	}, authz.Origin{Kind: domain.OriginStructural, Subject: bindingID}, now)
}

// ListBindings returns the org's bindings with their attention states, keeping
// the provider-availability and staleness states current in both directions.
func (s *SCIM) ListBindings(ctx context.Context, actor Actor, org domain.OrgID) ([]SCIMBindingView, error) {
	var out []SCIMBindingView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		scope := domain.Scope{Org: org}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpSCIMBindingList, scope)
		if err != nil {
			return err
		}
		bindings, err := r.SCIM().Bindings(ctx, p)
		if err != nil {
			return err
		}
		now := s.now()
		var events []grantEventInput
		for _, b := range bindings {
			c := scimContext{proof: p, binding: b}
			ev, err := s.refreshBindingAttention(ctx, r, az, c, now)
			if err != nil {
				return err
			}
			events = append(events, ev...)
			rows, err := r.SCIM().Attention(ctx, p, b.ID)
			if err != nil {
				return err
			}
			out = append(out, bindingView(b, rows))
		}
		events = append(events, adminReadEvent(string(org), "", "binding", len(out)))
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelOrg, events...)
	})
	return out, err
}

// GetBinding returns one binding. It deliberately does NOT require a live
// provider: "state is preserved for repair" is not preserved by a surface that
// refuses to show the state (§1).
func (s *SCIM) GetBinding(ctx context.Context, actor Actor, org domain.OrgID, id string) (SCIMBindingView, error) {
	var out SCIMBindingView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		scope := domain.Scope{Org: org}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpSCIMBindingGet, scope)
		if err != nil {
			return err
		}
		c, err := s.loadBinding(ctx, r, az, p, id, false)
		if err != nil {
			return err
		}
		now := s.now()
		events, err := s.refreshBindingAttention(ctx, r, az, c, now)
		if err != nil {
			return err
		}
		rows, err := r.SCIM().Attention(ctx, p, id)
		if err != nil {
			return err
		}
		out = bindingView(c.binding, rows)
		events = append(events, adminReadEvent(string(org), id, "binding", 1))
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelOrg, events...)
	})
	return out, err
}

func (s *SCIM) refreshBindingAttention(
	ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time,
) ([]grantEventInput, error) {
	events, err := s.reconcileProviderAttention(ctx, r, az, c, now)
	if err != nil {
		return nil, err
	}
	stale, err := s.reconcileStaleness(ctx, r, c, now)
	if err != nil {
		return nil, err
	}
	events = append(events, stale...)
	restored, err := s.reconcilePostRestore(ctx, r, az, c, now)
	if err != nil {
		return nil, err
	}
	events = append(events, restored...)
	cured, err := s.reconcileLockoutAttention(ctx, r, az, c)
	if err != nil {
		return nil, err
	}
	return append(events, cured...), nil
}

// reconcilePostRestore raises §9.1's post-restore state.
//
// A restore is not an operation this tree performs — #76 owns the
// quarantine/commit flow — but it leaves one observable trace HERE: every
// credential the backup carried was minted under an older instance credential
// epoch, and is therefore permanently dead by presentation. A binding that has
// credentials and none at the current epoch has been restored and not yet
// re-minted, which is exactly the ADR's entry condition.
//
// The EXIT is already implemented and deliberately not here: the wire clears it
// on the first authenticated request, which is re-mint (a live credential
// exists) plus the first completed re-assertion cycle (the identity provider
// actually called). Entering it on an administration read and leaving it on a
// wire request is the pair §9 requires, and without an entry path the state was
// an enum value nothing could ever raise.
func (s *SCIM) reconcilePostRestore(
	ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time,
) ([]grantEventInput, error) {
	creds, err := r.SCIM().Credentials(ctx, c.proof, c.binding.ID)
	if err != nil {
		return nil, err
	}
	// REVOKED credentials are not evidence of anything. An administrator who
	// mints, revokes, and later sees the instance epoch advance for an
	// unrelated reason has not restored a backup, and a state raised on that
	// shape would be a warning about an event that did not happen. The trace
	// this is looking for is a credential that WOULD be live except that its
	// epoch is stale.
	unrevoked := 0
	current := 0
	epoch, err := az.CredentialEpoch(ctx)
	if err != nil {
		return nil, err
	}
	for _, cred := range creds {
		if !cred.RevokedAt.IsZero() {
			continue
		}
		unrevoked++
		if cred.CredentialEpoch == epoch {
			current++
		}
	}
	if unrevoked == 0 || current > 0 {
		// Never minted (or every credential deliberately retired), or an
		// administrator has already re-minted under the current epoch.
		return nil, nil
	}
	return s.enterAttention(ctx, r, c, domain.AttentionPostRestore, "", domain.CauseReactivation, now)
}

// reconcileLockoutAttention lowers any `lockout_retention` state standing over a
// grant that no longer carries a retention origin.
//
// The cure that released it normally clears the state in its own transaction
// (§2.4, cureLockoutRetentions). Two shapes cannot: a cure driven by an
// INSTANCE-scope `manage-members` grant, whose proof carries no chain and so
// cannot address a tenant's rows, and break-glass, which has no principal and
// mints no proof at all. Both are exactly the emergencies that produce a cure,
// so leaving the warning standing would mean the org admin's first look after
// an incident shows a lockout that is already over.
//
// This is the same AUDITED exit path, under the administrator's own proof, on
// the surface where the state is read. It is reconciliation, not a second
// implementation of the cure: it releases nothing and decides nothing — it only
// stops describing a retention that is gone.
func (s *SCIM) reconcileLockoutAttention(
	ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext,
) ([]grantEventInput, error) {
	rows, err := r.SCIM().Attention(ctx, c.proof, c.binding.ID)
	if err != nil {
		return nil, err
	}
	var events []grantEventInput
	for _, row := range rows {
		if row.State != string(domain.AttentionLockoutRetention) || row.SubjectRef == "" {
			continue
		}
		origins, err := az.GrantOriginsFor(ctx, row.SubjectRef)
		if err != nil {
			return nil, err
		}
		retained := false
		for _, o := range origins {
			if o.Kind == domain.OriginLockoutRetention {
				retained = true
				break
			}
		}
		if retained {
			continue
		}
		ev, err := s.clearAttention(ctx, r, c,
			domain.AttentionLockoutRetention, row.SubjectRef, domain.CauseReactivation)
		if err != nil {
			return nil, err
		}
		events = append(events, ev...)
	}
	return events, nil
}

// DeleteBinding runs §6's atomic state machine, in the ADR's order:
//
//  1. revoke every credential — no new wire transaction can begin, and an
//     in-flight one fails at its next proof;
//  2. release every `scim` origin the binding holds, under §2.4 — lockout
//     conversion applies, and any resulting `lockout-retention` origins SURVIVE
//     the binding with their cause recorded, still cured by adding another
//     `manage-members` holder;
//  3. retire the provisioning connection: release the `structural(binding)`
//     origin, revoking the `scim-provision` grant, and delete the principal —
//     atomically with the directory resources, mapping table and binding row;
//  4. identity links SURVIVE. They are account property, exactly as they would
//     be had the user been invited; unlinking remains the account-security
//     mutation it always was, and nothing here touches it.
func (s *SCIM) DeleteBinding(ctx context.Context, actor Actor, org domain.OrgID, id string) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		scope := domain.Scope{Org: org}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpSCIMBindingDelete, scope)
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
		unlock, err := lockBindingRow(ctx, r, p, id)
		if err != nil {
			return err
		}
		defer unlock()
		c, err := s.loadBinding(ctx, r, az, p, id, false)
		if err != nil {
			return err
		}
		now := s.now()

		// (1) credentials first. The count is not in the payload: §10's field
		// list for this event is "org, provider ref, actor", and how many
		// credentials died is already one `scim.credential_revoked` per
		// credential — recorded once, where the ADR puts it.
		//
		// Each phase is marked AFTER its work, carrying WHAT IT DID. A label
		// emitted before the mutation proves only that the code reached a line,
		// which a wrong implementation satisfies just as well as a right one;
		// a label emitted after, carrying the count, is a statement about state.
		revoked, err := r.SCIM().RevokeCredentialsForBinding(ctx, p, id, now)
		if err != nil {
			return err
		}
		markSCIMPhaseN("credentials-revoked", int(revoked))

		// (2) every origin the binding holds, for every user it provisioned.
		users, err := r.SCIM().Users(ctx, p, id)
		if err != nil {
			return err
		}
		var events []grantEventInput
		releasedOrigins := 0
		for _, u := range users {
			principal, err := principalForAccount(ctx, az, u.AccountID)
			if err != nil {
				return err
			}
			outcome, evs, err := releaseSCIMOrigins(ctx, az, now, releaseArgs{
				binding: id, org: org, principal: principal,
				match: matchBinding(id), cause: domain.CauseBindingDelete,
			})
			if err != nil {
				return err
			}
			events = append(events, evs...)
			releasedOrigins += outcome.Released
			if outcome.AuthorityChanged() {
				if err := advanceAndSweep(ctx, az, principal); err != nil {
					return err
				}
			}
			for _, grantID := range outcome.Retained {
				ev, err := s.enterAttention(ctx, r, c,
					domain.AttentionLockoutRetention, grantID, domain.CauseBindingDelete, now)
				if err != nil {
					return err
				}
				events = append(events, ev...)
			}
		}

		markSCIMPhaseN("origins-released", releasedOrigins)

		// (3) the connection's structural origin, then the principal, then the
		// binding's own rows. The RESTRICT foreign key on grant_origins is what
		// makes the ordering a database fact rather than a comment.
		connection := domain.PrincipalID(c.binding.ConnectionPrincipalID)
		structural, err := releaseStructural(ctx, az, connection, id)
		if err != nil {
			return err
		}
		events = append(events, structural...)
		markSCIMPhaseN("connection-retired", len(structural))

		directory := len(users)
		if err := r.SCIM().DeleteGroupMembersForBinding(ctx, p, id); err != nil {
			return err
		}
		if err := r.SCIM().DeleteGroupsForBinding(ctx, p, id); err != nil {
			return err
		}
		if err := r.SCIM().DeleteUsersForBinding(ctx, p, id); err != nil {
			return err
		}
		if err := r.SCIM().DeleteMappingsForBinding(ctx, p, id); err != nil {
			return err
		}
		// Every raised state is cleared through the audited exit path BEFORE the
		// rows go. A bulk delete erases states that were entered in this very
		// transaction (a lockout conversion, say) leaving an entry event with
		// no exit — and §9 requires the pair.
		raised, err := r.SCIM().Attention(ctx, p, id)
		if err != nil {
			return err
		}
		for _, a := range raised {
			ev, err := s.clearAttention(ctx, r, c,
				domain.SCIMAttention(a.State), a.SubjectRef, domain.CauseBindingDelete)
			if err != nil {
				return err
			}
			events = append(events, ev...)
		}
		if err := r.SCIM().DeleteAttentionForBinding(ctx, p, id); err != nil {
			return err
		}
		if err := r.SCIM().DeleteCredentialsForBinding(ctx, p, id); err != nil {
			return err
		}
		markSCIMPhaseN("directory-deleted", directory)
		if err := r.SCIM().DeleteBinding(ctx, p, id); err != nil {
			return err
		}
		markSCIMPhaseN("binding-deleted", 1)
		// The connection is retired under the same PROOF, after its binding row
		// is gone (that row references it). `connection` was read from the
		// binding under this proof, and the statement can only remove a
		// provisioning connection no binding still owns — so neither half is a
		// caller-controlled delete-any-principal-by-id.
		if _, err := r.SCIM().RetireConnectionPrincipal(ctx, p, connection); err != nil {
			return err
		}

		events = append(events, grantEventInput{
			typ:    audit.EventSCIMBindingDeleted,
			object: audit.Object{Type: "scim-binding", ID: id},
			payload: audit.Payload{
				"org":          string(org),
				"provider_ref": c.providerID,
				"actor":        string(caller.Principal),
			},
		})
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelOrg, events...)
	})
}

// releaseStructural releases the `structural(binding)` origin and revokes the
// grant it held. The connection principal is deleted by the caller in the same
// transaction; a structural origin never converts to lockout retention, because
// `scim-provision` is not `manage-members`.
func releaseStructural(
	ctx context.Context, az *authz.TxAuthorizer, connection domain.PrincipalID, bindingID string,
) ([]grantEventInput, error) {
	if err := az.LockTargetPrincipal(ctx, connection); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	rows, err := az.GrantOriginsForPrincipal(ctx, connection)
	if err != nil {
		return nil, err
	}
	origin := authz.Origin{Kind: domain.OriginStructural, Subject: bindingID}
	var events []grantEventInput
	seen := map[string]bool{}
	for _, row := range rows {
		if row.Origin != origin || seen[row.ID] {
			continue
		}
		seen[row.ID] = true
		if _, err := az.ReleaseGrantOrigin(ctx, row.ID, connection, origin); err != nil {
			return nil, err
		}
		remaining, err := az.GrantOriginCount(ctx, row.ID)
		if err != nil {
			return nil, err
		}
		if remaining > 0 {
			return nil, fmt.Errorf(
				"service: the provisioning connection's grant %s still has %d origins after its structural release",
				row.ID, remaining)
		}
		if _, err := az.DeleteGrantRow(ctx, row.ID, connection); err != nil {
			return nil, err
		}
		events = append(events, grantEventInput{
			typ:    audit.EventGrantRevoked,
			object: audit.Object{Type: "grant", ID: row.ID},
			payload: audit.Payload{
				"target_principal":  string(connection),
				"capability":        string(row.Grant.Capability),
				"scope":             renderScope(row.Grant.Scope),
				"origin_kind":       string(domain.OriginStructural),
				"self_grant":        false,
				"unheld":            false,
				"target_class":      string(domain.ClassProvisioning),
				"origin_binding":    bindingID,
				"origins_remaining": 0,
				"sessions_revoked":  false,
			},
		})
	}
	return events, nil
}

// advanceAndSweep is the locked "revocation is immediate" pair: the generation
// advance and the session-row deletion, committing with the grant change so an
// open session dies with the capability rather than at token expiry.
func advanceAndSweep(ctx context.Context, az *authz.TxAuthorizer, p domain.PrincipalID) error {
	if err := az.AdvanceGeneration(ctx, p); err != nil {
		return err
	}
	return az.RevokeAllSessionsFor(ctx, p)
}

// principalForAccount resolves the principal a provisioned account's grants
// hang off. It rides the resolution surface, like every other account read.
func principalForAccount(ctx context.Context, az *authz.TxAuthorizer, accountID string) (domain.PrincipalID, error) {
	a, err := az.AccountByID(ctx, accountID)
	if err != nil {
		return "", err
	}
	return a.PrincipalID, nil
}

func bindingView(b store.SCIMBinding, attention []store.SCIMAttentionRow) SCIMBindingView {
	out := SCIMBindingView{
		ID: b.ID, OrgID: b.OrgID, ProviderKind: b.ProviderKind,
		ProviderSlug: b.ProviderSlug, ProviderIssuer: b.ProviderIssuer,
		SubjectSource: b.SubjectSource,
		// The whole NameID profile, not just the Format: it is immutable at
		// creation, so a surface that cannot show it cannot show what the
		// binding actually is — and presence is carried separately because the
		// injective encoder distinguishes absent from empty.
		NameIDFormat:             b.NameIDFormat,
		NameIDQualifier:          b.NameIDQualifier,
		NameIDQualifierPresent:   b.NameIDQualifierPresent,
		NameIDSPQualifier:        b.NameIDSPQualifier,
		NameIDSPQualifierPresent: b.NameIDSPQualifierPresent,
		ConnectionPrincipalID:    b.ConnectionPrincipalID,
		LastContactAt:            b.LastContactAt, CreatedAt: b.CreatedAt,
	}
	for _, a := range attention {
		out.Attention = append(out.Attention, SCIMAttentionView{
			State: a.State, SubjectRef: a.SubjectRef, Cause: a.Cause,
			EnteredAt: a.EnteredAt, Remediation: attentionRemediation(domain.SCIMAttention(a.State)),
		})
	}
	return out
}

// attentionRemediation is the server-authored "what to do about it" for each
// state. The ADR requires every attention state to name cause AND remediation;
// a state that only says something is wrong makes the binding view a puzzle.
func attentionRemediation(state domain.SCIMAttention) string {
	switch state {
	case domain.AttentionProviderUnavailable:
		return "The identity provider this binding references is disabled, removed, or has changed its issuer. The whole SCIM wire surface refuses until it is restored; nothing has been deleted."
	case domain.AttentionLockoutRetention:
		return "The identity provider withdrew the org's last manage-members grant. It is retained so the org stays administrable. Grant manage-members to another principal and the retention releases itself."
	case domain.AttentionManualGrantsRemain:
		return "The identity provider deprovisioned this user, but grants made by hand in this org remain. They are still usable, including after a fresh login through this or any other linked provider: push-only SCIM cannot prove the provider will refuse SSO, so this claims nothing it cannot observe. A human must decide about the remainder — review and revoke if that is not what you want."
	case domain.AttentionInertMapping:
		return "A mapping row names a group that no longer exists at the identity provider. It grants nothing; edit it to point at a live group, or delete it."
	case domain.AttentionStale:
		return "No contact from the identity provider within the staleness threshold. Hikyo never calls out; repair is the provider's own reconciliation cycle."
	case domain.AttentionPostRestore:
		return "This binding came back from a restore. Its credentials are permanently dead: re-mint, then let the provider's next cycle re-assert its users and groups."
	default:
		return ""
	}
}
