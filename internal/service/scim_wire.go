package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/scimproto"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// The SCIM WIRE surface (#73 §5, §6, §8): the IdP's own protocol path. Every
// operation authenticates a provisioning credential, proves it matches the
// binding in the path, authorizes `scim-provision(org)`, and applies DESIRED
// STATE — never event replay, which is what makes §5.4's transition table a
// table of states rather than a list of messages.

// resolveSCIMCredential authenticates a presented provisioning credential.
//
// Uniform failure is the point: unknown, malformed, revoked, expired,
// epoch-superseded and wrong-binding all answer ErrUnauthenticated, so
// presentation reveals nothing about which credentials exist. The one thing
// that is NOT uniform is the binding mismatch's own sentinel, which exists so
// the audit trail can record it — the response is identical either way.
func resolveSCIMCredential(ctx context.Context, az *authz.TxAuthorizer, a Actor, now time.Time) (authz.Identity, error) {
	identity, bindingID, err := az.AuthenticateSCIMCaller(ctx, a.scimToken, now)
	if err != nil {
		return authz.Identity{}, err
	}
	if bindingID != a.scimBinding {
		// §8 requires the mismatch to be AUDITED. The event is NOT written here:
		// this transaction is about to fail, and an event inside a rolled-back
		// transaction is not a record. wireTx writes it afterwards, in its own
		// transaction, which is what makes it durable.
		return authz.Identity{}, mismatchError{credential: identity.CredentialID, binding: a.scimBinding}
	}
	if err := az.TouchSCIMCredential(ctx, identity.CredentialID, now); err != nil {
		return authz.Identity{}, err
	}
	return identity, nil
}

// mismatchError carries the credential and binding a refused presentation
// named, so wireTx can write the durable record after the failed transaction.
// It answers ErrSCIMBindingMismatch to every caller, so the response is the
// uniform authentication failure regardless.
type mismatchError struct{ credential, binding string }

func (mismatchError) Error() string { return ErrSCIMBindingMismatch.Error() }
func (mismatchError) Unwrap() error { return ErrSCIMBindingMismatch }

// recordMismatch writes the durable refusal record in its OWN transaction.
func (s *SCIM) recordMismatch(ctx context.Context, m mismatchError) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		e, err := newAuditEvent(ctx, audit.EventSCIMCredentialRefused, "",
			audit.Object{Type: "scim-binding", ID: m.binding}, audit.OutcomeFailure, "",
			audit.Payload{
				"binding": m.binding, "credential_id": m.credential, "cause": "binding-mismatch",
			})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
}

// wireTx is the shape every wire operation shares: authenticate, authorize,
// load the binding (failing closed if its provider is gone), serialize on the
// binding row, and record contact.
//
// Per-binding writes SERIALIZE (§9): the binding row lock is taken as the
// first statement of every wire transaction, which keeps a single binding's
// origin arithmetic trivially race-free. Across bindings, contention on a
// shared grant row is real and is handled at the row — unique origin keys plus
// serializable transactions with bounded retry.
//
// The discovery operation stops after the preamble: no events, no attention
// reconciliation (§10; see SCIM.Discovery).
func (s *SCIM) wireTx(
	ctx context.Context, actor Actor, org domain.OrgID, bindingID string, op authz.Operation,
	body func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time) ([]grantEventInput, error),
) error {
	err := s.wireTxOnce(ctx, actor, org, bindingID, op, body)
	var mismatch mismatchError
	if errors.As(err, &mismatch) {
		if rerr := s.recordMismatch(ctx, mismatch); rerr != nil {
			return rerr
		}
		return ErrSCIMBindingMismatch
	}
	return err
}

func (s *SCIM) wireTxOnce(
	ctx context.Context, actor Actor, org domain.OrgID, bindingID string, op authz.Operation,
	body func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time) ([]grantEventInput, error),
) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		now := s.now()
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, op, domain.Scope{Org: org})
		if err != nil {
			return err
		}
		c, err := s.loadBinding(ctx, r, az, p, bindingID, true)
		if err != nil {
			return err
		}
		// Contact is recorded HERE, before the body, and that placement is the
		// serialization (§9) rather than a detail of when the clock is stamped.
		// It is an UPDATE on the binding row, so it takes the row's write lock
		// and holds it to commit: two concurrent wire transactions on ONE
		// binding serialize behind it, which is what makes that binding's
		// origin arithmetic trivially race-free. A plain SELECT would not have
		// done it, and the earlier shape — touching the row on the way out —
		// left the whole body unserialized on postgres while claiming
		// otherwise. sqlite serializes on its single writer either way.
		//
		// Recorded on the READS too: the IdP walking the directory IS contact,
		// and a staleness warning that only cleared on a write would flag a
		// healthy read-only reconciliation cycle.
		if err := r.SCIM().TouchBinding(ctx, p, bindingID, now); err != nil {
			return err
		}
		markSCIMPhase("wire-enter:" + bindingID)
		defer markSCIMPhase("wire-exit:" + bindingID)
		events, err := body(ctx, r, az, c, now)
		if err != nil {
			return err
		}
		// DISCOVERY (§10) stops here: everything above — authentication,
		// authorization, the binding load, the serialization lock and the
		// contact record — happens, and nothing below does. No attention
		// reconciliation, no audit event. See SCIM.Discovery.
		if op == authz.OpSCIMDiscovery {
			return nil
		}
		cleared, err := s.clearAttention(ctx, r, c, domain.AttentionStale, "", "")
		if err != nil {
			return err
		}
		events = append(events, cleared...)
		// The post-restore state exits at re-mint PLUS the first completed
		// re-assertion cycle (§9.1). The credential that authenticated this
		// request is live and this is the IdP asserting, so both halves have
		// now happened.
		restored, err := s.clearAttention(ctx, r, c, domain.AttentionPostRestore, "", "")
		if err != nil {
			return err
		}
		events = append(events, restored...)
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelOrg, events...)
	})
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

// SCIMUserResource is one provisioned user as the wire renders it.
type SCIMUserResource struct {
	ID         string
	ExternalID string
	UserName   string
	Active     bool
	Groups     []string
	Attributes map[string]any
	// Schemas is the `schemas` array this resource declares: the core User
	// schema plus every extension THIS BINDING declared that the resource
	// actually carries. It is computed here, beside the binding, rather than
	// in the transport — the transport cannot know what a binding declared,
	// and a resource declaring a schema discovery does not describe is the
	// half-implemented state §8 forbids.
	Schemas   []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SCIMUserInput is a create or a full replacement. It is DESIRED STATE: PUT is
// RFC replacement, so an omitted mutable attribute clears to its default and an
// omitted `active` defaults TRUE, which reactivates.
type SCIMUserInput struct {
	UserName   string
	ExternalID string
	// Active is a pointer so "omitted" and "explicitly false" stay different
	// inputs at this boundary; PUT resolves omitted to true, PATCH leaves it.
	Active *bool
	// SubjectRaw is the value found at the binding's declared subject-source
	// attribute path. It is raw IdP material; deriveSubject turns it into the
	// byte-exact subject the login path computes.
	//
	// The WIRE never sets it: it sets Resource, and the service reads the value
	// out at the binding's declared path. Below-the-wire callers (fixtures,
	// and anything that already knows the identity material) set it directly.
	// Keeping the extraction on this side means "what the subject source means"
	// exists once, beside the binding that declares it, rather than in a
	// transport that would need its own copy of the binding to know.
	SubjectRaw string
	// Resource is the decoded SCIM resource, when the caller is the wire.
	Resource map[string]any
	// Attributes is everything else, round-tripped as display metadata. A nil
	// VALUE inside it is an explicit CLEAR; an absent key is an omission. PUT
	// replaces the whole map; PATCH merges into the stored one.
	Attributes map[string]any
	// ExternalIDCleared marks an EXPLICIT removal of `externalId` (the PATCH
	// `remove externalId` cell), which is a different request from omitting it.
	// Without presence state the two collapsed onto `ExternalID == ""`, so an
	// explicit removal became a silent no-op on a mutable field — and, worse,
	// silently SUCCEEDED against a subject-source binding instead of refusing
	// the identity mutation with `mutability`.
	ExternalIDCleared bool
	// Patch marks a partial update. PUT is RFC replacement and PATCH is a
	// delta, and collapsing the two made every PATCH drop every attribute it
	// did not mention.
	Patch bool
}

// CreateUser is §5.2: an account with its external identity ALREADY BOUND —
// no invitation token, no credential-establishment authority, no session, no
// assurance — and ZERO grants beyond what the user's current group memberships
// and the mapping table produce.
//
// Idempotent attach, no cross-org oracle (§5.2 under the #23 amendment): if the
// asserted identity already exists instance-wide, this attaches that account.
// Both legs follow ONE query path and return a byte-shape-identical resource,
// so a caller cannot tell a fresh create from an attach — which is the whole
// point, because "it existed already" would otherwise be a cross-org oracle.
func (s *SCIM) CreateUser(ctx context.Context, actor Actor, org domain.OrgID, bindingID string, in SCIMUserInput) (SCIMUserResource, error) {
	var out SCIMUserResource
	err := s.wireTx(ctx, actor, org, bindingID, authz.OpSCIMUserCreate,
		func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time) ([]grantEventInput, error) {
			if in.UserName == "" {
				return nil, ErrSCIMUserNameRequired
			}
			subject, err := s.deriveSubject(c, subjectMaterial(c, in))
			if err != nil {
				return nil, err
			}
			// Duplicate userName inside this binding is `uniqueness`.
			if _, err := r.SCIM().UserByUserName(ctx, c.proof, bindingID, fold(in.UserName)); err == nil {
				return nil, ErrSCIMUniqueness
			} else if !errors.Is(err, domain.ErrNotFound) {
				return nil, err
			}
			if _, err := r.SCIM().UserBySubject(ctx, c.proof, bindingID, subject); err == nil {
				return nil, ErrSCIMUniqueness
			} else if !errors.Is(err, domain.ErrNotFound) {
				return nil, err
			}

			accountID, disposition, err := s.attachOrCreateAccount(ctx, az, c, subject, in, now)
			if err != nil {
				return nil, err
			}
			id, err := newID("scu")
			if err != nil {
				return nil, err
			}
			if err := c.checkDeclaredSchemas(in.Attributes); err != nil {
				return nil, err
			}
			attrs, err := marshalAttributes(in.Attributes)
			if err != nil {
				return nil, err
			}
			active := true
			if in.Active != nil {
				active = *in.Active
			}
			if err := r.SCIM().CreateUser(ctx, c.proof, store.NewSCIMUser{
				ID: id, BindingID: bindingID, AccountID: accountID,
				UserName: in.UserName, UserNameLower: fold(in.UserName),
				ExternalID: in.ExternalID, Subject: subject, Active: active,
				Attributes: attrs, CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				return nil, err
			}
			row, err := r.SCIM().User(ctx, c.proof, bindingID, id)
			if err != nil {
				return nil, err
			}
			// Grants come ONLY from group mappings. A pushed user with no
			// mapped groups authenticates and sees nothing — the same
			// zero-grant posture as JIT.
			principal, err := principalForAccount(ctx, az, accountID)
			if err != nil {
				return nil, err
			}
			mappings, err := s.desiredMappings(ctx, r, c, id)
			if err != nil {
				return nil, err
			}
			events, _, err := s.applyMappings(ctx, r, az, c, principal, mappings, now)
			if err != nil {
				return nil, err
			}
			out, err = s.renderUser(ctx, r, c, row)
			if err != nil {
				return nil, err
			}
			return append(events, grantEventInput{
				typ:    audit.EventSCIMUserProvisioned,
				object: audit.Object{Type: "scim-user", ID: id},
				payload: audit.Payload{
					"binding": bindingID, "resource_id": id, "account_id": accountID,
					"disposition": disposition, "subject_digest": subjectDigest(subject),
				},
			}), nil
		})
	return out, err
}

// attachOrCreateAccount is the ONE query path §5.2 requires: instance-wide
// identity lookup, exactly what the login path already does, followed by either
// an attach or a create. It never runs through a tenant-scoped store, and it
// takes the same branch structure whether the identity exists or not, so the
// timing discipline #23 claims composes.
func (s *SCIM) attachOrCreateAccount(
	ctx context.Context, az *authz.TxAuthorizer, c scimContext,
	subject string, in SCIMUserInput, now time.Time,
) (accountID, disposition string, err error) {
	kind := identityKind(c.binding)
	link, err := az.ExternalIdentityByKey(ctx, kind, c.binding.ProviderIssuer, subject)
	switch {
	case err == nil:
		// Attached: invited earlier, provisioned by another org's binding, or
		// already logged in through this provider. Email and profile attributes
		// are NEVER a linking key, so nothing here consults them.
		return link.AccountID, "attach", nil
	case errors.Is(err, domain.ErrNotFound):
	default:
		return "", "", err
	}

	principalID, err := newID("prn")
	if err != nil {
		return "", "", err
	}
	if err := az.CreateHumanPrincipal(ctx, domain.PrincipalID(principalID), now); err != nil {
		return "", "", err
	}
	newAccountID, err := newID("acc")
	if err != nil {
		return "", "", err
	}
	// The account HANDLE is opaque, not the SCIM `userName`.
	//
	// `accounts.username` is globally unique and is the LOCAL LOGIN handle; a
	// SCIM-provisioned account has no local credential, so nothing ever types
	// it. Copying a binding-scoped `userName` into it made a global namespace
	// out of a per-binding one — two bindings pushing the same handle for two
	// DIFFERENT humans collided, and the collision failed create while attach
	// succeeded, which is an existence oracle across orgs. The SCIM userName
	// keeps living in `scim_users`, where it is scoped the way SCIM scopes it.
	handle, err := newID("scim")
	if err != nil {
		return "", "", err
	}
	if err := az.CreateAccount(ctx, authz.Account{
		ID: newAccountID, PrincipalID: domain.PrincipalID(principalID),
		Username: handle, DisplayName: in.UserName, CreatedAt: now,
	}); err != nil {
		return "", "", err
	}
	identityID, err := newID("eid")
	if err != nil {
		return "", "", err
	}
	epoch, err := az.CredentialEpoch(ctx)
	if err != nil {
		return "", "", err
	}
	// The instance-wide (kind, issuer, subject) uniqueness constraint
	// arbitrates concurrent creates: one wins, the loser retries and attaches.
	if err := az.CreateExternalIdentity(ctx, authz.NewExternalIdentity{
		ID: identityID, AccountID: newAccountID, Kind: kind,
		Issuer: c.binding.ProviderIssuer, Subject: subject,
		ProviderID: c.providerID, CredentialEpoch: epoch, CreatedAt: now,
	}); err != nil {
		// The instance-wide (kind, issuer, subject) constraint arbitrating a
		// concurrent create (§5.2). The loser cannot re-read here — its failed
		// statement has aborted the transaction on postgres — so the WHOLE
		// transaction retries, and the second pass finds the identity and
		// attaches. Without this the loser answered a raw 23505 and never got
		// its SCIM resource at all.
		if isUniquenessRace(err) {
			return "", "", fmt.Errorf("%w: provisioning create lost the identity race", store.ErrRetrySerialization)
		}
		return "", "", err
	}
	return newAccountID, "create", nil
}

// isUniquenessRace reports whether an error is a uniqueness violation on the
// identity link. Both engines fold their unique violations onto store's
// ErrConflict, which is precise enough here: the only constraint this insert
// can violate is (kind, issuer, subject).
func isUniquenessRace(err error) bool { return errors.Is(err, store.ErrConflict) }

// ReplaceUser is RFC replacement (PUT): omitted mutable attributes clear to
// their defaults, `active` defaults TRUE — so an omitted `active` REACTIVATES,
// per the transition table — `userName` is required, the subject source is
// exempt from replacement (write-once), and `groups` is ignored on input.
func (s *SCIM) ReplaceUser(ctx context.Context, actor Actor, org domain.OrgID, bindingID, id string, in SCIMUserInput) (SCIMUserResource, error) {
	return s.mutateUser(ctx, actor, org, bindingID, id, authz.OpSCIMUserReplace, in, true)
}

// PatchUser applies the accepted cells of the matrix. The caller has already
// validated them against the closed table; what arrives here is desired state.
func (s *SCIM) PatchUser(ctx context.Context, actor Actor, org domain.OrgID, bindingID, id string, in SCIMUserInput) (SCIMUserResource, error) {
	return s.mutateUser(ctx, actor, org, bindingID, id, authz.OpSCIMUserPatch, in, false)
}

func (s *SCIM) mutateUser(
	ctx context.Context, actor Actor, org domain.OrgID, bindingID, id string,
	op authz.Operation, in SCIMUserInput, replace bool,
) (SCIMUserResource, error) {
	var out SCIMUserResource
	err := s.wireTx(ctx, actor, org, bindingID, op,
		func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time) ([]grantEventInput, error) {
			row, err := r.SCIM().User(ctx, c.proof, bindingID, id)
			if err != nil {
				return nil, err
			}
			next := row
			var changed []string
			// dirty is "the stored row would actually differ". It rides beside
			// `changed` because an attribute map can differ in BYTES without any
			// top-level name changing (re-encoding, key order), and because a
			// request that changes nothing must not bump `UpdatedAt` or emit an
			// update event: an identity provider re-asserting current truth on
			// every reconciliation cycle would otherwise fill the trail with
			// updates that updated nothing.
			dirty := false

			if replace || in.UserName != "" {
				if in.UserName == "" {
					return nil, ErrSCIMUserNameRequired
				}
				if fold(in.UserName) != row.UserNameLower {
					if _, err := r.SCIM().UserByUserName(ctx, c.proof, bindingID, fold(in.UserName)); err == nil {
						return nil, ErrSCIMUniqueness
					} else if !errors.Is(err, domain.ErrNotFound) {
						return nil, err
					}
				}
				// Compared RAW, not folded: `Dana@x` to `dana@x` is a change
				// the identity provider made and the trail must record, and a
				// folded comparison called it a no-op. The uniqueness probe
				// above stays folded, because that is what caseExact:false
				// means for collisions.
				if in.UserName != row.UserName {
					dirty = true
					changed = append(changed, "userName")
				}
				next.UserName, next.UserNameLower = in.UserName, fold(in.UserName)
			}
			// THE SUBJECT SOURCE IS EXEMPT FROM REPLACEMENT (§8), and on an
			// `externalId`-source binding that exemption has to be honoured
			// HERE, because `externalId` is then both an ordinary attribute and
			// the identity material.
			//
			// Without the exemption a PUT that simply omits `externalId` — a
			// perfectly ordinary RFC replacement — would clear it, notice the
			// derived subject moved, and refuse write-once: the identity
			// provider would be told it tried to migrate an identifier it never
			// mentioned. An extension-path binding never had that problem, and
			// the two must behave the same way.
			//
			// A PUT that EXPLICITLY supplies a different subject value is still
			// refused; that is a real migration attempt and the rebinding
			// hazard the identity model exists to prevent.
			subjectSourced := c.binding.SubjectSource == domain.SubjectSourceExternalID
			material := subjectMaterial(c, in)
			switch {
			case material != "":
				subject, err := s.deriveSubject(c, material)
				if err != nil {
					return nil, err
				}
				if subject != row.Subject {
					return nil, ErrSCIMSubjectWriteOnce
				}
			case subjectSourced && in.ExternalID != "" && in.ExternalID != row.ExternalID:
				// A PATCH naming externalId directly on an externalId-source
				// binding is the same migration attempt by another route.
				return nil, ErrSCIMSubjectWriteOnce
			case subjectSourced && in.ExternalIDCleared:
				// And an EXPLICIT removal is a third route to the same place.
				// Silently ignoring it would tell the identity provider it had
				// unbound an identity it did not unbind; the write-once rule
				// covers deletion as much as it covers replacement.
				return nil, ErrSCIMSubjectWriteOnce
			}
			switch {
			case subjectSourced:
				// Exempt: retained whatever the request said or did not say.
				next.ExternalID = row.ExternalID
			case replace || in.ExternalID != "" || in.ExternalIDCleared:
				if in.ExternalID != row.ExternalID {
					dirty = true
					changed = append(changed, "externalId")
				}
				next.ExternalID = in.ExternalID
			}
			if in.Attributes != nil || replace {
				stored, err := unmarshalAttributes(row.Attributes)
				if err != nil {
					return nil, err
				}
				desired := in.Attributes
				if in.Patch {
					// A PATCH is a DELTA. Replacing the stored map wholesale
					// dropped every attribute the request did not mention,
					// which is what PUT means and PATCH does not.
					desired = mergeAttributes(stored, in.Attributes)
				}
				if err := c.checkDeclaredSchemas(desired); err != nil {
					return nil, err
				}
				attrs, err := marshalAttributes(desired)
				if err != nil {
					return nil, err
				}
				if attrs != row.Attributes {
					dirty = true
					changed = append(changed, changedAttributeNames(stored, desired)...)
				}
				next.Attributes = attrs
			}
			active := row.Active
			if in.Active != nil {
				active = *in.Active
			} else if replace {
				active = true // RFC replacement: omitted `active` defaults true
			}

			events := []grantEventInput{}
			if active != row.Active {
				dirty = true
				changed = append(changed, "active")
			}
			next.Active = active
			if dirty {
				if err := r.SCIM().UpdateUser(ctx, c.proof, store.SCIMUserUpdate{
					ID: id, BindingID: bindingID, UserName: next.UserName,
					UserNameLower: next.UserNameLower, ExternalID: next.ExternalID,
					Active: next.Active, Attributes: next.Attributes, UpdatedAt: now,
				}); err != nil {
					return nil, err
				}
			}

			// The two lifecycle transitions, which are about ACTIVE and nothing
			// else. An attribute update leaves grants untouched (§5.4).
			switch {
			case row.Active && !active:
				evs, err := s.deprovision(ctx, r, az, c, next, domain.CauseDeprovision, now)
				if err != nil {
					return nil, err
				}
				events = append(events, evs...)
			case !row.Active && active:
				// Reactivation is DESIRED STATE, deterministic: recreate from
				// the CURRENT group memberships and mapping rows, not from
				// whatever was released when the user went inactive.
				principal, err := principalForAccount(ctx, az, next.AccountID)
				if err != nil {
					return nil, err
				}
				mappings, err := s.desiredMappings(ctx, r, c, id)
				if err != nil {
					return nil, err
				}
				evs, _, err := s.applyMappings(ctx, r, az, c, principal, mappings, now)
				if err != nil {
					return nil, err
				}
				events = append(events, evs...)
				// The manual-remainder warning is about a DEPROVISIONED user's
				// leftover hand grants. Reactivation ends that condition, so
				// the state comes down through the audited exit path — a state
				// that can be entered and never left is a permanent warning
				// nobody can act on.
				cleared, err := s.clearAttention(ctx, r, c,
					domain.AttentionManualGrantsRemain, id, domain.CauseReactivation)
				if err != nil {
					return nil, err
				}
				events = append(events, cleared...)
			}

			fresh, err := r.SCIM().User(ctx, c.proof, bindingID, id)
			if err != nil {
				return nil, err
			}
			out, err = s.renderUser(ctx, r, c, fresh)
			if err != nil {
				return nil, err
			}
			if dirty {
				events = append(events, grantEventInput{
					typ:    audit.EventSCIMUserUpdated,
					object: audit.Object{Type: "scim-user", ID: id},
					payload: audit.Payload{
						"binding": bindingID, "resource_id": id,
						"changed_attributes": sanitizedList(changed, 50),
					},
				})
			}
			return events, nil
		})
	return out, err
}

// deprovision is the `active: true -> false` transition (§5.3): every `scim`
// origin this binding holds for the user is released under §2.4, and the user's
// session generation advances UNCONDITIONALLY — even when no grant row changed,
// because the IdP has declared this human gone and surviving sessions must
// re-prove.
//
// Manual grants in this org SURVIVE — the IdP was not their source — and the
// binding raises the loud per-user attention flag. Stated honestly, as the ADR
// insists: those grants remain usable, including after a fresh login through
// this or any other linked provider. Push-only SCIM cannot prove the IdP will
// refuse SSO, and this claims nothing it cannot observe.
func (s *SCIM) deprovision(
	ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext,
	user store.SCIMUser, cause domain.SCIMCause, now time.Time,
) ([]grantEventInput, error) {
	principal, err := principalForAccount(ctx, az, user.AccountID)
	if err != nil {
		return nil, err
	}
	// Origins another ACTIVE resource of this same account still justifies must
	// survive. One account can be attached to several resources in one binding
	// — two identities the operator linked to one human — and releasing every
	// origin the binding holds for the PRINCIPAL would take away access the
	// identity provider is still asserting through the other resource.
	keep, err := s.originsJustifiedElsewhere(ctx, r, c, user)
	if err != nil {
		return nil, err
	}
	outcome, events, err := releaseSCIMOrigins(ctx, az, now, releaseArgs{
		binding: c.binding.ID, org: domain.OrgID(c.binding.OrgID), principal: principal,
		match: func(k domain.SCIMOriginKey) bool {
			return k.Binding == c.binding.ID && !keep[k.MappingRow]
		},
		cause: cause,
	})
	if err != nil {
		return nil, err
	}
	// UNCONDITIONAL, and deliberately not gated on outcome.AuthorityChanged():
	// the zero-grant-delta case is exactly the one the rule exists for.
	if err := advanceAndSweep(ctx, az, principal); err != nil {
		return nil, err
	}
	for _, grantID := range outcome.Retained {
		ev, err := s.enterAttention(ctx, r, c, domain.AttentionLockoutRetention, grantID, cause, now)
		if err != nil {
			return nil, err
		}
		events = append(events, ev...)
	}
	if outcome.ManualRemains {
		ev, err := s.enterAttention(ctx, r, c, domain.AttentionManualGrantsRemain, user.ID, cause, now)
		if err != nil {
			return nil, err
		}
		events = append(events, ev...)
	}
	typ := audit.EventSCIMUserDeprovisioned
	payload := audit.Payload{
		"binding": c.binding.ID, "resource_id": user.ID, "account_id": user.AccountID,
		"released_origin_count": outcome.Released,
		"manual_grants_remain":  outcome.ManualRemains,
	}
	if cause == domain.CauseUserDeleted {
		typ = audit.EventSCIMUserDeleted
	}
	return append(events, grantEventInput{
		typ: typ, object: audit.Object{Type: "scim-user", ID: user.ID}, payload: payload,
	}), nil
}

// originsJustifiedElsewhere returns the mapping rows still desired by ANOTHER
// active resource of the same account in this binding. It is the reconciliation
// §5.3's release needs: the release key is the binding, but the authority is
// the account's, and two resources can hold the same account.
func (s *SCIM) originsJustifiedElsewhere(
	ctx context.Context, r store.Repos, c scimContext, leaving store.SCIMUser,
) (map[string]bool, error) {
	peers, err := r.SCIM().Users(ctx, c.proof, c.binding.ID)
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	for _, peer := range peers {
		if peer.ID == leaving.ID || peer.AccountID != leaving.AccountID || !peer.Active {
			continue
		}
		mappings, err := s.desiredMappings(ctx, r, c, peer.ID)
		if err != nil {
			return nil, err
		}
		for _, m := range mappings {
			if !m.Inert {
				keep[m.ID] = true
			}
		}
	}
	return keep, nil
}

// DeleteUser is the same release plus removal from the binding's directory,
// INCLUDING removal of every member reference to that user from the binding's
// groups, in the same transaction — so a stale reference cannot exist and a
// re-create after DELETE gets a fresh id with nothing pointing at the old one.
//
// The account and its identity links are instance-level and SURVIVE: other
// orgs' memberships and other providers are not this IdP's to kill.
func (s *SCIM) DeleteUser(ctx context.Context, actor Actor, org domain.OrgID, bindingID, id string) error {
	return s.wireTx(ctx, actor, org, bindingID, authz.OpSCIMUserDelete,
		func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time) ([]grantEventInput, error) {
			row, err := r.SCIM().User(ctx, c.proof, bindingID, id)
			if err != nil {
				return nil, err
			}
			memberships, err := r.SCIM().MembershipsForUser(ctx, c.proof, c.binding.ID, id)
			if err != nil {
				return nil, err
			}
			events, err := s.deprovision(ctx, r, az, c, row, domain.CauseUserDeleted, now)
			if err != nil {
				return nil, err
			}
			if err := r.SCIM().RemoveMembershipsForUser(ctx, c.proof, c.binding.ID, id); err != nil {
				return nil, err
			}
			if err := r.SCIM().DeleteUser(ctx, c.proof, bindingID, id); err != nil {
				return nil, err
			}
			// The deprovision event above is the DELETE event; give it the one
			// extra field §10 requires of the delete variant.
			for i := range events {
				if events[i].typ == audit.EventSCIMUserDeleted {
					events[i].payload["member_references_removed"] = len(memberships)
				}
			}
			return events, nil
		})
}

// GetUser and ListUsers are authenticated machine READS. They are events too,
// in the `access` retention class: the ADR withdraws by name the earlier claim
// that every SCIM operation is mutating.
func (s *SCIM) GetUser(ctx context.Context, actor Actor, org domain.OrgID, bindingID, id string) (SCIMUserResource, error) {
	var out SCIMUserResource
	err := s.wireTx(ctx, actor, org, bindingID, authz.OpSCIMUserGet,
		func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time) ([]grantEventInput, error) {
			row, err := r.SCIM().User(ctx, c.proof, bindingID, id)
			if err != nil {
				return nil, err
			}
			out, err = s.renderUser(ctx, r, c, row)
			if err != nil {
				return nil, err
			}
			return []grantEventInput{directoryReadEvent(bindingID, "user", string(scimproto.FilterNone), 1, 1)}, nil
		})
	return out, err
}

// ListUsers answers the two User filters and the RFC's 1-based paging. An
// out-of-range page returns an empty resource list with a TRUTHFUL total.
func (s *SCIM) ListUsers(ctx context.Context, actor Actor, org domain.OrgID, bindingID string, filter scimproto.Filter, page scimproto.Page) ([]SCIMUserResource, int, error) {
	var out []SCIMUserResource
	total := 0
	err := s.wireTx(ctx, actor, org, bindingID, authz.OpSCIMUserList,
		func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time) ([]grantEventInput, error) {
			var rows []store.SCIMUser
			switch filter.Shape {
			case scimproto.FilterNone:
				all, err := r.SCIM().Users(ctx, c.proof, bindingID)
				if err != nil {
					return nil, err
				}
				rows = all
			case scimproto.FilterUserNameEq:
				row, err := r.SCIM().UserByUserName(ctx, c.proof, bindingID, fold(filter.Value))
				if err != nil && !errors.Is(err, domain.ErrNotFound) {
					return nil, err
				}
				if err == nil {
					rows = []store.SCIMUser{row}
				}
			case scimproto.FilterExternalIDEq:
				// MANY: externalId is not unique (only the subject is), so a
				// singular lookup would answer an arbitrary one of several and
				// report totalResults 1.
				matches, err := r.SCIM().UsersByExternalID(ctx, c.proof, bindingID, filter.Value)
				if err != nil {
					return nil, err
				}
				rows = matches
			default:
				return nil, fmt.Errorf("%w: service: filter %q is not answerable on Users", domain.ErrInvalid, filter.Shape)
			}
			total = len(rows)
			for _, row := range scimproto.Slice(rows, page) {
				view, err := s.renderUser(ctx, r, c, row)
				if err != nil {
					return nil, err
				}
				out = append(out, view)
			}
			return []grantEventInput{
				directoryReadEvent(bindingID, "user", string(filter.Shape), page.StartIndex, len(out)),
			}, nil
		})
	return out, total, err
}

func (s *SCIM) renderUser(ctx context.Context, r store.Repos, c scimContext, row store.SCIMUser) (SCIMUserResource, error) {
	memberships, err := r.SCIM().MembershipsForUser(ctx, c.proof, c.binding.ID, row.ID)
	if err != nil {
		return SCIMUserResource{}, err
	}
	attrs, err := unmarshalAttributes(row.Attributes)
	if err != nil {
		return SCIMUserResource{}, err
	}
	out := SCIMUserResource{
		ID: row.ID, ExternalID: row.ExternalID, UserName: row.UserName,
		Active: row.Active, Attributes: attrs,
		Schemas:   scimproto.SchemasFor(attrs, c.declaredExtensions()),
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
	for _, m := range memberships {
		out.Groups = append(out.Groups, m.GroupID)
	}
	return out, nil
}

// mergeAttributes applies a PATCH delta: a present key assigns, a NIL value
// clears, an absent key leaves the stored value alone.
func mergeAttributes(stored, delta map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range stored {
		out[k] = v
	}
	for k, v := range delta {
		if v == nil {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	return out
}

// changedAttributeNames diffs two attribute maps and returns the top-level
// names that moved. §10's `changed_attributes` is a list of ATTRIBUTE NAMES;
// recording the literal string "attributes" satisfied the schema and told a
// reader nothing.
func changedAttributeNames(before, after map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	note := func(k string) {
		if !seen[k] {
			seen[k], out = true, append(out, k)
		}
	}
	// Compared by their JSON encoding, not reflect.DeepEqual: the forgery guard
	// bans `reflect` from this package (a proof is a struct, and reflection is
	// how one gets forged), and these values came from JSON anyway — so the
	// encoding IS their identity.
	for k, v := range after {
		if encodeAttr(before[k]) != encodeAttr(v) {
			note(k)
		}
	}
	for k := range before {
		if _, still := after[k]; !still {
			note(k)
		}
	}
	sort.Strings(out)
	return out
}

func encodeAttr(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return "\x00unencodable"
	}
	return string(raw)
}

func marshalAttributes(in map[string]any) (string, error) {
	if in == nil {
		return "{}", nil
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return "", fmt.Errorf("%w: service: unserialisable SCIM attributes", domain.ErrInvalid)
	}
	return string(raw), nil
}

func unmarshalAttributes(raw string) (map[string]any, error) {
	if raw == "" {
		return map[string]any{}, nil
	}
	// Parse, never cast: what came back out of storage goes through the same
	// decoder the trust boundary used on the way in.
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("service: stored SCIM attributes are not a JSON object: %w", err)
	}
	return out, nil
}

// subjectMaterial reads the identity material out of the request, at the
// attribute path the BINDING declared. A wire caller hands over the decoded
// resource; a below-the-wire caller hands over the value itself.
func subjectMaterial(c scimContext, in SCIMUserInput) string {
	if in.Resource == nil {
		return in.SubjectRaw
	}
	return extractAttribute(in.Resource, c.binding.SubjectSource)
}

// extractAttribute walks a SCIM attribute path. Two shapes are recognised,
// which are the two RFC 7643 admits and the two §5.1 names: a top-level or
// dotted core attribute (`externalId`, `name.familyName`) and a
// schema-qualified extension path
// (`urn:…:extension:enterprise:2.0:User:employeeNumber`), where the schema URI
// is itself the key of a nested object in the resource.
//
// It returns "" for anything absent or non-scalar rather than guessing: an
// empty subject is refused by name one layer up, and a guessed one would bind
// the wrong human to the account.
func extractAttribute(body map[string]any, path string) string {
	if path == "" {
		return ""
	}
	if i := strings.LastIndex(path, ":"); i >= 0 {
		schema, attr := path[:i], path[i+1:]
		nested, ok := body[schema].(map[string]any)
		if !ok {
			return ""
		}
		return extractAttribute(nested, attr)
	}
	cursor := body
	parts := strings.Split(path, ".")
	for _, part := range parts[:len(parts)-1] {
		next, ok := cursor[part].(map[string]any)
		if !ok {
			return ""
		}
		cursor = next
	}
	v, _ := cursor[parts[len(parts)-1]].(string)
	return v
}

// Unsupported is the authenticated refusal of a feature this provider
// advertises as absent (§8). It authenticates and authorizes exactly like
// every other wire operation — so an unauthenticated caller gets the uniform
// refusal rather than a 501 that would confirm the binding exists — and then
// the transport renders HTTP 501 with the RFC error body.
func (s *SCIM) Unsupported(ctx context.Context, actor Actor, org domain.OrgID, bindingID, what string) error {
	return s.wireTx(ctx, actor, org, bindingID, authz.OpSCIMUnsupported,
		func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time) ([]grantEventInput, error) {
			return []grantEventInput{
				directoryReadEvent(bindingID, "discovery", string(scimproto.FilterNone), 1, 0),
			}, nil
		})
}

// Authenticate runs the wire gate and nothing else: credential, binding-path
// match, `scim-provision(org)`, provider liveness. The transport calls it when
// a request FAILED TO PARSE, so an unknown, revoked or wrong-binding credential
// still answers 401 rather than being told its body was malformed — a 400 to an
// unauthenticated caller confirms the binding exists.
//
// It costs an extra transaction only on the malformed path; a request that
// parses is authenticated by the operation itself.
func (s *SCIM) Authenticate(ctx context.Context, actor Actor, org domain.OrgID, bindingID string) error {
	return s.wireTx(ctx, actor, org, bindingID, authz.OpSCIMUnsupported,
		func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time) ([]grantEventInput, error) {
			return []grantEventInput{
				directoryReadEvent(bindingID, "discovery", string(scimproto.FilterNone), 1, 0),
			}, nil
		})
}

// PageBound is the server's `count` ceiling, so the transport clamps against
// the same number the service does.
func (s *SCIM) PageBound() int { return s.pageBound() }
