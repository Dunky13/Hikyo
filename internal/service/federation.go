package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Dunky13/hikyo/internal/admission"
	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/oidcfed"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/tx"
)

// OIDC federation (#62, machine-identities ADR § Federation, § Federated
// bindings expire, § JWKS, § Restore).
//
// Two surfaces live here and the split matters.
//
// ISSUER CONFIGURATION is instance-scoped, under `instance-config`, and never
// org- or project-scoped. #16 fixed this exact argument for human providers: an
// org-scoped issuer would let an org admin add a provider and mint identities
// authenticating into the instance.
//
// BINDINGS are project-scoped rows of `machine_credentials`, so creating one is
// a MINT and carries § Minting and widening's full formula —
// `manage-identities(project)` ∧ a per-class disclosure capability over every
// environment reachable in the resulting post-state ∧ reauthentication — for the
// same reason a bearer mint does: the actor walks away having decided which
// external identity may speak as this service account, and that identity reaches
// everything the account's grants reach.
//
// Bindings are IMMUTABLE. Changing the issuer, subject, audience or required
// claims is not an edit; it is a replacement mint. Editing in place would let a
// principal without `reveal` re-point a production binding at an identity they
// control while the recorded authorization stayed behind — the same
// authority-laundering shape #15 closed for adapters. Deleting or narrowing
// stays under the plain capability, because incident response must never be
// gated on disclosure rights: a binding is deleted by revoking its credential
// row through Identities.RevokeCredential.

// Federated-refusal causes: the closed enum recorded on
// identity.federation_refused. BY CLASS, never by detail, so the trail is not
// the oracle the uniform response is not.
const (
	causeFedNotAToken     = "not-a-token"
	causeFedUnknownIssuer = "unknown-issuer"
	causeFedKeys          = "keys-unavailable"
	causeFedStale         = "keys-stale"
	causeFedSignature     = "signature"
	causeFedTokenAge      = "token-age"
	causeFedAudience      = "audience"
	causeFedClaim         = "claim"
	causeFedEventName     = "event-name"
	causeFedRestore       = "restore-predicate"
	causeFedUnbound       = "unbound"
)

var (
	// ErrIssuerValue refuses an issuer configuration outside its own grammar.
	ErrIssuerValue = fmt.Errorf("%w: service: an issuer needs an https URL, a known type, a JWKS mode and at least one refused audience", domain.ErrInvalid)
	// ErrIssuerInUse refuses deleting an issuer that live bindings still name.
	// Removing it would be an authorization change wearing a configuration
	// change's clothes.
	ErrIssuerInUse = fmt.Errorf("%w: service: live bindings still name this issuer", domain.ErrConflict)
	// ErrNoSuchIssuer refuses a binding naming an issuer the instance does not
	// configure, and an administrative call against an id that is not there.
	ErrNoSuchIssuer = fmt.Errorf("%w: service: no such federation issuer", domain.ErrNotFound)
	// ErrBindingAudience refuses a binding with no audience, or one naming the
	// issuer's default audience. Both are the same rule: audience binding is
	// mandatory and the default is refused.
	ErrBindingAudience = fmt.Errorf("%w: service: a binding must name an audience, and never the issuer's default", domain.ErrInvalid)
	// ErrBindingClaims refuses a binding that pins nothing, or a pin that is
	// not a scalar.
	ErrBindingClaims = fmt.Errorf("%w: service: a binding must pin at least one claim, each a string, integer or boolean", domain.ErrInvalid)
	// ErrBindingImmutableID refuses a binding that does not pin the immutable
	// identifiers its platform exposes. It is its own refusal because the remedy
	// is specific: pin the numeric id, not the name — a renamed-and-reused
	// repository path or a recreated ServiceAccount otherwise inherits the
	// binding.
	ErrBindingImmutableID = fmt.Errorf("%w: service: a binding must pin the immutable identifiers this issuer exposes", domain.ErrInvalid)
	// ErrBindingEventName refuses a CI binding that does not pin `event_name`.
	// This is the load-bearing refusal of the whole CI story: without the pin,
	// a `pull_request_target` token carries the ordinary ref-form subject a
	// production binding names.
	ErrBindingEventName = fmt.Errorf("%w: service: a Forgejo or GitHub Actions binding must pin `event_name`", domain.ErrInvalid)
	// ErrBindingSubject refuses an empty subject. There is no wildcard: the
	// absence of a subject is not "any subject".
	ErrBindingSubject = fmt.Errorf("%w: service: a binding must name a subject", domain.ErrInvalid)
	// ErrNoSuchBinding refuses a replacement naming a credential this service
	// account does not hold.
	ErrNoSuchBinding = fmt.Errorf("%w: service: no such binding", domain.ErrNotFound)
)

// Federation owns the federation surface. Like every service here it opens one
// transaction, authorizes inside it, and performs the whole mutation before it
// commits — with one deliberate exception, Authenticate, whose network half runs
// BEFORE any transaction opens.
type Federation struct {
	DB *store.DB
	// Auth supplies the reauthentication conjunct for a binding mint. Machines
	// never reauthenticate; the human creating the binding does.
	Auth *Auth
	// Cache is the JWKS cache. Nil means federated presentation is refused,
	// which is the correct posture for a build that did not wire it.
	Cache *oidcfed.Cache
	// Admission is the instance-wide pre-authentication budget. The ADR is
	// explicit that it covers federated validation, not only human paths:
	// "pre-authentication admission limits apply to credential presentation and
	// to federated validation, under the same instance-wide budget". Federated
	// validation is the more expensive of the two — an RSA verify per presented
	// token, and on a cache miss an outbound fetch — so it is the one that most
	// needs a slot. Nil means unlimited, which is only for tests.
	Admission *admission.Limiter
	Now       func() time.Time
	// OnValidated runs between the pre-transaction validation and the caller's
	// authorizing transaction. It exists for exactly one fixture: the window an
	// administrator's issuer update can land in is real but unobservable from
	// outside, and a test that raced it with goroutines would be flaky rather
	// than a proof. Nil in production, and nothing else may use it.
	OnValidated func()
}

func (s *Federation) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

// IssuerView is one issuer configuration as the API renders it. The static JWKS
// document is NOT a field: it is configuration an operator supplied and can
// re-supply, it is not secret, and returning it would make the read surface
// carry a key document nothing needs back.
type IssuerView struct {
	ID               string
	Issuer           string
	Type             domain.IssuerType
	Mode             domain.JWKSMode
	RefusedAudiences []string
	CreatedAt        time.Time
	CreatedBy        domain.PrincipalID
	UpdatedAt        time.Time
	UpdatedBy        domain.PrincipalID
	// Bindings is how many bindings name this issuer, live or historical, so an
	// operator can see the blast radius of a delete before attempting one -- and
	// a delete is refused while any remain, including revoked ones, because
	// erasing the issuer a past binding trusted erases what it trusted.
	Bindings int64
}

// IssuerRequest configures one issuer.
type IssuerRequest struct {
	Issuer           string
	Type             domain.IssuerType
	Mode             domain.JWKSMode
	StaticJWKS       string
	RefusedAudiences []string
}

// CreateIssuer configures an issuer under `instance-config`.
func (s *Federation) CreateIssuer(ctx context.Context, actor Actor, req IssuerRequest) (IssuerView, error) {
	if err := checkIssuerRequest(req); err != nil {
		return IssuerView{}, err
	}
	id, err := newID("fis")
	if err != nil {
		return IssuerView{}, err
	}
	now := s.now()
	var out IssuerView
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpFederationIssuerCreate, domain.Scope{})
		if err != nil {
			return err
		}
		if err := az.CreateFederationIssuer(ctx, authz.NewFederationIssuer{
			ID: id, Issuer: req.Issuer, Type: req.Type, Mode: req.Mode,
			StaticJWKS: req.StaticJWKS, RefusedAudiences: req.RefusedAudiences,
			CreatedAt: now, CreatedBy: caller.Principal,
		}); err != nil {
			return err
		}
		out = IssuerView{
			ID: id, Issuer: req.Issuer, Type: req.Type, Mode: req.Mode,
			RefusedAudiences: req.RefusedAudiences, CreatedAt: now, CreatedBy: caller.Principal,
		}
		e, err := issuerEvent(ctx, caller.Principal, id, req.Issuer, "created", req)
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, e)
	})
	return out, err
}

// UpdateIssuer moves the MUTABLE half — the JWKS source and the refused
// audiences. It cannot move the issuer string or the platform type: changing
// either would silently re-point every binding underneath at a different
// external authority, which is a replacement, not an edit.
func (s *Federation) UpdateIssuer(ctx context.Context, actor Actor, id string, mode domain.JWKSMode, staticJWKS string, refused []string) (IssuerView, error) {
	if err := checkJWKSMode(mode, staticJWKS); err != nil {
		return IssuerView{}, err
	}
	if err := checkRefusedAudiences(refused); err != nil {
		return IssuerView{}, err
	}
	now := s.now()
	var out IssuerView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpFederationIssuerUpdate, domain.Scope{})
		if err != nil {
			return err
		}
		before, err := az.FederationIssuerByID(ctx, id)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return ErrNoSuchIssuer
			}
			return err
		}
		if _, err := az.UpdateFederationIssuer(ctx, id, mode, staticJWKS, refused, caller.Principal, now); err != nil {
			return err
		}
		out = IssuerView{
			ID: id, Issuer: before.Issuer, Type: before.Type, Mode: mode,
			RefusedAudiences: refused, CreatedAt: before.CreatedAt, CreatedBy: before.CreatedBy,
			UpdatedAt: now, UpdatedBy: caller.Principal,
		}
		e, err := issuerEvent(ctx, caller.Principal, id, before.Issuer, "updated", IssuerRequest{
			Issuer: before.Issuer, Type: before.Type, Mode: mode,
			StaticJWKS: staticJWKS, RefusedAudiences: refused,
		})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, e)
	})
	return out, err
}

// ListIssuers reads every configured issuer with its live-binding census.
//
// Audited rather than `audited: none`: the audit model's default-deny permit
// rule admits only tenant-class bare-`read` operations, and reading which
// external authorities the instance trusts is neither.
func (s *Federation) ListIssuers(ctx context.Context, actor Actor) ([]IssuerView, error) {
	now := s.now()
	var out []IssuerView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpFederationIssuerList, domain.Scope{})
		if err != nil {
			return err
		}
		issuers, err := az.FederationIssuers(ctx)
		if err != nil {
			return err
		}
		out = make([]IssuerView, 0, len(issuers))
		for _, iss := range issuers {
			bindings, err := az.BindingsForIssuer(ctx, iss.ID)
			if err != nil {
				return err
			}
			out = append(out, IssuerView{
				ID: iss.ID, Issuer: iss.Issuer, Type: iss.Type, Mode: iss.Mode,
				RefusedAudiences: iss.RefusedAudiences, CreatedAt: iss.CreatedAt,
				CreatedBy: iss.CreatedBy, UpdatedAt: iss.UpdatedAt, UpdatedBy: iss.UpdatedBy,
				Bindings: bindings,
			})
		}
		e, err := newAuditEvent(ctx, audit.EventFederationIssuerRead, caller.Principal,
			audit.Object{Type: "instance", ID: "federation_issuers"}, audit.OutcomeSuccess, "",
			audit.Payload{"row_count": len(out)})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, e)
	})
	return out, err
}

// DeleteIssuer removes a configuration, refusing while live bindings name it.
//
// The refusal is not politeness. A cascade would revoke every binding
// underneath, which is a deprovisioning of N workloads performed by an
// operation whose name says "configuration"; and a delete that orphaned the
// rows would leave bindings whose issuer cannot be resolved, i.e. bindings that
// silently stop authenticating. The operator revokes the bindings first, which
// is the same act stated honestly.
func (s *Federation) DeleteIssuer(ctx context.Context, actor Actor, id string) error {
	now := s.now()
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpFederationIssuerDelete, domain.Scope{})
		if err != nil {
			return err
		}
		before, err := az.FederationIssuerByID(ctx, id)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return ErrNoSuchIssuer
			}
			return err
		}
		bindings, err := az.BindingsForIssuer(ctx, id)
		if err != nil {
			return err
		}
		if bindings > 0 {
			return fmt.Errorf("%w (%d)", ErrIssuerInUse, bindings)
		}
		if _, err := az.DeleteFederationIssuer(ctx, id); err != nil {
			return err
		}
		e, err := issuerEvent(ctx, caller.Principal, id, before.Issuer, "deleted", IssuerRequest{
			Issuer: before.Issuer, Type: before.Type, Mode: before.Mode,
			RefusedAudiences: before.RefusedAudiences,
		})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, e)
	})
}

// ClaimPin is one pinned claim, as a DISCRIMINATED scalar rather than a
// free-form JSON value.
//
// Exactly one of the three value members is set, and that is what makes "a
// string is never folded to a number" true at the API boundary rather than only
// inside the validator: `repository_id: 123` and `repository_id: "123"` are two
// different requests that cannot be confused for one another, and an int64
// survives the wire without passing through a float.
type ClaimPin struct {
	Claim   string
	String  *string
	Number  *int64
	Boolean *bool
}

// BindingRequest is one binding mint.
type BindingRequest struct {
	// Issuer is the byte-exact `iss` of a configured issuer.
	Issuer string
	// Subject is the byte-exact `sub`. No wildcards, no patterns, no prefixes.
	Subject string
	// Audience is mandatory and may not be the issuer's default.
	Audience string
	// RequiredClaims must be non-empty, and must pin `event_name` for a CI
	// issuer.
	RequiredClaims []ClaimPin
	// Indefinite and Lifetime are the same typed lifetime a bearer credential
	// carries, governed by the same instance ceiling and the same default-off
	// opt-in. Renewal is a mint.
	Indefinite bool
	Lifetime   time.Duration
	// Replaces names the binding this one supersedes. Because a binding is
	// immutable, every change is a replacement: the predecessor is revoked and
	// the successor inserted in ONE transaction, which is also what lets the
	// live-row unique index hold across the swap.
	Replaces string
}

// BindingView is a binding's metadata. There is no secret to omit — a binding
// holds nothing at rest — so unlike a bearer credential this view is complete.
type BindingView struct {
	CredentialID   string
	IssuerID       string
	Issuer         string
	IssuerType     domain.IssuerType
	Subject        string
	Audience       string
	RequiredClaims []ClaimPin
	Lifetime       domain.CredentialLifetime
	ExpiresAt      time.Time
	CreatedAt      time.Time
	CreatedBy      domain.PrincipalID
	RevokedAt      time.Time
	ReactivatedAt  time.Time
	ExpiringSoon   bool
	// Clamped reports that the instance ceiling shortened the requested
	// lifetime.
	Clamped bool
	// ReplacedID is the predecessor this mint revoked, empty when none.
	ReplacedID string
}

// CreateBinding mints a federated binding.
//
// The authorization formula is the ADR's SECOND minting row, and it ranges over
// the WHOLE post-state rather than over anything the mint adds — a binding adds
// no grants at all, so an "added environments" reading would require `reveal` on
// nothing and let a principal holding `manage-identities` and no `reveal`
// re-point a production binding at an identity they control.
func (s *Federation) CreateBinding(ctx context.Context, actor Actor, scope domain.Scope, saID string, req BindingRequest) (BindingView, error) {
	if req.Lifetime < 0 {
		return BindingView{}, ErrCredentialLifetime
	}
	if req.Subject == "" {
		return BindingView{}, ErrBindingSubject
	}
	if req.Audience == "" {
		return BindingView{}, ErrBindingAudience
	}
	claimsJSON, err := encodeClaimPins(req.RequiredClaims)
	if err != nil {
		return BindingView{}, err
	}
	credID, err := newID("mcr")
	if err != nil {
		return BindingView{}, err
	}
	now := s.now()
	var out BindingView
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpBindingCreate, scope)
		if err != nil {
			return err
		}
		sa, err := az.ServiceAccountAt(ctx, scope, saID)
		if err != nil {
			return err
		}
		// LOCK ORDER: the policy row, then the service account's principal row
		// — the same order the bearer mint, the policy writer and the grant
		// writers take, so the four cannot deadlock against each other. Both
		// locks are load-bearing for the same reasons the bearer mint states.
		if err := az.LockCredentialPolicy(ctx); err != nil {
			return err
		}
		if err := az.LockMachinePrincipal(ctx, sa.PrincipalID); err != nil {
			return err
		}
		policy, err := az.CredentialPolicy(ctx)
		if err != nil {
			return err
		}
		lifetime, expires, clamped, err := resolveLifetime(
			MintRequest{Indefinite: req.Indefinite, Lifetime: req.Lifetime}, policy, now)
		if err != nil {
			return err
		}

		issuer, err := az.FederationIssuerByIssuer(ctx, req.Issuer)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return ErrNoSuchIssuer
			}
			return err
		}
		if err := checkBindingAgainstIssuer(issuer, req.Audience, claimsJSON); err != nil {
			return err
		}

		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}

		// The replacement leg. It runs BEFORE the cap census and the insert:
		// a replacement does not grow the fleet, so it must not be refused by
		// a cap the predecessor is itself occupying, and the live-row unique
		// index needs the predecessor revoked before the successor lands.
		replaced := ""
		if req.Replaces != "" {
			revoked, err := az.RevokeMachineCredential(ctx, sa.ID, req.Replaces, now)
			if err != nil {
				return err
			}
			if !revoked {
				// Either it is not this account's credential or it was already
				// revoked. Both answer the same thing, so this surface cannot
				// be used to enumerate credential ids across accounts.
				return ErrNoSuchBinding
			}
			replaced = req.Replaces
		}

		live, err := az.LiveMachineCredentialCount(ctx, sa.ID, epoch, now)
		if err != nil {
			return err
		}
		if live >= policy.MaxLiveCredentials {
			return fmt.Errorf("%w (%d)", ErrCredentialCap, policy.MaxLiveCredentials)
		}

		// The whole-post-state disclosure conjunct, per authority class, and
		// the reauthentication conjunct over the same set.
		reach, err := s.postStateReach(ctx, az, scope, sa)
		if err != nil {
			return err
		}
		actorGrants, err := az.GrantRowsForPrincipal(ctx, caller.Principal)
		if err != nil {
			return err
		}
		if s.Auth == nil {
			return errors.New("service: the federation surface has no reauthentication seam wired")
		}
		current, historical := sortedKeys(reach.Current), sortedKeys(reach.Historical)
		if err := s.Auth.RequireDisclosureAuthority(ctx, az, caller, actorGrants, scope, current, historical, now); err != nil {
			return err
		}

		if err := az.CreateMachineCredential(ctx, authz.NewCredential{
			ID: credID, ServiceAccountID: sa.ID, Kind: domain.CredentialOIDCFederation,
			Binding: authz.Binding{
				IssuerID: issuer.ID, Subject: req.Subject,
				Audience: req.Audience, RequiredClaimsJSON: claimsJSON,
			},
			Lifetime: lifetime, ExpiresAt: expires, CredentialEpoch: epoch,
			CreatedAt: now, CreatedBy: caller.Principal,
		}); err != nil {
			return err
		}

		out = BindingView{
			CredentialID: credID, IssuerID: issuer.ID, Issuer: issuer.Issuer,
			IssuerType: issuer.Type, Subject: req.Subject, Audience: req.Audience,
			RequiredClaims: req.RequiredClaims, Lifetime: lifetime, ExpiresAt: expires,
			CreatedAt: now, CreatedBy: caller.Principal, Clamped: clamped, ReplacedID: replaced,
		}
		out.ExpiringSoon = expiringSoon(CredentialView{
			Lifetime: lifetime, ExpiresAt: expires,
		}, now)

		payload := audit.Payload{
			"service_account_id":          sa.ID,
			"target_principal":            string(sa.PrincipalID),
			"principal_class":             string(sa.Kind),
			"credential_id":               credID,
			"issuer_id":                   issuer.ID,
			"issuer":                      issuer.Issuer,
			"issuer_type":                 string(issuer.Type),
			"subject":                     audit.SanitizeFreeText(req.Subject),
			"audience":                    audit.SanitizeFreeText(req.Audience),
			"pinned_claims":               pinnedClaimNames(req.RequiredClaims),
			"lifetime":                    string(lifetime),
			"clamped":                     clamped,
			"replaces":                    replaced,
			"reveal_environments":         envStrings(current),
			"reveal_history_environments": envStrings(historical),
		}
		if lifetime == domain.LifetimeFinite {
			payload["expires_at"] = expires.Format(time.RFC3339)
		}
		e, err := domainEvent(ctx, audit.EventBindingCreated, caller.Principal,
			audit.Object{Type: "machine_credential", ID: credID}, payload)
		if err != nil {
			return err
		}
		if err := r.Audit().InsertTenant(ctx, p, e); err != nil {
			return err
		}
		if replaced == "" {
			return nil
		}
		// The predecessor's death is its own fact, recorded with the same
		// cardinality an ordinary revoke has: the forensic question after a leak
		// is which credential, and a replacement that recorded only the arrival
		// would leave the departure unattributed.
		re, err := domainEvent(ctx, audit.EventCredentialRevoked, caller.Principal,
			audit.Object{Type: "machine_credential", ID: replaced}, audit.Payload{
				"service_account_id": sa.ID,
				"target_principal":   string(sa.PrincipalID),
				"principal_class":    string(sa.Kind),
				"credential_id":      replaced,
				"credential_kind":    string(domain.CredentialOIDCFederation),
				"cause":              "replaced",
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, re)
	})
	if err != nil {
		return BindingView{}, err
	}
	return out, nil
}

// Reactivate records a restore-time re-validation of one binding (§ Restore).
//
// A binding may be re-activated where a bearer verifier may never be, and the
// asymmetry is not leniency: a binding holds no bearer value, so there is
// nothing an attacker can have captured and nothing to redistribute. What it
// still needs is the `iat` predicate, because a restore can resurrect a binding
// that was removed precisely BECAUSE that workload was compromised.
//
// #76 owns the operator ceremony (recovery mode, per-principal, no bulk-accept).
// This is the write it will call, and it exists now because the refusal it
// arms — every later token must have been issued after re-activation, by a
// margin that swallows clock skew — is what this ticket had to prove.
func (s *Federation) Reactivate(ctx context.Context, actor Actor, scope domain.Scope, saID, credentialID string) (time.Time, error) {
	now := s.now()
	var at time.Time
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		// Re-activation NARROWS: it can only refuse tokens the binding would
		// otherwise have accepted. So it rides the plain capability, like every
		// other narrowing, with no disclosure gate.
		p, err := az.Authorize(ctx, caller, authz.OpCredentialRevoke, scope)
		if err != nil {
			return err
		}
		sa, err := az.ServiceAccountAt(ctx, scope, saID)
		if err != nil {
			return err
		}
		creds, err := az.MachineCredentialsFor(ctx, sa.ID)
		if err != nil {
			return err
		}
		found := false
		for _, c := range creds {
			if c.ID == credentialID && c.Kind == domain.CredentialOIDCFederation {
				found = true
			}
		}
		if !found {
			return ErrNoSuchBinding
		}
		ok, err := az.ReactivateBinding(ctx, credentialID, now)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNoSuchBinding
		}
		at = now
		e, err := domainEvent(ctx, audit.EventBindingReactivated, caller.Principal,
			audit.Object{Type: "machine_credential", ID: credentialID}, audit.Payload{
				"service_account_id": sa.ID,
				"target_principal":   string(sa.PrincipalID),
				"principal_class":    string(sa.Kind),
				"credential_id":      credentialID,
				"reactivated_at":     now.Format(time.RFC3339),
				"skew_seconds":       int(oidcfed.MaxClockSkew / time.Second),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, e)
	})
	return at, err
}

// FederatedCaller is a validated federated presentation: the issuer it names and
// the binding predicate its claims imply.
//
// It exists because the two halves of federated authentication must happen on
// opposite sides of a transaction boundary. Validation needs the network (a JWKS
// refresh) and must therefore run BEFORE any transaction opens — on sqlite a
// hung issuer inside a write transaction would stall every writer in the
// instance. Binding resolution must happen INSIDE the authorizing transaction,
// uncached, because that is what makes revocation bite at the next fetch.
type FederatedCaller struct {
	IssuerID string
	Subject  string
	// Check is the binding half of validation, closed over the issuer
	// configuration and the token's claims. The chokepoint refuses a nil one.
	Check authz.BindingPredicate
	// Cause is the closed refusal cause when validation failed, for the audit
	// event. Empty on success.
	Cause string
}

// Authenticate is the PRE-TRANSACTION half of federated authentication: peek at
// the unverified issuer, resolve its configuration, refresh the JWKS cache if
// the age or an unknown `kid` calls for it, and validate the token completely.
//
// Every failure answers the SAME error — domain.ErrUnauthenticated — whatever
// the cause. The cause reaches the audit trail and nothing else, which is the
// unauthorized-is-indistinguishable-from-nonexistent rule one layer earlier than
// the chokepoint.
func (s *Federation) Authenticate(ctx context.Context, presented string) (FederatedCaller, error) {
	now := s.now()
	if s.Cache == nil {
		// A build that did not wire the cache refuses federated presentation
		// rather than skipping validation. Fail closed.
		return FederatedCaller{}, domain.ErrUnauthenticated
	}
	// ADMISSION FIRST, before any parse, any database read and any signature
	// check. This whole function is pre-authentication work an unauthenticated
	// caller can trigger by presenting a string, and the expensive part — an RSA
	// verify, plus an outbound fetch on a cache miss — sits below.
	if s.Admission != nil {
		release, err := s.Admission.Enter(ctx, audit.FromContext(ctx).SourceIP)
		if err != nil {
			// The uniform overload answer, not a refusal by cause: an overloaded
			// instance must not become an oracle either.
			return FederatedCaller{}, err
		}
		defer release()
	}
	tokenIssuer, _, err := oidcfed.Peek(presented)
	if err != nil {
		if auditErr := s.recordRefusal(ctx, "", causeFedNotAToken); auditErr != nil {
			return FederatedCaller{}, auditErr
		}
		return FederatedCaller{}, domain.ErrUnauthenticated
	}

	// The issuer configuration is read in its own transaction, before the
	// operation's, because the validation it feeds needs the network. It is
	// therefore a SNAPSHOT, and the closure below re-reads the row inside the
	// authorizing transaction and refuses when the two disagree — see
	// issuerPolicyMoved.
	var issuer authz.FederationIssuer
	if err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		iss, err := az.FederationIssuerByIssuer(ctx, tokenIssuer)
		if err != nil {
			return err
		}
		issuer = iss
		return nil
	}); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			if auditErr := s.recordRefusal(ctx, tokenIssuer, causeFedUnknownIssuer); auditErr != nil {
				return FederatedCaller{}, auditErr
			}
			return FederatedCaller{}, domain.ErrUnauthenticated
		}
		return FederatedCaller{}, err
	}

	fedIssuer := oidcfed.Issuer{
		ID: issuer.ID, Issuer: issuer.Issuer, Type: issuer.Type, Mode: issuer.Mode,
		StaticJWKS: issuer.StaticJWKS, RefusedAudiences: issuer.RefusedAudiences,
	}
	claims, state, err := s.Cache.Verify(ctx, fedIssuer, presented, now)
	// The JWKS observations are recorded whatever the outcome: a tolerated
	// refresh failure and a staleness breach are both events the ADR requires,
	// and only the second one is a refusal.
	if auditErr := s.recordKeyState(ctx, issuer.Issuer, state, err); auditErr != nil {
		return FederatedCaller{}, auditErr
	}
	if err != nil {
		if auditErr := s.recordRefusal(ctx, issuer.Issuer, refusalCause(err)); auditErr != nil {
			return FederatedCaller{}, auditErr
		}
		return FederatedCaller{}, domain.ErrUnauthenticated
	}

	if s.OnValidated != nil {
		s.OnValidated()
	}
	return FederatedCaller{
		IssuerID: issuer.ID,
		Subject:  claims.Subject,
		Check: func(current authz.FederationIssuer, b authz.Binding) error {
			// THE POLICY THIS REQUEST WAS VALIDATED UNDER MUST STILL BE THE
			// CURRENT ONE. Everything above ran outside a transaction against
			// `issuer`; `current` is the row as it stands in the authorizing
			// transaction. If an administrator narrowed the refused-audience list
			// or switched the key source while verification was in flight, this
			// request would otherwise complete under the superseded policy — after
			// the update committed.
			//
			// The refusal is not a retry loop: the caller presents again and picks
			// up the new policy, which is what "revocation bites at the next
			// request" already means everywhere else in this system.
			if issuerPolicyMoved(issuer, current) {
				return fmt.Errorf("%w: issuer configuration changed during validation", oidcfed.ErrNoIssuer)
			}
			// The IN-TRANSACTION row feeds the check, not the snapshot, so even a
			// change this comparison somehow failed to notice cannot widen what is
			// accepted.
			return oidcfed.CheckBinding(oidcfed.Issuer{
				ID: current.ID, Issuer: current.Issuer, Type: current.Type,
				Mode: current.Mode, StaticJWKS: current.StaticJWKS,
				RefusedAudiences: current.RefusedAudiences,
			}, oidcfed.Binding{
				Audience:           b.Audience,
				RequiredClaimsJSON: b.RequiredClaimsJSON,
				ReactivatedAt:      b.ReactivatedAt,
			}, claims, now)
		},
	}, nil
}

// issuerPolicyMoved reports whether any POLICY-RELEVANT field of an issuer
// configuration differs between the snapshot validation ran under and the row in
// the authorizing transaction.
//
// It compares fields rather than an `updated_at` timestamp, and the reason is
// that a timestamp is a proxy: it moves on changes that do not matter and, at
// coarse clock granularity, can fail to move on ones that do. Every field named
// here changes what a token may be. `created_at`/`created_by` and the id are
// deliberately absent — they cannot change for a given row, and a difference in
// them means the row was replaced, which the id comparison catches.
func issuerPolicyMoved(before, current authz.FederationIssuer) bool {
	if before.ID != current.ID || before.Issuer != current.Issuer ||
		before.Type != current.Type || before.Mode != current.Mode ||
		before.StaticJWKS != current.StaticJWKS {
		return true
	}
	return !slices.Equal(before.RefusedAudiences, current.RefusedAudiences)
}

// RecordBindingRefusal records a refusal the CHOKEPOINT produced — an unbound
// identity, a revoked binding, a failed binding predicate — which the
// pre-transaction half cannot see, because the row it turns on is read only
// inside the operation's transaction.
//
// It must be called AFTER that transaction has ended, not inside it. Two reasons,
// both real: the operation's transaction rolled back, so an event staged inside
// it would be a durable record that is not durable; and on sqlite a nested write
// transaction deadlocks against the single writer until the retry deadline
// elapses.
//
// It records ONE cause for all three outcomes, and the collapse is deliberate.
// The resolution surface hands the binding predicate a DECOY binding on a miss —
// which is what keeps an unbound identity from being the cheap case — so the
// predicate's verdict on a miss is the decoy's verdict, not any real binding's.
// Reporting it as a cause would therefore sometimes report the decoy. The
// PRE-transaction causes (unknown issuer, unavailable or stale keys, signature,
// token age, audience) are reported individually, because nothing decoy-shaped
// is involved in producing them.
func (s *Federation) RecordBindingRefusal(ctx context.Context, issuer string) error {
	return s.recordRefusal(ctx, issuer, causeFedUnbound)
}

// refusalCause maps a validation error onto the closed audit enum. By class,
// never by detail.
func refusalCause(err error) string {
	switch {
	case errors.Is(err, oidcfed.ErrNotAToken):
		return causeFedNotAToken
	case errors.Is(err, oidcfed.ErrNoIssuer):
		return causeFedUnknownIssuer
	case errors.Is(err, oidcfed.ErrKeysStale):
		return causeFedStale
	case errors.Is(err, oidcfed.ErrKeysUnavailable):
		return causeFedKeys
	case errors.Is(err, oidcfed.ErrTokenAge):
		return causeFedTokenAge
	case errors.Is(err, oidcfed.ErrAudience):
		return causeFedAudience
	case errors.Is(err, oidcfed.ErrEventName):
		return causeFedEventName
	case errors.Is(err, oidcfed.ErrRestorePredicate):
		return causeFedRestore
	case errors.Is(err, oidcfed.ErrClaim):
		return causeFedClaim
	default:
		return causeFedSignature
	}
}

// recordRefusal writes one federated-authentication refusal.
//
// It rides the resolution surface's pre-authentication audit writer, exactly as
// #54's `auth.oidc_refused` does, and for the same reason: the presentation
// failed, so there is no resolved principal and no proof to write under — which
// is the case that writer exists for. The row lands in the instance trail.
//
// FAIL CLOSED: the audit-write error propagates. A denial without its durable
// record is exactly what the discipline forbids, so a trail that cannot be
// written turns the refusal into a fault rather than a quiet refusal.
func (s *Federation) recordRefusal(ctx context.Context, issuer, cause string) error {
	payload := audit.Payload{
		"issuer": audit.SanitizeFreeText(issuer),
		"cause":  cause,
	}
	return tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		e, err := newAuditEvent(ctx, audit.EventFederationRefused, "",
			audit.Object{Type: "federation_presentation"}, audit.OutcomeFailure, "", payload)
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
}

// recordKeyState records the ADR's two JWKS events: a refresh failure the cache
// ABSORBED by serving stale keys, and the staleness-bound breach that fails
// closed. One event type carries both, discriminated by the `served_stale` and
// `staleness_breached` members — they are the same fact about the same object at
// two severities, and splitting them would have made a reader join two streams
// to answer "was this issuer reachable".
//
// It returns nothing but an error, and a nil KeyState writes nothing: the
// overwhelmingly common case is a cache hit inside the refresh interval, which
// is not an event.
func (s *Federation) recordKeyState(ctx context.Context, issuer string, state oidcfed.KeyState, verifyErr error) error {
	breached := errors.Is(verifyErr, oidcfed.ErrKeysStale)
	unavailable := errors.Is(verifyErr, oidcfed.ErrKeysUnavailable)
	if state.RefreshFailed == nil && !state.RefreshThrottled && !breached && !unavailable {
		return nil
	}
	payload := audit.Payload{
		"issuer":             audit.SanitizeFreeText(issuer),
		"age_seconds":        int(state.Age / time.Second),
		"served_stale":       state.ServedStale,
		"staleness_breached": breached || unavailable,
		"refresh_throttled":  state.RefreshThrottled,
	}
	return tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		e, err := newAuditEvent(ctx, audit.EventJWKSRefreshFailed, "",
			audit.Object{Type: "federation_jwks"}, audit.OutcomeFailure, "", payload)
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
}

// checkIssuerRequest validates the whole configuration before any row is
// written.
func checkIssuerRequest(req IssuerRequest) error {
	if req.Issuer == "" || !strings.HasPrefix(req.Issuer, "https://") {
		// https only, and not as ceremony: discovery and JWKS are fetched from
		// this URL, and an http issuer means the instance's whole federation
		// trust rests on whoever holds the network path.
		return ErrIssuerValue
	}
	if !domain.IsIssuerType(req.Type) {
		return ErrIssuerValue
	}
	if err := checkJWKSMode(req.Mode, req.StaticJWKS); err != nil {
		return err
	}
	return checkRefusedAudiences(req.RefusedAudiences)
}

func checkJWKSMode(mode domain.JWKSMode, staticJWKS string) error {
	if !domain.IsJWKSMode(mode) {
		return ErrIssuerValue
	}
	if (mode == domain.JWKSStatic) != (staticJWKS != "") {
		// The pairing is total: static mode needs a document, discovery mode
		// must not carry one. A document that is stored but unused is a key set
		// nobody rotates.
		return ErrIssuerValue
	}
	return nil
}

// checkRefusedAudiences requires at least one. That is deliberate rather than
// tidy: the whole default-audience rule turns on the instance knowing what the
// default IS, and the Kubernetes API-server audience is operator-supplied — not
// derivable from anything Hikyo can see. An issuer configured with an empty
// refused list would silently accept the audience the ADR says MUST be refused.
func checkRefusedAudiences(refused []string) error {
	if len(refused) == 0 {
		return ErrIssuerValue
	}
	for _, a := range refused {
		if a == "" || strings.ContainsAny(a, "\n\r") {
			// Newline is the storage separator, so a value containing one would
			// split into two audiences on read.
			return ErrIssuerValue
		}
	}
	return nil
}

// checkBindingAgainstIssuer enforces the two per-issuer binding rules at
// CREATION time, which is the first of their two enforcement points (the second
// is oidcfed.CheckBinding, at every validation). Both exist because they answer
// different questions: creation refuses a binding that could never be safe,
// validation refuses a token that is not what the binding named.
func checkBindingAgainstIssuer(issuer authz.FederationIssuer, audience, claimsJSON string) error {
	for _, refused := range issuer.RefusedAudiences {
		if audience == refused {
			return fmt.Errorf("%w (%q)", ErrBindingAudience, refused)
		}
	}
	pinned, err := oidcfed.ParseRequiredClaims(claimsJSON)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBindingClaims, err)
	}
	if len(pinned) == 0 {
		return ErrBindingClaims
	}
	// EVERY CI binding must pin `event_name`, and it is named first because it
	// has its own refusal: without it a `pull_request_target` token carries the
	// ordinary ref-form subject — the default branch's subject, the one a
	// production binding names — and a crafted pull request against such a
	// workflow yields a token bearing it.
	if domain.IsCIIssuerType(issuer.Type) {
		if _, ok := pinned[oidcfed.EventNameClaim]; !ok {
			return ErrBindingEventName
		}
	}
	// THE IMMUTABLE IDENTIFIERS THIS PLATFORM EXPOSES. The ADR reads as a MUST —
	// "where an issuer exposes immutable numeric identifiers for the repository
	// and its owner, the binding pins those rather than the names. A rename or
	// transfer otherwise silently re-points a production binding at whatever now
	// occupies the old path" — so it is enforced here rather than left to
	// operator diligence. There is no override flag; see oidcfed.RequiredPins.
	if missing := oidcfed.MissingRequiredPins(issuer.Type, pinned); len(missing) > 0 {
		return fmt.Errorf("%w: %s requires %s", ErrBindingImmutableID,
			issuer.Type, strings.Join(missing, ", "))
	}
	return nil
}

// encodeClaimPins renders the discriminated pins as the stored canonical JSON
// object. json.Marshal of a map sorts its keys, so the stored document is
// deterministic for a given pin set — which matters because the document is
// compared, logged and rendered back.
func encodeClaimPins(pins []ClaimPin) (string, error) {
	if len(pins) == 0 {
		return "", ErrBindingClaims
	}
	out := map[string]json.RawMessage{}
	for _, pin := range pins {
		if pin.Claim == "" {
			return "", ErrBindingClaims
		}
		if _, dup := out[pin.Claim]; dup {
			// Two pins for one claim is two different requirements for one
			// value, and a precedence rule on a security predicate is exactly
			// the quiet ambiguity fail-loud exists to prevent.
			return "", fmt.Errorf("%w: %q is pinned twice", ErrBindingClaims, pin.Claim)
		}
		set := 0
		var raw json.RawMessage
		var err error
		if pin.String != nil {
			set++
			raw, err = json.Marshal(*pin.String)
		}
		if pin.Number != nil {
			set++
			raw, err = json.Marshal(*pin.Number)
		}
		if pin.Boolean != nil {
			set++
			raw, err = json.Marshal(*pin.Boolean)
		}
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrBindingClaims, err)
		}
		if set != 1 {
			// Exactly one, never a precedence rule. A pin naming both a string
			// and a number names two different claim values.
			return "", fmt.Errorf("%w: %q names %d values", ErrBindingClaims, pin.Claim, set)
		}
		out[pin.Claim] = raw
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBindingClaims, err)
	}
	return string(encoded), nil
}

// DecodeClaimPins renders a stored pinned-claim document back as discriminated
// pins, for the read surface. It is the inverse of encodeClaimPins and refuses
// anything the encoder could not have produced.
func DecodeClaimPins(raw string) ([]ClaimPin, error) {
	if raw == "" {
		return nil, nil
	}
	parsed, err := oidcfed.ParseRequiredClaims(raw)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(parsed))
	for name := range parsed {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]ClaimPin, 0, len(names))
	for _, name := range names {
		pin := ClaimPin{Claim: name}
		value := parsed[name]
		var s string
		var n int64
		var b bool
		switch {
		case json.Unmarshal(value, &s) == nil:
			pin.String = &s
		case json.Unmarshal(value, &n) == nil:
			pin.Number = &n
		case json.Unmarshal(value, &b) == nil:
			pin.Boolean = &b
		default:
			return nil, fmt.Errorf("%w: %q is not a string, integer or boolean", ErrBindingClaims, name)
		}
		out = append(out, pin)
	}
	return out, nil
}

// pinnedClaimNames is what the audit event records: the claim NAMES, never their
// values. A pinned value can be a repository path or a workflow reference, which
// is schema-ish rather than secret — but it can also be whatever an operator
// chose to pin, and a trail is not the place to find out.
func pinnedClaimNames(pins []ClaimPin) []string {
	out := make([]string, 0, len(pins))
	for _, pin := range pins {
		out = append(out, pin.Claim)
	}
	sort.Strings(out)
	return out
}

// postStateReach mirrors the bearer mint's computation: a binding changes no
// grants, so the post-state IS the current state — which is exactly why the ADR
// phrases the conjunct over the post-state rather than over what the mint adds.
func (s *Federation) postStateReach(ctx context.Context, az *authz.TxAuthorizer, scope domain.Scope, sa authz.ServiceAccount) (authz.Reachable, error) {
	envs, err := az.EnvironmentsInProject(ctx, scope)
	if err != nil {
		return authz.Reachable{}, err
	}
	grants, err := az.GrantsOf(ctx, sa.PrincipalID)
	if err != nil {
		return authz.Reachable{}, err
	}
	return authz.ReachableFrom(scope, envs, grants), nil
}

func issuerEvent(ctx context.Context, actor domain.PrincipalID, id, issuer, change string, req IssuerRequest) (audit.Event, error) {
	return newAuditEvent(ctx, audit.EventFederationIssuerChanged, actor,
		audit.Object{Type: "instance", ID: id}, audit.OutcomeSuccess, "", audit.Payload{
			"issuer_id":         id,
			"issuer":            audit.SanitizeFreeText(issuer),
			"issuer_type":       string(req.Type),
			"change":            change,
			"jwks_mode":         string(req.Mode),
			"refused_audiences": req.RefusedAudiences,
		})
}
