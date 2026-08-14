package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// Machine identities (#61, machine-identities ADR): service accounts, their
// credentials, and the three-operation authorization table.
//
// The table, restated because naming only its first row is the mistake this
// file exists to prevent:
//
//	Minting a credential (first issue or replacement)
//	    manage-identities(project) ∧ disclosure over EVERY environment
//	    reachable in the resulting POST-STATE ∧ reauthentication.
//	    The whole post-state, because the actor RECEIVES the credential —
//	    delivery is display-once TO THEM — so they walk away holding
//	    everything it can reach. A rotation adds no environment and would
//	    otherwise require `reveal` on nothing, which is how a principal with
//	    manage-identities and no reveal walks off with a live production
//	    token.
//	Grant mutation expanding a machine principal's authority
//	    the same formula over the DELTA only, in one transaction with
//	    ordinary grant authorization, stricter wins. It lives in
//	    grants.go's checkMachineWidening.
//	Narrowing — revoke, delete, reduce, list
//	    plain manage-identities. NO disclosure gate, because incident
//	    response must never be gated on disclosure rights.
//
// "Disclosure" is two capabilities, never one: `reveal` over newly reachable
// CURRENT plaintext and `reveal-history` over newly reachable HISTORICAL
// plaintext, computed independently. Auth.RequireDisclosureAuthority is the
// single implementation both rows call.

// DefaultCredentialLifetime is the per-credential default when a mint names
// none. It is finite by the ADR's rule that "the easy path is bounded and a
// long-lived credential is a typed choice someone made".
//
// OPERATIONS-SPEC FOG VALUE, chosen here and recorded for ratification: 30
// days. Short enough that an unnoticed leak has a bound, long enough that a
// quarterly rotation cadence does not become a weekly one.
const DefaultCredentialLifetime = 30 * 24 * time.Hour

// prefixHintChars is how much of a minted value the metadata surface keeps:
// the whole grammar prefix (`hik_1_wl_`) plus six body characters. Enough to
// tell two live credentials apart in a list, far short of anything a search
// can narrow — the value carries 256 bits and six base62 characters are ~36
// of them, which identifies nothing and brute-forces nothing.
const prefixHintChars = 6

var (
	// ErrServiceAccountName refuses a name outside the grammar. It is
	// ErrInvalid, decided before any tenant resolution, so it discloses
	// nothing about what exists.
	ErrServiceAccountName = fmt.Errorf("%w: service: a service-account name must be 1-64 characters", domain.ErrInvalid)
	// ErrServiceAccountKind refuses a kind outside the closed set. Kind is
	// immutable after creation, so this is the only gate there is.
	ErrServiceAccountKind = fmt.Errorf("%w: service: a service account is `workload` or `automation`", domain.ErrInvalid)
	// ErrCredentialCap refuses a mint that would exceed the instance's
	// concurrent-credential cap. Overlap-based rotation needs room; an
	// unbounded mint loop is a different thing.
	ErrCredentialCap = fmt.Errorf("%w: service: this service account already holds the maximum number of live credentials", domain.ErrLimitExceeded)
	// ErrIndefiniteNotAllowed refuses an indefinite credential where the
	// instance opt-in is off. It is a SEPARATE refusal from the lifetime
	// clamp on purpose: raising the ceiling can never manufacture indefinite.
	ErrIndefiniteNotAllowed = fmt.Errorf("%w: service: this instance does not permit indefinite credentials", domain.ErrConflict)
	// ErrCredentialLifetime refuses a non-positive requested lifetime.
	ErrCredentialLifetime = fmt.Errorf("%w: service: a credential lifetime must be positive", domain.ErrInvalid)
	// ErrNoSuchCredential refuses a revoke of a credential this service
	// account does not hold.
	ErrNoSuchCredential = fmt.Errorf("%w: service: no such credential", domain.ErrNotFound)
	// ErrPolicyValue refuses an instance policy outside its own bounds.
	ErrPolicyValue = fmt.Errorf("%w: service: a credential policy needs a positive lifetime ceiling and credential cap", domain.ErrInvalid)
)

// Identities owns the machine-identity surface. Like every service here it
// opens one transaction, authorizes inside it, and performs the whole
// mutation before it commits.
type Identities struct {
	DB *store.DB
	// Auth supplies the reauthentication conjunct. Machines never
	// reauthenticate; the human minting one does.
	Auth *Auth
	Now  func() time.Time
}

func (s *Identities) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

// ServiceAccountView is the metadata surface of one service account.
type ServiceAccountView struct {
	ID        string
	Principal domain.PrincipalID
	Name      string
	Kind      domain.PrincipalClass
	CreatedAt time.Time
	CreatedBy domain.PrincipalID
	// LiveCredentials is how many of its credentials currently authenticate,
	// so an operator can see at a glance which accounts are actually in use.
	LiveCredentials int64
}

// CredentialView is a credential's metadata. There is no value field, and
// that absence is the display-once rule expressed in a type: nothing in the
// system returns a credential value after mint, so there is nowhere to read
// one from.
type CredentialView struct {
	ID         string
	Kind       domain.CredentialKind
	PrefixHint string
	Lifetime   domain.CredentialLifetime
	// ExpiresAt is the zero time for an indefinite credential.
	ExpiresAt  time.Time
	CreatedAt  time.Time
	CreatedBy  domain.PrincipalID
	RevokedAt  time.Time
	LastUsedAt time.Time
	// ExpiringSoon is the in-product expiry warning the ADR asks for first,
	// before any transport. It is computed, never stored: a stored flag would
	// be stale the moment the clock moved past it.
	ExpiringSoon bool
	// The binding half, populated only for an `oidc-federation` row and the
	// zero value for a bearer credential — the kind discriminates, so there is
	// no second boolean saying which half of the view is meaningful.
	//
	// A binding IS a credential row (#62), listed and revoked through these
	// routes, so its identity has to travel on the listing: an operator cannot
	// audit a byte-exact `(issuer, subject)` pair they cannot see, and the
	// contract has always said this row "carries the binding members instead"
	// of a prefix hint. `Issuer` is the byte-exact string rather than the
	// configuration's id, because the id is not what the external authority
	// presents and not what an operator compares against a cluster.
	Issuer         string
	Subject        string
	Audience       string
	RequiredClaims []ClaimPin
	// ReactivatedAt is the restore predicate's instant, zero unless this
	// binding has been through a restore. It is a permanent refusal floor, not
	// a quarantine window, and the surface that hides it hides the reason a
	// workload stopped authenticating.
	ReactivatedAt time.Time
}

// ExpiryWarningWindow is how far ahead a live finite credential is flagged
// as expiring. OPERATIONS-SPEC FOG VALUE, recorded for ratification: 14 days.
//
// The ADR also asks for "an audit event at each threshold", and that half is
// NOT here. It needs something to notice a threshold crossing when nobody is
// looking, and this binary has no scheduler, no outbox and no background
// sweep — a threshold event emitted only when a credential happens to be
// listed would fire on polling rather than on expiry, which is worse than
// absent because it looks like coverage. The in-product half the ADR puts
// first (this field, surfaced on every list and mint response) is complete;
// the event lands with whatever ticket introduces periodic work.
const ExpiryWarningWindow = 14 * 24 * time.Hour

// MintRequest names the lifetime a caller wants. The zero value asks for the
// finite default, which is the ADR's "the easy path is bounded".
type MintRequest struct {
	// Indefinite selects the DISTINCT typed lifetime. It is a separate field
	// from Lifetime rather than a sentinel duration, because `indefinite` is
	// a value and must be unreachable by raising any ceiling.
	Indefinite bool
	// Lifetime is the requested finite duration; zero means the default.
	Lifetime time.Duration
}

// MintResult carries the credential value EXACTLY ONCE, to exactly one
// caller. Nothing persists it and no read path returns it.
type MintResult struct {
	Value      string
	Credential CredentialView
	// Clamped reports that the instance ceiling shortened what was asked
	// for, so the caller can say so rather than let the operator discover it
	// when the credential dies early.
	Clamped bool
}

// CreateServiceAccount creates a project-owned machine principal. `kind` is
// declared here and is immutable: there is no update path, because in-place
// widening of a class that N workloads already hold is what the ADR refuses.
//
// Creation itself carries NO disclosure gate. A fresh service account holds
// no grants, so it reaches nothing; the gate fires when a grant lands on it
// (grants.go's widening rule) or when a credential is minted for it.
func (s *Identities) CreateServiceAccount(ctx context.Context, actor Actor, scope domain.Scope, name string, kind domain.PrincipalClass) (ServiceAccountView, error) {
	if name == "" || len(name) > 64 {
		return ServiceAccountView{}, ErrServiceAccountName
	}
	if !domain.IsServiceAccountKind(kind) {
		return ServiceAccountView{}, ErrServiceAccountKind
	}
	saID, err := newID("sa")
	if err != nil {
		return ServiceAccountView{}, err
	}
	principalID, err := newID("mch")
	if err != nil {
		return ServiceAccountView{}, err
	}
	now := s.now()
	var out ServiceAccountView
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpServiceAccountCreate, scope)
		if err != nil {
			return err
		}
		if err := az.CreateMachinePrincipal(ctx, domain.PrincipalID(principalID), kind, now); err != nil {
			return err
		}
		sa := authz.NewServiceAccount{
			ID: saID, PrincipalID: domain.PrincipalID(principalID),
			Org: scope.Org, Project: scope.Project, Name: name, Kind: kind,
			CreatedAt: now, CreatedBy: caller.Principal,
		}
		if err := az.CreateServiceAccount(ctx, sa); err != nil {
			return err
		}
		out = ServiceAccountView{
			ID: saID, Principal: domain.PrincipalID(principalID), Name: name,
			Kind: kind, CreatedAt: now, CreatedBy: caller.Principal,
		}
		e, err := domainEvent(ctx, audit.EventServiceAccountCreated, caller.Principal,
			audit.Object{Type: "service_account", ID: saID}, audit.Payload{
				"service_account_id": saID,
				"target_principal":   principalID,
				"principal_class":    string(kind),
				"name":               audit.SanitizeFreeText(name),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, e)
	})
	return out, err
}

// ListServiceAccounts lists a project's machine principals with their live
// credential counts. Listing is a narrowing-class operation: plain
// manage-identities, no disclosure gate.
func (s *Identities) ListServiceAccounts(ctx context.Context, actor Actor, scope domain.Scope) ([]ServiceAccountView, error) {
	now := s.now()
	var out []ServiceAccountView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpServiceAccountList, scope)
		if err != nil {
			return err
		}
		accounts, err := az.ServiceAccountsIn(ctx, scope)
		if err != nil {
			return err
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		// One census for the whole project rather than a count per account: an
		// administrative list must not scale with the fleet it describes.
		live, err := az.LiveMachineCredentialCounts(ctx, scope, epoch, now)
		if err != nil {
			return err
		}
		out = make([]ServiceAccountView, 0, len(accounts))
		for _, sa := range accounts {
			out = append(out, ServiceAccountView{
				ID: sa.ID, Principal: sa.PrincipalID, Name: sa.Name, Kind: sa.Kind,
				CreatedAt: sa.CreatedAt, CreatedBy: sa.CreatedBy, LiveCredentials: live[sa.ID],
			})
		}
		e, err := domainEvent(ctx, audit.EventCredentialsListed, caller.Principal,
			audit.Object{Type: "project", ID: string(scope.Project)}, audit.Payload{
				"scope": renderScope(scope), "row_count": len(out),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, e)
	})
	return out, err
}

// DeleteServiceAccount revokes every credential and releases every grant in
// ONE transaction (#15's atomic revocation), then removes the principal.
//
// It runs under the PLAIN capability with no disclosure gate and no
// reauthentication: this is the sharpest narrowing in the surface, and
// requiring `reveal` to deprovision a compromised workload would be a
// self-inflicted incident-response delay.
func (s *Identities) DeleteServiceAccount(ctx context.Context, actor Actor, scope domain.Scope, id string) error {
	now := s.now()
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpServiceAccountDelete, scope)
		if err != nil {
			return err
		}
		sa, err := az.ServiceAccountAt(ctx, scope, id)
		if err != nil {
			return err
		}
		// The revoke runs before the delete so the trail records the
		// transition — and its blast radius — while the rows still exist.
		revoked, err := az.RevokeAllMachineCredentials(ctx, sa.ID, now)
		if err != nil {
			return err
		}
		if err := az.DeleteMachineCredentials(ctx, sa.ID); err != nil {
			return err
		}
		if _, err := az.DeleteServiceAccount(ctx, scope, sa.ID); err != nil {
			return err
		}
		// Grants and principal last: the grant release is what makes deletion
		// deprovisioning rather than merely credential revocation.
		if err := az.DeleteMachinePrincipal(ctx, sa.PrincipalID); err != nil {
			return err
		}
		e, err := domainEvent(ctx, audit.EventServiceAccountDeleted, caller.Principal,
			audit.Object{Type: "service_account", ID: sa.ID}, audit.Payload{
				"service_account_id":  sa.ID,
				"target_principal":    string(sa.PrincipalID),
				"principal_class":     string(sa.Kind),
				"credentials_revoked": int(revoked),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, e)
	})
}

// MintCredential issues a bearer credential for one service account and
// returns its value EXACTLY ONCE.
//
// This is the ADR's first authorization row, and the post-state phrasing is
// the load-bearing part: the disclosure conjunct ranges over every
// environment reachable in the RESULTING STATE, not over anything the mint
// adds — a mint adds no grants at all, so an "added environments" reading
// would require `reveal` on nothing and let a principal holding
// manage-identities and no reveal rotate a production credential and walk
// away with a live production-reading token.
//
// Rotation is this call plus a revoke of the predecessor (ADR § Rotation:
// "mint a second credential, distribute it, revoke the first"). It is
// deliberately not one atomic verb: overlap is the intended steady state, so
// a mint that succeeds and a revoke that fails leaves the operator with two
// live credentials — the safe direction — rather than none.
func (s *Identities) MintCredential(ctx context.Context, actor Actor, scope domain.Scope, saID string, req MintRequest) (MintResult, error) {
	if req.Lifetime < 0 {
		return MintResult{}, ErrCredentialLifetime
	}
	credID, err := newID("mcr")
	if err != nil {
		return MintResult{}, err
	}
	now := s.now()
	var out MintResult
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpCredentialMint, scope)
		if err != nil {
			return err
		}
		sa, err := az.ServiceAccountAt(ctx, scope, saID)
		if err != nil {
			return err
		}
		// LOCK ORDER: the policy row, then the service account's principal
		// row — the same order SetPolicy and the grant writers take, so the
		// three cannot deadlock against each other.
		//
		// Both locks are load-bearing rather than defensive. Everything below
		// is a read-then-write across a window a concurrent transaction can
		// commit into, and postgres READ COMMITTED will let it: a grant
		// landing on this principal would widen the account after the
		// post-state check and hand out a token whose authority never passed
		// the gate; a tightening would let this insert land under a ceiling
		// that no longer exists; a sibling mint would let two callers both
		// see capacity and exceed the cap. sqlite's single writer hides all
		// three, which is exactly why they must not be left to it.
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

		lifetime, expires, clamped, err := resolveLifetime(req, policy, now)
		if err != nil {
			return err
		}

		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		live, err := az.LiveMachineCredentialCount(ctx, sa.ID, epoch, now)
		if err != nil {
			return err
		}
		if live >= policy.MaxLiveCredentials {
			return fmt.Errorf("%w (%d)", ErrCredentialCap, policy.MaxLiveCredentials)
		}

		// The whole-post-state disclosure conjunct, per authority class.
		reach, err := s.postStateReach(ctx, az, scope, sa)
		if err != nil {
			return err
		}
		actorGrants, err := az.GrantRowsForPrincipal(ctx, caller.Principal)
		if err != nil {
			return err
		}
		if s.Auth == nil {
			return errors.New("service: the identity surface has no reauthentication seam wired")
		}
		current, historical := sortedKeys(reach.Current), sortedKeys(reach.Historical)
		if err := s.Auth.RequireDisclosureAuthority(ctx, az, caller, actorGrants, scope, current, historical, now); err != nil {
			return err
		}

		artifact, err := machineArtifactType(sa.Kind)
		if err != nil {
			return err
		}
		value, verifier, err := crypto.NewArtifact(artifact)
		if err != nil {
			return err
		}
		hint, err := prefixHint(value)
		if err != nil {
			return err
		}
		if err := az.CreateMachineCredential(ctx, authz.NewCredential{
			ID: credID, ServiceAccountID: sa.ID, Kind: domain.CredentialHikyoToken,
			Verifier: verifier, PrefixHint: hint, Lifetime: lifetime, ExpiresAt: expires,
			CredentialEpoch: epoch, CreatedAt: now, CreatedBy: caller.Principal,
		}); err != nil {
			return err
		}

		view := CredentialView{
			ID: credID, Kind: domain.CredentialHikyoToken, PrefixHint: hint,
			Lifetime: lifetime, ExpiresAt: expires, CreatedAt: now, CreatedBy: caller.Principal,
		}
		view.ExpiringSoon = expiringSoon(view, now)
		out = MintResult{Value: value, Credential: view, Clamped: clamped}

		payload := audit.Payload{
			"service_account_id":          sa.ID,
			"target_principal":            string(sa.PrincipalID),
			"principal_class":             string(sa.Kind),
			"credential_id":               credID,
			"credential_kind":             string(domain.CredentialHikyoToken),
			"lifetime":                    string(lifetime),
			"clamped":                     clamped,
			"reveal_environments":         envStrings(current),
			"reveal_history_environments": envStrings(historical),
		}
		if lifetime == domain.LifetimeFinite {
			payload["expires_at"] = expires.Format(time.RFC3339)
		}
		e, err := domainEvent(ctx, audit.EventCredentialMinted, caller.Principal,
			audit.Object{Type: "machine_credential", ID: credID}, payload)
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, e)
	})
	if err != nil {
		return MintResult{}, err
	}
	return out, nil
}

// ListCredentials returns metadata only — prefix hint, kind, lifetime,
// expiry, creation and last use. Never the value: there is no field for it
// and no query that selects one.
func (s *Identities) ListCredentials(ctx context.Context, actor Actor, scope domain.Scope, saID string) ([]CredentialView, error) {
	now := s.now()
	var out []CredentialView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpCredentialList, scope)
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
		// Issuer strings are resolved once per DISTINCT configuration rather
		// than once per row: a service account's bindings usually name the
		// same issuer, and a lookup per row would make the listing's cost
		// scale with the fleet rather than with the instance's configuration.
		issuers := map[string]string{}
		out = make([]CredentialView, 0, len(creds))
		for _, c := range creds {
			view := CredentialView{
				ID: c.ID, Kind: c.Kind, PrefixHint: c.PrefixHint, Lifetime: c.Lifetime,
				ExpiresAt: c.ExpiresAt, CreatedAt: c.CreatedAt, CreatedBy: c.CreatedBy,
				RevokedAt: c.RevokedAt, LastUsedAt: c.LastUsedAt,
			}
			if c.Kind == domain.CredentialOIDCFederation {
				issuer, ok := issuers[c.Binding.IssuerID]
				if !ok {
					configured, err := az.FederationIssuerByID(ctx, c.Binding.IssuerID)
					if err != nil {
						return err
					}
					issuer = configured.Issuer
					issuers[c.Binding.IssuerID] = issuer
				}
				pins, err := DecodeClaimPins(c.Binding.RequiredClaimsJSON)
				if err != nil {
					return err
				}
				view.Issuer = issuer
				view.Subject = c.Binding.Subject
				view.Audience = c.Binding.Audience
				view.RequiredClaims = pins
				view.ReactivatedAt = c.Binding.ReactivatedAt
			}
			view.ExpiringSoon = expiringSoon(view, now)
			out = append(out, view)
		}
		e, err := domainEvent(ctx, audit.EventCredentialsListed, caller.Principal,
			audit.Object{Type: "service_account", ID: sa.ID}, audit.Payload{
				"scope": renderScope(scope), "row_count": len(out),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, e)
	})
	return out, err
}

// RevokeCredential kills one credential. It bites at the NEXT request: the
// liveness predicate is read in the authenticating transaction, uncached, so
// there is no window in which a revoked credential still reads anything.
//
// Revoking one credential is NOT deprovisioning — grants are untouched and
// sibling credentials keep working — and it runs under the plain capability
// with no disclosure gate and no reauthentication.
func (s *Identities) RevokeCredential(ctx context.Context, actor Actor, scope domain.Scope, saID, credentialID string) error {
	now := s.now()
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpCredentialRevoke, scope)
		if err != nil {
			return err
		}
		sa, err := az.ServiceAccountAt(ctx, scope, saID)
		if err != nil {
			return err
		}
		// The kind is read BEFORE the revoke, from the row about to die. The
		// forensic question after a leak is not only which credential but what
		// sort of thing it was — a bearer value someone may still hold, or a
		// binding that held nothing — and after the revoke that is still
		// readable, but reading it first keeps the event's payload a description
		// of the state the operation acted on.
		kind, err := credentialKindOf(ctx, az, sa.ID, credentialID)
		if err != nil {
			return err
		}
		revoked, err := az.RevokeMachineCredential(ctx, sa.ID, credentialID, now)
		if err != nil {
			return err
		}
		if !revoked {
			// Either it is not this account's credential or it was already
			// revoked. Both answer the same thing, so a caller cannot use
			// this surface to enumerate credential ids across accounts.
			return ErrNoSuchCredential
		}
		e, err := domainEvent(ctx, audit.EventCredentialRevoked, caller.Principal,
			audit.Object{Type: "machine_credential", ID: credentialID}, audit.Payload{
				"service_account_id": sa.ID,
				"target_principal":   string(sa.PrincipalID),
				"principal_class":    string(sa.Kind),
				"credential_id":      credentialID,
				"credential_kind":    string(kind),
				"cause":              "revoked",
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, e)
	})
}

// PolicyView is the instance lifetime governance as the API renders it.
type PolicyView struct {
	MaxFiniteLifetime  time.Duration
	AllowIndefinite    bool
	MaxLiveCredentials int64
	UpdatedAt          time.Time
	UpdatedBy          domain.PrincipalID
}

// Policy reads the instance credential policy under `instance-config`.
func (s *Identities) Policy(ctx context.Context, actor Actor) (PolicyView, error) {
	var out PolicyView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpCredentialPolicyRead, domain.Scope{})
		if err != nil {
			return err
		}
		p, err := az.CredentialPolicy(ctx)
		if err != nil {
			return err
		}
		out = PolicyView(p)
		// A read transaction would be cheaper, but an instance-class
		// operation cannot be `audited: none` under the default-deny permit
		// rule, and the trail write has to share the read's transaction.
		e, err := domainEvent(ctx, audit.EventCredentialPolicyRead, caller.Principal,
			audit.Object{Type: "instance", ID: "credential_policy"}, audit.Payload{})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, proof, e)
	})
	return out, err
}

// PolicyChange is a requested policy, plus the acknowledgement a TIGHTENING
// needs.
type PolicyChange struct {
	MaxFiniteLifetime  time.Duration
	AllowIndefinite    bool
	MaxLiveCredentials int64
	// Confirm acknowledges the enumerated affected credentials. The ADR
	// requires them shown to the actor BEFORE the change commits, so an
	// unconfirmed tightening answers with the list and refuses.
	Confirm bool
}

// PolicyResult reports what a policy change did, or — when it was a preview —
// what it would have done.
type PolicyResult struct {
	// Applied is false when the change was a PREVIEW: a tightening whose
	// affected credentials the actor has not yet acknowledged. The ADR
	// requires them enumerated BEFORE the change commits, so an unconfirmed
	// tightening answers with the list and changes nothing. It is a distinct
	// field rather than an error because the enumeration IS the answer, and
	// a refusal whose body cannot carry it would enumerate to nobody.
	Applied bool
	Policy  PolicyView
	// Affected is the enumeration: every live credential the change clamps
	// or strands. It is populated on the refusal too, which is the point.
	Affected []AffectedCredentialView
	Clamped  int64
}

// AffectedCredentialView names one credential a policy change touches.
type AffectedCredentialView struct {
	ID               string
	ServiceAccountID string
	// ExpiresAt is the expiry the credential had BEFORE the clamp, so the
	// actor sees what they are shortening rather than what it becomes.
	ExpiresAt time.Time
	// Reason is one of the two closed values below. They are different
	// consequences and the operator is owed the difference.
	Reason AffectedReason
}

// AffectedReason is why a policy change touches one credential.
type AffectedReason string

const (
	// ReasonClamped is a finite credential beyond the new ceiling.
	ReasonClamped AffectedReason = "clamped"
	// ReasonIndefiniteWithdrawn is an indefinite credential the opt-in no
	// longer permits, which the confirmed change clamps to the ceiling.
	ReasonIndefiniteWithdrawn AffectedReason = "indefinite-withdrawn"
)

// SetPolicy moves the instance lifetime controls, enumerating every affected
// credential before it commits and clamping afterwards.
//
// Clamping only ever moves an expiry DOWN. That asymmetry is what keeps
// `indefinite` a value rather than a number: raising the ceiling later
// cannot restore a window this clamp took away, and cannot turn a finite
// credential into an indefinite one however high it goes.
//
// Withdrawing allow_indefinite converts every live indefinite credential to a
// finite one expiring at the new ceiling. It is not silent — the actor is
// shown the list and has to confirm it — and it is not a revocation: the
// credentials keep working until the ceiling, so the fleet has the same
// window to rotate that any other tightening gives it. Enumerating them and
// leaving them alone would report the control as withdrawn while unbounded
// credentials kept working, which is the control not being withdrawn.
func (s *Identities) SetPolicy(ctx context.Context, actor Actor, change PolicyChange) (PolicyResult, error) {
	if change.MaxFiniteLifetime <= 0 || change.MaxLiveCredentials <= 0 {
		return PolicyResult{}, ErrPolicyValue
	}
	now := s.now()
	var out PolicyResult
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpCredentialPolicyUpdate, domain.Scope{})
		if err != nil {
			return err
		}
		// Same lock, taken first: a mint reading this ceiling blocks until
		// the tightening commits, so no credential is written under a
		// ceiling this call has already replaced.
		if err := az.LockCredentialPolicy(ctx); err != nil {
			return err
		}
		before, err := az.CredentialPolicy(ctx)
		if err != nil {
			return err
		}

		ceiling := now.Add(change.MaxFiniteLifetime)
		var affected []AffectedCredentialView
		if change.MaxFiniteLifetime < before.MaxFiniteLifetime {
			rows, err := az.CredentialsBeyondCeiling(ctx, ceiling)
			if err != nil {
				return err
			}
			for _, row := range rows {
				affected = append(affected, AffectedCredentialView{
					ID: row.ID, ServiceAccountID: row.ServiceAccountID,
					ExpiresAt: row.ExpiresAt, Reason: ReasonClamped,
				})
			}
		}
		if before.AllowIndefinite && !change.AllowIndefinite {
			rows, err := az.IndefiniteCredentials(ctx)
			if err != nil {
				return err
			}
			for _, row := range rows {
				affected = append(affected, AffectedCredentialView{
					ID: row.ID, ServiceAccountID: row.ServiceAccountID,
					Reason: ReasonIndefiniteWithdrawn,
				})
			}
		}
		out.Affected = affected
		if len(affected) > 0 && !change.Confirm {
			// The preview changes no policy, but it is not a silent call: it
			// enumerated every live credential in the instance to the actor,
			// which is exactly the read the policy-read event exists to
			// record. Emitting nothing would leave an instance-wide
			// credential enumeration with no trace of who asked.
			out.Policy = PolicyView(before)
			e, err := newAuditEvent(ctx, audit.EventCredentialPolicyRead, caller.Principal,
				audit.Object{Type: "instance", ID: "credential_policy"}, audit.OutcomeSuccess, "",
				audit.Payload{})
			if err != nil {
				return err
			}
			return r.Audit().InsertInstance(ctx, p, e)
		}

		next := authz.CredentialPolicy{
			MaxFiniteLifetime:  change.MaxFiniteLifetime,
			AllowIndefinite:    change.AllowIndefinite,
			MaxLiveCredentials: change.MaxLiveCredentials,
			UpdatedAt:          now,
			UpdatedBy:          caller.Principal,
		}
		if err := az.SetCredentialPolicy(ctx, next, caller.Principal, now); err != nil {
			return err
		}
		clamped, err := az.ClampCredentialExpiry(ctx, ceiling)
		if err != nil {
			return err
		}
		// Withdrawing the opt-in CLAMPS the credentials it withdraws, at the
		// same ceiling every finite credential now lives under. The ADR's
		// word is "then clamps", and it has to mean these too: reporting the
		// control as withdrawn while an unbounded credential kept working
		// would be the withdrawal not having happened. They are clamped
		// rather than revoked, so the fleet gets the same window to rotate
		// that every other tightening gives it — and the operator saw the
		// list before this committed.
		if before.AllowIndefinite && !change.AllowIndefinite {
			n, err := az.ClampIndefiniteCredentials(ctx, ceiling)
			if err != nil {
				return err
			}
			clamped += n
		}
		out.Policy, out.Clamped, out.Applied = PolicyView(next), clamped, true

		ids := make([]string, 0, len(affected))
		for _, a := range affected {
			ids = append(ids, a.ID)
		}
		e, err := newAuditEvent(ctx, audit.EventCredentialPolicyChanged, caller.Principal,
			audit.Object{Type: "instance", ID: "credential_policy"}, audit.OutcomeSuccess, "",
			audit.Payload{
				"max_finite_lifetime_seconds": int(change.MaxFiniteLifetime / time.Second),
				"allow_indefinite":            change.AllowIndefinite,
				"max_live_credentials":        int(change.MaxLiveCredentials),
				"affected_credentials":        ids,
				"clamped_count":               int(clamped),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, e)
	})
	if err != nil {
		return PolicyResult{}, err
	}
	return out, nil
}

// postStateReach computes what the service account's credentials reach in
// the state a mint would leave behind. A mint changes no grants, so the
// post-state IS the current state — which is exactly why the ADR phrases the
// mint conjunct over the post-state rather than over what the mint adds.
func (s *Identities) postStateReach(ctx context.Context, az *authz.TxAuthorizer, scope domain.Scope, sa authz.ServiceAccount) (authz.Reachable, error) {
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

// resolveLifetime applies the two instance controls, and keeps them
// independent. `indefinite` is refused by its own opt-in and is never
// produced by the ceiling; the ceiling clamps a finite request and never
// converts one into the other.
func resolveLifetime(req MintRequest, policy authz.CredentialPolicy, now time.Time) (domain.CredentialLifetime, time.Time, bool, error) {
	// Two lifetimes named at once is a refusal, never a precedence rule. A
	// silent precedence on a credential is the quiet ambiguity the fail-loud
	// principle exists to prevent, and the CLI already refuses it — the API
	// must not be the softer door.
	if req.Indefinite && req.Lifetime != 0 {
		return "", time.Time{}, false, fmt.Errorf(
			"%w: `indefinite` and a finite lifetime name two different lifetimes", ErrCredentialLifetime)
	}
	if req.Indefinite {
		if !policy.AllowIndefinite {
			return "", time.Time{}, false, ErrIndefiniteNotAllowed
		}
		return domain.LifetimeIndefinite, time.Time{}, false, nil
	}
	want := req.Lifetime
	if want == 0 {
		want = DefaultCredentialLifetime
	}
	clamped := false
	if want > policy.MaxFiniteLifetime {
		want, clamped = policy.MaxFiniteLifetime, true
	}
	return domain.LifetimeFinite, now.Add(want), clamped, nil
}

// machineArtifactType maps a service account's class onto its token prefix.
// The prefix is a HINT — for humans and for secret scanners — and nothing
// reads it back: authentication resolves the verifier and trusts the row.
func machineArtifactType(kind domain.PrincipalClass) (crypto.ArtifactType, error) {
	switch kind {
	case domain.ClassWorkload:
		return crypto.ArtifactWorkload, nil
	case domain.ClassAutomation:
		return crypto.ArtifactAutomation, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrServiceAccountKind, kind)
	}
}

// prefixHint keeps the grammar prefix plus a few body characters. It cannot
// be lengthened casually: every character stored here is a character an
// attacker holding the database gets for free against a value that is
// otherwise only a hash.
//
// A value that does not match the grammar is an ERROR, not an empty hint. The
// column is NOT NULL and the caller is about to persist whatever this returns,
// so a silent "" would store a hint that identifies nothing while claiming to
// — and the only way to reach it is crypto.NewArtifact having produced
// something outside its own grammar, which is a fault worth hearing about.
func prefixHint(value string) (string, error) {
	// hik_<version>_<type>_<body> — the fourth underscore-separated field is
	// the body, and everything before it is fixed vocabulary.
	parts := strings.SplitN(value, "_", 4)
	if len(parts) != 4 || len(parts[3]) < prefixHintChars {
		return "", fmt.Errorf("service: minted artifact does not match the bearer grammar")
	}
	head := len(value) - len(parts[3])
	return value[:head+prefixHintChars], nil
}

// expiringSoon is the in-product expiry warning. Revoked and indefinite
// credentials never warn: one is already dead and the other has no horizon.
func expiringSoon(c CredentialView, now time.Time) bool {
	if !c.RevokedAt.IsZero() || c.Lifetime != domain.LifetimeFinite {
		return false
	}
	return c.ExpiresAt.After(now) && c.ExpiresAt.Before(now.Add(ExpiryWarningWindow))
}

func sortedKeys(m map[domain.EnvID]bool) []domain.EnvID {
	return newlyReachable(nil, m)
}

// credentialKindOf answers which kind a credential is, for the revoke event's
// payload. It reads the account's credential list rather than adding a by-id
// query: the list is already the surface's own read, the cap keeps it small
// (five live credentials per account), and a second query shape over the same
// rows would be a second predicate to keep chain-correct.
//
// An id this account does not hold answers the empty kind rather than an error:
// the revoke below is the one that decides, and refusing here would give this
// surface a distinguishable "no such credential" one statement earlier than the
// uniform refusal.
func credentialKindOf(ctx context.Context, az *authz.TxAuthorizer, saID, credentialID string) (domain.CredentialKind, error) {
	creds, err := az.MachineCredentialsFor(ctx, saID)
	if err != nil {
		return "", err
	}
	for _, c := range creds {
		if c.ID == credentialID {
			return c.Kind, nil
		}
	}
	return "", nil
}
