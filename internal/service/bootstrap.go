package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/crypto"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/tx"
)

// First-administrator bootstrap (human-auth ADR § First-administrator
// bootstrap).
//
// Ordering is fixed by the encryption ADR: the root key must be present and
// the instance initialized before any principal exists. No administrator
// predates the crypto that protects them — which is why this runs after
// app.Boot has loaded the keyring, and why it is a verb of the same binary
// executed ON THE SERVER HOST rather than a network endpoint.
//
// There is deliberately NO HTTP route to anything in this file. The
// classification-totality invariant is what keeps that true: `cli:admin` is
// classified ClassSystem, whose probe contract is network unreachability.

// BootstrapTemplate is the role template the first administrator is seeded
// with: `operator`, at instance scope, expanded from the ADR's own closed
// table rather than from a bespoke list beside it.
//
// This reconciles two clauses of the permission ADR that pull apart at
// bootstrap, and the reconciliation is stated rather than assumed:
//
//   - Propagations → #16 says the first administrator MUST be bootstrapped
//     "via the `admin` template (so reveal/reveal-history are seeded as
//     separate visible grants)".
//   - The template table makes `admin` applicable at org/project scope ONLY,
//     and § Administrative power says instance scope inherits downward, so an
//     instance operator "can reach any org's data through an explicit audited
//     grant, NEVER BY BUNDLE" — while `operator` is defined as the operator
//     set plus `manage-members`, with no disclosure at all.
//
// At bootstrap there is no org for an org-scoped template to attach to, so the
// two cannot both be satisfied literally at the same moment. The reading taken
// here: bootstrap seeds `operator` at instance scope — separate visible
// grants, no disclosure, no tenant data reachable by bundle — and the
// `admin`-template clause is satisfied where it can be, at ORG scope, when the
// first administrator creates the first org and applies `admin` to themselves
// through their instance `manage-members` (the ADR's own unheld-granting
// power, audited like any other grant). `reveal` and `reveal-history` arrive
// there, as the separate seeded rows the clause asks for.
//
// The previous bespoke list is gone. It seeded `read`, `reveal` and
// `reveal-history` AT INSTANCE SCOPE, which is precisely the bundle the ADR
// forbids: the first administrator held secret access over every org that
// would ever exist, before any of them did.
const BootstrapTemplate = domain.TemplateOperator

// ErrInstanceAlreadyBootstrapped refuses a second first-administrator. It is
// loud: silently minting another instance-wide admin because a command was
// run twice is exactly the surprise a secrets control plane must not have.
var ErrInstanceAlreadyBootstrapped = errors.New(
	"this instance already has an account; `admin create` mints the FIRST administrator only")

// ErrAccountExists reports a username collision.
var ErrAccountExists = errors.New("an account with that username already exists")

// BootstrapResult carries the one-time authority out to the caller, which is
// responsible for delivering it through the print triad. The value is in
// memory only, is returned exactly once, and is never re-displayed: if it
// lapses, a new one is minted from the CLI on the host.
type BootstrapResult struct {
	Authority   string
	AuthorityID string
	AccountID   string
	PrincipalID domain.PrincipalID
	Username    string
	ExpiresAt   time.Time
}

// BootstrapAdmin creates the first administrator and mints its
// credential-establishment authority.
//
// The authority is what resolves the otherwise-circular requirement that a
// credential predate every enrolment: it establishes the first
// administrator's initial credential and nothing else, granting no session
// and no assurance.
//
// delivery names how the caller will hand the value over, and is recorded in
// the audit event because delivery mode IS the security property — a value
// that reached a log shipper is a different event from one written to a
// root-owned file.
func (s *Auth) BootstrapAdmin(ctx context.Context, username, displayName, delivery string) (BootstrapResult, error) {
	if username == "" {
		return BootstrapResult{}, errors.New("a username is required")
	}
	if displayName == "" {
		displayName = username
	}

	value, verifier, err := crypto.NewArtifact(crypto.ArtifactBootstrap)
	if err != nil {
		return BootstrapResult{}, err
	}
	principalID, err := newID("usr")
	if err != nil {
		return BootstrapResult{}, err
	}
	accountID, err := newID("acc")
	if err != nil {
		return BootstrapResult{}, err
	}
	authorityID, err := newID("cea")
	if err != nil {
		return BootstrapResult{}, err
	}

	now := s.now()
	expires := now.Add(BootstrapLifetime)

	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		n, err := az.AccountCount(ctx)
		if err != nil {
			return err
		}
		if n > 0 {
			return ErrInstanceAlreadyBootstrapped
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		if err := az.CreateHumanPrincipal(ctx, domain.PrincipalID(principalID), now); err != nil {
			return err
		}
		if err := az.CreateAccount(ctx, authz.Account{
			ID: accountID, PrincipalID: domain.PrincipalID(principalID),
			Username: username, DisplayName: displayName, CreatedAt: now,
		}); err != nil {
			return err
		}
		caps, err := domain.ExpandTemplate(BootstrapTemplate, domain.LevelNone)
		if err != nil {
			return err
		}
		// One row per capability: the expansion is the point.
		for _, capability := range caps {
			grantID, err := newID("grt")
			if err != nil {
				return err
			}
			if err := az.CreateGrant(ctx, grantID, domain.PrincipalID(principalID),
				domain.Grant{Capability: capability}, now); err != nil {
				return err
			}
			// Every grant row carries at least one origin (#55, scim
			// amendment (a)) — a row no origin holds is a row nothing can
			// ever release. Bootstrap has no granting principal, so the fill
			// is the self-grant the amendment's own wording implies for
			// pre-existing rows: manual(granted_by), visible as such on the
			// membership line rather than invented as somebody else's act.
			originID, err := newID("gor")
			if err != nil {
				return err
			}
			if err := az.AddGrantOrigin(ctx, originID, grantID, domain.PrincipalID(principalID),
				authz.Origin{Kind: domain.OriginManual, Subject: principalID}, now); err != nil {
				return err
			}
		}
		if err := az.MintAuthority(ctx, authz.NewCredentialAuthority{
			ID: authorityID, Verifier: verifier, AccountID: accountID,
			Purpose: "establish-credential", IssuedBy: "bootstrap",
			CredentialEpoch: epoch, ExpiresAt: expires, CreatedAt: now,
		}); err != nil {
			return err
		}
		e, err := newAuditEvent(ctx, audit.EventAuthAuthorityMinted, domain.PrincipalID(principalID),
			audit.Object{Type: "credential_authority", ID: authorityID}, audit.OutcomeSuccess, "",
			audit.Payload{
				"authority_id": authorityID, "account_id": accountID,
				"issued_by": "bootstrap", "delivery": delivery,
			})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
	if err != nil {
		return BootstrapResult{}, err
	}

	return BootstrapResult{
		Authority: value, AuthorityID: authorityID, AccountID: accountID,
		PrincipalID: domain.PrincipalID(principalID), Username: username, ExpiresAt: expires,
	}, nil
}

// BootstrapPending reports whether the instance still has no account, so the
// CLI can tell an operator what to do next without guessing.
func (s *Auth) BootstrapPending(ctx context.Context) (bool, error) {
	var pending bool
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		n, err := az.AccountCount(ctx)
		if err != nil {
			return err
		}
		pending = n == 0
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("service: bootstrap state: %w", err)
	}
	return pending, nil
}
