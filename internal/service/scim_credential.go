package service

import (
	"context"
	"fmt"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// Provisioning-credential administration and the provisioned directory views
// (#73 §7, §8). Credentials are PLURAL and id-addressable: overlap rotation is
// mint-new -> update the IdP -> revoke-old, with identical authority
// throughout, so "rotate" is not a third verb and the surface never has to take
// the binding offline to change a secret.

// SCIMCredentialView is one credential as the surface renders it: ids and
// metadata, never token material — which does not exist to be listed, because
// only the verifier was ever stored.
type SCIMCredentialView struct {
	ID         string
	BindingID  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time
	LastUsedAt time.Time
	Live       bool
}

// SCIMMintResult carries the display-once value beside the row it belongs to.
type SCIMMintResult struct {
	Credential SCIMCredentialView
	// Token is returned exactly once, to exactly one caller. Nothing persists
	// it; the store holds only its SHA-256 verifier.
	Token string
	// Rotated reports that this mint JOINED an already-live credential rather
	// than being the binding's first. That is what overlap rotation is, and it
	// is the difference between the two audit events.
	Rotated bool
}

// MintCredential issues a NEW credential for the binding; several may be live
// at once with identical authority.
func (s *SCIM) MintCredential(ctx context.Context, actor Actor, org domain.OrgID, bindingID string, indefinite bool, proof string) (SCIMMintResult, error) {
	// The reauthentication half of §7's formula. VERIFICATION runs before the
	// transaction — an Argon2 or TOTP check must not hold a write transaction
	// open, and a failed one must mint nothing — but the evidence is CONSUMED
	// inside it, below, so a single TOTP code cannot mint two credentials and a
	// proof obtained on one session cannot be spent by another.
	evidence, err := s.verifyMintReauth(ctx, actor, proof)
	if err != nil {
		return SCIMMintResult{}, err
	}
	var out SCIMMintResult
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		scope := domain.Scope{Org: org}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		// The evidence is spent HERE, against the principal this transaction
		// authenticated: a replayed TOTP step and a proof from another session
		// both fail closed, and the spend commits with the credential or not at
		// all.
		if s.Auth != nil {
			if err := s.Auth.ConsumeReauthEvidence(ctx, az, evidence, caller.Principal); err != nil {
				return err
			}
		}
		p, err := az.Authorize(ctx, caller, authz.OpSCIMCredentialMint, scope)
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
		now := s.now()
		existing, err := r.SCIM().Credentials(ctx, p, bindingID)
		if err != nil {
			return err
		}
		live := 0
		for _, e := range existing {
			if e.Live(now) {
				live++
			}
		}
		// Overlap rotation is the point of several live credentials, but an
		// unbounded set is a pile of year-long bearers nobody is tracking. The
		// cap is inherited from the machine-credential mechanics and refuses by
		// name rather than silently minting the sixth.
		if live >= MaxLiveCredentials {
			return ErrSCIMCredentialLimit
		}
		rotated := live > 0
		value, minted, err := s.mintCredential(ctx, r, az, p, c.binding, indefinite, now)
		if err != nil {
			return err
		}
		row, err := r.SCIM().Credential(ctx, p, bindingID, minted.ID)
		if err != nil {
			return err
		}
		out = SCIMMintResult{Credential: credentialView(row, now), Token: value, Rotated: rotated}

		typ := audit.EventSCIMCredentialMinted
		if rotated {
			typ = audit.EventSCIMCredentialRotated
		}
		events := []grantEventInput{{
			typ:    typ,
			object: audit.Object{Type: "scim-credential", ID: minted.ID},
			payload: audit.Payload{
				"binding": bindingID, "credential_id": minted.ID,
				"actor": string(caller.Principal),
			},
		}}
		// A re-mint is the first half of the post-restore exit condition (§9.1):
		// the credentials a restore brought back are permanently dead, so a live
		// one existing again is real progress. The state clears fully only once
		// the IdP has also re-asserted, which the wire path does.
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelOrg, events...)
	})
	return out, err
}

// verifyMintReauth enforces `∧ reauthentication`. A local-authority actor has
// no session to reauthenticate and is exempt, exactly as authorize() exempts it
// from the MFA-mandatory rule; a NETWORK actor with no Auth library configured
// fails closed rather than skipping the gate.
func (s *SCIM) verifyMintReauth(ctx context.Context, actor Actor, proof string) (ReauthEvidence, error) {
	if actor.bearer == "" {
		return ReauthEvidence{exempt: true}, nil
	}
	if s.Auth == nil {
		return ReauthEvidence{}, fmt.Errorf(
			"%w: service: reauthentication is required to mint a provisioning credential and is not configured",
			domain.ErrConflict)
	}
	return s.Auth.VerifyReauthProof(ctx, actor.bearer, proof)
}

// ListCredentials returns the binding's credentials — ids and metadata only.
func (s *SCIM) ListCredentials(ctx context.Context, actor Actor, org domain.OrgID, bindingID string) ([]SCIMCredentialView, error) {
	var out []SCIMCredentialView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		scope := domain.Scope{Org: org}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpSCIMCredentialList, scope)
		if err != nil {
			return err
		}
		if _, err := s.loadBinding(ctx, r, az, p, bindingID, false); err != nil {
			return err
		}
		rows, err := r.SCIM().Credentials(ctx, p, bindingID)
		if err != nil {
			return err
		}
		now := s.now()
		for _, row := range rows {
			out = append(out, credentialView(row, now))
		}
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelOrg, adminReadEvent(string(org), bindingID, "credential", len(out)))
	})
	return out, err
}

// GetCredential returns one credential by id.
func (s *SCIM) GetCredential(ctx context.Context, actor Actor, org domain.OrgID, bindingID, id string) (SCIMCredentialView, error) {
	var out SCIMCredentialView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		scope := domain.Scope{Org: org}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpSCIMCredentialGet, scope)
		if err != nil {
			return err
		}
		if _, err := s.loadBinding(ctx, r, az, p, bindingID, false); err != nil {
			return err
		}
		// The store predicates on (org from the proof, binding from the path),
		// so a credential belonging to another org or another binding matches
		// no row — the uniform nonexistent outcome, decided in SQL rather than
		// by a Go check beside a caller-controlled id.
		row, err := r.SCIM().Credential(ctx, p, bindingID, id)
		if err != nil {
			return err
		}
		out = credentialView(row, s.now())
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelOrg, adminReadEvent(string(org), bindingID, "credential", 1))
	})
	return out, err
}

// RevokeCredential kills one credential. Revocation bites at the next request:
// the row is marked rather than deleted, so the verifier stays occupied and the
// id keeps naming a real thing on this surface.
func (s *SCIM) RevokeCredential(ctx context.Context, actor Actor, org domain.OrgID, bindingID, id string) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		scope := domain.Scope{Org: org}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpSCIMCredentialRevoke, scope)
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
		if _, err := s.loadBinding(ctx, r, az, p, bindingID, false); err != nil {
			return err
		}
		// The read proves the credential is this org's and this binding's before
		// the revoke, which is a predicate the UPDATE repeats anyway; keeping it
		// makes a credential from another binding the uniform not-found rather
		// than a silent zero-row revoke.
		if _, err := r.SCIM().Credential(ctx, p, bindingID, id); err != nil {
			return err
		}
		revoked, err := r.SCIM().RevokeCredential(ctx, p, bindingID, id, s.now())
		if err != nil {
			return err
		}
		if !revoked {
			// Already dead. The trail must not record a transition that did not
			// happen — an investigator counting revocations would count polls.
			return nil
		}
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelOrg, grantEventInput{
			typ:    audit.EventSCIMCredentialRevoked,
			object: audit.Object{Type: "scim-credential", ID: id},
			payload: audit.Payload{
				"binding": bindingID, "credential_id": id,
				"actor": string(caller.Principal),
			},
		})
	})
}

// ---------------------------------------------------------------------------
// The provisioned directory views
// ---------------------------------------------------------------------------

// SCIMDirectoryUser is one provisioned user as the ADMIN surface renders it.
// It carries the per-user attention flag the ADR requires after a deprovision:
// "IdP deprovisioned this user; manual grants remain."
type SCIMDirectoryUser struct {
	ID         string
	UserName   string
	ExternalID string
	AccountID  string
	Active     bool
	Groups     []string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Attention  []SCIMAttentionView
}

// SCIMDirectoryGroup is one provisioned group with its member count.
type SCIMDirectoryGroup struct {
	ID          string
	DisplayName string
	ExternalID  string
	MemberCount int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// DirectoryUsers is `hikyo scim user list <binding>`.
func (s *SCIM) DirectoryUsers(ctx context.Context, actor Actor, org domain.OrgID, bindingID string) ([]SCIMDirectoryUser, error) {
	var out []SCIMDirectoryUser
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		scope := domain.Scope{Org: org}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpSCIMDirectoryUsers, scope)
		if err != nil {
			return err
		}
		if _, err := s.loadBinding(ctx, r, az, p, bindingID, false); err != nil {
			return err
		}
		users, err := r.SCIM().Users(ctx, p, bindingID)
		if err != nil {
			return err
		}
		attention, err := r.SCIM().Attention(ctx, p, bindingID)
		if err != nil {
			return err
		}
		for _, u := range users {
			memberships, err := r.SCIM().MembershipsForUser(ctx, p, bindingID, u.ID)
			if err != nil {
				return err
			}
			view := SCIMDirectoryUser{
				ID: u.ID, UserName: u.UserName, ExternalID: u.ExternalID,
				AccountID: u.AccountID, Active: u.Active,
				CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
			}
			for _, m := range memberships {
				view.Groups = append(view.Groups, m.GroupID)
			}
			for _, a := range attention {
				if a.SubjectRef != u.ID {
					continue
				}
				view.Attention = append(view.Attention, SCIMAttentionView{
					State: a.State, SubjectRef: a.SubjectRef, Cause: a.Cause,
					EnteredAt:   a.EnteredAt,
					Remediation: attentionRemediation(domain.SCIMAttention(a.State)),
				})
			}
			out = append(out, view)
		}
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelOrg, adminReadEvent(string(org), bindingID, "directory", len(out)))
	})
	return out, err
}

// DirectoryGroups is `hikyo scim group list <binding>`.
func (s *SCIM) DirectoryGroups(ctx context.Context, actor Actor, org domain.OrgID, bindingID string) ([]SCIMDirectoryGroup, error) {
	var out []SCIMDirectoryGroup
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		scope := domain.Scope{Org: org}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpSCIMDirectoryGroups, scope)
		if err != nil {
			return err
		}
		if _, err := s.loadBinding(ctx, r, az, p, bindingID, false); err != nil {
			return err
		}
		groups, err := r.SCIM().Groups(ctx, p, bindingID)
		if err != nil {
			return err
		}
		for _, g := range groups {
			members, err := r.SCIM().GroupMembers(ctx, p, bindingID, g.ID)
			if err != nil {
				return err
			}
			out = append(out, SCIMDirectoryGroup{
				ID: g.ID, DisplayName: g.DisplayName, ExternalID: g.ExternalID,
				MemberCount: len(members), CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt,
			})
		}
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelOrg, adminReadEvent(string(org), bindingID, "directory", len(out)))
	})
	return out, err
}

func credentialView(row store.SCIMCredential, now time.Time) SCIMCredentialView {
	return SCIMCredentialView{
		ID: row.ID, BindingID: row.BindingID, CreatedAt: row.CreatedAt,
		ExpiresAt: row.ExpiresAt, RevokedAt: row.RevokedAt, LastUsedAt: row.LastUsedAt,
		Live: row.Live(now),
	}
}

// directoryReadEvent is the one shape every authenticated SCIM read lands in.
// The ADR withdraws by name the earlier claim that every SCIM operation is
// mutating: reads are events too, in the `access` retention class.
func directoryReadEvent(bindingID, resourceType, filterShape string, start, count int) grantEventInput {
	return grantEventInput{
		typ:    audit.EventSCIMDirectoryRead,
		object: audit.Object{Type: "scim-binding", ID: bindingID},
		payload: audit.Payload{
			"binding": bindingID, "resource_type": resourceType, "filter_shape": filterShape,
			"page": audit.Payload{"start_index": start, "count": count},
		},
	}
}

// adminReadEvent is the ADMINISTRATION surface's read. It is a different event
// from `scim.directory_read` because §10 closes that one's `resource_type` to
// the identity provider's own resources; a human listing bindings, mappings or
// credentials is reading configuration, not walking a directory.
func adminReadEvent(org, bindingID, resourceType string, rows int) grantEventInput {
	p := audit.Payload{
		"org": org, "resource_type": resourceType, "row_count": rows,
	}
	if bindingID != "" {
		p["binding"] = bindingID
	}
	object := audit.Object{Type: "scim-binding", ID: bindingID}
	if bindingID == "" {
		object = audit.Object{Type: "org", ID: org}
	}
	return grantEventInput{typ: audit.EventSCIMAdminRead, object: object, payload: p}
}
