package service

import (
	"context"
	"errors"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// Administrator-issued and break-glass credential reset (#54, human-auth ADR -
// Recovery). Two tiers reach one shared mint:
//
//   - network: a credential-reset-capability holder resets an org-bounded target,
//     under the org-bounded serializable test;
//   - break-glass: `hikyo admin reset-credential` on the host, root key required,
//     no network route, reaching any target including instance-capability holders.
//
// Both mint a single-use, hashed, expiring credential-establishment authority
// that establishes a password and nothing else, advance the target's generation,
// and revoke its sessions in one transaction — the recovery flow's shape, minus
// self-service.

// ErrNoResetTarget is the ONE uniform refusal for every network reset that must
// not enumerate the target's grant shape: an unknown principal, a machine
// principal with no account, and — collapsed here so it is indistinguishable on
// the wire (B2) — a target holding an instance capability, which has no network
// reset path at all (ADR - Recovery), break-glass only. The operator learns to
// use break-glass from the docs, not from a differential response; the durable
// audit still records the true cause (see stageResetRefusal).
var ErrNoResetTarget = errors.New("service: no such account to reset")

// ResetLifetime is the out-of-band credential-establishment window for an
// administrator-issued or break-glass reset. Longer than the self-service
// recovery window because the token is transmitted out of band to the target.
const ResetLifetime = BootstrapLifetime

// ResetResult carries the one-time authority out to the caller, delivered once
// through the print triad and never re-displayed.
type ResetResult struct {
	Authority     string
	AuthorityID   string
	TargetAccount string
	TargetUser    string
	ExpiresAt     time.Time
}

// ResetCredential is the network tier: a credential-reset holder resets a target.
//
// The org-bounded test is evaluated and acted on in ONE serializable transaction
// with the target's grant set (ADR - Recovery). The reset locks the target's
// `principals` row, which every grant mutation also locks (B14): a concurrent
// grant landing that would give the target instance authority or a second org
// conflicts with the in-flight reset, so the classification cannot go stale
// between the check and the mint.
func (s *Auth) ResetCredential(ctx context.Context, actor Actor, targetPrincipal, delivery string) (ResetResult, error) {
	value, verifier, err := crypto.NewArtifact(crypto.ArtifactBootstrap)
	if err != nil {
		return ResetResult{}, err
	}
	authorityID, err := newID("cea")
	if err != nil {
		return ResetResult{}, err
	}
	now := s.now()
	target := domain.PrincipalID(targetPrincipal)
	var out ResetResult
	var refused error
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		// Lock the target row FIRST so the classification and the mint serialize
		// against every grant mutation on that target (B14). ErrNotFound is a
		// missing principal.
		if err := az.LockTargetPrincipal(ctx, target); errors.Is(err, domain.ErrNotFound) {
			// An authenticated caller reaching for a principal that does not exist:
			// audit the attempt (ADR - Recovery: failures are audited), answer
			// uniformly. The event commits; the sentinel is returned after the tx.
			if aerr := s.stageResetRefusal(ctx, az, caller.Principal, targetPrincipal, "", causeUnknownTarget, now); aerr != nil {
				return aerr
			}
			refused = ErrNoResetTarget
			return nil
		} else if err != nil {
			return err
		}
		account, err := az.AccountByPrincipal(ctx, target)
		if errors.Is(err, domain.ErrNotFound) {
			// The principal exists but is not a resettable human account (a machine
			// principal): same uniform, audited refusal.
			if aerr := s.stageResetRefusal(ctx, az, caller.Principal, targetPrincipal, "", causeUnknownTarget, now); aerr != nil {
				return aerr
			}
			refused = ErrNoResetTarget
			return nil
		}
		if err != nil {
			return err
		}
		grants, err := az.GrantsForResetTarget(ctx, target)
		if err != nil {
			return err
		}
		org, instanceCap, orgCount := classifyResetTarget(grants)
		if instanceCap {
			// Instance-capability targets have no network path — break-glass only,
			// UNCONDITIONALLY, prior to and independent of the org-count branch (A3).
			// Authorize the instance operation FIRST so a caller without
			// credential-reset gets the uniform refusal (denial-captured) and learns
			// nothing; a holder is then audited by cause and refused — but with the
			// SAME uniform sentinel a nonexistent target returns (B2), so the wire
			// response is a grant-shape oracle no longer. The true cause is durable
			// in the trail.
			if _, err := az.Authorize(ctx, caller, authz.OpCredentialResetInstance, domain.Scope{}); err != nil {
				return err
			}
			if aerr := s.stageResetRefusal(ctx, az, caller.Principal, targetPrincipal, account.ID, causeInstanceTarget, now); aerr != nil {
				return aerr
			}
			refused = ErrNoResetTarget
			return nil
		}
		// Org-bounded (one org) → the org operation, satisfied by an org-scoped OR
		// an inherited instance-scoped credential-reset grant. Multi-org or
		// zero-grant (fail-closed) → the instance operation, reachable only by an
		// instance-scope holder.
		if orgCount == 1 {
			if _, err := az.Authorize(ctx, caller, authz.OpCredentialReset, domain.Scope{Org: domain.OrgID(org)}); err != nil {
				return err
			}
		} else if _, err := az.Authorize(ctx, caller, authz.OpCredentialResetInstance, domain.Scope{}); err != nil {
			return err
		}
		out, err = s.mintResetAuthority(ctx, az, account, "credential-reset", "network", delivery, authorityID, verifier, now)
		return err
	})
	if err != nil {
		return ResetResult{}, err
	}
	if refused != nil {
		return ResetResult{}, refused
	}
	out.Authority = value
	return out, nil
}

// Failure causes for a refused network reset (closed, by class never by detail).
const (
	causeInstanceTarget = "instance-capability-target"
	causeUnknownTarget  = "unknown-target"
)

// stageResetRefusal records a refused network reset in the caller's transaction
// so the trail carries the attempt (ADR - Recovery), on the same fail-closed
// contract as failRecovery: a nil return means the record is staged and the
// caller may return the sentinel; a non-nil return must be propagated loudly.
func (s *Auth) stageResetRefusal(ctx context.Context, az *authz.TxAuthorizer, actor domain.PrincipalID, targetPrincipal, targetAccount, cause string, now time.Time) error {
	payload := audit.Payload{
		"target_principal": targetPrincipal,
		"issued_by":        "credential-reset",
		"authority":        "network",
		"cause":            cause,
	}
	if targetAccount != "" {
		payload["target_account"] = targetAccount
	}
	e, err := newAuditEvent(ctx, audit.EventAuthCredentialResetIssued, actor,
		audit.Object{Type: "account", ID: targetAccount}, audit.OutcomeFailure, "", payload)
	if err != nil {
		return err
	}
	return az.RecordAuthEvent(ctx, e)
}

// BreakGlassResetCredential is the host-local tier: `hikyo admin reset-credential`.
// It runs on the server's own host under local authority (root key + host access
// resolved by the caller before this runs), reaches no chokepoint operation, and
// is the ONLY path permitted to reset a target regardless of the org-bounded
// predicate — including an instance-capability holder. There is deliberately NO
// network route; the classification-totality invariant keeps it that way.
func (s *Auth) BreakGlassResetCredential(ctx context.Context, targetPrincipal, delivery string) (ResetResult, error) {
	value, verifier, err := crypto.NewArtifact(crypto.ArtifactBootstrap)
	if err != nil {
		return ResetResult{}, err
	}
	authorityID, err := newID("cea")
	if err != nil {
		return ResetResult{}, err
	}
	now := s.now()
	target := domain.PrincipalID(targetPrincipal)
	var out ResetResult
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		// Take the same row lock the network path and every grant writer take, so
		// break-glass serializes identically (ADR - Recovery: "the same
		// serialization applies to break-glass").
		if err := az.LockTargetPrincipal(ctx, target); err != nil {
			return err
		}
		account, err := az.AccountByPrincipal(ctx, target)
		if errors.Is(err, domain.ErrNotFound) {
			return ErrNoResetTarget
		}
		if err != nil {
			return err
		}
		out, err = s.mintResetAuthority(ctx, az, account, "break-glass", "local-host", delivery, authorityID, verifier, now)
		return err
	})
	if err != nil {
		return ResetResult{}, err
	}
	out.Authority = value
	return out, nil
}

// mintResetAuthority is the shared write both tiers run inside their own locked
// transaction: sweep the target's outstanding authorities (B12), mint the new
// one, advance the generation and revoke every session, then audit the issuance
// and the mint. The verifier is the caller-held value's hash; the value never
// touches this layer.
func (s *Auth) mintResetAuthority(ctx context.Context, az *authz.TxAuthorizer, account authz.Account, issuedBy, authority, delivery, authorityID string, verifier []byte, now time.Time) (ResetResult, error) {
	epoch, err := az.CredentialEpoch(ctx)
	if err != nil {
		return ResetResult{}, err
	}
	// Minting an authority sweeps every outstanding one for this account (B12).
	if err := az.ConsumeOutstandingAuthorities(ctx, account.ID, now); err != nil {
		return ResetResult{}, err
	}
	expires := now.Add(ResetLifetime)
	if err := az.MintAuthority(ctx, authz.NewCredentialAuthority{
		ID: authorityID, Verifier: verifier, AccountID: account.ID,
		Purpose: "establish-credential", IssuedBy: issuedBy,
		CredentialEpoch: epoch, ExpiresAt: expires, CreatedAt: now,
	}); err != nil {
		return ResetResult{}, err
	}
	// Reset advances the generation and revokes sessions in the same tx (ADR:
	// reset is generation-advancing), so the target's current sessions die with
	// the reset even before the new credential is established.
	if err := az.AdvanceGeneration(ctx, account.PrincipalID); err != nil {
		return ResetResult{}, err
	}
	if err := az.RevokeAllSessionsFor(ctx, account.PrincipalID); err != nil {
		return ResetResult{}, err
	}
	// The authority coming into existence is its own record (factors MEDIUM-7):
	// audit consumers that watch authority issuance must see every mint.
	minted, err := newAuditEvent(ctx, audit.EventAuthAuthorityMinted, account.PrincipalID,
		audit.Object{Type: "authority", ID: authorityID}, audit.OutcomeSuccess, "",
		audit.Payload{"authority_id": authorityID, "account_id": account.ID, "issued_by": issuedBy, "delivery": delivery})
	if err != nil {
		return ResetResult{}, err
	}
	if err := az.RecordAuthEvent(ctx, minted); err != nil {
		return ResetResult{}, err
	}
	e, err := newAuditEvent(ctx, audit.EventAuthCredentialResetIssued, account.PrincipalID,
		audit.Object{Type: "account", ID: account.ID}, audit.OutcomeSuccess, "",
		audit.Payload{
			"target_principal": string(account.PrincipalID), "target_account": account.ID,
			"authority_id": authorityID, "issued_by": issuedBy, "authority": authority,
			"delivery": delivery, "sessions_revoked": true,
		})
	if err != nil {
		return ResetResult{}, err
	}
	if err := az.RecordAuthEvent(ctx, e); err != nil {
		return ResetResult{}, err
	}
	return ResetResult{
		AuthorityID: authorityID, TargetAccount: account.ID,
		TargetUser: account.Username, ExpiresAt: expires,
	}, nil
}

// classifyResetTarget derives the reset reachability of a target from its grant
// set. An instance-scoped grant of ANY capability is treated as an instance
// capability (fail-closed: it confers instance-wide reach), routing the target to
// break-glass only. Otherwise the count of distinct orgs the target holds grants
// in decides: exactly one → org-bounded (that org); zero or many → instance
// operation only (a zero-grant target has no owning org to address, fail-closed).
func classifyResetTarget(grants []domain.Grant) (org string, instanceCap bool, orgCount int) {
	orgs := map[string]bool{}
	for _, g := range grants {
		if g.Scope.Org == "" {
			return "", true, 0
		}
		orgs[string(g.Scope.Org)] = true
	}
	for o := range orgs {
		org = o
	}
	return org, false, len(orgs)
}
