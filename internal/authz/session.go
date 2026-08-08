package authz

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Dunky13/wenv/internal/crypto"
	"github.com/Dunky13/wenv/internal/domain"
)

// Session resolution sits HERE, on the transaction's authorizer, because the
// human-auth ADR's propagation to the architecture ADR requires it: session
// resolution and the session-assurance check run inside the same chokepoint
// as authorize(), in the same transaction, uncached. A middleware that
// decided "authenticated" before a transaction existed would be exactly the
// cross-request cache the permission model forbids, wearing a different name.

// Assurance is how THIS session authenticated — the method, the factor
// classes actually presented, when, and which ceremony. Authorization of an
// MFA-mandatory capability consults this record, never the account's
// credential inventory: an account that owns a passkey but logged in through
// a weak path has not presented it.
type Assurance struct {
	Method          string
	Factors         []string
	AuthenticatedAt time.Time
	CeremonyID      string
}

// Identity is a live, resolved caller.
type Identity struct {
	Principal         domain.PrincipalID
	SessionID         string
	Artifact          string
	Assurance         Assurance
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

// MFAMandatory is the closed set of capabilities the human-auth ADR makes
// MFA-mandatory. A viewer on a development environment is deliberately not
// forced to enrol; these are the powers that are.
var MFAMandatory = map[domain.Capability]bool{
	domain.CapReveal:          true,
	domain.CapRevealHistory:   true,
	domain.CapManageMembers:   true,
	domain.CapCredentialReset: true,
	domain.CapInstanceConfig:  true,
}

// AssuranceEnforced reports whether the chokepoint refuses an MFA-mandatory
// operation from a single-factor session.
//
// The GATE is plumbed (Authorize threads the caller's Identity and consults
// assuranceInadequate after the grant check, so only a capability-holder ever
// learns a step-up is required; session-less local host authority is exempt).
// The constant stays FALSE until the factor endpoints land in the same PR: the
// moment a factor beyond a password becomes mintable — signalled by any factor
// audit event registering — this flips to true and the demo/bootstrap flows
// enrol a factor. Flipping it before an enrolment path exists would strand a
// freshly bootstrapped administrator with no way to satisfy the rule.
//
// isolation.TestAssuranceEnforcementCannotBeForgotten fails the build if a
// factor event registers while this is still false, so the flip cannot be
// forgotten. See docs/handoff/54-human-auth-full.md.
const AssuranceEnforced = false

// AdequateAssurance reports whether a session's assurance record satisfies the
// MFA-mandatory rule: two distinct factor classes, or a WebAuthn assertion
// (user-verifying, inherently two-factor). OIDC sessions whose provider policy
// asserted multi-factor are handled where that policy is recorded (#54 OIDC
// slice); here a single-factor session — password only, or an unelevated OIDC
// login — is inadequate.
func AdequateAssurance(a Assurance) bool {
	distinct := map[string]bool{}
	for _, f := range a.Factors {
		if f == "webauthn" {
			return true
		}
		distinct[f] = true
	}
	return len(distinct) >= 2
}

// Authenticate resolves a presented artifact into a live identity inside this
// transaction.
//
// Every failure returns domain.ErrUnauthenticated and nothing else: absent,
// malformed, unknown, expired, generation-superseded and epoch-superseded
// artifacts are indistinguishable, so presentation reveals nothing about
// which artifacts exist.
func (a *TxAuthorizer) Authenticate(ctx context.Context, presented string, now time.Time) (Identity, error) {
	// The grammar check is local and constant-cost, and a value that fails it
	// cannot correspond to any row, so short-circuiting here reveals only
	// that the caller sent something that is not a wenv artifact — a fact
	// they already knew.
	if presented == "" || crypto.ParseArtifact(presented, crypto.ArtifactCLISession) != nil {
		return Identity{}, domain.ErrUnauthenticated
	}

	// From here every presentation performs the SAME THREE READS in the same
	// order, whatever it turns out to be. Returning as soon as one predicate
	// fails would make an unknown artifact cost one query, an expired one
	// two, and a generation-superseded one three — a query-count oracle for
	// which artifacts exist and why they died. The predicates are evaluated
	// after all three reads, together.
	row, rowErr := a.r.SessionByVerifier(ctx, crypto.ArtifactVerifier(presented))
	if rowErr != nil && !errors.Is(rowErr, domain.ErrNotFound) {
		return Identity{}, rowErr
	}
	live := rowErr == nil

	// A missing session still reads a generation, for the empty principal —
	// which resolves to nothing, at the same cost.
	generation, genErr := a.r.PrincipalGeneration(ctx, row.PrincipalID)
	if genErr != nil && !errors.Is(genErr, domain.ErrNotFound) {
		return Identity{}, genErr
	}
	generationOK := genErr == nil && generation == row.SessionGeneration

	epoch, err := a.r.CredentialEpoch(ctx)
	if err != nil {
		return Identity{}, err
	}

	var factors []string
	factorsOK := true
	if row.Factors != "" {
		factorsOK = json.Unmarshal([]byte(row.Factors), &factors) == nil
	}

	switch {
	case !live:
	// Two independent clocks. The absolute lifetime is never extended by
	// activity; only the idle clock slides.
	case !now.Before(row.IdleExpiresAt) || !now.Before(row.AbsoluteExpiresAt):
		live = false
	// The generation counter is how a grant change — revocation OR addition,
	// since a session that authenticated before a promotion carries the
	// assurance it had then — reaches an idle or stolen session that is never
	// told anything.
	case !generationOK:
		live = false
	// The credential epoch is what makes "restored verifiers are never
	// trusted as-is" a mechanism rather than an assertion.
	case epoch != row.CredentialEpoch:
		live = false
	// A session row we cannot read is not a session we may trust.
	case !factorsOK:
		live = false
	}
	if !live {
		return Identity{}, domain.ErrUnauthenticated
	}

	return Identity{
		Principal: row.PrincipalID,
		SessionID: row.ID,
		Artifact:  row.Artifact,
		Assurance: Assurance{
			Method:          row.AuthMethod,
			Factors:         factors,
			AuthenticatedAt: row.AuthenticatedAt,
			CeremonyID:      row.CeremonyID,
		},
		CreatedAt:         row.CreatedAt,
		LastSeenAt:        row.LastSeenAt,
		IdleExpiresAt:     row.IdleExpiresAt,
		AbsoluteExpiresAt: row.AbsoluteExpiresAt,
	}, nil
}

// FormulaDemandsMFA reports whether an operation's formula touches an
// MFA-mandatory capability. Exported so the pending-enforcement guard can
// enumerate exactly which operations will need an adequate session once
// factors exist.
func FormulaDemandsMFA(op Operation) bool {
	spec, ok := operations[op]
	if !ok {
		return false
	}
	for _, atom := range spec.formula {
		if MFAMandatory[atom.Cap] {
			return true
		}
	}
	return false
}
