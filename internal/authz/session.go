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
// It is FALSE in this slice, deliberately and visibly. No factor exists yet —
// TOTP, WebAuthn and recovery codes are #54 — so enforcing the rule now would
// mean a freshly bootstrapped administrator could never perform the very
// operations that administer the instance, with no in-product path to enrol
// out of it. The assurance record is written from day one so no migration is
// needed when the check turns on.
//
// isolation.TestAssuranceEnforcementCannotBeForgotten fails the build the
// moment any factor beyond a password becomes mintable, so this cannot decay
// into a permanent hole.
const AssuranceEnforced = false

// Authenticate resolves a presented artifact into a live identity inside this
// transaction.
//
// Every failure returns domain.ErrUnauthenticated and nothing else: absent,
// malformed, unknown, expired, generation-superseded and epoch-superseded
// artifacts are indistinguishable, so presentation reveals nothing about
// which artifacts exist.
func (a *TxAuthorizer) Authenticate(ctx context.Context, presented string, now time.Time) (Identity, error) {
	if presented == "" {
		return Identity{}, domain.ErrUnauthenticated
	}
	// The local grammar check first: a truncated or mistyped value is refused
	// with no database work at all.
	if err := crypto.ParseArtifact(presented, crypto.ArtifactCLISession); err != nil {
		return Identity{}, domain.ErrUnauthenticated
	}
	row, err := a.r.SessionByVerifier(ctx, crypto.ArtifactVerifier(presented))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return Identity{}, domain.ErrUnauthenticated
		}
		return Identity{}, err
	}

	// Two independent clocks. The absolute lifetime is never extended by
	// activity; only the idle clock slides.
	if !now.Before(row.IdleExpiresAt) || !now.Before(row.AbsoluteExpiresAt) {
		return Identity{}, domain.ErrUnauthenticated
	}

	// The generation counter is how a grant change — revocation OR addition,
	// since a session that authenticated before a promotion carries the
	// assurance it had then — reaches an idle or stolen session that is never
	// told anything.
	generation, err := a.r.PrincipalGeneration(ctx, row.PrincipalID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return Identity{}, domain.ErrUnauthenticated
		}
		return Identity{}, err
	}
	if generation != row.SessionGeneration {
		return Identity{}, domain.ErrUnauthenticated
	}

	// The credential epoch is what makes "restored verifiers are never
	// trusted as-is" a mechanism rather than an assertion.
	epoch, err := a.r.CredentialEpoch(ctx)
	if err != nil {
		return Identity{}, err
	}
	if epoch != row.CredentialEpoch {
		return Identity{}, domain.ErrUnauthenticated
	}

	var factors []string
	if row.Factors != "" {
		if err := json.Unmarshal([]byte(row.Factors), &factors); err != nil {
			// A session row we cannot read is not a session we may trust.
			return Identity{}, domain.ErrUnauthenticated
		}
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
