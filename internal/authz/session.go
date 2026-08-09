package authz

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Dunky13/wenv/internal/crypto"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store/authn"
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
// ENFORCED (#54): the factor endpoints have landed, so a session that presented
// only a password is refused an MFA-mandatory operation and must step up. The
// gate is consulted in assuranceInadequate AFTER the grant check, so only a
// capability-holder ever learns a step-up is required; session-less local host
// authority (bootstrap, break-glass, `wenv admin`) presents no session and is
// exempt. Enrolment and step-up endpoints are themselves never MFA-gated (they
// are the path out), so a freshly bootstrapped administrator can always reach
// them.
//
// isolation.TestAssuranceEnforcementCannotBeForgotten held the flip to the
// registration of the first factor audit event, which has now happened. See
// docs/handoff/54-human-auth-full.md.
const AssuranceEnforced = true

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

// AssuranceRank orders assurance tiers so a step-up (e.g. an OIDC reauth) can
// refuse to re-establish a session with weaker evidence than it already holds:
//
//	2 — phishing-resistant (a WebAuthn assertion)
//	1 — multi-factor (two distinct factor classes)
//	0 — single-factor
//
// A reauth may only proceed with evidence of rank >= the session's rank. OIDC
// evidence is capped at rank 1 by construction (oidcFactors never yields
// "webauthn"): wenv cannot verify the phishing-resistance of a federated
// ceremony, so a federated token can never re-authorize a WebAuthn session.
func AssuranceRank(a Assurance) int {
	for _, f := range a.Factors {
		if f == "webauthn" {
			return 2
		}
	}
	if AdequateAssurance(a) {
		return 1
	}
	return 0
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
	// they already knew. Both session artifact types are accepted here (A10):
	// a CLI session ("cli") and a browser session ("br"). The transport decides
	// which leg a value arrived on (header vs cookie) and enforces the CSRF
	// requirement there; the verifier scheme is identical, so resolution does
	// not branch on the type.
	if presented == "" ||
		(crypto.ParseArtifact(presented, crypto.ArtifactCLISession) != nil &&
			crypto.ParseArtifact(presented, crypto.ArtifactBrowserSession) != nil) {
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
	return a.authenticateResolvedSession(ctx, row, rowErr, now)
}

// AuthenticateSessionByID revalidates the session recorded in a server-side
// cross-site ceremony after that ceremony's independent opaque cookie has
// been proven. A session id by itself is never accepted from the wire.
func (a *TxAuthorizer) AuthenticateSessionByID(ctx context.Context, id string, now time.Time) (Identity, error) {
	if id == "" {
		return Identity{}, domain.ErrUnauthenticated
	}
	row, rowErr := a.r.SessionByID(ctx, id)
	if rowErr != nil && !errors.Is(rowErr, domain.ErrNotFound) {
		return Identity{}, rowErr
	}
	return a.authenticateResolvedSession(ctx, row, rowErr, now)
}

func (a *TxAuthorizer) authenticateResolvedSession(ctx context.Context, row authn.SessionRow, rowErr error, now time.Time) (Identity, error) {
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
