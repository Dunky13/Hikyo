package authz

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store/authn"
)

// Session resolution sits HERE, on the transaction's authorizer, because the
// human-auth ADR's propagation to the system-architecture ADR requires it: session
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

// Identity is a live, resolved caller — human or machine.
type Identity struct {
	Principal domain.PrincipalID
	// Class is what this identity authenticated AS. It is set on every
	// resolution path, never inferred from an empty field: the ADR requires
	// machine principals to be visibly distinct from humans everywhere they
	// appear, and a distinction carried by absence is one a caller forgets.
	// A LocalPrincipal actor carries no class, because local host authority
	// is neither.
	Class domain.PrincipalClass
	// SessionID is empty for a machine identity. A machine has no session,
	// no cookie and no assurance record (#16's propagation), which is also
	// what exempts it from the MFA-mandatory check it could never satisfy.
	SessionID string
	// CredentialID names the machine credential presented, and is empty for
	// a human. It is the forensic answer to "which token", which is the
	// question after a leak — one service account holds several.
	CredentialID string
	Artifact     string
	// CredentialExpiresAt is the presenting MACHINE credential's expiry when it
	// is finite, and the zero time for an indefinite credential or a human
	// session (which has its own idle/absolute clocks instead). The delivery
	// surface returns it so a consumer can raise the ADR's ahead-of-time
	// expiry condition; it is read from the same credential row resolution
	// already loaded, never a second read.
	CredentialExpiresAt time.Time
	Assurance           Assurance
	CreatedAt           time.Time
	LastSeenAt          time.Time
	IdleExpiresAt       time.Time
	AbsoluteExpiresAt   time.Time
	// CSRFVerifier is the browser session's synchronizer-token verifier, nil
	// for a CLI session. Carrying the VERIFIER (a hash) rather than the token
	// out of the transaction is safe and lets the transport enforce the CSRF
	// contract it owns (#54 A10, #56).
	CSRFVerifier []byte
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
	// The multi-instance ADR's amendment to #16 (#71). Its restatement of the
	// "every instance capability is MFA-mandatory" rule binds HUMAN SESSIONS,
	// and names the instance-connection machine principal as its single
	// exemption — which needs no code here, because assuranceInadequate already
	// requires a non-empty SessionID and a machine has none.
	//
	// So this row costs the connection principal nothing and gains the human
	// side the gate the ADR requires: the directory listing carries another
	// instance's org and project NAMES, which is foreign structure, and reading
	// is power that #24's precedent says is never bundled.
	domain.CapInstanceDirector: true,
}

// AssuranceEnforced reports whether the chokepoint refuses an MFA-mandatory
// operation from a single-factor session.
//
// ENFORCED (#54): the factor endpoints have landed, so a session that presented
// only a password is refused an MFA-mandatory operation and must step up. The
// gate is consulted in assuranceInadequate AFTER the grant check, so only a
// capability-holder ever learns a step-up is required; session-less local host
// authority (bootstrap, break-glass, `hikyo admin`) presents no session and is
// exempt. Enrolment and step-up endpoints are themselves never MFA-gated (they
// are the path out), so a freshly bootstrapped administrator can always reach
// them.
//
// isolation.TestAssuranceEnforcementCannotBeForgotten held the flip to the
// registration of the first factor audit event, which has now happened. See
// docs/handoff/54-human-auth-full.md.
const AssuranceEnforced = true

// WorkspaceArtifact is the value a WORKSPACE session's `artifact` column
// stores. It is NOT crypto.ArtifactWorkspaceSession ("ws"), which is the bearer
// grammar's type: the two are different strings on purpose, and a rule keyed on
// the wrong one silently matches nothing. It lives here rather than in the
// service because the authentication leg is the first consumer.
const WorkspaceArtifact = "workspace"

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
// "webauthn"): hikyo cannot verify the phishing-resistance of a federated
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
// Resolution failures return domain.ErrUnauthenticated and nothing else:
// absent, malformed, unknown, expired, generation-superseded and
// epoch-superseded artifacts are indistinguishable. On HTTP requests a live
// identity is then admitted against the attached OpenAPI operation; an excluded
// class returns the uniform domain.ErrNotFound and records the named refusal.
func (a *TxAuthorizer) Authenticate(ctx context.Context, presented string, now time.Time) (Identity, error) {
	// The contract's human-session class includes workspace sessions for
	// ordinary data access. This account-security door is narrower: a workspace
	// bearer lives in another origin's JavaScript and may not mutate the human's
	// own credentials.
	//
	// In-process calls use the narrow CLI/browser grammar directly. HTTP calls
	// first resolve every bearer class so the OpenAPI admission decision returns
	// the uniform class-mismatch refusal before the structural session guard.
	return a.authenticateSessionSurface(ctx, presented, now, false,
		crypto.ArtifactCLISession, crypto.ArtifactBrowserSession)
}

// authenticateSession is Authenticate's body, parameterised by the artifact
// types the caller admits. The parameter exists for exactly one reason: a
// WORKSPACE session (#71) resolves through identical machinery — same verifier
// scheme, same three reads, same clocks, generation and epoch predicates — but
// must NOT be admitted by Authenticate itself, because Authenticate is the
// account-security surface (logout, factor enrolment, passkeys, identity
// linking, step-up) and a workspace bearer is a cross-origin credential held in
// another origin's JavaScript. Letting it mutate the account's own credentials
// would hand the viewing origin's XSS surface the human's authentication
// factors, which is precisely the blast radius the ADR bounds.
//
// So the admitting set is a parameter rather than a constant, and the broad
// set is named only by AuthenticateCaller — the same structural trick #61 used
// to keep machine tokens out of the human session surface. A new
// session-surface verb is workspace-proof unless someone opts it in.
func (a *TxAuthorizer) authenticateSession(ctx context.Context, presented string, now time.Time, admits ...crypto.ArtifactType) (Identity, error) {
	if presented == "" {
		return Identity{}, domain.ErrUnauthenticated
	}
	grammatical := false
	for _, t := range admits {
		if crypto.ParseArtifact(presented, t) == nil {
			grammatical = true
			break
		}
	}
	if !grammatical {
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

// AuthenticateCaller resolves every ordinary caller class — a human session,
// service-account credential, or instance connection — plus a SCIM
// provisioning credential when an HTTP operation is attached. Direct
// in-process SCIM callers must use AuthenticateSCIMCaller so the caller that
// owns the wire can also enforce its binding-path match. All resolve inside
// this same transaction, uncached, at the same chokepoint that mints proofs,
// which is what the machine-identities ADR requires and what makes revocation
// bite at the next request.
//
// The split from Authenticate is deliberate and is the guard: a machine
// credential has no session, no cookie and no assurance record (#16), so a
// verb that manipulates one must not be reachable with a token. Making the
// broad function the named one, rather than the default, means a new
// session-surface verb is machine-proof unless someone opts it in.
//
// The branch is on the TYPE THE CALLER TYPED, not on anything the server
// trusts: a value whose prefix says `au` still resolves against whatever row
// its verifier matches, and the row decides everything.
func (a *TxAuthorizer) AuthenticateCaller(ctx context.Context, presented string, now time.Time) (Identity, error) {
	if presented == "" {
		return Identity{}, domain.ErrUnauthenticated
	}
	if crypto.ParseArtifact(presented, crypto.ArtifactWorkload) == nil ||
		crypto.ParseArtifact(presented, crypto.ArtifactAutomation) == nil {
		return a.authenticateMachine(ctx, presented, now)
	}
	if _, wire := api.OperationFromContext(ctx); wire && crypto.ParseArtifact(presented, crypto.ArtifactSCIM) == nil {
		identity, _, err := a.AuthenticateSCIMCaller(ctx, presented, now)
		return identity, err
	}
	// The instance-connection credential (#71). It is a machine artifact with
	// its own table and its own resolution leg, and it is admitted HERE rather
	// than in Authenticate for the same reason the service-account credentials
	// are: it has no session row to mutate, so every account-security verb
	// refuses it by construction.
	//
	// Admission is not authorization. What this credential may actually reach
	// is decided at the chokepoint from the embedded OpenAPI declaration, which
	// confines it to the directory-serve operation and nothing else.
	if crypto.ParseArtifact(presented, crypto.ArtifactInstanceConn) == nil {
		return a.authenticateInstanceConnection(ctx, presented, now)
	}
	// The session leg, admitting the WORKSPACE artifact (#71) alongside the two
	// same-origin ones. This is the ONLY entry point that admits it: see
	// authenticateSession for why Authenticate must not.
	return a.authenticateSession(ctx, presented, now,
		crypto.ArtifactCLISession, crypto.ArtifactBrowserSession, crypto.ArtifactWorkspaceSession)
}

// AuthenticateSCIMCaller resolves a live provisioning credential without
// assuming which route received it. The SCIM wire applies its binding-path
// match and last-used write after operation admission; generic HTTP routes need
// only the trusted class so an excluded SCIM credential reaches that admission.
func (a *TxAuthorizer) AuthenticateSCIMCaller(ctx context.Context, presented string, now time.Time) (Identity, string, error) {
	if err := crypto.ParseArtifact(presented, crypto.ArtifactSCIM); err != nil {
		return Identity{}, "", domain.ErrUnauthenticated
	}
	row, err := a.SCIMCredentialByVerifier(ctx, crypto.ArtifactVerifier(presented))
	if errors.Is(err, domain.ErrNotFound) {
		return Identity{}, "", domain.ErrUnauthenticated
	}
	if err != nil {
		return Identity{}, "", err
	}
	if !row.Live(now) {
		return Identity{}, "", domain.ErrUnauthenticated
	}
	epoch, err := a.CredentialEpoch(ctx)
	if err != nil {
		return Identity{}, "", err
	}
	if row.CredentialEpoch != epoch {
		return Identity{}, "", domain.ErrUnauthenticated
	}
	return Identity{
		Principal: row.PrincipalID, Class: domain.ClassProvisioning,
		Artifact: string(crypto.ArtifactSCIM), CredentialID: row.ID,
	}, row.BindingID, nil
}

// AuthenticateSelfSurface is the door for the SELF-SCOPED surface — the
// caller's own active-session listing and its revoke. It admits the three
// SESSION artifacts and nothing else.
//
// It remains a named entry rather than a flag on AuthenticateCaller because
// the service behind it assumes a session row exists. HTTP calls first resolve
// every bearer class and apply the exact OpenAPI operation declaration, then
// this door narrows an admitted human-session to the three session artifacts.
//
// A workspace bearer IS admitted, and must be: the shell's liveness poll is
// this endpoint, and it is how both kill switches become visible to a foreign
// origin. What a workspace bearer may SEE and REVOKE here is narrowed to its
// own row by the service, because enumerating and ending the human's CLI and
// browser sessions is not a power a credential living in another origin's
// JavaScript may hold.
func (a *TxAuthorizer) AuthenticateSelfSurface(ctx context.Context, presented string, now time.Time) (Identity, error) {
	return a.authenticateSessionSurface(ctx, presented, now, true,
		crypto.ArtifactCLISession, crypto.ArtifactBrowserSession, crypto.ArtifactWorkspaceSession)
}

func (a *TxAuthorizer) authenticateSessionSurface(
	ctx context.Context,
	presented string,
	now time.Time,
	admitsWorkspace bool,
	inProcessArtifacts ...crypto.ArtifactType,
) (Identity, error) {
	if _, wire := api.OperationFromContext(ctx); wire {
		identity, err := a.AuthenticateCaller(ctx, presented, now)
		if err != nil {
			return Identity{}, err
		}
		if err := a.AdmitOperation(ctx, identity); err != nil {
			return Identity{}, err
		}
		if identity.SessionID == "" || (!admitsWorkspace && identity.Artifact == WorkspaceArtifact) {
			return Identity{}, domain.ErrUnauthenticated
		}
		return identity, nil
	}
	return a.authenticateSession(ctx, presented, now, inProcessArtifacts...)
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
	// THE WORKSPACE SESSION'S ORIGIN BINDING (#71). A `ws` bearer is bound to
	// exactly one requesting origin at issuance, and this is where that binding
	// becomes an authentication predicate rather than a revocation key. Without
	// it, a bearer exfiltrated from allowlisted origin A authenticates happily
	// from allowlisted origin B — the allowlist would be the only gate, and it
	// admits every consented shell rather than the one this session belongs to.
	//
	// ABSENCE IS MISMATCH. A workspace bearer only ever legitimately lives in
	// browser JavaScript making cross-origin requests, and those always carry
	// an Origin header; a presentation without one is a presentation from
	// somewhere that is not the shell it was issued to. Non-workspace artifacts
	// are untouched — a CLI or same-origin browser session has no bound origin
	// and this predicate never looks at them.
	case row.Artifact == WorkspaceArtifact &&
		row.RequestingOrigin != audit.FromContext(ctx).RequestOrigin:
		live = false
	}
	if !live {
		return Identity{}, domain.ErrUnauthenticated
	}

	return Identity{
		Principal: row.PrincipalID,
		Class:     domain.ClassHuman,
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
		CSRFVerifier:      row.CSRFVerifier,
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
