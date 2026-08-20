package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// The grant surface (#55, permission-model ADR).
//
// A grant is a triple (principal, capability, scope) and that is the only
// thing stored, evaluated and revoked. Everything else here is a refusal rule
// applied BEFORE the write: the closed atom set, the deepest-level rule, the
// normative machine allowlists, the project-scope grantor's held-capability
// bound, the lockout invariant, and dedup — which is this API's job because
// the table deliberately carries no uniqueness over the triple (NULL-scope
// UNIQUE semantics diverge between engines).
//
// Nothing here is consulted by authorize(). Origins, templates and classes are
// bookkeeping and refusals; authority is the bare triple.

// Refusals. Each is its own sentinel so the transport can map it and a test
// can assert WHICH rule fired — "the grant was refused" is not an assertion.
//
// Each also WRAPS a domain sentinel, so the transport's uniform writer has a
// code for it. Left bare they all rendered `internal`, which tells a script the
// server broke when it had in fact answered correctly — the same defect #48
// found when `conflict` and `limit_exceeded` fell through the CLI's status
// mapping. Every refusal here is decided AFTER authorization succeeded, so it
// may have its own code without disclosing anything a caller could not already
// read: shape errors are `invalid`, state refusals are `conflict`, and a triple
// that is not held is `not found`.
// MaxGrantsPerOrg is the ops-spec § 8 loud sanity cap on grant rows per
// organization — it exists to make runaway grant-minting loud, not to ration.
const MaxGrantsPerOrg = 1000

var (
	// ErrNoSuchCapability refuses a capability outside the ADR's closed set.
	ErrNoSuchCapability = fmt.Errorf("%w: service: no such capability", domain.ErrInvalid)
	// ErrCapabilityScope refuses an atom granted deeper than its own level —
	// `manage-projects` on one environment is not a narrower grant, it is a
	// grant that can never be evaluated.
	ErrCapabilityScope = fmt.Errorf("%w: service: this capability cannot be granted at this scope", domain.ErrInvalid)
	// ErrGrantorLacksCapability is the project-scope bound: `manage-members`
	// held at PROJECT scope may grant only capabilities the grantor currently
	// holds at or above the target scope. A stolen project-admin account is
	// therefore not automatic full compromise of that project's secrets.
	ErrGrantorLacksCapability = fmt.Errorf("%w: service: a project-scope member manager may grant only capabilities it holds", domain.ErrConflict)
	// ErrMachineCapability is the normative machine allowlist refusing. It is
	// a refusal by the API, not a convention.
	ErrMachineCapability = fmt.Errorf("%w: service: this capability is not on the principal class's allowlist", domain.ErrConflict)
	// ErrMachineRevealOptIn refuses `reveal` on a workload or automation
	// principal while the project's machine-reveal opt-in is off
	// (source-of-truth ADR: "an explicit, documented, per-project operator
	// opt-in, never a default"). The grant API names the opt-in so the
	// operator learns which act admits it, rather than a bare allowlist refusal.
	ErrMachineRevealOptIn = fmt.Errorf("%w: service: reveal on a machine principal requires the project's machine-reveal opt-in", domain.ErrConflict)
	// ErrMachineScope refuses a machine grant that is SHALLOWER than its
	// class admits — a workload outside an explicit (project, environment),
	// or automation above project depth. The allowlist bounds which
	// capability; this bounds where, which is the other half of the same ADR
	// sentence and the half that makes `read` at org scope not a workload
	// grant at all.
	ErrMachineScope = fmt.Errorf("%w: service: this principal class may not hold a grant at this scope depth", domain.ErrConflict)
	// ErrMachineProject refuses a machine grant in a project other than the
	// one the principal's existing grants already sit in. The ADR bounds
	// automation to "one project's scope"; the first grant fixes which.
	ErrMachineProject = fmt.Errorf("%w: service: this machine principal is already bound to a different project", domain.ErrConflict)
	// ErrSystemCreatedOnly refuses a grant the system creates with its own
	// binding — `scim-provision` rides its SCIM binding (#73), never this API.
	ErrSystemCreatedOnly = fmt.Errorf("%w: service: this capability is system-created with its binding, never granted through this API", domain.ErrConflict)
	// ErrLastMemberManager is the lockout invariant: removing the last
	// `manage-members` holder at org or instance scope is refused, because an
	// unadministrable org is a support incident with no in-product recovery.
	ErrLastMemberManager = fmt.Errorf("%w: service: this is the last manage-members holder at this scope", domain.ErrConflict)
	// ErrNoSuchGrant refuses a revoke of a triple that is not held.
	ErrNoSuchGrant = fmt.Errorf("%w: service: no such grant", domain.ErrNotFound)
	// ErrUnknownPrincipal refuses a grant to a principal that does not exist.
	ErrUnknownPrincipal = fmt.Errorf("%w: service: no such principal", domain.ErrInvalid)
	// ErrDisclosureAuthority is the machine-identities ADR's mint/widen
	// refusal: the actor holds `manage-identities` but not the disclosure
	// capability over an environment the operation would make reachable.
	//
	// It is ErrConflict, exactly like ErrGrantorLacksCapability above and for
	// the same reason: authorization for the OPERATION succeeded — the actor
	// administers this project's identities and can list them — so the
	// nonexistent mask would be a lie they could disprove with their next
	// call, and 403 is reserved on tenant routes for the assurance refusal.
	// What refuses is the resulting state, which is what `conflict` means
	// everywhere else in this surface.
	ErrDisclosureAuthority = fmt.Errorf("%w: service: this operation would make plaintext reachable in an environment you may not disclose", domain.ErrConflict)
	// ErrReauthRequired is the reauthentication conjunct refusing. The
	// underlying cause (no window, expired, spent, wrong unit) is deliberately
	// not distinguished on the wire: the remedy is the same in every case.
	ErrReauthRequired = fmt.Errorf("%w: service: reauthenticate over the environments this operation makes reachable, then retry", domain.ErrConflict)
)

// Grants owns the grant surface. Every method opens one transaction,
// authorizes inside it, and performs the whole mutation — grant row, origin,
// session-generation advance and audit — before it commits. There is no
// authorization cache to invalidate, and this ticket keeps it that way.
type Grants struct {
	DB *store.DB
	// Auth supplies the reauthentication conjunct a WIDENING grant on a
	// machine principal carries (#61). It is only consulted on that path: an
	// ordinary human grant has never required reauthentication and does not
	// start now.
	Auth *Auth
	Now  func() time.Time
}

func (s *Grants) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

// GrantSpec names one grant: who gets what, where.
type GrantSpec struct {
	Target     domain.PrincipalID
	Capability domain.Capability
	// Scope is where the grant applies. The zero Scope is instance scope.
	Scope domain.Scope
}

// GrantResult reports what a create actually did, so the caller can render
// "granted" versus "already held, now also held by you" without a second read.
type GrantResult struct {
	GrantID string
	// Created is false when an existing row was deduplicated and this call
	// only attached an origin to it.
	Created bool
	// OriginAdded is false when the caller's own origin already held the row —
	// a genuinely idempotent repeat.
	OriginAdded bool
}

// grantOps maps an addressed scope depth to the (create, revoke, list,
// template) operation quartet. Keeping the four registry rows per depth in one
// table is what stops a caller reaching a depth through the wrong formula.
type grantOps struct {
	create, revoke, list, template authz.Operation
}

var grantOpsByLevel = map[domain.Level]grantOps{
	domain.LevelNone: {
		authz.OpGrantCreateInstance, authz.OpGrantRevokeInstance,
		authz.OpGrantListInstance, authz.OpTemplateApplyInstance,
	},
	domain.LevelOrg: {
		authz.OpGrantCreateOrg, authz.OpGrantRevokeOrg,
		authz.OpGrantListOrg, authz.OpTemplateApplyOrg,
	},
	domain.LevelProject: {
		authz.OpGrantCreateProject, authz.OpGrantRevokeProject,
		authz.OpGrantListProject, authz.OpTemplateApplyProject,
	},
	// There is no grant.list-env: the membership surface is read per org (or
	// at instance scope) and filtered client-side, because "who can reach this
	// environment" must include the org- and project-scoped grants that reach
	// it, which an env-only query would silently omit.
	domain.LevelEnv: {
		create: authz.OpGrantCreateEnv, revoke: authz.OpGrantRevokeEnv,
		template: authz.OpTemplateApplyEnv,
	},
}

func opsFor(scope domain.Scope) (grantOps, domain.Level, error) {
	level, err := scope.Level()
	if err != nil {
		return grantOps{}, 0, fmt.Errorf("%w: %s", domain.ErrInvalid, err)
	}
	return grantOpsByLevel[level], level, nil
}

// Create grants one capability at one scope, deduplicating against the
// grantee's existing rows.
func (s *Grants) Create(ctx context.Context, actor Actor, spec GrantSpec) (GrantResult, error) {
	var out GrantResult
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		ops, level, err := opsFor(spec.Scope)
		if err != nil {
			return err
		}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, ops.create, spec.Scope)
		if err != nil {
			return err
		}
		res, evs, err := s.grantOne(ctx, az, caller, spec, level, "")
		if err != nil {
			return err
		}
		out = res
		// §2.4's deterministic cure runs in the SAME transaction as any grant
		// write that could have cured a lockout retention (#73).
		_, cured, err := cureIfMemberManagement(ctx, az, retentionAttentionClearer(r, p), spec.Capability, spec.Scope, res)
		if err != nil {
			return err
		}
		return insertGrantEvent(ctx, r, p, caller.Principal, level, append(evs, cured...)...)
	})
	return out, err
}

// grantEventInput is one grant-lifecycle event before it is written, so the
// create path and the template path build it once and the trail cannot drift
// between them.
type grantEventInput struct {
	typ     audit.EventType
	object  audit.Object
	payload audit.Payload
}

// insertGrantEvent writes a grant-lifecycle event into the trail its scope
// owns: tenant for org/project/env grants, instance for instance-scope ones.
func insertGrantEvent(ctx context.Context, r store.Repos, p authz.Proof, actor domain.PrincipalID, level domain.Level, evs ...grantEventInput) error {
	for _, in := range evs {
		// The zero event is "nothing happened" (F5): a grant writer that
		// changed no state hands one back rather than inventing a transition.
		if in.typ == "" {
			continue
		}
		e, err := domainEvent(ctx, in.typ, actor, in.object, in.payload)
		if err != nil {
			return err
		}
		if level == domain.LevelNone {
			if err := r.Audit().InsertInstance(ctx, p, e); err != nil {
				return err
			}
			continue
		}
		if err := r.Audit().InsertTenant(ctx, p, e); err != nil {
			return err
		}
	}
	return nil
}

// grantOne is the whole create path minus transport and audit writing: every
// refusal rule, the dedup, the origin attach and the session kill. The
// template path calls it once per expanded capability, so a template can never
// take a shortcut past a rule an individual grant must satisfy.
func (s *Grants) grantOne(
	ctx context.Context, az *authz.TxAuthorizer, caller authz.Identity,
	spec GrantSpec, level domain.Level, template domain.Template,
) (GrantResult, []grantEventInput, error) {
	var zero GrantResult
	grantor := caller.Principal
	now := s.now()

	if err := checkGrantable(spec.Capability, level); err != nil {
		return zero, nil, err
	}

	class, err := lockAndClassify(ctx, az, spec.Target, spec.Capability, spec.Scope)
	if err != nil {
		return zero, nil, err
	}

	// The grant-authority rule. `manage-members` held at ORG or INSTANCE
	// scope may grant capabilities the grantor does not hold — the escalation
	// path the threat model accepts and the one that keeps a fresh
	// installation bootstrappable. Held only at PROJECT scope, it may grant
	// only what the grantor currently holds at or above the target scope.
	grantorGrants, err := az.GrantRowsForPrincipal(ctx, grantor)
	if err != nil {
		return zero, nil, err
	}
	unheld := !holds(grantorGrants, spec.Capability, spec.Scope)
	if unheld && !mayGrantUnheld(grantorGrants, spec.Scope) {
		return zero, nil, ErrGrantorLacksCapability
	}

	// The machine-widening gate (#61). It runs BEFORE the write, in this same
	// transaction, and the ADR is explicit that both authorizations apply and
	// the stricter refuses: a grant landing on a machine principal is not an
	// ordinary grant, because authority lives entirely in the grants and the
	// mutation therefore re-scopes EVERY CREDENTIAL ALREADY IN CIRCULATION —
	// instantly, with nobody re-presenting anything.
	widening, err := s.checkMachineWidening(ctx, az, caller, grantorGrants, spec, class)
	if err != nil {
		return zero, nil, err
	}

	origin := authz.Origin{Kind: domain.OriginManual, Subject: string(grantor)}
	out, err := writeGrantRow(ctx, az, spec, origin, now)
	if err != nil {
		return zero, nil, err
	}

	// F5: the lifecycle event must match the state transition. A repeat that
	// created no row and attached no origin changed nothing — emitting
	// `grant.modified` for it would put a modification in the trail that never
	// happened, and an investigator counting modifications would count polls.
	if !out.Created && !out.OriginAdded {
		return out, nil, nil
	}
	typ := audit.EventGrantModified
	if out.Created {
		typ = audit.EventGrantCreated
	}
	payload := audit.Payload{
		"target_principal": string(spec.Target),
		"capability":       string(spec.Capability),
		"scope":            renderScope(spec.Scope),
		"origin_kind":      string(origin.Kind),
		"self_grant":       spec.Target == grantor,
		"unheld":           unheld,
		"target_class":     string(class),
	}
	if template != "" {
		payload["template"] = string(template)
	}
	events := []grantEventInput{{
		typ: typ, object: audit.Object{Type: "grant", ID: out.GrantID}, payload: payload,
	}}
	// A widening on a machine principal is a SECOND fact, not a nuance of the
	// first: grant.created says a row appeared, identity.grant_widened says
	// plaintext became newly reachable to credentials that are already out
	// there. The audit-model ADR's propagation asks for the second by name.
	if widening != nil {
		widening.object = audit.Object{Type: "grant", ID: out.GrantID}
		events = append(events, *widening)
	}
	return out, events, nil
}

// checkMachineWidening is the ADR's third authorization row — the one an
// implementer misses. It answers: does this grant make plaintext NEWLY
// reachable to the machine principal, and if so does the ACTOR hold the
// matching disclosure right over the newly reachable environments?
//
// Three properties are load-bearing and each of them is a named ADR rule:
//
//  1. It is computed on the DELTA, never the post-state. A delegated project
//     administrator who deliberately holds no production `reveal` must still
//     be able to add a development-only grant to a service account that
//     already reaches production. Requiring production `reveal` there would
//     refuse a change that discloses nothing new and would pressure
//     administrators into acquiring exactly the access least privilege
//     withheld from them.
//
//  2. The delta is computed PER AUTHORITY CLASS, independently. Collapsing
//     "current plaintext" and "historical plaintext" into one boolean is a
//     named bypass: a service account already holding read(E) ∧ reveal(E)
//     shows an EMPTY delta when granted reveal-history(E), so an actor with
//     no historical access at all could hand a machine principal the power
//     to read superseded secrets — which may still be live in an external
//     service.
//
//  3. It carries the reauthentication conjunct too, over the same delta.
//     Machines never reauthenticate; the human performing the widening does.
//
// It returns nil for every non-widening mutation — a human target, a machine
// grant that reaches no new plaintext, a repeat — so narrowing and ordinary
// least-privilege granting stay under the plain capability.
func (s *Grants) checkMachineWidening(
	ctx context.Context, az *authz.TxAuthorizer, caller authz.Identity,
	actorGrants []authz.GrantRow, spec GrantSpec, class domain.PrincipalClass,
) (*grantEventInput, error) {
	if !domain.IsMachineClass(class) {
		return nil, nil
	}
	// Only the three disclosure-relevant atoms can move a reachable set:
	// `read` gates delivery, `reveal` and `reveal-history` gate plaintext.
	// Anything else on the allowlists (edit, publish, definitions-edit)
	// cannot make plaintext reachable however it is scoped.
	switch spec.Capability {
	case domain.CapRead, domain.CapReveal, domain.CapRevealHistory:
	default:
		return nil, nil
	}

	project := domain.Scope{Org: spec.Scope.Org, Project: spec.Scope.Project}
	if project.Org == "" || project.Project == "" {
		// A machine grant is refused above project depth by checkMachineScope,
		// so this is unreachable rather than a case to handle quietly.
		return nil, fmt.Errorf("service: machine grant at scope %q has no project", renderScope(spec.Scope))
	}
	envs, err := az.EnvironmentsInProject(ctx, project)
	if err != nil {
		return nil, err
	}
	pre, err := az.GrantsOf(ctx, spec.Target)
	if err != nil {
		return nil, err
	}
	post := append(append([]domain.Grant{}, pre...), domain.Grant{
		Capability: spec.Capability, Scope: spec.Scope,
	})
	before := authz.ReachableFrom(project, envs, pre)
	after := authz.ReachableFrom(project, envs, post)

	current := newlyReachable(before.Current, after.Current)
	historical := newlyReachable(before.Historical, after.Historical)
	if len(current) == 0 && len(historical) == 0 {
		return nil, nil
	}

	if s.Auth == nil {
		return nil, errors.New("service: the grant surface has no reauthentication seam wired")
	}
	// The full formula, not two thirds of it: the ADR's widening row is
	// `manage-identities(project)` ∧ disclosure ∧ reauthentication, and the
	// grant route's own chokepoint asked only the `manage-members` question.
	// Where the two disagree the stricter refuses, so an org member manager
	// who does not administer this project's identities cannot re-scope its
	// credentials by granting.
	if !holds(actorGrants, domain.CapManageIdentities, project) {
		return nil, fmt.Errorf("%w: %s over %s", ErrDisclosureAuthority,
			domain.CapManageIdentities, renderScope(project))
	}
	if err := s.Auth.RequireDisclosureAuthority(ctx, az, caller, actorGrants, project, current, historical, s.now()); err != nil {
		return nil, err
	}
	return &grantEventInput{
		typ: audit.EventMachineGrantWidened,
		payload: audit.Payload{
			"target_principal":           string(spec.Target),
			"principal_class":            string(class),
			"capability":                 string(spec.Capability),
			"scope":                      renderScope(spec.Scope),
			"newly_reachable_current":    envStrings(current),
			"newly_reachable_historical": envStrings(historical),
		},
	}, nil
}

// RequireDisclosureAuthority is the shared conjunct of the MINT row and the
// WIDEN row of the machine-identities ADR's authorization table: over the
// environments handed to it, the actor must hold the matching disclosure
// capability AND a live reauthentication window.
//
// It lives on *Auth because the reauthentication half is *Auth's machinery
// and the two callers — the credential mint and the grant surface's widening
// gate — must not be able to disagree about what the conjunct means.
//
// The two environment sets stay separate all the way down. Accepting
// `reveal` over an environment where only HISTORICAL plaintext became
// reachable would be the collapse the ADR names as a bypass, one function
// later than where it was designed out.
//
// The reauthentication conjunct ranges over exactly the environments the
// disclosure conjunct ranged over, and over nothing when that set is empty.
// That is not a loophole: the ADR gates "every operation that creates,
// replaces, or expands a working path from a machine credential to
// plaintext", and an operation reaching no plaintext creates no such path —
// the same reason its `reveal` conjunct is vacuous there. Machines never
// reauthenticate; the human performing the act does.
func (s *Auth) RequireDisclosureAuthority(
	ctx context.Context, az *authz.TxAuthorizer, caller authz.Identity,
	actorGrants []authz.GrantRow, project domain.Scope, current, historical []domain.EnvID,
	now time.Time,
) error {
	for _, env := range current {
		at := domain.Scope{Org: project.Org, Project: project.Project, Env: env}
		if !holds(actorGrants, domain.CapReveal, at) {
			return fmt.Errorf("%w: %s over %s", ErrDisclosureAuthority, domain.CapReveal, renderScope(at))
		}
	}
	for _, env := range historical {
		at := domain.Scope{Org: project.Org, Project: project.Project, Env: env}
		if !holds(actorGrants, domain.CapRevealHistory, at) {
			return fmt.Errorf("%w: %s over %s", ErrDisclosureAuthority, domain.CapRevealHistory, renderScope(at))
		}
	}
	for _, env := range union(current, historical) {
		// No operation is named and no key set is enumerated: this conjunct is
		// about reaching plaintext through a credential, not about one named
		// disclosure. An UNBOUND window (every #54 ceremony) satisfies it; a
		// window BOUND to a step-up's exact operation does not, and that refusal
		// is correct — consent to reveal DATABASE_URL in a foreign shell is not
		// consent to widen a machine credential's reach.
		err := s.ConsumeReauthWindow(ctx, az, caller.SessionID, PurposeMint, string(env), "", nil, now)
		switch {
		case err == nil:
		case errors.Is(err, ErrNoReauthWindow), errors.Is(err, ErrReauthWindowExpired),
			errors.Is(err, ErrReauthUnitMismatch), errors.Is(err, ErrReauthWindowSpent):
			// One refusal for four causes. Which window predicate failed is
			// the caller's own state, and the remedy — reauthenticate over
			// this environment and retry — is identical for all of them.
			// Carried as wire detail: the environment is one the caller named,
			// and the remedy - a reauthentication over it - is what the CLI's
			// inline ceremony and the browser's modal both key on.
			return &detailErr{
				detail: fmt.Sprintf("reauthenticate over the environments this operation makes reachable, then retry (%s)", env),
				err:    fmt.Errorf("%w (%s)", ErrReauthRequired, env),
			}
		default:
			return err
		}
	}
	return nil
}

// newlyReachable is the per-class delta: what the post-state reaches that the
// pre-state did not. Sorted, so the audit payload and the refusal message are
// stable.
func newlyReachable(before, after map[domain.EnvID]bool) []domain.EnvID {
	var out []domain.EnvID
	for env := range after {
		if !before[env] {
			out = append(out, env)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func union(a, b []domain.EnvID) []domain.EnvID {
	seen := map[domain.EnvID]bool{}
	var out []domain.EnvID
	for _, e := range append(append([]domain.EnvID{}, a...), b...) {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func envStrings(envs []domain.EnvID) []string {
	out := make([]string, 0, len(envs))
	for _, e := range envs {
		out = append(out, string(e))
	}
	return out
}

// hasOrigin reports whether this exact origin already holds the row, reading
// the grant's own origin list.
//
// It propagates the read error rather than answering false, because the two
// are not the same statement: "no such origin" makes the caller attach one,
// and doing that after a FAILED read turns a transient database error into a
// UNIQUE violation on an origin that was already there, with the real cause
// gone. A read that did not happen is not evidence of absence.
func hasOrigin(ctx context.Context, az *authz.TxAuthorizer, grantID string, o authz.Origin) (bool, error) {
	origins, err := az.GrantOriginsFor(ctx, grantID)
	if err != nil {
		return false, err
	}
	for _, held := range origins {
		if held == o {
			return true, nil
		}
	}
	return false, nil
}

// lockAndClassify is the first half every grant writer shares: take the
// target's row lock BEFORE any read-then-write, resolve the class the
// normative allowlists key on, and apply them.
//
// The lock precedes the dedup read because the schema deliberately carries no
// uniqueness over the triple — two concurrent creates would otherwise both
// read no row and both insert. Resolving the class also proves the principal
// exists: granting to a principal that is not there writes a row nothing can
// ever evaluate.
func lockAndClassify(ctx context.Context, az *authz.TxAuthorizer, target domain.PrincipalID, capability domain.Capability, scope domain.Scope) (domain.PrincipalClass, error) {
	if err := az.LockTargetPrincipal(ctx, target); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return "", ErrUnknownPrincipal
		}
		return "", err
	}
	class, err := az.PrincipalClass(ctx, target)
	if errors.Is(err, domain.ErrNotFound) {
		return "", ErrUnknownPrincipal
	}
	if err != nil {
		return "", err
	}
	if class == domain.ClassHuman {
		if err := checkPrincipalClass(class, capability, false); err != nil {
			return "", err
		}
		return class, nil
	}
	// The per-project machine-reveal opt-in (source-of-truth ADR) is the ONLY
	// thing that admits `reveal` onto a machine principal, and it is read
	// live, here, under the row lock - never cached on the allowlist. A scope
	// above project depth carries no project and therefore no opt-in; the
	// depth check below refuses it by name either way.
	optIn := false
	if scope.Project != "" {
		st, err := az.ProjectMachineReveal(ctx, string(scope.Project))
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return "", err
		}
		optIn = err == nil && st.Enabled
	}
	if err := checkPrincipalClass(class, capability, optIn); err != nil {
		return "", err
	}
	if err := checkMachineScope(class, scope); err != nil {
		return "", err
	}
	// Subtree confinement. The owning project comes from the SERVICE ACCOUNT
	// ROW, which exists precisely to record it (#61); the principal's prior
	// grants are the fallback for a machine principal that is not a service
	// account. Read under the row lock taken above.
	if err := checkMachineProject(ctx, az, target, scope); err != nil {
		return "", err
	}
	return class, nil
}

// checkMachineScope enforces the ADR's scope bound per machine class: a
// workload grant must address an explicit (project, environment), automation
// must sit at project depth or below. A grant shallower than the class admits
// reaches more than the credential was ever meant to.
func checkMachineScope(class domain.PrincipalClass, scope domain.Scope) error {
	level, err := scope.Level()
	if err != nil {
		return err
	}
	deepest, ok := domain.MachineScopeDepth(class)
	if !ok {
		return fmt.Errorf("%w: class %q has no scope rule", ErrMachineScope, class)
	}
	if level < deepest {
		return fmt.Errorf("%w: class %q requires a grant at depth %d or deeper, got %d",
			ErrMachineScope, class, deepest, level)
	}
	return nil
}

// checkMachineProject holds the "one project" boundary the ADR draws around a
// machine credential: "its grants are confined to its owning project's
// subtree. A grant naming a scope outside that project is refused, regardless
// of the granter's authority."
//
// OWNERSHIP IS READ FROM THE SERVICE-ACCOUNT ROW, and that is the whole point
// of this function. Deriving it from the principal's PRIOR GRANTS — what this
// did before #61 shipped the row — is unenforceable at exactly the moment it
// matters: a freshly created service account holds no grants, so an
// inference has nothing to say, and its FIRST grant could name any project in
// any org. A project-A service account would be handed project-B authority,
// and the mint gate's post-state enumeration would never see the escape
// because that enumeration ranges over the OWNING project's environments.
//
// The prior-grant rule survives as the fallback for a machine principal that
// is not a service account: the provisioning and instance connections
// (#73/#71) own no service_accounts row, and neither do machine principals
// predating this table. For those the first grant still fixes the project,
// which is strictly what they had before.
func checkMachineProject(ctx context.Context, az *authz.TxAuthorizer, target domain.PrincipalID, scope domain.Scope) error {
	sa, err := az.ServiceAccountByPrincipal(ctx, target)
	switch {
	case err == nil:
		if sa.Org != scope.Org || sa.Project != scope.Project {
			return fmt.Errorf("%w: owned by %s/%s, asked for %s/%s",
				ErrMachineProject, sa.Org, sa.Project, scope.Org, scope.Project)
		}
		return nil
	case errors.Is(err, domain.ErrNotFound):
		// Not a service account. Fall through to the prior-grant rule.
	default:
		return err
	}
	rows, err := az.GrantRowsForPrincipal(ctx, target)
	if err != nil {
		return err
	}
	for _, row := range rows {
		bound := row.Grant.Scope
		if bound.Project == "" {
			continue // an instance/org-scope row cannot exist for a machine; ignore rather than trust
		}
		if bound.Org != scope.Org || bound.Project != scope.Project {
			return fmt.Errorf("%w: bound to %s/%s, asked for %s/%s",
				ErrMachineProject, bound.Org, bound.Project, scope.Org, scope.Project)
		}
	}
	return nil
}

// writeGrantRow is the second half every grant writer shares: dedup against
// the target's existing rows, create the row if it is new, attach the origin
// if this one does not already hold it, and kill the target's sessions when
// authority actually changed.
//
// It is shared by the ordinary grant path and by break-glass, which differ in
// exactly two things — the origin kind and where the audit event goes. Keeping
// them one body is not tidiness: the divergence is what let a swallowed read
// error live in one caller and not the other.
func writeGrantRow(ctx context.Context, az *authz.TxAuthorizer, spec GrantSpec, origin authz.Origin, now time.Time) (GrantResult, error) {
	var out GrantResult
	rows, err := az.GrantRowsForPrincipal(ctx, spec.Target)
	if err != nil {
		return GrantResult{}, err
	}
	existing := findGrant(rows, spec.Capability, spec.Scope)
	out.Created = existing == nil
	if existing != nil {
		out.GrantID = existing.ID
	} else {
		// The per-org sanity cap (ops-spec § 8: ≤ 1000 grants per org). Counted
		// under this transaction so a concurrent mint cannot walk past it, and
		// only for org-anchored grants — instance-scope grants are the tiny
		// bootstrap set, not the runaway-minting concern the cap names.
		if spec.Scope.Org != "" {
			n, err := az.CountGrantsInOrg(ctx, string(spec.Scope.Org))
			if err != nil {
				return GrantResult{}, err
			}
			if n >= MaxGrantsPerOrg {
				return GrantResult{}, fmt.Errorf("%w: an organization holds at most %d grants",
					domain.ErrLimitExceeded, MaxGrantsPerOrg)
			}
		}
		grantID, err := newID("grt")
		if err != nil {
			return GrantResult{}, err
		}
		if err := az.CreateGrant(ctx, grantID, spec.Target,
			domain.Grant{Capability: spec.Capability, Scope: spec.Scope}, now); err != nil {
			return GrantResult{}, err
		}
		out.GrantID = grantID
	}

	// Attaching an origin that already holds the row is a genuine no-op, not
	// an error: the same administrator granting the same thing twice changed
	// nothing, and the trail should say so rather than invent a modification.
	attach := true
	if existing != nil {
		held, err := hasOrigin(ctx, az, out.GrantID, origin)
		if err != nil {
			return GrantResult{}, err
		}
		attach = !held
	}
	if attach {
		originID, err := newID("gor")
		if err != nil {
			return GrantResult{}, err
		}
		if err := az.AddGrantOrigin(ctx, originID, out.GrantID, spec.Target, origin, now); err != nil {
			return GrantResult{}, err
		}
		out.OriginAdded = true
	}

	// Every EFFECTIVE authority change kills the grantee's sessions in the
	// same transaction (human-auth ADR: grant addition/widening/revocation
	// each invalidate sessions).
	//
	// A new row is such a change: the capability becomes held. A second
	// origin joining a row that ALREADY holds the capability is not — the
	// grantee's authority is identical before and after, so killing their
	// sessions would be a denial of service triggered by somebody else's
	// bookkeeping. The trail still records it as `grant.modified`, which is
	// what it is. (Symmetric with revoke, where the advance is gated on the
	// row actually dying.)
	if out.Created {
		if err := az.AdvanceGeneration(ctx, spec.Target); err != nil {
			return GrantResult{}, err
		}
		if err := az.RevokeAllSessionsFor(ctx, spec.Target); err != nil {
			return GrantResult{}, err
		}
	}
	return out, nil
}

// Revoke releases the calling surface's origins from one grant, and deletes
// the row when the last origin is gone — with the session-generation advance
// and the session-row deletion, in the same transaction. There is no
// authorization cache, so an in-flight authorization dies with the row.
func (s *Grants) Revoke(ctx context.Context, actor Actor, spec GrantSpec) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		ops, level, err := opsFor(spec.Scope)
		if err != nil {
			return err
		}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, ops.revoke, spec.Scope)
		if err != nil {
			return err
		}

		// Lock first, read second — the whole revoke is a read-then-write over
		// the target's grant rows.
		if err := az.LockTargetPrincipal(ctx, spec.Target); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return ErrNoSuchGrant
			}
			return err
		}
		rows, err := az.GrantRowsForPrincipal(ctx, spec.Target)
		if err != nil {
			return err
		}
		existing := findGrant(rows, spec.Capability, spec.Scope)
		if existing == nil {
			return ErrNoSuchGrant
		}

		origins, err := az.GrantOriginsFor(ctx, existing.ID)
		if err != nil {
			return err
		}

		// The lockout invariant, evaluated BEFORE the release — but only when
		// this release would actually REMOVE the row. A row this surface can
		// only partly release (a `scim` or `lockout-retention` origin survives
		// beside the manual one) keeps the capability held, so refusing here
		// would refuse an act that takes nothing away and leave the
		// administrator unable to tidy their own origin off a row that stays.
		//
		// The census locks every current holder's principal row in a
		// deterministic order first, so two concurrent revokes of the last two
		// holders cannot each count the other as remaining.
		if wouldEmptyRow(origins) {
			if err := s.checkLockout(ctx, az, spec); err != nil {
				return err
			}
		}
		var releasedKinds []string
		for _, o := range origins {
			// Only origins this surface owns are released here. A `scim` or
			// `structural` origin is released by the binding that holds it
			// (#73); a human revoke does not reach past it, and the row
			// survives as a modification rather than a revocation.
			if !domain.IsMintableOrigin(o.Kind) {
				continue
			}
			ok, err := az.ReleaseGrantOrigin(ctx, existing.ID, spec.Target, o)
			if err != nil {
				return err
			}
			if ok && !slices.Contains(releasedKinds, string(o.Kind)) {
				releasedKinds = append(releasedKinds, string(o.Kind))
			}
		}
		if len(releasedKinds) == 0 {
			// The row EXISTS and the caller may revoke — this surface just owns
			// none of the origins holding it. Answering ErrNoSuchGrant here
			// would send an administrator looking for a grant that is visible
			// on the membership line in front of them, so each system origin
			// refuses BY NAME and states its own lever (#73 §4).
			return systemOriginRefusal(origins)
		}
		slices.Sort(releasedKinds)
		remaining, err := az.GrantOriginCount(ctx, existing.ID)
		if err != nil {
			return err
		}
		if remaining == 0 {
			if _, err := az.DeleteGrantRow(ctx, existing.ID, spec.Target); err != nil {
				return err
			}
		}

		// Revocation is immediate: the generation advance and the session-row
		// deletion commit with the grant change, so an open session dies with
		// the capability rather than at token expiry.
		//
		// Only when EFFECTIVE POLICY changed (F5). Releasing one origin from a
		// row another origin still holds takes nothing away — the principal
		// still holds the capability — and killing their sessions for a
		// bookkeeping change would be a denial of service dressed as security.
		if remaining == 0 {
			if err := az.AdvanceGeneration(ctx, spec.Target); err != nil {
				return err
			}
			if err := az.RevokeAllSessionsFor(ctx, spec.Target); err != nil {
				return err
			}
		}

		// F5: releasing this surface's origins while another kind still holds
		// the row is a MODIFICATION — the row lives and the capability is
		// still held. Only the release that deleted the row is a revocation.
		// The registry's own comment said so; the emitter did not.
		typ := audit.EventGrantRevoked
		if remaining > 0 {
			typ = audit.EventGrantModified
		}
		return insertGrantEvent(ctx, r, p, caller.Principal, level, grantEventInput{
			typ:     typ,
			object:  audit.Object{Type: "grant", ID: existing.ID},
			payload: revokePayload(spec, caller.Principal, releasedKinds, remaining, typ),
		})
	})
}

// checkLockout refuses a revocation that would leave an org — or the whole
// instance — with no `manage-members` holder.
func (s *Grants) checkLockout(ctx context.Context, az *authz.TxAuthorizer, spec GrantSpec) error {
	if spec.Capability != domain.CapManageMembers {
		return nil
	}
	level, err := spec.Scope.Level()
	if err != nil {
		return err
	}
	// Project-scope `manage-members` is not the invariant's subject: an org
	// with no project-scope member manager is still administrable from the
	// org, which is where the ADR draws the line.
	if level != domain.LevelNone && level != domain.LevelOrg {
		return nil
	}
	remaining, err := remainingMemberManagers(ctx, az, spec.Target, spec.Scope)
	if err != nil {
		return err
	}
	if remaining == 0 {
		return ErrLastMemberManager
	}
	return nil
}

// remainingMemberManagers counts the `manage-members` holders that would remain
// at `scope` once the target's grant AT THAT EXACT SCOPE is gone.
//
// It is shared by the human revoke path — where a zero is the locked REFUSAL —
// and by the SCIM release algorithm (#73 §2.4), where a zero is the trigger for
// the lockout-retention CONVERSION and a non-zero is what cures one. The two
// answers must be computed from the same census or "the moment the org gains
// another holder" and "the moment it would lose its last" would disagree.
func remainingMemberManagers(
	ctx context.Context, az *authz.TxAuthorizer, target domain.PrincipalID, scope domain.Scope,
) (int, error) {
	holders, err := az.ManageMembersHolders(ctx, string(scope.Org))
	if err != nil {
		return 0, err
	}
	// Lock every holder's row in a deterministic order BEFORE counting, so
	// two concurrent revocations of the last two holders serialize instead of
	// each seeing the other as the remaining one. Sorted order is what makes
	// the pairwise lock acquisition deadlock-free.
	sort.Slice(holders, func(i, j int) bool { return holders[i] < holders[j] })
	for _, h := range holders {
		if err := az.LockTargetPrincipal(ctx, h); errors.Is(err, domain.ErrNotFound) {
			continue // the holder's principal row went away; the re-read below is authoritative
		} else if err != nil {
			return 0, err
		}
	}
	// Re-read UNDER the locks. Counting from the pre-lock list is the bug the
	// locks were taken to prevent: two revocations of the last two holders
	// would each see the other as remaining. Every grant writer takes the
	// target's row lock, so nothing that can change this census is still in
	// flight once the locks are held.
	holders, err = az.ManageMembersHolders(ctx, string(scope.Org))
	if err != nil {
		return 0, err
	}

	// Count the holders that REMAIN AFTER this revocation, which is not the
	// same as "every holder except the target". A principal can hold
	// `manage-members` at more than one scope — org-scoped and instance-scoped
	// at once — and revoking one of those grants leaves the other covering the
	// scope. Excluding the principal wholesale refused a revocation that left
	// the org perfectly administrable, by the same person.
	var targetRows []authz.GrantRow
	remaining := 0
	for _, h := range holders {
		if h != target {
			remaining++
			continue
		}
		if targetRows == nil {
			targetRows, err = az.GrantRowsForPrincipal(ctx, target)
			if err != nil {
				return 0, err
			}
		}
		if retainsMemberManagement(targetRows, scope) {
			remaining++
		}
	}
	return remaining, nil
}

// retainsMemberManagement reports whether the target still manages members at
// `scope` once the grant AT that exact scope is gone: another `manage-members`
// grant of theirs, at a different scope, that still covers it.
//
// Project-scope grants are skipped for the same reason the invariant itself
// skips them — an org with no project-scope member manager is still
// administrable from the org, so one cannot stand in for the org's last
// holder either.
func retainsMemberManagement(rows []authz.GrantRow, scope domain.Scope) bool {
	for _, row := range rows {
		if row.Grant.Capability != domain.CapManageMembers {
			continue
		}
		if row.Grant.Scope == scope {
			continue // the grant being revoked
		}
		if row.Grant.Scope.Project != "" {
			continue
		}
		if scopeCovers(row.Grant.Scope, scope) {
			return true
		}
	}
	return false
}

// ApplyTemplate expands a role template into independent grants at grant
// time. Nothing stores "Alice is a maintainer"; what is stored is the
// capabilities the template created, each on its own line and revocable on
// its own.
func (s *Grants) ApplyTemplate(ctx context.Context, actor Actor, template domain.Template, target domain.PrincipalID, scope domain.Scope) ([]GrantResult, error) {
	var out []GrantResult
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		ops, level, err := opsFor(scope)
		if err != nil {
			return err
		}
		caps, err := domain.ExpandTemplate(template, level)
		if err != nil {
			return fmt.Errorf("%w: %s", domain.ErrInvalid, err)
		}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, ops.template, scope)
		if err != nil {
			return err
		}

		events := make([]grantEventInput, 0, len(caps)+1)
		results := make([]GrantResult, 0, len(caps))
		created, joined, unchanged := 0, 0, 0
		names := make([]string, 0, len(caps))
		for _, capability := range caps {
			res, evs, err := s.grantOne(ctx, az, caller, GrantSpec{
				Target: target, Capability: capability, Scope: scope,
			}, level, template)
			if err != nil {
				return err
			}
			results = append(results, res)
			events = append(events, evs...)
			names = append(names, string(capability))
			switch {
			case res.Created:
				created++
			case res.OriginAdded:
				joined++
			default:
				unchanged++
			}
		}
		out = results

		// The template event records ONE administrator performing ONE act;
		// the per-capability rows above record what it produced. Without the
		// first the trail can say ten capabilities appeared but not why.
		summary := grantEventInput{
			typ:    audit.EventGrantTemplateApplied,
			object: audit.Object{Type: "principal", ID: string(target)},
			payload: audit.Payload{
				"template":         string(template),
				"target_principal": string(target),
				"scope":            renderScope(scope),
				"capability_count": len(caps),
				"grants_created":   created,
				"grants_deduped":   joined + unchanged,
				"grants_joined":    joined,
				"grants_unchanged": unchanged,
				"self_grant":       target == caller.Principal,
				"capabilities":     strings.Join(names, ","),
			},
		}
		for i, capability := range caps {
			_, cured, err := cureIfMemberManagement(ctx, az, retentionAttentionClearer(r, p), capability, scope, results[i])
			if err != nil {
				return err
			}
			events = append(events, cured...)
		}
		return insertGrantEvent(ctx, r, p, caller.Principal, level, append([]grantEventInput{summary}, events...)...)
	})
	return out, err
}

// Membership is one capability line on the membership surface: a principal,
// a capability, the scope it was granted at, and the origins holding it.
type Membership struct {
	GrantID    string
	Principal  domain.PrincipalID
	Capability domain.Capability
	Scope      domain.Scope
	Origins    []authz.Origin
	CreatedAt  time.Time
}

// List returns the membership surface for the addressed scope: every grant
// line inside the org (or at instance scope), narrowed to the addressed
// project when one is addressed.
//
// Grants ABOVE the addressed scope are deliberately absent even though they
// reach it by inheritance. Showing an instance operator on an org's member
// list would invite revoking them from a page that has no authority to.
func (s *Grants) List(ctx context.Context, actor Actor, scope domain.Scope) ([]Membership, error) {
	var out []Membership
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		ops, level, err := opsFor(scope)
		if err != nil {
			return err
		}
		if ops.list == "" {
			return fmt.Errorf("%w: the membership surface is listed at org, project or instance scope", domain.ErrInvalid)
		}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, ops.list, scope)
		if err != nil {
			return err
		}
		// One query per addressed depth. The project listing is NOT the org
		// listing filtered afterwards: a project member manager authorizes for
		// one project, and reading the org's rows to throw most away makes the
		// work scale with sibling-project membership — observable, and it
		// materializes administrative data the caller was never authorized to
		// see.
		var lines []authz.GrantLine
		switch level {
		case domain.LevelNone:
			lines, err = az.GrantLinesAtInstance(ctx)
		case domain.LevelProject:
			lines, err = az.GrantLinesInProject(ctx, string(scope.Org), string(scope.Project))
		default:
			lines, err = az.GrantLinesInOrg(ctx, string(scope.Org))
		}
		if err != nil {
			return err
		}
		for _, line := range lines {
			out = append(out, Membership{
				GrantID: line.ID, Principal: line.Principal,
				Capability: line.Grant.Capability, Scope: line.Grant.Scope,
				Origins: line.Origins, CreatedAt: line.CreatedAt,
			})
		}
		return insertGrantEvent(ctx, r, p, caller.Principal, level, grantEventInput{
			typ:    audit.EventGrantMembershipRead,
			object: audit.Object{Type: "scope", ID: renderScope(scope)},
			payload: audit.Payload{
				"scope": renderScope(scope), "row_count": len(out),
			},
		})
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Refusal rules
// ---------------------------------------------------------------------------

// checkGrantable enforces the closed atom set and the deepest-level rule.
func checkGrantable(capability domain.Capability, at domain.Level) error {
	deepest, ok := domain.DeepestLevel(capability)
	if !ok {
		return fmt.Errorf("%w: %q", ErrNoSuchCapability, capability)
	}
	if at > deepest {
		return fmt.Errorf("%w: %q", ErrCapabilityScope, capability)
	}
	return nil
}

// checkPrincipalClass applies the NORMATIVE machine allowlists. A human holds
// anything in the closed set except the machine-only atoms; a machine holds
// only what its class's list admits, which is what makes "no machine principal
// may hold manage-members, manage-projects, project-settings or any instance
// capability" a refusal rather than a convention.
func checkPrincipalClass(class domain.PrincipalClass, capability domain.Capability, machineRevealOptIn bool) error {
	if capability == domain.CapSCIMProvision {
		// Machine-only AND system-created: the provisioning connection's own
		// grant is written with its SCIM binding (#73) and retired with it.
		return fmt.Errorf("%w: %q", ErrSystemCreatedOnly, capability)
	}
	if class == domain.ClassHuman {
		// `instance-directory` is deliberately NOT refused here. It is the
		// multi-instance ADR's own grantable atom for the viewing side — "on a
		// multi-user install the admin grants the hop to exactly the humans who
		// work across instances" — and refusing it to humans would close the
		// surface the atom exists for. The machine half is refused below.
		return nil
	}
	if capability == domain.CapInstanceDirector {
		// A MACHINE holding `instance-directory` is the instance-connection
		// principal and nothing else (#71), and its grant is system-created:
		// `remote-credential create` writes principal, credential and grant as
		// one unit at the store layer, and `revoke` retires all three together.
		//
		// The class allowlist alone would admit this write, because
		// MachineMayHold(instance-connection, instance-directory) is true — it
		// has to be, or the chokepoint could not evaluate the formula. That
		// makes the allowlist the wrong guard here: it answers "may this
		// principal HOLD it", and the question this API asks is "may it be
		// ATTACHED BY HAND", whose answer is no. Without this branch a grant
		// could outlive the credential binding that justifies it.
		return fmt.Errorf("%w: %q", ErrSystemCreatedOnly, capability)
	}
	if capability == domain.CapReveal && domain.MachineMayHoldRevealByOptIn(class) {
		if !machineRevealOptIn {
			return fmt.Errorf("%w: class %q may hold %q only under the project's machine-reveal opt-in, which is off", ErrMachineRevealOptIn, class, capability)
		}
		return nil
	}
	if !domain.MachineMayHold(class, capability) {
		return fmt.Errorf("%w: class %q may not hold %q", ErrMachineCapability, class, capability)
	}
	return nil
}

// mayGrantUnheld reports whether the grantor's `manage-members` sits at org or
// instance scope FOR THE TARGET SCOPE — the only place the ADR permits handing
// out a capability the grantor does not hold.
func mayGrantUnheld(grantorGrants []authz.GrantRow, target domain.Scope) bool {
	for _, g := range grantorGrants {
		if g.Grant.Capability != domain.CapManageMembers {
			continue
		}
		// Instance scope (empty org) or an org-scope grant covering the
		// target org. A project-scope `manage-members` is deliberately not
		// enough, which is the whole point of the rule.
		if g.Grant.Scope.Org == "" {
			return true
		}
		if g.Grant.Scope.Project == "" && g.Grant.Scope.Org == target.Org {
			return true
		}
	}
	return false
}

// holds reports whether the grantor currently holds the capability at or above
// the target scope — the project-scope grantor's bound.
func holds(grantorGrants []authz.GrantRow, capability domain.Capability, target domain.Scope) bool {
	for _, g := range grantorGrants {
		if g.Grant.Capability == capability && scopeCovers(g.Grant.Scope, target) {
			return true
		}
	}
	return false
}

// findGrant returns the row holding an exact triple, or nil. Exactness is the
// point: a `read` at org scope does NOT dedup a `read` at env scope, because
// they are different rows with different blast radii and revoking one must not
// take the other with it.
func findGrant(rows []authz.GrantRow, capability domain.Capability, scope domain.Scope) *authz.GrantRow {
	for i := range rows {
		if rows[i].Grant.Capability == capability && rows[i].Grant.Scope == scope {
			return &rows[i]
		}
	}
	return nil
}

// scopeCovers mirrors the chokepoint's own ancestor-or-equal rule. It is
// duplicated here deliberately: the chokepoint's copy answers "may this
// operation proceed" and must never grow a caller-facing exception, while this
// one answers "does the grantor hold enough to hand this out" — a policy
// question the chokepoint has no business knowing about.
func scopeCovers(g, target domain.Scope) bool {
	if g.Org == "" {
		return true
	}
	if g.Org != target.Org {
		return false
	}
	if g.Project == "" {
		return true
	}
	if g.Project != target.Project {
		return false
	}
	if g.Env == "" {
		return true
	}
	return g.Env == target.Env
}

// renderScope is the audit and CLI rendering of a scope: `instance`, or the
// chain joined by `/`. It is not parsed back anywhere — the wire carries the
// ids separately.
func renderScope(s domain.Scope) string {
	parts := make([]string, 0, 3)
	for _, part := range []string{string(s.Org), string(s.Project), string(s.Env)} {
		if part == "" {
			break
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return "instance"
	}
	return strings.Join(parts, "/")
}

// ---------------------------------------------------------------------------
// Break-glass
// ---------------------------------------------------------------------------

// BreakGlassGrant issues a recovery grant under LOCAL HOST AUTHORITY —
// `hikyo admin grant`, on the server's own host, root key already loaded by the
// caller. It reaches no chokepoint operation and is, in the ADR's own words,
// "the only authorization path in the system not evaluated against a grant".
// There is deliberately no network route; the classification-totality
// invariant is what keeps that true.
//
// It adds no attacker capability: host access plus the root key already means
// full control-plane compromise per the threat model. What it adds is a way
// out of the lockout invariant's one irrecoverable state — an instance with no
// `manage-members` holder — without an API that could be reached remotely.
//
// The origin is `break-glass`, NOT `manual`. That is a reading of the ADR, not
// a convenience: `manual(granted_by)` names a granting principal whose own
// authority was evaluated, and this path has no granting principal at all.
// Recording it as manual would put a principal's name on an act no principal
// performed, and would make the row indistinguishable from an ordinary grant
// on the membership surface — which is exactly the thing an auditor is looking
// for after an incident.
func (s *Grants) BreakGlassGrant(ctx context.Context, spec GrantSpec) (GrantResult, error) {
	var out GrantResult
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		level, err := spec.Scope.Level()
		if err != nil {
			return fmt.Errorf("%w: %s", domain.ErrInvalid, err)
		}
		// The closed atom set and the deepest-level rule still bind: local
		// authority is not permission to write a row nothing can evaluate.
		if err := checkGrantable(spec.Capability, level); err != nil {
			return err
		}
		// The machine allowlists are normative for every writer, including
		// this one: break-glass exists to restore human administration, not to
		// hand a CI runner an instance capability by the back door.
		if _, err := lockAndClassify(ctx, az, spec.Target, spec.Capability, spec.Scope); err != nil {
			return err
		}
		out, err = writeGrantRow(ctx, az, spec,
			authz.Origin{Kind: domain.OriginBreakGlass, Subject: breakGlassSubject}, s.now())
		if err != nil {
			return err
		}
		// A recovery grant of `manage-members` is exactly the cure §2.4
		// describes, and the retention must not outlive it: the whole point of
		// break-glass is an org that has no member manager left.
		// No clearer: break-glass has NO principal and mints no tenant proof,
		// so the binding's attention row is reconciled by
		// refreshBindingAttention on the next administration read — the same
		// audited exit path, under the org admin's own proof. The RELEASE
		// itself is unconditional.
		_, cured, err := cureIfMemberManagement(ctx, az, nil, spec.Capability, spec.Scope, out)
		if err != nil {
			return err
		}
		for _, ev := range cured {
			e, err := domainEvent(ctx, ev.typ, "", ev.object, ev.payload)
			if err != nil {
				return err
			}
			if err := az.RecordAuthEvent(ctx, e); err != nil {
				return err
			}
		}

		// The durable recovery record. It rides RecordAuthEvent (the
		// resolution surface's proof-free writer) for the same reason the
		// break-glass credential reset does: there is no proof to bind it to,
		// and it commits in the same transaction as the grant, so durability
		// holds.
		e, err := newAuditEvent(ctx, audit.EventBreakGlassGrant, "",
			audit.Object{Type: "grant", ID: out.GrantID}, audit.OutcomeSuccess, "",
			audit.Payload{
				"target_principal": string(spec.Target),
				"capability":       string(spec.Capability),
				"scope":            renderScope(spec.Scope),
				"authority":        "local-host",
				"grant_created":    out.Created,
			})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
	return out, err
}

// breakGlassSubject is the `subject` a break-glass origin carries. It is a
// constant rather than a principal because there is no granting principal: the
// authority is the host.
const breakGlassSubject = "local-host-authority"

// revokePayload builds the release event's payload. The two lifecycle types
// carry different schemas — `grant.revoked` adds the surviving-origin count
// and the session outcome, `grant.modified` shares the plain grant shape — so
// the payload is built where the type is decided rather than assembled once
// and hoped to fit both.
func revokePayload(spec GrantSpec, actor domain.PrincipalID, releasedKinds []string, remaining int64, typ audit.EventType) audit.Payload {
	p := audit.Payload{
		"target_principal": string(spec.Target),
		"capability":       string(spec.Capability),
		"scope":            renderScope(spec.Scope),
		// The kinds ACTUALLY released, not an assumption. A revoke releases
		// every origin this surface owns, break-glass included, and hardcoding
		// `manual` would erase from the trail the very distinction the
		// break-glass origin exists to make.
		"origin_kind":  strings.Join(releasedKinds, ","),
		"self_grant":   spec.Target == actor,
		"unheld":       false,
		"target_class": "",
	}
	if typ == audit.EventGrantRevoked {
		p["origins_remaining"] = int(remaining)
		p["sessions_revoked"] = true
	}
	return p
}

// systemOriginRefusal names WHICH system origin is holding a row a human tried
// to revoke, so the refusal states the lever that actually removes it (#73 §4).
func systemOriginRefusal(origins []authz.Origin) error {
	var scim, retention, structural bool
	for _, o := range origins {
		switch o.Kind {
		case domain.OriginSCIM:
			scim = true
		case domain.OriginLockoutRetention:
			retention = true
		case domain.OriginStructural:
			structural = true
		}
	}
	switch {
	case scim:
		return ErrSCIMOriginOnly
	case retention:
		return ErrLockoutRetained
	case structural:
		return ErrStructuralGrant
	default:
		return ErrNoSuchGrant
	}
}

// cureIfMemberManagement runs §2.4's deterministic release after a grant write,
// but only when the write could possibly have cured something: a NEW
// `manage-members` row. An origin joining a row the principal already held
// changes no census, and neither does any other capability.
func cureIfMemberManagement(
	ctx context.Context, az *authz.TxAuthorizer, clear clearRetentionAttention,
	capability domain.Capability, scope domain.Scope, res GrantResult,
) ([]CureResult, []grantEventInput, error) {
	if capability != domain.CapManageMembers || !res.Created {
		return nil, nil, nil
	}
	return cureLockoutRetentions(ctx, az, clear, res.GrantID, scope)
}

// retentionAttentionClearer builds the cure's audited exit path for a caller
// that holds a tenant proof: it lowers the binding's `lockout_retention` state
// in the SAME transaction that released the retention, so a warning cannot
// outlive the thing it describes.
func retentionAttentionClearer(r store.Repos, p authz.Proof) clearRetentionAttention {
	return func(ctx context.Context, binding, grantID string) ([]grantEventInput, error) {
		n, err := r.SCIM().ClearAttention(ctx, p, binding,
			string(domain.AttentionLockoutRetention), grantID)
		if err != nil || n == 0 {
			return nil, err
		}
		return []grantEventInput{{
			typ:    audit.EventSCIMAttentionCleared,
			object: audit.Object{Type: "grant", ID: grantID},
			payload: audit.Payload{
				"binding": binding,
				"state":   string(domain.AttentionLockoutRetention),
				"cause":   string(domain.CauseReactivation),
			},
		}}, nil
	}
}

// wouldEmptyRow reports whether releasing every origin THIS surface owns would
// leave the row with none — i.e. whether the revoke is a real revocation rather
// than the release of one origin among several.
func wouldEmptyRow(origins []authz.Origin) bool {
	for _, o := range origins {
		if !domain.IsMintableOrigin(o.Kind) {
			return false
		}
	}
	return true
}
