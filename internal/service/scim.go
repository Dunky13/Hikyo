package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/samlsp"
	"github.com/Hikyo-Org/hikyo/internal/scimproto"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// SCIM provisioning (#73, scim-provisioning ADR). This file is the engine the
// administration surface and the wire surface both stand on: loading a binding
// (and failing closed when its provider is gone), deriving the subject the
// login path will compute, turning mapping rows into grants, and the attention
// states that answer "what does SCIM think is wrong?".

// SCIM owns the provisioning surface.
type SCIM struct {
	DB  *store.DB
	Now func() time.Time

	// Auth is the reauthentication library. Minting a provisioning credential
	// is `manage-members(org)` ∧ REAUTHENTICATION (§7): a stolen elevated
	// session must not be able to issue a year-long bearer without re-proving
	// the human. Nil means the below-the-network paths only, and a network
	// mint with no Auth fails closed rather than silently skipping the gate.
	Auth *Auth

	// CredentialTTL is the lifetime ceiling every provisioning credential is
	// clamped to. AllowIndefinite is the instance opt-in that permits a
	// credential with no ceiling at all; it is default-off, and a request for
	// an indefinite credential is refused by name without it.
	CredentialTTL   time.Duration
	AllowIndefinite bool

	// Staleness is how long a binding may go without IdP contact before the
	// binding surface shows the warning. Nothing self-heals from it and no
	// grant expires because of it: converting an IdP outage into org-wide
	// revocation is the scrub-on-timer failure the ADR rejects by name.
	Staleness time.Duration

	// MaxPageSize bounds a SCIM ListResponse. A request above it is clamped,
	// not refused: RFC 7644 §3.4.2.4 makes `count` a request, and the server's
	// bound is the answer.
	MaxPageSize int
}

func (s *SCIM) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

func (s *SCIM) staleness() time.Duration {
	if s.Staleness <= 0 {
		return DefaultSCIMStaleness
	}
	return s.Staleness
}

func (s *SCIM) pageBound() int {
	if s.MaxPageSize <= 0 {
		return DefaultSCIMPageSize
	}
	return s.MaxPageSize
}

// Bounds the ops spec owns; chosen here because the code needs non-zero ones
// to be correct at all, and stated as such rather than left broken. The
// staleness default follows the ADR's own observation that Entra reconciles at
// roughly 40 minutes and Okta similarly: a threshold below one full IdP cycle
// would flag every healthy binding.
const (
	DefaultSCIMStaleness = 3 * time.Hour
	DefaultSCIMPageSize  = 200
	// DefaultSCIMCredentialTTL is the lifetime ceiling a mint is clamped to
	// when the instance has not configured one.
	DefaultSCIMCredentialTTL = 365 * 24 * time.Hour
)

// Refusals. Each is its own sentinel, wrapping a domain sentinel so the
// transport has a code for it and a test can assert WHICH rule fired.
var (
	// ErrSCIMProviderUnavailable is the fail-closed refusal of §1: while the
	// referenced provider is disabled or removed, the binding's ENTIRE wire
	// surface refuses — read and write alike — state is preserved for repair,
	// and the binding sits in the attention state naming it.
	ErrSCIMProviderUnavailable = fmt.Errorf("%w: service: this SCIM binding's identity provider is disabled or removed", domain.ErrConflict)
	// ErrSCIMSubjectSource refuses a binding whose declared subject source is
	// not usable as identity material — `userName` by name (§5.1).
	ErrSCIMSubjectSource = fmt.Errorf("%w: service: this SCIM attribute may not be a subject source", domain.ErrInvalid)
	// ErrSCIMSubjectWriteOnce refuses a mutation that would change a resource's
	// derived subject. An IdP-side identifier migration is the rebinding hazard
	// the identity model exists to prevent; deprovision-and-recreate is the
	// explicit path.
	ErrSCIMSubjectWriteOnce = fmt.Errorf("%w: service: a SCIM user's subject is write-once; deprovision and recreate instead", domain.ErrConflict)
	// ErrSCIMSubjectMissing refuses a resource carrying no value at the
	// binding's declared subject-source path.
	ErrSCIMSubjectMissing = fmt.Errorf("%w: service: this SCIM resource carries no value at the binding's subject source", domain.ErrInvalid)
	// ErrSCIMPasswordRefused refuses the SCIM `password` attribute BY NAME
	// (§5.2). Provisioning never establishes credentials.
	ErrSCIMPasswordRefused = fmt.Errorf("%w: service: the SCIM password attribute is not supported; provisioning never establishes credentials", domain.ErrInvalid)
	// ErrSCIMUserNameRequired refuses a create or PUT with no `userName`.
	ErrSCIMUserNameRequired = fmt.Errorf("%w: service: userName is required", domain.ErrInvalid)
	// ErrSCIMNestedGroup refuses a group-typed member reference (§6): v1 is
	// flat, and Okta and Entra provision direct user members.
	ErrSCIMNestedGroup = fmt.Errorf("%w: service: nested group members are not supported", domain.ErrInvalid)
	// ErrSCIMUnknownMember refuses a member reference resolving to no user this
	// binding provisioned. The IdP can only reference ids this server minted.
	ErrSCIMUnknownMember = fmt.Errorf("%w: service: this member reference names no user provisioned by this binding", domain.ErrInvalid)
	// ErrSCIMUniqueness refuses a duplicate `userName`, displayName or
	// subject-source collision.
	ErrSCIMUniqueness = fmt.Errorf("%w: service: this value is already taken in this binding", domain.ErrConflict)
	// ErrSCIMMappingScope refuses a mapping row naming a scope outside the
	// binding's own org — refused at authoring time and again at sync time (§1).
	ErrSCIMMappingScope = fmt.Errorf("%w: service: a mapping row may not name a scope outside the binding's org", domain.ErrInvalid)
	// ErrSCIMTemplate refuses a mapping row targeting a template that is not
	// structurally mappable — `operator` is instance-scoped and out of an org
	// binding's reach by construction (§3).
	ErrSCIMTemplate = fmt.Errorf("%w: service: this role template cannot be mapped by a SCIM binding", domain.ErrInvalid)
	// ErrSCIMIndefiniteRefused refuses an indefinite credential while the
	// instance opt-in is off — which it is by default.
	ErrSCIMIndefiniteRefused = fmt.Errorf("%w: service: indefinite provisioning credentials require the instance opt-in", domain.ErrConflict)
	// ErrSCIMBindingMismatch is the credential-versus-binding-path refusal
	// (§8). It is an AUTHENTICATION failure, never a SCIM 400: there is no
	// ambient routing by credential.
	ErrSCIMBindingMismatch = fmt.Errorf("%w: service: this credential does not belong to the addressed binding", domain.ErrUnauthenticated)
)

// scimContext is one loaded binding plus the proof the operation minted. Every
// SCIM method takes exactly this after its own authorization, so "the binding
// in the path is this org's" is decided once.
type scimContext struct {
	proof   authz.Proof
	binding store.SCIMBinding
	// allowEmailNameID carries the SAML provider's `emailAddress` carve so the
	// subject derivation composes with it unchanged.
	allowEmailNameID bool
	// providerID is the referenced provider's ROW id, not its slug. A
	// provisioned identity link records it, and the login path refuses a link
	// whose recorded provider is not the currently enabled one for that issuer
	// — a restored or superseded link, referred to operator reconciliation. A
	// slug stored here would fail that check on every provisioned login.
	providerID string
}

// loadBinding reads the binding and, for a WIRE operation, proves its provider
// is still usable. `requireProvider` is false only for the administration
// reads, which must keep working precisely so a human can repair the binding
// whose provider went away — "state is preserved for repair" (§1) is not
// preserved by a surface that refuses to show it.
func (s *SCIM) loadBinding(
	ctx context.Context, r store.Repos, az *authz.TxAuthorizer, p authz.Proof, id string, requireProvider bool,
) (scimContext, error) {
	b, err := r.SCIM().Binding(ctx, p, id)
	if err != nil {
		return scimContext{}, err
	}
	out := scimContext{proof: p, binding: b}
	live, provider, err := s.providerLive(ctx, az, b)
	if err != nil {
		return scimContext{}, err
	}
	out.allowEmailNameID, out.providerID = provider.allowEmailNameID, provider.id
	if !live && requireProvider {
		return scimContext{}, ErrSCIMProviderUnavailable
	}
	return out, nil
}

// declaredExtensions is the closed set of schema extensions THIS BINDING
// declares (§5.1's "declared enterprise/custom extension path"). The enterprise
// extension is always in it — it is built in and fully described — plus the
// schema URN of the binding's own subject source when that source is an
// extension path.
//
// One list feeds three things that must never disagree: what discovery
// advertises, what a rendered resource may declare in `schemas`, and what
// ingest accepts. Declaration at binding creation is what closes the set;
// without it "custom extension" meant "any URN at all", and discovery could
// not be the closed truth §8 requires.
func (c scimContext) declaredExtensions() []scimproto.ExtensionDecl {
	out := []scimproto.ExtensionDecl{scimproto.EnterpriseExtension()}
	urn, attribute, ok := domain.SplitExtensionPath(c.binding.SubjectSource)
	if !ok || strings.EqualFold(urn, scimproto.SchemaEnterpriseExt) {
		return out
	}
	return append(out, scimproto.ExtensionDecl{URN: urn, Attribute: attribute})
}

// checkDeclaredSchemas refuses an attribute stored under a schema this binding
// never declared.
func (c scimContext) checkDeclaredSchemas(attributes map[string]any) error {
	if urn := scimproto.UndeclaredExtension(attributes, c.declaredExtensions()); urn != "" {
		// An RFC error, so the refusal NAMES the schema on the wire — a fixed
		// "the request is not valid" would leave a connector guessing which of
		// its attributes this server would not take. It answers
		// domain.ErrInvalid off the wire, so a below-the-network caller
		// classifies it like any other invalid request.
		return scimproto.ErrInvalidValue(fmt.Sprintf(
			"This binding declares no schema extension %q; discovery lists the ones it does.", urn))
	}
	return nil
}

// providerFacts is what the binding needs to know about its referenced
// provider: its row id (which a provisioned identity link records) and the one
// provider-side policy the subject derivation composes with.
type providerFacts struct {
	id               string
	issuer           string
	allowEmailNameID bool
}

// providerLive reports whether the binding's referenced provider still exists
// and is enabled.
//
// The issuer is compared byte-exactly against the copy frozen at binding
// creation: a provider whose issuer moved under a binding is a rebinding
// hazard, not a rename to follow silently.
func (s *SCIM) providerLive(ctx context.Context, az *authz.TxAuthorizer, b store.SCIMBinding) (bool, providerFacts, error) {
	switch domain.ProviderKind(b.ProviderKind) {
	case domain.ProviderOIDC:
		p, err := az.ProviderBySlug(ctx, b.ProviderSlug)
		if errors.Is(err, domain.ErrNotFound) {
			return false, providerFacts{}, nil
		}
		if err != nil {
			return false, providerFacts{}, err
		}
		// Liveness is by the immutable ROW id, not the slug: a provider deleted
		// and recreated under the same slug is a DIFFERENT provider, and a
		// binding that followed the slug would silently re-point at it.
		live := p.Enabled && p.Issuer == b.ProviderIssuer && p.ID == b.ProviderID
		return live, providerFacts{id: b.ProviderID, issuer: p.Issuer}, nil
	case domain.ProviderSAML:
		p, err := az.SAMLProviderBySlug(ctx, b.ProviderSlug)
		if errors.Is(err, domain.ErrNotFound) {
			return false, providerFacts{}, nil
		}
		if err != nil {
			return false, providerFacts{}, err
		}
		live := p.Enabled && p.EntityID == b.ProviderIssuer && p.ID == b.ProviderID
		return live, providerFacts{
			id: b.ProviderID, issuer: p.EntityID, allowEmailNameID: p.AllowEmailNameID,
		}, nil
	default:
		return false, providerFacts{}, fmt.Errorf("service: binding %s has provider kind %q", b.ID, b.ProviderKind)
	}
}

// deriveSubject turns the value at the binding's subject-source attribute into
// the byte-exact subject the LOGIN path computes — which is protocol-specific
// (§5.1), and is the whole reason a binding declares a NameID profile.
//
// OIDC: the value IS the `sub`, consumed as opaque bytes.
//
// SAML: the locked subject is the injective encoding of (NameID value, Format,
// NameQualifier, SPNameQualifier), which a scalar SCIM attribute cannot carry.
// The binding declares the profile; the attribute supplies the VALUE alone; and
// this runs `samlSubject` — the SAME function the ACS path runs, not a second
// implementation of it. If the two ever diverge, the provisioned identity stops
// matching the login path, which is exactly the failure the E2E fixtures exist
// to catch.
func (s *SCIM) deriveSubject(c scimContext, raw string) (string, error) {
	if raw == "" {
		return "", ErrSCIMSubjectMissing
	}
	switch domain.ProviderKind(c.binding.ProviderKind) {
	case domain.ProviderOIDC:
		return raw, nil
	case domain.ProviderSAML:
		id := samlsp.NameID{Value: []byte(raw)}
		// Presence is encoded, not merely the value: an absent qualifier and an
		// empty-string qualifier are different inputs to the injective encoder,
		// and collapsing them would make two distinct SAML subjects collide.
		if c.binding.NameIDFormat != "" {
			format := c.binding.NameIDFormat
			id.Format = &format
		}
		if c.binding.NameIDQualifierPresent {
			q := c.binding.NameIDQualifier
			id.NameQualifier = &q
		}
		if c.binding.NameIDSPQualifierPresent {
			q := c.binding.NameIDSPQualifier
			id.SPNameQualifier = &q
		}
		return samlSubject(id, c.allowEmailNameID)
	default:
		return "", fmt.Errorf("service: binding %s has provider kind %q", c.binding.ID, c.binding.ProviderKind)
	}
}

// identityKind is the `external_identities.kind` discriminator a binding's
// provisioned links carry. It is the login path's own vocabulary, so a
// provisioned link and a login-created link are the same row shape.
func identityKind(b store.SCIMBinding) string {
	if domain.ProviderKind(b.ProviderKind) == domain.ProviderSAML {
		return SAMLKind
	}
	return OIDCKind
}

// subjectDigest is the SHA-256 hex of a derived subject. The subject itself is
// identity material and never appears in plaintext in the trail (§10).
func subjectDigest(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(sum[:])
}

// scopeObject is §10's `scope` payload type: the DEEPEST level addressed and
// that level's own id. It is a pair rather than a rendered chain because a
// reader must be able to tell which id is which level without parsing.
func scopeObject(s domain.Scope) audit.Payload {
	switch {
	case s.Env != "":
		return audit.Payload{"level": "environment", "scope_id": string(s.Env)}
	case s.Project != "":
		return audit.Payload{"level": "project", "scope_id": string(s.Project)}
	default:
		return audit.Payload{"level": "org", "scope_id": string(s.Org)}
	}
}

// mappingScope turns a mapping row into the scope its grants land at. The org
// is the binding's — a binding can cause grants only inside its own org
// subtree (§1) — and the two deeper dimensions are the row's own.
func mappingScope(b store.SCIMBinding, m store.SCIMMapping) domain.Scope {
	return domain.Scope{
		Org:     domain.OrgID(b.OrgID),
		Project: domain.ProjectID(m.ScopeProjectID),
		Env:     domain.EnvID(m.ScopeEnvID),
	}
}

// checkMappingScope refuses a row naming a scope outside the binding's org and
// a template no binding may map. Both are checked at AUTHORING time and again
// at sync time, because the mapping table and the group memberships move
// independently.
// ErrSCIMScopeAncestry refuses a mapping row whose project or environment does
// not actually live under the binding's org.
var ErrSCIMScopeAncestry = fmt.Errorf(
	"%w: service: this scope does not belong to the binding's organisation", domain.ErrInvalid)

// resolveMappingScope proves the ancestry a syntactic depth check cannot: that
// the named project belongs to the binding's ORG and the named environment to
// that project. §1 bounds a binding to its own org subtree, and without this
// a mapping row could name another tenant's project and grant into it.
//
// It runs at AUTHORING and again at SYNC time, because the mapping table and
// the hierarchy move independently: a project deleted and its id reused, or a
// row authored before a check existed, must not expand on the next push.
func (s *SCIM) resolveMappingScope(
	ctx context.Context, r store.Repos, az *authz.TxAuthorizer, p authz.Proof, b store.SCIMBinding, project, env string,
) error {
	if project == "" {
		return nil
	}
	// First half: the PROJECT is one of this org's, read under the org proof
	// this operation already holds.
	projects, err := r.Projects().List(ctx, p)
	if err != nil {
		return err
	}
	found := false
	for _, row := range projects {
		if row.ID == project {
			found = true
			break
		}
	}
	if !found {
		return ErrSCIMScopeAncestry
	}
	if env == "" {
		return nil
	}
	// Second half: the ENVIRONMENT belongs to that project. The earlier
	// argument — "a mismatched environment fails chain resolution at every
	// authorize() and therefore grants nothing" — is true about reachability
	// and false about state: the mapping row still persists, still expands, and
	// still writes grant rows naming a chain that does not exist, which the
	// membership surface then renders. Ancestry is answered by the same
	// single-query chain resolution authorize() performs, so this is not a
	// second implementation of the hierarchy and not a project-depth predicate
	// on `environments`.
	chain, err := az.ResolveChain(ctx, domain.Scope{
		Org: domain.OrgID(b.OrgID), Project: domain.ProjectID(project), Env: domain.EnvID(env),
	})
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrSCIMScopeAncestry
		}
		return err
	}
	if string(chain.Org) != b.OrgID || string(chain.Project) != project || string(chain.Env) != env {
		return ErrSCIMScopeAncestry
	}
	return nil
}

func checkMappingScope(b store.SCIMBinding, template domain.Template, project, env string) error {
	if !domain.IsMappableTemplate(template) {
		return fmt.Errorf("%w: %q", ErrSCIMTemplate, template)
	}
	if env != "" && project == "" {
		return fmt.Errorf("%w: an environment scope needs its project", domain.ErrInvalid)
	}
	scope := domain.Scope{
		Org: domain.OrgID(b.OrgID), Project: domain.ProjectID(project), Env: domain.EnvID(env),
	}
	level, err := scope.Level()
	if err != nil {
		return fmt.Errorf("%w: %s", domain.ErrInvalid, err)
	}
	if _, err := domain.ExpandTemplate(template, level); err != nil {
		return fmt.Errorf("%w: %s", ErrSCIMTemplate, err)
	}
	return nil
}

// applyMappings materialises one user's grants from a set of mapping rows: the
// SAME per-capability rows a human applying that template would create, each
// carrying the `scim(binding, mapping_row, group)` origin (§3).
//
// It is deliberately additive and idempotent. A user in several mapped groups
// gets the union — the grant model's only combining rule — and a row that
// already exists gains an origin rather than a duplicate.
func (s *SCIM) applyMappings(
	ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext,
	target domain.PrincipalID, mappings []store.SCIMMapping, now time.Time,
) ([]grantEventInput, int, error) {
	var events []grantEventInput
	created := 0
	for _, m := range mappings {
		if m.Inert {
			continue // the group it names is gone; a human decides, not a sync
		}
		// Re-checked at SYNC time, not only at authoring: the mapping table and
		// the hierarchy move independently, and a row authored against a
		// project that has since gone must not expand on the next push.
		if err := s.resolveMappingScope(ctx, r, az, c.proof, c.binding, m.ScopeProjectID, m.ScopeEnvID); err != nil {
			return nil, 0, err
		}
		scope := mappingScope(c.binding, m)
		level, err := scope.Level()
		if err != nil {
			return nil, 0, fmt.Errorf("%w: %s", domain.ErrInvalid, err)
		}
		caps, err := domain.ExpandTemplate(domain.Template(m.Template), level)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: %s", ErrSCIMTemplate, err)
		}
		origin := authz.Origin{
			Kind: domain.OriginSCIM,
			Subject: domain.SCIMOriginKey{
				Binding: c.binding.ID, MappingRow: m.ID, Group: m.GroupID,
			}.Subject(),
		}
		for _, capability := range caps {
			spec := GrantSpec{Target: target, Capability: capability, Scope: scope}
			if err := checkGrantable(capability, level); err != nil {
				return nil, 0, err
			}
			// The same refusal rules an individual grant must satisfy: the row
			// lock first, then the principal class and the normative machine
			// allowlists. A sync must not take a shortcut past a rule a human
			// grant cannot.
			if _, err := lockAndClassify(ctx, az, target, capability, scope); err != nil {
				return nil, 0, err
			}
			out, err := writeGrantRow(ctx, az, spec, origin, now)
			if err != nil {
				return nil, 0, err
			}
			var typ audit.EventType
			switch out.Outcome {
			case GrantUnchanged():
				continue // already held by this exact origin: nothing happened
			case GrantCreated():
				created++
				typ = audit.EventGrantCreated
			case GrantOriginAdded():
				typ = audit.EventGrantModified
			default:
				return nil, 0, fmt.Errorf("invalid grant outcome %q", out.Outcome)
			}
			events = append(events, grantEventInput{
				typ:    typ,
				object: audit.Object{Type: "grant", ID: out.GrantID},
				payload: audit.Payload{
					"target_principal":   string(target),
					"capability":         string(capability),
					"scope":              renderScope(scope),
					"origin_kind":        string(domain.OriginSCIM),
					"self_grant":         false,
					"unheld":             false,
					"target_class":       string(domain.ClassHuman),
					"template":           m.Template,
					"origin_binding":     c.binding.ID,
					"origin_mapping_row": m.ID,
					"origin_group":       m.GroupID,
				},
			})
			// A sync IS a granter (§9): a group-driven `manage-members` grant
			// can cure a retention exactly as a human's would — and the cure
			// clears the binding's attention state through the audited exit
			// path, not by leaving it standing over a released retention.
			results, cured, err := cureIfMemberManagement(ctx, az, retentionAttentionClearer(r, c.proof), capability, scope, out)
			if err != nil {
				return nil, 0, err
			}
			events = append(events, cured...)
			for _, res := range results {
				if res.Binding != c.binding.ID {
					continue
				}
				ev, err := s.clearAttention(ctx, r, c,
					domain.AttentionLockoutRetention, res.GrantID, domain.CauseDeprovision)
				if err != nil {
					return nil, 0, err
				}
				events = append(events, ev...)
			}
		}
	}
	return events, created, nil
}

// desiredMappings is the desired-state read §5.4 is written around: the mapping
// rows that apply to one user RIGHT NOW, from their current group memberships.
// Every transition that recreates origins — reactivation, group create, member
// add — goes through it rather than replaying events.
func (s *SCIM) desiredMappings(
	ctx context.Context, r store.Repos, c scimContext, userID string,
) ([]store.SCIMMapping, error) {
	memberships, err := r.SCIM().MembershipsForUser(ctx, c.proof, c.binding.ID, userID)
	if err != nil {
		return nil, err
	}
	var out []store.SCIMMapping
	for _, m := range memberships {
		rows, err := r.SCIM().MappingsForGroup(ctx, c.proof, c.binding.ID, m.GroupID)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Attention states
// ---------------------------------------------------------------------------

// enterAttention raises one attention state, audited on entry. Re-entering a
// state already held is a no-op and emits nothing: the UNIQUE key makes the
// second insert a conflict, and a trail that recorded it would say the binding
// broke twice when it broke once.
func (s *SCIM) enterAttention(
	ctx context.Context, r store.Repos, c scimContext,
	state domain.SCIMAttention, subjectRef string, cause domain.SCIMCause, now time.Time,
) ([]grantEventInput, error) {
	rows, err := r.SCIM().Attention(ctx, c.proof, c.binding.ID)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.State == string(state) && row.SubjectRef == subjectRef {
			return nil, nil
		}
	}
	id, err := newID("sat")
	if err != nil {
		return nil, err
	}
	if err := r.SCIM().EnterAttention(ctx, c.proof, store.SCIMAttentionRow{
		ID: id, BindingID: c.binding.ID, State: string(state),
		SubjectRef: subjectRef, Cause: string(cause), EnteredAt: now,
	}); err != nil {
		return nil, err
	}
	return []grantEventInput{{
		typ:    audit.EventSCIMAttentionEntered,
		object: attentionObject(c, state, subjectRef),
		payload: audit.Payload{
			"binding": c.binding.ID, "state": string(state), "cause": string(cause),
		},
	}}, nil
}

// clearAttention lowers one attention state, audited on exit. Clearing a state
// that is not held emits nothing, for the same reason entering a held one does.
func (s *SCIM) clearAttention(
	ctx context.Context, r store.Repos, c scimContext,
	state domain.SCIMAttention, subjectRef string, cause domain.SCIMCause,
) ([]grantEventInput, error) {
	n, err := r.SCIM().ClearAttention(ctx, c.proof, c.binding.ID, string(state), subjectRef)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	return []grantEventInput{{
		typ:    audit.EventSCIMAttentionCleared,
		object: attentionObject(c, state, subjectRef),
		payload: audit.Payload{
			"binding": c.binding.ID, "state": string(state), "cause": string(cause),
		},
	}}, nil
}

// attentionObject names WHICH thing a state is about. §10's payload list for
// these two events is "binding, state, cause" — so the subject rides the event
// OBJECT, which is envelope rather than payload, and an entry and its exit pair
// up on it.
func attentionObject(c scimContext, state domain.SCIMAttention, subjectRef string) audit.Object {
	if subjectRef == "" {
		return audit.Object{Type: "scim-binding", ID: c.binding.ID}
	}
	switch state {
	case domain.AttentionLockoutRetention:
		return audit.Object{Type: "grant", ID: subjectRef}
	case domain.AttentionInertMapping:
		return audit.Object{Type: "scim-mapping", ID: subjectRef}
	default:
		return audit.Object{Type: "scim-user", ID: subjectRef}
	}
}

// reconcileProviderAttention keeps the `provider_unavailable` state honest in
// both directions on every binding read, so the surface the org admin looks at
// is current rather than as of the last write.
func (s *SCIM) reconcileProviderAttention(
	ctx context.Context, r store.Repos, az *authz.TxAuthorizer, c scimContext, now time.Time,
) ([]grantEventInput, error) {
	live, _, err := s.providerLive(ctx, az, c.binding)
	if err != nil {
		return nil, err
	}
	if live {
		return s.clearAttention(ctx, r, c, domain.AttentionProviderUnavailable, "", "")
	}
	return s.enterAttention(ctx, r, c, domain.AttentionProviderUnavailable, "", "", now)
}

// reconcileStaleness is the push-only staleness rule (§9): the binding records
// last contact, and past the threshold the surface warns. Nothing self-heals
// and no grant expires — converting an IdP outage into org-wide revocation is
// the scrub-on-timer failure shape the ADR rejects by name.
func (s *SCIM) reconcileStaleness(
	ctx context.Context, r store.Repos, c scimContext, now time.Time,
) ([]grantEventInput, error) {
	// A binding that has never been contacted is measured from its CREATION,
	// not treated as instantly stale: §9 makes staleness a threshold, and a
	// warning that fires the moment a binding exists says nothing about the
	// identity provider's health — it just makes every new binding look broken
	// while the operator is still installing its credential.
	since := c.binding.LastContactAt
	if since.IsZero() {
		since = c.binding.CreatedAt
	}
	stale := now.Sub(since) > s.staleness()
	if stale {
		return s.enterAttention(ctx, r, c, domain.AttentionStale, "", "", now)
	}
	return s.clearAttention(ctx, r, c, domain.AttentionStale, "", "")
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

// mintCredential is the shared body of the mint verb and the binding-creation
// path. Everything inherits unchanged from the locked machine-credential
// mechanics; what is SCIM's own is the token TYPE and the binding it names.
func (s *SCIM) mintCredential(
	ctx context.Context, r store.Repos, az *authz.TxAuthorizer, p authz.Proof,
	b store.SCIMBinding, indefinite bool, now time.Time,
) (string, store.NewSCIMCredential, error) {
	if indefinite && !s.AllowIndefinite {
		return "", store.NewSCIMCredential{}, ErrSCIMIndefiniteRefused
	}
	value, verifier, err := crypto.NewArtifact(crypto.ArtifactSCIM)
	if err != nil {
		return "", store.NewSCIMCredential{}, err
	}
	id, err := newID("scr")
	if err != nil {
		return "", store.NewSCIMCredential{}, err
	}
	epoch, err := az.CredentialEpoch(ctx)
	if err != nil {
		return "", store.NewSCIMCredential{}, err
	}
	n := store.NewSCIMCredential{
		ID: id, BindingID: b.ID, PrincipalID: b.ConnectionPrincipalID,
		Verifier: verifier, CredentialEpoch: epoch, CreatedAt: now,
	}
	if !indefinite {
		n.ExpiresAt = now.Add(s.credentialTTL())
	}
	if err := r.SCIM().CreateCredential(ctx, p, n); err != nil {
		return "", store.NewSCIMCredential{}, err
	}
	return value, n, nil
}

// MaxLiveCredentials bounds overlap rotation. Several live credentials is the
// point — mint-new, update the identity provider, revoke-old — but an unbounded
// set is a pile of year-long bearers nobody is tracking.
const MaxLiveCredentials = 5

// ErrSCIMCredentialLimit refuses a mint at the cap, by name.
var ErrSCIMCredentialLimit = fmt.Errorf(
	"%w: service: this binding already holds the maximum number of live provisioning credentials; revoke one first",
	domain.ErrLimitExceeded)

func (s *SCIM) credentialTTL() time.Duration {
	if s.CredentialTTL <= 0 {
		return DefaultSCIMCredentialTTL
	}
	return s.CredentialTTL
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

// fold is the RFC 7643 `caseExact: false` comparison key for `userName` and
// `displayName`. It is a stored column rather than a LOWER() in the predicate
// because a function in a WHERE clause defeats both the index and the SQL
// predicate analyzer at once.
func fold(s string) string { return strings.ToLower(s) }

// sanitizedList bounds and sanitizes a list of IdP-supplied strings for an
// audit payload: each entry through the free-text filter, the list capped, the
// order stable.
func sanitizedList(in []string, max int) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, audit.SanitizeFreeText(v))
	}
	sort.Strings(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// ---------------------------------------------------------------------------
// Test seams
// ---------------------------------------------------------------------------

// scimPhaseObserver records the ORDERED phases of a multi-step SCIM act, so a
// fixture can assert §6's teardown ordering — credentials dead, then origins
// released, then the connection retired, then the directory gone — rather than
// only its end state. An end-state assertion cannot tell a correct order from
// a wrong one that happens to converge.
//
// It is nil in production and costs one atomic load per phase. The same shape
// as the resolution surface's query seam, and pinned by the same test
// (TestQueryObserverIsTestOnly): it must have no production installer.
var scimPhaseObserver atomic.Pointer[func(string, map[string]int)]

// SetSCIMPhaseObserver installs the observer and returns a restore func. It is
// exported for internal/isolation only; nothing in production installs one.
//
// The callback runs SYNCHRONOUSLY INSIDE the transaction, so returning from it
// is what lets the transaction continue: a fixture that blocks in it has paused
// the act at that boundary. `state` carries the facts the phase is about, read
// under the transaction's own proof — the only way to see uncommitted
// intermediate state, since an outside reader sees the pre-transaction
// snapshot on both engines.
func SetSCIMPhaseObserver(fn func(phase string, state map[string]int)) func() {
	prev := scimPhaseObserver.Load()
	scimPhaseObserver.Store(&fn)
	return func() {
		if prev == nil {
			scimPhaseObserver.Store(nil)
			return
		}
		scimPhaseObserver.Store(prev)
	}
}

// lockBindingRow takes §9's per-binding row lock for an ADMINISTRATION mutation
// and marks the serialized section. It uses the SAME phase names the wire
// transaction uses, because it is the same lock protecting the same origin
// arithmetic: a fixture asserting that the marks never nest is then asserting
// serialization across BOTH surfaces, not only within one.
func lockBindingRow(ctx context.Context, r store.Repos, p authz.Proof, bindingID string) (func(), error) {
	if err := r.SCIM().LockBinding(ctx, p, bindingID); err != nil {
		return nil, err
	}
	markSCIMPhase("wire-enter:" + bindingID)
	return func() { markSCIMPhase("wire-exit:" + bindingID) }, nil
}

// markSCIMPhaseN marks a phase WITH the count of what it did. A bare label is
// satisfied by an implementation that reaches the line and does nothing; a
// count is a statement about the state the phase left behind, which is what
// §6's ordering is actually about.
func markSCIMPhaseN(phase string, n int) {
	markSCIMPhase(phase + "=" + strconv.Itoa(n))
}

func markSCIMPhase(phase string) {
	if fn := scimPhaseObserver.Load(); fn != nil {
		(*fn)(phase, nil)
	}
}

// scimPhaseObserved reports whether anyone is watching, so a phase that would
// have to READ to describe itself does not pay for that in production.
func scimPhaseObserved() bool { return scimPhaseObserver.Load() != nil }

// markSCIMPhaseState marks a phase boundary with the state it produced.
func markSCIMPhaseState(phase string, state map[string]int) {
	if fn := scimPhaseObserver.Load(); fn != nil {
		(*fn)(phase, state)
	}
}
