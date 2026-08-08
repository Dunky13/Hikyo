package authz

import (
	"maps"

	"github.com/Dunky13/wenv/internal/audit"
)

// The wire registry: the probe classification for every non-operation entry
// point (tenant-isolation ADR, invariant 1). Service operations carry their
// class in the operation registry; everything else that can be reached from
// outside — HTTP routes, CLI verbs, background job types, SSE emit sites —
// is classified here. The classification-totality invariant enumerates the
// actual router, the actual CLI verb table and the (currently empty) job and
// SSE registries against this table: an unclassified entry point fails the
// build, and a stale entry here fails it too.

// ClassStub marks a CLI verb that is not an operation yet: it refuses (exit
// 2), reaches no server and no store, and has no entry in the operation
// registry — the totality check enforces exactly that. It is deliberately
// not one of the ADR's four probe classes: classifying an unimplemented
// verb as tenant-scoped or unauthenticated now would let the eventual
// implementation ride in on a stale class without ever meeting its probe
// contract. When a verb's ticket lands, its class here changes and the
// matching probes must exist.
const ClassStub Class = -1

var wireRegistry = map[string]Class{
	"http:GET /healthz": ClassUnauthenticated,
	"http:GET /readyz":  ClassUnauthenticated,

	// The contract surface (#47). Every entry below exists in
	// api/openapi.yaml and carries the same class there under
	// `x-wenv-class`; api.TestContractClassesMatchTheWireRegistry fails the
	// build if the two ever disagree, so the document cannot describe an
	// authorization posture the router does not have.
	//
	// Identity-protocol endpoints are unauthenticated-class: their probe
	// contract is enumeration uniformity — no pre-authentication path may
	// distinguish an existing account, session or authority from a missing
	// one. `logout` and `whoami` take an artifact but are classified here
	// too, because an unresolvable artifact is exactly the case they must not
	// distinguish.
	"http:GET /api/v1/meta":                       ClassUnauthenticated,
	"http:POST /api/v1/auth/credential/establish": ClassUnauthenticated,
	"http:POST /api/v1/auth/local/login":          ClassUnauthenticated,
	"http:POST /api/v1/auth/logout":               ClassUnauthenticated,
	"http:GET /api/v1/auth/whoami":                ClassUnauthenticated,

	// Factor endpoints (#54). Unauthenticated-class like logout/whoami: they
	// take a session but an unresolvable one is exactly the case they must not
	// distinguish, so their probe contract is enumeration uniformity, not
	// tenancy. `recovery/begin` is fully pre-auth. None reaches an authz
	// operation — the account-security mutations resolve and rotate the acting
	// session, which is resolution rather than authorization, so their audit
	// obligation is discharged directly through wireEvents like every other
	// authentication-surface endpoint.
	"http:POST /api/v1/auth/totp/enrol/start":          ClassUnauthenticated,
	"http:POST /api/v1/auth/totp/enrol/confirm":        ClassUnauthenticated,
	"http:POST /api/v1/auth/totp/step-up":              ClassUnauthenticated,
	"http:DELETE /api/v1/auth/totp":                    ClassUnauthenticated,
	"http:POST /api/v1/auth/recovery-codes/regenerate": ClassUnauthenticated,
	"http:POST /api/v1/auth/recovery/begin":            ClassUnauthenticated,

	// OIDC (#54). Login/callback are pre-auth; link/reauth take a session but an
	// unresolvable one is exactly the case they must not distinguish, so all are
	// unauthenticated-class (enumeration uniformity). methods is public
	// discovery. Provider administration is instance-config (below).
	"http:GET /api/v1/auth/methods":                  ClassUnauthenticated,
	"http:POST /api/v1/auth/oidc/{provider}/start":   ClassUnauthenticated,
	"http:GET /api/v1/auth/oidc/{provider}/callback": ClassUnauthenticated,
	"http:GET /api/v1/auth/identities":               ClassUnauthenticated,
	"http:POST /api/v1/auth/identities/link":         ClassUnauthenticated,
	"http:DELETE /api/v1/auth/identities/{id}":       ClassUnauthenticated,
	// WebAuthn / passkeys (#54). Enrolment, login, step-up, reauth, removal and
	// the credential inventory. Login is fully pre-auth; the rest take a session
	// but an unresolvable one is exactly the case they must not distinguish, so
	// all are unauthenticated-class (enumeration uniformity). None reaches an
	// authz operation — the mutations resolve and rotate the acting session,
	// which is resolution rather than authorization, so their audit obligation
	// is discharged directly through wireEvents.
	"http:POST /api/v1/auth/webauthn/enrol/start":        ClassUnauthenticated,
	"http:POST /api/v1/auth/webauthn/enrol/finish":       ClassUnauthenticated,
	"http:POST /api/v1/auth/webauthn/login/start":        ClassUnauthenticated,
	"http:POST /api/v1/auth/webauthn/login/finish":       ClassUnauthenticated,
	"http:POST /api/v1/auth/webauthn/step-up/start":      ClassUnauthenticated,
	"http:POST /api/v1/auth/webauthn/step-up/finish":     ClassUnauthenticated,
	"http:POST /api/v1/auth/webauthn/reauth/start":       ClassUnauthenticated,
	"http:POST /api/v1/auth/webauthn/reauth/finish":      ClassUnauthenticated,
	"http:GET /api/v1/auth/webauthn/credentials":         ClassUnauthenticated,
	"http:DELETE /api/v1/auth/webauthn/credentials/{id}": ClassUnauthenticated,
	"http:GET /api/v1/instance/oidc-providers":           ClassInstance,
	"http:GET /api/v1/instance/oidc-providers/{slug}":    ClassInstance,
	"http:PUT /api/v1/instance/oidc-providers/{slug}":    ClassInstance,
	"http:DELETE /api/v1/instance/oidc-providers/{slug}": ClassInstance,

	// Credential reset (#54). Unauthenticated-class for its probe contract:
	// the target-principal path parameter makes enumeration uniformity the
	// dominant concern, so every failure that could reveal the target's grant
	// shape answers a uniform 401 (the instance-capability refusal is the one
	// named 403, reached only after the caller is authorized at instance scope).
	// The route dispatches at runtime between two credential-reset operations, so
	// it names no single operation in wireRoutes; its audit obligation is
	// discharged through wireEvents like the account-security surface.
	"http:POST /api/v1/accounts/{principal}/credential-reset": ClassUnauthenticated,

	// Org creation and enumeration are instance-scoped: the probe contract is
	// grant refusal, not tenancy, because no tenant object exists whose
	// nonexistence could be mimicked — a create has no parent tenant and a
	// list of every org spans all of them.
	"http:GET /api/v1/orgs":  ClassInstance,
	"http:POST /api/v1/orgs": ClassInstance,

	// The hierarchy surface (#48). EVERY by-id route is tenant-class, org
	// included: mvp-boundary C1 requires the uniform nonexistent shape at each
	// level, and an org route that answered 403 on grant refusal would leak the
	// existence of every org an operator cannot reach.
	"http:GET /api/v1/orgs/{org}":    ClassTenant,
	"http:PATCH /api/v1/orgs/{org}":  ClassTenant,
	"http:DELETE /api/v1/orgs/{org}": ClassTenant,

	"http:GET /api/v1/orgs/{org}/projects":              ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects":             ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}":    ClassTenant,
	"http:PATCH /api/v1/orgs/{org}/projects/{project}":  ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}": ClassTenant,

	"http:GET /api/v1/orgs/{org}/projects/{project}/environments":                  ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments":                 ClassTenant,
	"http:PUT /api/v1/orgs/{org}/projects/{project}/environments/order":            ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}":    ClassTenant,
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/environments/{environment}":  ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}": ClassTenant,

	"http:GET /api/v1/orgs/{org}/projects/{project}/folders":             ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/folders":            ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/folders/{folder}":    ClassTenant,
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/folders/{folder}":  ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/folders/{folder}": ClassTenant,

	// `wenv admin create`: the bootstrap member of the closed local-authority
	// exception set. System class, whose probe contract is network
	// unreachability — the totality invariant asserts it by finding no HTTP
	// route, which is the guarantee that matters here: a first-administrator
	// endpoint reachable from the network is the trust-on-first-use race the
	// ADR rejected outright.
	"cli:admin": ClassSystem,

	// Process entry points with no principal: boot (server) and migration.
	// Their system-proof mint sites are enumerated in systemSites; the probe
	// contract is network unreachability, which the totality check asserts
	// by finding no HTTP route for them.
	"cli:server":  ClassSystem,
	"cli:migrate": ClassSystem,

	// `wenv version` (#46): local print of build metadata — no principal,
	// no server, no store; the pre-auth contract is trivially total.
	"cli:version": ClassUnauthenticated,

	// Client verbs that reach the server. Their probe contract is the HTTP
	// route they call, classified above; the verb itself carries the class of
	// what it reaches, so a verb whose class is still ClassStub cannot
	// silently start making requests.
	"cli:login":   ClassUnauthenticated,
	"cli:logout":  ClassUnauthenticated,
	"cli:whoami":  ClassUnauthenticated,
	"cli:account": ClassUnauthenticated,
	// `context` is entirely client-local: the trust store and the named
	// contexts live on this box and reach no server.
	"cli:context": ClassUnauthenticated,
	// `org` still reaches the instance-scoped create/list as well as the
	// tenant-scoped by-id routes, so it carries the wider of the two classes:
	// a verb whose class understated its reach would let an instance-scoped
	// call ride in under a tenant probe contract. `project`, `env` and `folder`
	// reach tenant routes exclusively.
	"cli:org":     ClassInstance,
	"cli:project": ClassTenant,
	"cli:env":     ClassTenant,
	"cli:folder":  ClassTenant,

	"cli:run":         ClassStub,
	"cli:render":      ClassStub,
	"cli:sync":        ClassStub,
	"cli:adopt":       ClassStub,
	"cli:doctor":      ClassStub,
	"cli:definitions": ClassStub,
	"cli:import":      ClassStub,

	// Outbox job types and SSE emit sites: none exist. Their registries are
	// this table's "job:" and "sse:" key spaces; the first entry of each
	// kind must arrive with its probe class.
}

// wireEvents maps a wire entry to the audit event types it emits DIRECTLY,
// without an operation registry row behind it.
//
// It exists because authentication is the one surface that cannot be modelled
// as an operation: `authorize()` needs a principal, and these endpoints are
// what produce one. Their audit obligation is real all the same — the
// human-auth ADR requires login success and failure, logout, session
// creation, and credential-establishment mint, consumption and refusal — so
// the completeness invariant reads this table beside the operation registry
// rather than letting an unaudited pre-auth path hide behind "no operation".
//
// Most wire entries are either operation-backed (wireRoutes) or declare their
// events directly here (the authentication surface). The credential-reset route
// (#54) is deliberately BOTH: it is listed in wireRoutes against the two
// operations it dispatches between at runtime — so the operation linkage records
// that it reaches CapCredentialReset (MFA-mandatory) — AND declares its events
// here, because its writes and audit ride the resolution surface (like the
// account-security mutations) rather than a single operation row. It names no
// single x-wenv-operation in the contract, since two ops of different classes
// cannot be carried by one row; the completeness invariant unions both sources.
var wireEvents = map[string][]audit.EventType{
	"http:POST /api/v1/auth/local/login": {
		audit.EventAuthLogin,
		audit.EventAuthSessionCreated,
		audit.EventAuthThrottleCrossed,
	},
	"http:POST /api/v1/auth/logout": {audit.EventAuthLogout},
	"http:POST /api/v1/auth/credential/establish": {
		audit.EventAuthCredentialEstablished,
		audit.EventAuthAuthorityRefused,
	},

	// Factor endpoints (#54). The account-security mutations emit their
	// mutation event plus auth.session_created for the reissued session; step-up
	// emits auth.reauthenticated (it rotates, mints no new session row);
	// recovery/begin emits recovery_code_consumed (success and failure) and
	// mints an establishment authority whose consumption is recorded by the
	// establish path.
	// Each factor ceremony validates a proof under the per-account backoff, so
	// a crossed threshold is an event it can emit — declared here so the
	// audit-completeness contract covers it.
	"http:POST /api/v1/auth/totp/enrol/start": {audit.EventAuthThrottleCrossed},
	"http:POST /api/v1/auth/totp/enrol/confirm": {
		audit.EventAuthFactorEnrolled,
		audit.EventAuthSessionCreated,
		audit.EventAuthThrottleCrossed,
	},
	"http:POST /api/v1/auth/totp/step-up": {
		audit.EventAuthReauthenticated,
		audit.EventAuthThrottleCrossed,
	},
	"http:DELETE /api/v1/auth/totp": {
		audit.EventAuthFactorRemoved,
		audit.EventAuthSessionCreated,
		audit.EventAuthThrottleCrossed,
	},
	"http:POST /api/v1/auth/recovery-codes/regenerate": {
		audit.EventAuthRecoveryCodesGenerated,
		audit.EventAuthSessionCreated,
		audit.EventAuthThrottleCrossed,
	},
	"http:POST /api/v1/auth/recovery/begin": {
		audit.EventAuthRecoveryCodeConsumed,
		// A successful consume mints a recovery-issued credential-establishment
		// authority; the authority coming into existence is its own record.
		audit.EventAuthAuthorityMinted,
		// Pre-auth like login: a crossed per-account backoff threshold is its
		// own event, emitted directly by recordThrottleCrossing.
		audit.EventAuthThrottleCrossed,
	},
	// whoami resolves a session and reports it. It writes nothing and its
	// result duplicates what the login event already recorded, so it is the
	// one auth path with no event of its own — pinned in the exemption
	// fixture with that reason rather than silently absent.

	// OIDC (#54). start emits only a throttle crossing directly; the callback
	// is where a login/link/reauth lands, so it carries the family of outcomes
	// (login success, refusal by cause, link, JIT, the reissued/rotated session,
	// reauth). link start mirrors start; unlink emits the unlink plus the
	// reissued session. Provider administration is operation-modeled (wireRoutes).
	"http:POST /api/v1/auth/oidc/{provider}/start": {audit.EventAuthThrottleCrossed},
	"http:GET /api/v1/auth/oidc/{provider}/callback": {
		audit.EventOIDCLogin,
		audit.EventOIDCRefused,
		audit.EventIdentityLinked,
		audit.EventJITProvisioned,
		audit.EventAuthSessionCreated,
		audit.EventAuthReauthenticated,
		audit.EventAuthThrottleCrossed,
	},
	"http:POST /api/v1/auth/identities/link": {audit.EventAuthThrottleCrossed},
	"http:DELETE /api/v1/auth/identities/{id}": {
		audit.EventIdentityUnlinked,
		audit.EventAuthSessionCreated,
		audit.EventAuthThrottleCrossed,
	},

	// Credential reset (#54). A successful reset mints a credential-establishment
	// authority (its own record, factors MEDIUM-7) and records the reset issuance
	// naming the tier. See the exception note above for why this route audits here
	// rather than through an operation row.
	"http:POST /api/v1/accounts/{principal}/credential-reset": {
		audit.EventAuthCredentialResetIssued,
		audit.EventAuthAuthorityMinted,
	},

	// WebAuthn / passkeys (#54). The three start ceremonies and the credential
	// read emit nothing directly and are exemption-pinned; the finish endpoints
	// carry the outcomes. enrol validates a proof under the per-account backoff
	// (a crossed threshold is its own event) and adds a credential + reissues
	// the session; login mints a session and, on a signature-count regression,
	// disables the cloned credential; step-up and reauth append the factor
	// (reauthenticated) and can likewise detect a clone; removal removes the
	// credential and reissues the session.
	"http:POST /api/v1/auth/webauthn/enrol/start": {audit.EventAuthThrottleCrossed},
	"http:POST /api/v1/auth/webauthn/enrol/finish": {
		audit.EventAuthPasskeyAdded,
		audit.EventAuthSessionCreated,
	},
	"http:POST /api/v1/auth/webauthn/login/finish": {
		audit.EventAuthLogin,
		audit.EventAuthSessionCreated,
		audit.EventAuthPasskeyCloned,
		audit.EventAuthThrottleCrossed,
	},
	"http:POST /api/v1/auth/webauthn/step-up/finish": {
		audit.EventAuthReauthenticated,
		audit.EventAuthPasskeyCloned,
	},
	"http:POST /api/v1/auth/webauthn/reauth/finish": {
		audit.EventAuthReauthenticated,
		audit.EventAuthPasskeyCloned,
	},
	"http:DELETE /api/v1/auth/webauthn/credentials/{id}": {
		audit.EventAuthPasskeyRemoved,
		audit.EventAuthSessionCreated,
		audit.EventAuthThrottleCrossed,
	},

	// The bootstrap verb, running on the server's own host under local
	// authority. Its mint is audited including the DELIVERY MODE, because a
	// token that reached a log shipper is a different event from one written
	// to a root-owned file. `wenv admin reset-credential` (#54 break-glass) is the
	// same local-authority verb group and emits the reset issuance beside the mint.
	"cli:admin": {audit.EventAuthAuthorityMinted, audit.EventAuthCredentialResetIssued},
}

// wireRoutes maps an HTTP entry point to the registered operation(s) it reaches.
// The audit-completeness invariant follows it so a domain route inherits its
// operation's audit mapping instead of needing a second declaration that
// could drift from the first. Most routes reach exactly one operation; a route
// that dispatches at runtime between operations (credential reset) lists them
// all, so the linkage records every operation the route can reach.
var wireRoutes = map[string][]Operation{
	"http:POST /api/v1/orgs":         {OpOrgCreate},
	"http:GET /api/v1/orgs":          {OpOrgList},
	"http:GET /api/v1/orgs/{org}":    {OpOrgGet},
	"http:PATCH /api/v1/orgs/{org}":  {OpOrgRename},
	"http:DELETE /api/v1/orgs/{org}": {OpOrgDelete},

	// The hierarchy surface (#48).
	"http:GET /api/v1/orgs/{org}/projects":              {OpProjectList},
	"http:POST /api/v1/orgs/{org}/projects":             {OpProjectCreate},
	"http:GET /api/v1/orgs/{org}/projects/{project}":    {OpProjectGet},
	"http:PATCH /api/v1/orgs/{org}/projects/{project}":  {OpProjectRename},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}": {OpProjectDelete},

	"http:GET /api/v1/orgs/{org}/projects/{project}/environments":                  {OpEnvList},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments":                 {OpEnvCreate},
	"http:PUT /api/v1/orgs/{org}/projects/{project}/environments/order":            {OpEnvReorder},
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}":    {OpEnvRead},
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/environments/{environment}":  {OpEnvRename},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}": {OpEnvDelete},

	"http:GET /api/v1/orgs/{org}/projects/{project}/folders":             {OpFolderList},
	"http:POST /api/v1/orgs/{org}/projects/{project}/folders":            {OpFolderCreate},
	"http:GET /api/v1/orgs/{org}/projects/{project}/folders/{folder}":    {OpFolderGet},
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/folders/{folder}":  {OpFolderRename},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/folders/{folder}": {OpFolderDelete},

	// OIDC provider administration (#54), instance-config.
	"http:GET /api/v1/instance/oidc-providers":           {OpProviderList},
	"http:GET /api/v1/instance/oidc-providers/{slug}":    {OpProviderGet},
	"http:PUT /api/v1/instance/oidc-providers/{slug}":    {OpProviderPut},
	"http:DELETE /api/v1/instance/oidc-providers/{slug}": {OpProviderDelete},

	// Credential reset (#54). ONE route dispatches at runtime between the
	// org-scoped and instance-scoped credential-reset operations by the target's
	// grant classification, resolved under the target-row lock inside the
	// handler's tx. Both are mapped here so the operation linkage records that
	// this route reaches CapCredentialReset (MFA-mandatory): the chokepoint —
	// authorize(), which the service calls on the chosen op inside that tx —
	// enforces capability + MFA + assurance. The route keeps its unauthenticated
	// probe class (enumeration uniformity is its dominant contract, reinforced by
	// B2's uniform refusal) and carries no single x-wenv-operation, since two ops
	// of different classes cannot be named by one contract row; its audit events
	// also ride wireEvents below.
	"http:POST /api/v1/accounts/{principal}/credential-reset": {OpCredentialReset, OpCredentialResetInstance},
}

// WireRoutes returns the route→operation(s) mapping for the invariant tests and
// the contract cross-check.
func (RegistryFacts) WireRoutes() map[string][]Operation {
	return maps.Clone(wireRoutes)
}

// WireEvents returns the direct wire→event mapping for the invariant tests.
func (RegistryFacts) WireEvents() map[string][]audit.EventType {
	return maps.Clone(wireEvents)
}

// Cache is one registered cache holding derived tenant material
// (tenant-isolation ADR invariant 12). Registration is mandatory: the
// invariant test fails on any cache-shaped declaration in the module that
// is not listed here, so a new cache cannot appear without stating how it
// is keyed and who may reach it.
type Cache struct {
	// KeyConstructor is the single function that builds its keys. The ADR's
	// keying rule: the full id chain to the owning scope, structured and
	// injectively encoded (length-prefixed — bare concatenation is how
	// (org "a", project "bc") and (org "ab", project "c") collide).
	KeyConstructor string
	// ProofGatedAt names the layer that supplies the proof for reads and
	// writes. For the DEK LRU this is deliberately NOT inside the cache:
	// internal/crypto is a locked leaf package (encryption ADR; enforced by
	// the boundary test) and may not import the authorization package, so
	// its accessors cannot take an authz.Proof. The access rule is therefore
	// discharged one layer up, at the service seam that resolves a scope
	// before asking crypto to seal for it.
	ProofGatedAt string
}

// caches is the closed cache registry.
var caches = map[string]Cache{
	"crypto.dek-lru": {
		KeyConstructor: "internal/crypto.dekScope",
		// No tenant-facing caller exists yet: the DEK LRU is reachable only
		// from Keyring.ForProject, whose only callers today are crypto's own
		// tests and the boot path. The first tenant consumer is #50 (flat
		// encrypted values), which MUST resolve the scope through
		// authorize() and pass the proof's chain — a cache hit must not be a
		// proof-free path to tenant material.
		ProofGatedAt: "service seam (#50); no tenant caller today",
	},
}

// Caches returns the cache registry for the invariant test.
func (RegistryFacts) Caches() map[string]Cache {
	return maps.Clone(caches)
}

// Wire returns the wire registry for the invariant tests.
func (RegistryFacts) Wire() map[string]Class {
	return maps.Clone(wireRegistry)
}
