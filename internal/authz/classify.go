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

	// Org administration is instance-scoped: the probe contract is grant
	// refusal, not tenancy, because no tenant object exists whose
	// nonexistence could be mimicked.
	"http:GET /api/v1/orgs":       ClassInstance,
	"http:POST /api/v1/orgs":      ClassInstance,
	"http:GET /api/v1/orgs/{org}": ClassInstance,

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
	"cli:org":     ClassInstance,

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
// A wire entry that appears here and also reaches a registered operation is a
// modelling mistake, and the completeness invariant says so.
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
	// whoami resolves a session and reports it. It writes nothing and its
	// result duplicates what the login event already recorded, so it is the
	// one auth path with no event of its own — pinned in the exemption
	// fixture with that reason rather than silently absent.

	// The bootstrap verb, running on the server's own host under local
	// authority. Its mint is audited including the DELIVERY MODE, because a
	// token that reached a log shipper is a different event from one written
	// to a root-owned file.
	"cli:admin": {audit.EventAuthAuthorityMinted},
}

// wireRoutes maps an HTTP entry point to the registered operation it reaches.
// The audit-completeness invariant follows it so a domain route inherits its
// operation's audit mapping instead of needing a second declaration that
// could drift from the first.
var wireRoutes = map[string]Operation{
	"http:POST /api/v1/orgs":      OpOrgCreate,
	"http:GET /api/v1/orgs":       OpOrgList,
	"http:GET /api/v1/orgs/{org}": OpOrgGet,
}

// WireRoutes returns the route→operation mapping for the invariant tests and
// the contract cross-check.
func (RegistryFacts) WireRoutes() map[string]Operation {
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
