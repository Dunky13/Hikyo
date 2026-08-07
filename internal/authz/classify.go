package authz

import "maps"

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

	// Process entry points with no principal: boot (server) and migration.
	// Their system-proof mint sites are enumerated in systemSites; the probe
	// contract is network unreachability, which the totality check asserts
	// by finding no HTTP route for them.
	"cli:server":  ClassSystem,
	"cli:migrate": ClassSystem,

	// `wenv version` (#46): local print of build metadata — no principal,
	// no server, no store; the pre-auth contract is trivially total.
	"cli:version": ClassUnauthenticated,

	"cli:login":       ClassStub,
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
