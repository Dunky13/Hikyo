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

	"cli:login":       ClassStub,
	"cli:run":         ClassStub,
	"cli:render":      ClassStub,
	"cli:sync":        ClassStub,
	"cli:adopt":       ClassStub,
	"cli:doctor":      ClassStub,
	"cli:definitions": ClassStub,
	"cli:import":      ClassStub,

	// Outbox job types, SSE emit sites and tenant-data caches: none exist.
	// Their registries are this table's key spaces ("job:", "sse:",
	// "cache:"); the first entry of each kind must arrive with its probe
	// class (jobs, SSE) or its proof-taking accessors and key constructor
	// (caches, invariant 12).
}

// Wire returns the wire registry for the invariant tests.
func (RegistryFacts) Wire() map[string]Class {
	return maps.Clone(wireRegistry)
}
