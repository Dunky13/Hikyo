package authz

import (
	"sort"

	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/domain"
)

// Artifact eligibility: the second half of the multi-instance ADR's DOUBLE
// CONFINEMENT (#71, § The instance-connection principal and its credential).
//
// The first half is capability confinement, and it already exists: the grant
// API caps the instance-connection principal class at exactly
// `instance-directory` (domain.machineAllowlists). The ADR is explicit that
// this is not enough:
//
//	"Capability confinement alone would not confine the CREDENTIAL: a future
//	operation whose formula accepts `instance-directory` would widen every
//	existing token without any grant changing."
//
// So the credential is capped independently of the capability, per artifact
// per operation — which is what makes the bound survive a formula being
// reused. A later operation may adopt the `instance-directory` formula for its
// own reasons and reach exactly nothing new, because eligibility is keyed on
// the artifact and names its operations one at a time.
//
// The table is an ALLOWLIST OF CONFINED TYPES, not a total matrix, and the
// asymmetry is deliberate. An artifact type ABSENT from this map is
// unconfined — which is today's behaviour for cli, browser, workspace,
// workload and automation artifacts, whose reach is decided by their grants
// alone. An artifact type PRESENT is confined to the operations listed and
// refused everywhere else. Writing the matrix out in full would mean every new
// operation had to be added to five rows to keep working, and the row someone
// forgot would be a silent denial rather than a silent widening — a different
// failure, not a better one.
var artifactEligibility = map[crypto.ArtifactType]map[Operation]bool{
	// The ADR's amendment to the API/CLI ADR's artifact-eligibility matrix:
	// "the instance-connection credential as a new row, eligible for EXACTLY
	// ONE operation: directory-serve".
	crypto.ArtifactInstanceConn: {
		OpRemoteDirectoryServe: true,
	},
}

// confinedClasses is the SECOND KEY on the same confinement, and it exists
// because Identity.Artifact has mixed provenance: a session carries the
// database's artifact string ("cli", "browser", "workspace"), while
// authenticateMachine carries the CREDENTIAL KIND ("hikyo-token"). A resolver
// written by copying the machine leg would therefore set Artifact to
// "hikyo-token" for an instance connection too, and the artifact table alone
// would silently never match — a confinement that is inert rather than wrong,
// which is the worse failure because every test of the table itself still
// passes.
//
// Class does not have that problem: the Identity contract requires it to be
// set on every resolution path, never inferred from an empty field. So the
// confinement is keyed both ways and either key is sufficient to refuse. The
// artifact table stays because the ADR names the artifact-eligibility matrix
// specifically, and because it is the key that survives a class being reused.
var confinedClasses = map[domain.PrincipalClass]map[Operation]bool{
	domain.ClassInstanceConn: {
		OpRemoteDirectoryServe: true,
	},
}

// Eligible reports whether this caller may present against this operation at
// all, by EITHER key. It is the form the chokepoint calls.
func Eligible(caller Identity, op Operation) bool {
	if !ArtifactEligible(crypto.ArtifactType(caller.Artifact), op) {
		return false
	}
	confined, isConfined := confinedClasses[caller.Class]
	if !isConfined {
		return true
	}
	return confined[op]
}

// ArtifactEligible reports whether a credential of this artifact type may be
// presented to this operation at all — a question asked BEFORE the formula, and
// answered without consulting a single grant.
//
// An unknown or empty artifact is eligible: emptiness is what local host
// authority (bootstrap, break-glass, `hikyo admin`) presents, and refusing it
// here would refuse the recovery paths that exist for when authorization is
// what is broken.
func ArtifactEligible(artifact crypto.ArtifactType, op Operation) bool {
	confined, isConfined := artifactEligibility[artifact]
	if !isConfined {
		return true
	}
	return confined[op]
}

// ConfinedArtifacts returns the artifact types this table confines, sorted.
// Exported so the CI invariant can enumerate the confinement rather than
// restate it — a test that repeated the list would pass against a table that
// had quietly lost a row.
func ConfinedArtifacts() []crypto.ArtifactType {
	out := make([]crypto.ArtifactType, 0, len(artifactEligibility))
	for a := range artifactEligibility {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// EligibleOperations returns the operations an artifact type is confined to,
// sorted, and nil when it is unconfined.
func EligibleOperations(artifact crypto.ArtifactType) []Operation {
	confined, isConfined := artifactEligibility[artifact]
	if !isConfined {
		return nil
	}
	out := make([]Operation, 0, len(confined))
	for op := range confined {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
