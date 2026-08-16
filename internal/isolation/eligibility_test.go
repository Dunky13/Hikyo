package isolation

import (
	"slices"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
)

// The multi-instance ADR's acceptance criterion 4, second half, in the form
// the criterion itself demands — "refuses by artifact eligibility
// (CI-asserted)":
//
//	"the instance-connection credential presented to any endpoint other than
//	directory-serve refuses by artifact eligibility"
//
// The assertion ranges over the embedded OpenAPI registry: runtime admission
// consumes this exact declaration, so there is no second eligibility table to
// drift or forget when an operation is added.

func TestInstanceConnectionCredentialReachesOnlyDirectoryServe(t *testing.T) {
	ops, err := api.Operations()
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) == 0 {
		t.Fatal("the contract operation registry is empty — this check would be vacuously green")
	}
	var eligible []string
	for id, op := range ops {
		if slices.Contains(op.Artifacts, api.ArtifactInstanceCredential) {
			eligible = append(eligible, id)
		}
	}
	if len(eligible) != 1 || eligible[0] != "serveDirectory" {
		t.Fatalf("instance-credential operations = %v, want exactly [serveDirectory]", eligible)
	}
	if got := ops["serveDirectory"].AuthzOp; got != string(authz.OpRemoteDirectoryServe) {
		t.Fatalf("serveDirectory maps to %q, want %q", got, authz.OpRemoteDirectoryServe)
	}
}

// Eligibility must be declared per ARTIFACT CLASS PER WIRE OPERATION, not
// derived from the formula. The ADR is explicit about why: "a future operation reusing the
// `instance-directory` formula does NOT widen what this credential reaches."
//
// This is the test that would catch someone re-deriving eligibility from the
// capability — it registers no new operation and touches no production table,
// it simply asserts that sharing the formula is not sufficient. If a second
// `instance-directory` operation is ever added and this test starts failing,
// the OpenAPI declaration is what must be reviewed, not this assertion.
func TestSharingTheDirectoryFormulaDoesNotWidenTheCredential(t *testing.T) {
	formulas := authz.RegistryFacts{}.Formulas()
	ops, err := api.Operations()
	if err != nil {
		t.Fatal(err)
	}

	var sharing []authz.Operation
	for op, formula := range formulas {
		for _, atom := range formula {
			if atom.Cap == domain.CapInstanceDirector {
				sharing = append(sharing, op)
				break
			}
		}
	}
	if len(sharing) == 0 {
		t.Fatal("no operation carries instance-directory — the confinement has nothing to confine")
	}

	for _, op := range sharing {
		if op == authz.OpRemoteDirectoryServe {
			continue
		}
		for id, contractOp := range ops {
			if authz.Operation(contractOp.AuthzOp) != op {
				continue
			}
			if slices.Contains(contractOp.Artifacts, api.ArtifactInstanceCredential) {
				t.Errorf("%s shares the instance-directory formula and became reachable by the "+
					"instance-connection credential — eligibility must be per-artifact-per-operation, "+
					"never derived from the formula", id)
			}
		}
	}
}

// Every HTTP route in OpenAPI is confined by that exact operation's artifact
// declaration, including account-security and self-scoped routes that mint no
// authorization proof. Only operational routes outside OpenAPI need a pin.
// This keeps the runtime invariant fail-closed without a parallel eligibility
// table: adding a contract route or changing its declaration needs no Go edit.
func TestEveryRouteIsConfinedByOpenAPIOrPinnedAsOperational(t *testing.T) {
	pinned := map[string]bool{
		"http:GET /healthz": true,
		"http:GET /metrics": true,
		"http:GET /readyz":  true,
	}

	ops, err := api.Operations()
	if err != nil {
		t.Fatal(err)
	}
	contractRoutes := make(map[string]api.Operation, len(ops))
	for _, op := range ops {
		contractRoutes["http:"+strings.ToUpper(op.Method)+" "+op.Path] = op
	}

	routes := authz.RegistryFacts{}.WireRoutes()
	wire := authz.RegistryFacts{}.Wire()
	if len(wire) == 0 {
		t.Fatal("the wire registry is empty — this check would be vacuously green")
	}
	seen := map[string]bool{}
	for route := range wire {
		if !strings.HasPrefix(route, "http:") {
			continue // CLI verbs reach the chokepoint through the same operations.
		}
		if op, described := contractRoutes[route]; described {
			if op.AdmitsArtifact(api.ArtifactInstanceCredential) && op.ID != "serveDirectory" {
				t.Errorf("%s admits instance-credential outside serveDirectory", route)
			}
			if pinned[route] {
				t.Errorf("%s is now described by OpenAPI and must leave the operational pin", route)
			}
			continue
		}
		if len(routes[route]) > 0 {
			t.Errorf("%s maps to authorization operations but has no OpenAPI operation", route)
			continue
		}
		seen[route] = true
		if !pinned[route] {
			t.Errorf("%s is in the wire registry but absent from OpenAPI and the operational pin", route)
		}
	}
	for route := range pinned {
		if !seen[route] {
			t.Errorf("%s is pinned as operation-less but is not in the wire registry "+
				"(renamed or removed) — a stale pin hides the next route that needs review", route)
		}
	}
}
