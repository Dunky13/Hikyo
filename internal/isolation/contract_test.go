package isolation

import (
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/Dunky13/wenv/api"
	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/domain"
)

// The contract cross-check.
//
// api/openapi.yaml records, per operation, the probe class, the authz
// operation it reaches, that operation's formula, and its artifact
// eligibility. The api-cli-surface ADR says the behavioural half of the
// freeze promise "rests on review of a hand-written spec" — and it does, but
// the parts a machine CAN check must be checked, or the document quietly
// becomes a description of a system that no longer exists.
//
// What this proves: the document and the Go registries describe the same
// authorization posture. What it cannot prove: that either of them is the
// posture the ADR intended. That remains review, stated as such.

var classNames = map[authz.Class]string{
	authz.ClassTenant:          "tenant",
	authz.ClassInstance:        "instance",
	authz.ClassUnauthenticated: "unauthenticated",
	authz.ClassSystem:          "system",
}

var levelNames = map[domain.Level]string{
	domain.LevelNone: "instance", domain.LevelOrg: "org",
	domain.LevelProject: "project", domain.LevelEnv: "environment",
}

// wireKey is how a contract operation appears in the wire registry.
func wireKey(method, path string) string { return "http:" + method + " " + path }

func TestContractRoutesMatchTheRouter(t *testing.T) {
	ops, err := api.Operations()
	if err != nil {
		t.Fatal(err)
	}
	wire := facts.Wire()
	for id, op := range ops {
		key := wireKey(op.Method, chiPath(op.Path))
		if _, ok := wire[key]; !ok {
			t.Errorf("contract operation %s (%s) has no wire-registry entry %q — either the route is missing or it is unclassified",
				id, op.ID, key)
		}
	}
	// And the other direction: an /api/v1 route the router serves but the
	// contract does not describe would be an unfrozen, un-contract-tested
	// authorization path — exactly the `/api/internal` shape the ADR rejected.
	described := map[string]bool{}
	for _, op := range ops {
		described[wireKey(op.Method, chiPath(op.Path))] = true
	}
	for key := range wire {
		if !strings.HasPrefix(key, "http:") {
			continue
		}
		_, route, _ := strings.Cut(key, " ")
		if !strings.HasPrefix(route, api.PathPrefix) {
			continue // health probes are not API
		}
		if !described[key] {
			t.Errorf("route %q is served but not described in api/openapi.yaml", key)
		}
	}
}

func TestContractClassesMatchTheWireRegistry(t *testing.T) {
	ops, err := api.Operations()
	if err != nil {
		t.Fatal(err)
	}
	wire := facts.Wire()
	for id, op := range ops {
		key := wireKey(op.Method, chiPath(op.Path))
		class, ok := wire[key]
		if !ok {
			continue // reported by TestContractRoutesMatchTheRouter
		}
		if got := classNames[class]; got != op.Class {
			t.Errorf("%s: contract says x-wenv-class %q, the wire registry says %q — the document describes an authorization posture the code does not have",
				id, op.Class, got)
		}
	}
}

func TestContractFormulasMatchTheOperationRegistry(t *testing.T) {
	ops, err := api.Operations()
	if err != nil {
		t.Fatal(err)
	}
	formulas := facts.Formulas()
	routes := facts.WireRoutes()
	for id, op := range ops {
		if op.AuthzOp == "" {
			continue
		}
		operation := authz.Operation(op.AuthzOp)
		formula, ok := formulas[operation]
		if !ok {
			t.Errorf("%s: contract names authz operation %q, which is not registered", id, op.AuthzOp)
			continue
		}
		want := make([]string, 0, len(formula))
		for _, atom := range formula {
			want = append(want, string(atom.Cap)+"@"+levelNames[atom.At])
		}
		got := append([]string(nil), op.Formula...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: contract records formula %v, the operation registry evaluates %v — the freeze promise covers behaviour, and this is where the two would silently diverge",
				id, got, want)
		}
		// The route→operation map must agree with the document, so the audit
		// completeness invariant and the contract cannot name different
		// operations for one route. A route that dispatches between operations
		// lists them all; the contract's single named operation must be one of
		// them.
		key := wireKey(op.Method, chiPath(op.Path))
		if mapped, ok := routes[key]; ok && !slices.Contains(mapped, operation) {
			t.Errorf("%s: the contract names %q but the route map names %v", id, operation, mapped)
		}
	}
}

func TestContractSecuredOperationsTakeAnArtifact(t *testing.T) {
	ops, err := api.Operations()
	if err != nil {
		t.Fatal(err)
	}
	for id, op := range ops {
		// Every verb declares its eligible artifact set as a closed matrix.
		// This slice ships human sessions only; a machine-credential entry
		// appearing here without the machine-identity surface behind it would
		// be a promise nothing keeps.
		for _, artifact := range op.Artifacts {
			if artifact == "machine-credential" {
				t.Errorf("%s declares machine-credential eligibility, which no code serves yet (#61)", id)
			}
		}
		if op.Secured && len(op.Artifacts) == 1 && op.Artifacts[0] == "none" {
			t.Errorf("%s: secured but eligible for no artifact", id)
		}
	}
}

// chiPath converts an OpenAPI path template to chi's spelling. They agree
// today ({org} in both); the conversion exists so a divergence is a compile
// -level concern in one place rather than a silent mismatch in every test.
func chiPath(p string) string {
	if strings.Contains(p, "{") && !strings.Contains(p, "}") {
		panic(fmt.Sprintf("malformed path template %q", p))
	}
	return p
}

// TestTenantRoutesDeclareForbiddenOnlyForMFA is the registry-aware half of the
// tenant-refusal contract, and it is an IFF in both directions.
//
// Grant refusal on a tenant-scoped operation is the uniform 404 — authorize()
// returns ErrNotFound there, so a declared 403 would either be dead or a leak.
// The one exception is the assurance leg: a caller who HOLDS an MFA-mandatory
// capability but presents a single-factor session is refused with
// ErrUnauthorized, deliberately, because they can already reach the object and
// hiding it would tell a capability holder it is missing. So:
//
//   - MFA-mandatory tenant operation  => 403 MUST be declared (the code can
//     produce it, and an undeclared status is a contract the server breaks).
//   - every other tenant operation    => 403 MUST NOT be declared (unreachable,
//     and declaring it invites a handler to start answering it).
func TestTenantRoutesDeclareForbiddenOnlyForMFA(t *testing.T) {
	ops, err := api.Operations()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := api.Doc()
	if err != nil {
		t.Fatal(err)
	}
	for id, op := range ops {
		if op.Class != "tenant" || op.AuthzOp == "" {
			continue
		}
		item := doc.Paths.Find(op.Path)
		if item == nil {
			t.Fatalf("%s: contract path %q vanished", id, op.Path)
		}
		operation := item.GetOperation(op.Method)
		if operation == nil || operation.Responses == nil {
			t.Fatalf("%s: no operation at %s %s", id, op.Method, op.Path)
		}
		declared := operation.Responses.Status(http.StatusForbidden) != nil
		wanted := authz.FormulaDemandsMFA(authz.Operation(op.AuthzOp))
		switch {
		case wanted && !declared:
			t.Errorf("%s is tenant-class with an MFA-mandatory formula (%v) but declares no 403 — the assurance refusal it can return is undeclared",
				id, op.Formula)
		case !wanted && declared:
			t.Errorf("%s (formula %v) is tenant-class and not MFA-mandatory but declares a 403 — grant refusal there is the uniform 404, so the status is unreachable or a leak",
				id, op.Formula)
		}
	}
}
