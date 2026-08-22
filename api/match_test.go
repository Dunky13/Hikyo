package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
)

// countingRouter counts contract route lookups. The admission path's cost is
// not a detail: every lookup is a second chance for two matches to disagree
// about which operation a request is, and the artifact allowlist is decided
// from that row.
type countingRouter struct {
	inner routers.Router
	calls int
}

func (c *countingRouter) FindRoute(r *http.Request) (*routers.Route, map[string]string, error) {
	c.calls++
	return c.inner.FindRoute(r)
}

type fixedRouter struct {
	route *routers.Route
}

func (f fixedRouter) FindRoute(*http.Request) (*routers.Route, map[string]string, error) {
	return f.route, nil, nil
}

// withCountingRouter swaps the package router for a counting wrapper. The
// document is loaded FIRST: loadOnce would otherwise overwrite the wrapper.
func withCountingRouter(t *testing.T) *countingRouter {
	t.Helper()
	if _, err := Doc(); err != nil {
		t.Fatalf("load the embedded contract: %v", err)
	}
	counting := &countingRouter{inner: router}
	previous := router
	router = counting
	t.Cleanup(func() { router = previous })
	return counting
}

// TestMatchRequestResolvesTheContractRouteExactlyOnce pins the public match
// seam to one underlying router lookup. The server test separately proves its
// admission middleware calls this seam once.
func TestMatchRequestResolvesTheContractRouteExactlyOnce(t *testing.T) {
	counting := withCountingRouter(t)

	req := httptest.NewRequest(http.MethodPost, PathPrefix+"/orgs",
		strings.NewReader(`{"name":"acme"}`))
	req.Header.Set("Content-Type", "application/json")

	match, err := MatchRequest(req)
	if err != nil {
		t.Fatalf("createOrg did not resolve through the embedded contract: %v", err)
	}
	op := match.Operation()
	if op.ID != "createOrg" {
		t.Fatalf("operation id = %q, want createOrg", op.ID)
	}
	if IsSCIMWireOperation(op.ID) {
		t.Fatal("createOrg classified as a SCIM wire operation")
	}
	validated, err := match.Validate()
	if err != nil {
		t.Fatalf("a contract-conforming request was refused: %v", err)
	}
	admitted := validated.Request()
	if admitted.URL.Path != req.URL.Path {
		t.Fatalf("validated request path = %q, want original %q", admitted.URL.Path, req.URL.Path)
	}
	attached, ok := OperationFromContext(admitted.Context())
	if !ok {
		t.Fatal("the matched operation was not attached to the request context")
	}
	if attached.ID != op.ID {
		t.Fatalf("attached operation = %q, want %q", attached.ID, op.ID)
	}

	if counting.calls != 1 {
		t.Fatalf("route lookups = %d, want 1", counting.calls)
	}
}

// TestMatchedOperationIsACopyOfTheImmutableRow pins that a caller holding a
// match cannot edit the artifact allowlist the next request is admitted by.
func TestMatchedOperationIsACopyOfTheImmutableRow(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, PathPrefix+"/orgs",
		strings.NewReader(`{"name":"acme"}`))
	req.Header.Set("Content-Type", "application/json")

	match, err := MatchRequest(req)
	if err != nil {
		t.Fatalf("createOrg did not resolve through the embedded contract: %v", err)
	}
	mutated := match.Operation()
	mutated.Artifacts[0] = "forged"

	fresh := match.Operation()
	if fresh.Artifacts[0] == "forged" {
		t.Fatal("editing a matched operation changed the row a later consumer reads")
	}
	validated, err := match.Validate()
	if err != nil {
		t.Fatalf("a contract-conforming request was refused: %v", err)
	}
	validatedCopy := validated.Operation()
	validatedCopy.Artifacts[0] = "forged"
	ctx := validated.Request().Context()
	originalRegistryRow := operations[fresh.ID]
	changedRegistryRow := cloneOperation(originalRegistryRow)
	changedRegistryRow.Artifacts[0] = "registry-forged"
	operations[fresh.ID] = changedRegistryRow
	t.Cleanup(func() { operations[fresh.ID] = originalRegistryRow })
	if attached, ok := OperationFromContext(ctx); !ok ||
		attached.Artifacts[0] == "forged" {
		t.Fatal("editing a returned operation changed the validated row attached to context")
	} else if attached.Artifacts[0] == "registry-forged" {
		t.Fatal("context re-read the registry instead of carrying the validated row")
	}
}

// TestMatchRequestRefusesAnUndescribedPath keeps the no-route refusal
// distinguishable from a malformed request: the server answers the first with
// 404 and the second with 400.
func TestMatchRequestRefusesAnUndescribedPath(t *testing.T) {
	counting := withCountingRouter(t)

	req := httptest.NewRequest(http.MethodGet, PathPrefix+"/nothing-here", nil)
	if _, err := MatchRequest(req); err != ErrNoRoute {
		t.Fatalf("error = %v, want ErrNoRoute", err)
	}
	if counting.calls != 1 {
		t.Fatalf("route lookups = %d, want 1", counting.calls)
	}
}

func TestMatchRequestFailsLoudOnContractInvariantBreak(t *testing.T) {
	if _, err := Doc(); err != nil {
		t.Fatalf("load the embedded contract: %v", err)
	}
	for name, route := range map[string]*routers.Route{
		"route without operation": {},
		"operation absent from registry": {
			Operation: &openapi3.Operation{OperationID: "notInRegistry"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			previous := router
			router = fixedRouter{route: route}
			t.Cleanup(func() { router = previous })

			_, err := MatchRequest(httptest.NewRequest(http.MethodGet, PathPrefix+"/meta", nil))
			if err == nil {
				t.Fatal("broken contract invariant was accepted")
			}
			if errors.Is(err, ErrNoRoute) {
				t.Fatalf("contract invariant error was downgraded to ErrNoRoute: %v", err)
			}
		})
	}
}

// TestZeroValidatedRequestReturnsNoRequest pins the in-process semantics: a
// value an out-of-package caller can construct cannot attach any operation.
func TestZeroValidatedRequestReturnsNoRequest(t *testing.T) {
	var zero ValidatedRequest
	if zero.Request() != nil {
		t.Fatal("a zero-value validation result returned an admitted request")
	}
}
