package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api"
)

// admitted runs a request through the contract-admission middleware and
// reports the response plus the operation the handler saw, so the admission
// boundary is pinned from outside: what reaches a handler, and under which
// contract row.
func admitted(t *testing.T, r *http.Request) (*httptest.ResponseRecorder, api.Operation, bool) {
	t.Helper()
	var (
		reached   bool
		operation api.Operation
		attached  bool
	)
	next := http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		reached = true
		operation, attached = api.OperationFromContext(req.Context())
	})
	rec := httptest.NewRecorder()
	(&API{}).validateAgainstContract(next).ServeHTTP(rec, r)
	if !reached {
		return rec, api.Operation{}, false
	}
	if !attached {
		t.Fatal("an admitted request reached the handler with no contract operation")
	}
	return rec, operation, true
}

func TestAdmissionAttachesTheMatchedOperation(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, api.PathPrefix+"/orgs",
		strings.NewReader(`{"name":"acme"}`))
	req.Header.Set("Content-Type", "application/json")

	rec, operation, reached := admitted(t, req)
	if !reached {
		t.Fatalf("a contract-conforming request was refused: %d %s", rec.Code, rec.Body)
	}
	if operation.ID != "createOrg" {
		t.Fatalf("operation id = %q, want createOrg", operation.ID)
	}
	if len(operation.Artifacts) == 0 {
		t.Fatal("the attached operation carries no artifact allowlist")
	}
}

func TestAdmissionCallsTheRouteMatcherExactlyOnce(t *testing.T) {
	calls := 0
	matcher := func(r *http.Request) (*api.MatchedRequest, error) {
		calls++
		return api.MatchRequest(r)
	}
	reached := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, api.PathPrefix+"/orgs",
		strings.NewReader(`{"name":"acme"}`))
	req.Header.Set("Content-Type", "application/json")

	(&API{}).validateAgainstContractWith(matcher, next).ServeHTTP(rec, req)

	if !reached {
		t.Fatalf("a contract-conforming request was refused: %d %s", rec.Code, rec.Body)
	}
	if calls != 1 {
		t.Fatalf("route matcher calls = %d, want 1", calls)
	}
}

func TestAdmissionRendersMatcherInvariantFailureAsInternal(t *testing.T) {
	matcher := func(*http.Request) (*api.MatchedRequest, error) {
		return nil, errors.New("broken contract registry")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, api.PathPrefix+"/meta", nil)

	(&API{}).validateAgainstContractWith(matcher, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("matcher invariant failure reached the handler")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "internal") {
		t.Fatalf("body = %s, want the uniform internal refusal", rec.Body)
	}
}

func TestAdmissionRefusesAnUndescribedPathAsNotFound(t *testing.T) {
	rec, _, reached := admitted(t, httptest.NewRequest(http.MethodGet, api.PathPrefix+"/nothing-here", nil))
	if reached {
		t.Fatal("an undescribed path reached a handler")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not_found") {
		t.Fatalf("body = %s, want the uniform not_found refusal", rec.Body)
	}
}

func TestAdmissionRefusesAMalformedRequestNamingTheMember(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, api.PathPrefix+"/auth/local/login",
		strings.NewReader(`{"username":"","password":"x"}`))
	req.Header.Set("Content-Type", "application/json")

	rec, _, reached := admitted(t, req)
	if reached {
		t.Fatal("a malformed request reached a handler")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "username") {
		t.Fatalf("body = %s, want the offending member named", rec.Body)
	}
}

func TestAdmissionRefusesAnOverBoundBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, api.PathPrefix+"/orgs",
		strings.NewReader(`{"name":"`+strings.Repeat("a", MaxRequestBytes+1)+`"}`))
	req.Header.Set("Content-Type", "application/json")

	rec, _, reached := admitted(t, req)
	if reached {
		t.Fatal("an over-bound body reached a handler")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
