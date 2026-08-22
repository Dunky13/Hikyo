package api_test

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api"
)

// The contract's own well-formedness. Cross-checks against the authorization
// and audit registries live in internal/isolation, which may import both
// sides; this package stays importable by anything.

func TestDocumentLoadsAndValidates(t *testing.T) {
	doc, err := api.Doc()
	if err != nil {
		t.Fatalf("contract does not load: %v", err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.1") {
		t.Fatalf("contract is %q, the bound profile is 3.1", doc.OpenAPI)
	}
}

func TestAdapterTargetUpdateDeclaresInPlaceAndMoveResponses(t *testing.T) {
	doc, err := api.Doc()
	if err != nil {
		t.Fatal(err)
	}
	operation := doc.Paths.Find("/api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}").Patch
	if operation == nil || operation.Responses.Status(http.StatusOK) == nil || operation.Responses.Status(http.StatusAccepted) == nil {
		t.Fatalf("adapter target PATCH must expose 200 AdapterTarget and 202 AdapterMove")
	}
}

func TestAdapterTargetSchemaCarriesPendingConflictArtifacts(t *testing.T) {
	doc, err := api.Doc()
	if err != nil {
		t.Fatal(err)
	}
	schema := doc.Components.Schemas["AdapterTarget"].Value
	if schema == nil || schema.Properties["conflicts"] == nil || !slices.Contains(schema.Required, "conflicts") {
		t.Fatalf("AdapterTarget must require pending conflict artifacts")
	}
}

func TestCollectedRevisionOperationsDeclareConflict(t *testing.T) {
	doc, err := api.Doc()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/orgs/{org}/projects/{project}/environments/{environment}/delivery"},
		{http.MethodPost, "/api/v1/orgs/{org}/projects/{project}/environments/{environment}/revisions/{revision}/rollback"},
		{http.MethodPost, "/api/v1/orgs/{org}/projects/{project}/environments/{environment}/pins"},
		{http.MethodGet, "/api/v1/orgs/{org}/projects/{project}/environments/{environment}/revisions/{revision}"},
		{http.MethodPost, "/api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/export"},
	}
	for _, tc := range tests {
		item := doc.Paths.Find(tc.path)
		if item == nil {
			t.Errorf("%s %s is missing", tc.method, tc.path)
			continue
		}
		op := item.Get
		if tc.method == http.MethodPost {
			op = item.Post
		}
		if op == nil || op.Responses.Value("409") == nil || op.Responses.Value("409").Ref != "#/components/responses/Conflict" {
			t.Errorf("%s %s does not declare the shared Conflict response", tc.method, tc.path)
		}
	}
}

func TestBoundProfile(t *testing.T) {
	if err := api.CheckProfile(api.SpecYAML); err != nil {
		t.Fatalf("contract violates the bound 3.1 profile:\n%v", err)
	}
}

// The profile check has to fail on each prohibited construct, or it is
// decoration. Every case is a minimal document that differs from a conforming
// one by exactly the prohibited thing.
func TestBoundProfileRefusals(t *testing.T) {
	const conforming = `
openapi: 3.1.0
jsonSchemaDialect: https://spec.openapis.org/oas/3.1/dialect/base
info: {title: t, version: "1"}
paths: {}
components:
  schemas:
    Ok: {type: string}
`
	if err := api.CheckProfile([]byte(conforming)); err != nil {
		t.Fatalf("control document rejected, so the refusals below prove nothing: %v", err)
	}

	cases := map[string]struct{ doc, want string }{
		"legacy nullable": {`
openapi: 3.1.0
jsonSchemaDialect: https://spec.openapis.org/oas/3.1/dialect/base
info: {title: t, version: "1"}
paths: {}
components:
  schemas:
    Bad: {type: string, nullable: true}
`, "nullable"},
		"alternate dialect": {`
openapi: 3.1.0
jsonSchemaDialect: https://json-schema.org/draft/2019-09/schema
info: {title: t, version: "1"}
paths: {}
`, "jsonSchemaDialect"},
		"absent dialect": {`
openapi: 3.1.0
info: {title: t, version: "1"}
paths: {}
`, "jsonSchemaDialect"},
		"top-level webhooks": {`
openapi: 3.1.0
jsonSchemaDialect: https://spec.openapis.org/oas/3.1/dialect/base
info: {title: t, version: "1"}
paths: {}
webhooks:
  onThing:
    post: {responses: {"200": {description: ok}}}
`, "webhooks"},
		"3.0 document": {`
openapi: 3.0.3
jsonSchemaDialect: https://spec.openapis.org/oas/3.1/dialect/base
info: {title: t, version: "1"}
paths: {}
`, "3.1"},
		"open enum that also closes itself": {`
openapi: 3.1.0
jsonSchemaDialect: https://spec.openapis.org/oas/3.1/dialect/base
info: {title: t, version: "1"}
paths: {}
components:
  schemas:
    Bad:
      type: string
      enum: [a, b]
      x-extensible-enum: [a, b]
`, "x-extensible-enum"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := api.CheckProfile([]byte(tc.doc))
			if err == nil {
				t.Fatal("prohibited construct accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal does not name %q: %v", tc.want, err)
			}
		})
	}
}

func TestEveryOperationCarriesItsContractExtensions(t *testing.T) {
	ops, err := api.Operations()
	if err != nil {
		t.Fatalf("contract registry: %v", err)
	}
	if len(ops) == 0 {
		t.Fatal("contract has no operations")
	}
	validClasses := map[string]bool{
		"tenant": true, "instance": true, "unauthenticated": true, "system": true,
	}
	validArtifacts := map[string]bool{
		"none": true, "human-session": true, "machine-credential": true,
		"instance-credential": true, "local": true,
		// `scim-credential` is the SCIM provisioning connection's own artifact
		// class (#73 §7): the machine-identities ADR's closed token-type list
		// gains `scim` by the scim-provisioning amendment, and this is that
		// type's eligibility name.
		//
		// It stays SEPARATE from `machine-credential` now that #61 has landed.
		// #61 serves the service-account taxonomy — `wl`/`au` values against
		// service-account rows, minted under the environment-keyed disclosure
		// and reauthentication conjuncts — and it declares that class on NO
		// route (isolation.TestContractSecuredOperationsTakeAnArtifact still
		// refuses it, and still passes). A provisioning connection is a
		// different principal class with a different formula, a different
		// lifetime story and a different mint ceremony; collapsing the two
		// eligibility names would say the SCIM wire accepts a service-account
		// token, which it does not.
		"scim-credential": true,
	}
	for id, op := range ops {
		if !validClasses[op.Class] {
			t.Errorf("%s: unknown probe class %q", id, op.Class)
		}
		if op.MinRevision < 1 || op.MinRevision > api.Revision {
			t.Errorf("%s: x-hikyo-min-revision %d is outside [1,%d] — an operation cannot require a revision this server does not serve",
				id, op.MinRevision, api.Revision)
		}
		if len(op.Artifacts) == 0 {
			t.Errorf("%s: empty artifact eligibility set", id)
		}
		for _, a := range op.Artifacts {
			if !validArtifacts[a] {
				t.Errorf("%s: unknown artifact class %q", id, a)
			}
		}
		if !strings.HasPrefix(op.Path, api.PathPrefix+"/") {
			t.Errorf("%s: path %q is outside the version prefix", id, op.Path)
		}
		// An operation that names an authz operation must state its formula,
		// and one that names none must not: the pair is the behavioural half
		// of the freeze promise, recorded per operation.
		if (op.AuthzOp == "") != (len(op.Formula) == 0) {
			t.Errorf("%s: x-hikyo-operation and x-hikyo-formula must be present together (op=%q formula=%v)",
				id, op.AuthzOp, op.Formula)
		}
		// A pre-authentication path takes no artifact, and an artifact-taking
		// path must actually be secured — otherwise the matrix is decorative.
		if op.Secured && len(op.Artifacts) == 1 && op.Artifacts[0] == "none" {
			t.Errorf("%s: secured but declares artifact eligibility `none`", id)
		}
		if !op.Secured && op.AuthzOp != "" {
			t.Errorf("%s: reaches authz operation %q with the security requirement cleared", id, op.AuthzOp)
		}
	}
}

func TestBearerAdmittingOperationsDeclareArtifactRefusal(t *testing.T) {
	doc, err := api.Doc()
	if err != nil {
		t.Fatal(err)
	}
	ops, err := api.Operations()
	if err != nil {
		t.Fatal(err)
	}
	for path, item := range doc.Paths.Map() {
		for method, operation := range item.Operations() {
			row := ops[operation.OperationID]
			admitsBearer := false
			for _, artifact := range row.Artifacts {
				if artifact != api.ArtifactNone {
					admitsBearer = true
					break
				}
			}
			if admitsBearer && operation.Responses.Status(http.StatusNotFound) == nil {
				t.Errorf("%s %s (%s) admits an authenticated artifact but does not declare the uniform 404 class-mismatch response",
					method, path, operation.OperationID)
			}
		}
	}
}

func TestRequestValidationRefusesUnknownMembers(t *testing.T) {
	// `additionalProperties: false` on every request body is the fail-fast
	// rule at the wire: an unknown member is a client that believes something
	// untrue about this server, and silently dropping it hides that.
	req := httptest.NewRequest(http.MethodPost, api.PathPrefix+"/orgs",
		bytes.NewReader([]byte(`{"name":"acme","typo":true}`)))
	req.Header.Set("Content-Type", "application/json")
	var verr *api.ValidationError
	_, err := api.ValidateRequest(req)
	if !errors.As(err, &verr) {
		t.Fatalf("unknown member accepted: %v", err)
	}
}

func TestRequestValidationAcceptsAbsentNullAndValue(t *testing.T) {
	// The 3.1 nullability round-trip the amendment banner demands: for a
	// `type: [object, "null"]` member, all three states are accepted and
	// distinguishable.
	for name, body := range map[string]string{
		"absent": `{"name":"acme"}`,
		"null":   `{"name":"acme","metadata":null}`,
		"value":  `{"name":"acme","metadata":{"team":"platform"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, api.PathPrefix+"/orgs",
				bytes.NewReader([]byte(body)))
			req.Header.Set("Content-Type", "application/json")
			if _, err := api.ValidateRequest(req); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

func TestRequestValidationReportsTheOffendingMember(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, api.PathPrefix+"/auth/local/login",
		bytes.NewReader([]byte(`{"username":"","password":"x"}`)))
	req.Header.Set("Content-Type", "application/json")
	var verr *api.ValidationError
	if _, err := api.ValidateRequest(req); !errors.As(err, &verr) {
		t.Fatal("empty username accepted")
	}
	if verr.Member != "username" {
		t.Fatalf("member = %q, want username", verr.Member)
	}
}

func TestUnroutedRequestIsDistinguishableFromMalformed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, api.PathPrefix+"/nothing-here", nil)
	if _, err := api.ValidateRequest(req); !errors.Is(err, api.ErrNoRoute) {
		t.Fatal("an undescribed path must be reported as unrouted, not as a bad body")
	}
}

// The embedded copy is what the server enforces; the file on disk is what CI
// diffs and what the TypeScript generator reads. They cannot be allowed to
// differ.
func TestEmbeddedSpecMatchesTheFileOnDisk(t *testing.T) {
	onDisk, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	if !bytes.Equal(onDisk, api.SpecYAML) {
		t.Fatal("the embedded contract differs from api/openapi.yaml")
	}
}
