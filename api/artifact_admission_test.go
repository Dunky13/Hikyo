package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestOperationForDerivesArtifactEligibilityFromEmbeddedContract(t *testing.T) {
	req := &http.Request{
		Method: http.MethodGet,
		URL: &url.URL{Path: PathPrefix +
			"/orgs/org_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0fee/projects/" +
			"prj_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0fdd/environments/" +
			"env_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0fcc/values"},
		Header: http.Header{},
	}
	op, ok := OperationFor(req)
	if !ok {
		t.Fatal("embedded contract did not resolve the values-list operation")
	}
	if op.ID != "listValues" {
		t.Fatalf("operation id = %q, want listValues", op.ID)
	}
	if len(op.Artifacts) != 1 || op.Artifacts[0] != "human-session" {
		t.Fatalf("artifact eligibility = %v, want [human-session]", op.Artifacts)
	}
}

func TestAuthorizationOperationArtifactEligibilityDerivesFromEmbeddedContract(t *testing.T) {
	tests := []struct {
		operation string
		artifact  string
		want      bool
	}{
		{"remote.directory-serve", ArtifactInstanceCredential, true},
		{"remote.list", ArtifactInstanceCredential, false},
		{"delivery.fetch", ArtifactMachineCredential, true},
		{"delivery.fetch", ArtifactHumanSession, false},
	}
	for _, tt := range tests {
		t.Run(tt.operation+"/"+tt.artifact, func(t *testing.T) {
			got, described := AuthorizationOperationAdmitsArtifact(tt.operation, tt.artifact)
			if !described {
				t.Fatalf("authorization operation %q is absent from embedded contract", tt.operation)
			}
			if got != tt.want {
				t.Fatalf("admitted = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestCollectOperationsRejectsMissingOrEmptyArtifactEligibility(t *testing.T) {
	const base = `
openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /api/v1/test:
    get:
      operationId: testOperation
      x-hikyo-class: tenant
      ARTIFACTS
      x-hikyo-min-revision: 1
      responses:
        "200": {description: ok}
`
	for name, declaration := range map[string]string{
		"missing": "",
		"empty":   "x-hikyo-artifacts: []",
	} {
		t.Run(name, func(t *testing.T) {
			loader := &openapi3.Loader{IsExternalRefsAllowed: false}
			doc, err := loader.LoadFromData([]byte(strings.Replace(base, "ARTIFACTS", declaration, 1)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := collectOperations(doc); err == nil || !strings.Contains(err.Error(), "x-hikyo-artifacts") {
				t.Fatalf("collect operations error = %v, want named artifact declaration refusal", err)
			}
		})
	}
}
