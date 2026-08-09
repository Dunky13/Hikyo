package api_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Dunky13/wenv/api"
)

func TestSAMLContractSurfaceIsLocked(t *testing.T) {
	ops, err := api.Operations()
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]struct {
		method  string
		path    string
		class   string
		authzOp string
	}{
		"samlStart":                   {http.MethodPost, "/api/v1/auth/saml/{provider}/start", "unauthenticated", ""},
		"samlACS":                     {http.MethodPost, "/api/v1/auth/saml/{provider}/acs", "unauthenticated", ""},
		"samlMetadata":                {http.MethodGet, "/api/v1/auth/saml/{provider}/metadata", "unauthenticated", ""},
		"listSamlProviders":           {http.MethodGet, "/api/v1/instance/saml-providers", "instance", "saml-provider.list"},
		"getSamlProvider":             {http.MethodGet, "/api/v1/instance/saml-providers/{slug}", "instance", "saml-provider.get"},
		"putSamlProvider":             {http.MethodPut, "/api/v1/instance/saml-providers/{slug}", "instance", "saml-provider.put"},
		"patchSamlProvider":           {http.MethodPatch, "/api/v1/instance/saml-providers/{slug}", "instance", "saml-provider.patch"},
		"deleteSamlProvider":          {http.MethodDelete, "/api/v1/instance/saml-providers/{slug}", "instance", "saml-provider.delete"},
		"refreshSamlProviderMetadata": {http.MethodPost, "/api/v1/instance/saml-providers/{slug}/refresh-metadata", "instance", "saml-provider.refresh-metadata"},
		"listSamlSpKeys":              {http.MethodGet, "/api/v1/instance/saml-sp-keys", "instance", "saml-sp-key.list"},
		"rotateSamlSpKey":             {http.MethodPost, "/api/v1/instance/saml-sp-keys/rotate", "instance", "saml-sp-key.rotate"},
		"retireSamlSpKey":             {http.MethodDelete, "/api/v1/instance/saml-sp-keys/{fingerprint}", "instance", "saml-sp-key.retire"},
		"compromiseRetireSamlSpKey":   {http.MethodPost, "/api/v1/instance/saml-sp-keys/{fingerprint}/compromise-retire", "instance", "saml-sp-key.compromise-retire"},
	}
	for id, expected := range want {
		op, ok := ops[id]
		if !ok {
			t.Errorf("missing operation %q", id)
			continue
		}
		if op.Method != expected.method || op.Path != expected.path || op.Class != expected.class || op.AuthzOp != expected.authzOp {
			t.Errorf("%s = %s %s class=%q authz=%q, want %s %s class=%q authz=%q",
				id, op.Method, op.Path, op.Class, op.AuthzOp,
				expected.method, expected.path, expected.class, expected.authzOp)
		}
	}
	var gotIDs []string
	for id, op := range ops {
		if strings.Contains(op.Path, "/saml") || strings.HasPrefix(op.AuthzOp, "saml-provider.") {
			gotIDs = append(gotIDs, id)
		}
	}
	slices.Sort(gotIDs)
	wantIDs := make([]string, 0, len(want))
	for id := range want {
		wantIDs = append(wantIDs, id)
	}
	slices.Sort(wantIDs)
	if !slices.Equal(gotIDs, wantIDs) {
		t.Errorf("SAML operation IDs = %v, want exact locked surface %v", gotIDs, wantIDs)
	}
	for _, id := range []string{"samlStart", "samlACS"} {
		op := ops[id]
		if !slices.Contains(op.Artifacts, "none") || !slices.Contains(op.Artifacts, "human-session") {
			t.Errorf("%s artifact eligibility = %v, want anonymous login plus session-bound link/reauth", id, op.Artifacts)
		}
	}
	doc, err := api.Doc()
	if err != nil {
		t.Fatal(err)
	}
	start := doc.Paths.Find("/api/v1/auth/saml/{provider}/start").Post
	if start.Security == nil || len(*start.Security) != 2 {
		t.Fatalf("SAML start security = %v, want anonymous or bearer session", start.Security)
	}
	acs := doc.Paths.Find("/api/v1/auth/saml/{provider}/acs").Post
	if acs.Security == nil || len(*acs.Security) != 0 {
		t.Fatalf("SAML ACS security = %v, want no bearer requirement", acs.Security)
	}
}

func TestSAMLProviderPatchPreservesOmittedFields(t *testing.T) {
	doc, err := api.Doc()
	if err != nil {
		t.Fatal(err)
	}
	schema, ok := doc.Components.Schemas["SamlProviderPatch"]
	if !ok || schema.Value == nil {
		t.Fatal("missing SamlProviderPatch schema")
	}
	if len(schema.Value.Required) != 0 {
		t.Fatalf("patch requires %v; omitted members must preserve stored values", schema.Value.Required)
	}
	for _, member := range []string{"display_name", "assurance_policy", "allow_email_nameid", "force_sign_requests", "enabled"} {
		if _, ok := schema.Value.Properties[member]; !ok {
			t.Errorf("patch cannot update %q", member)
		}
	}
	for _, forbidden := range []string{"entity_id", "metadata_source", "metadata_document", "metadata_url", "jit_policy"} {
		if _, ok := schema.Value.Properties[forbidden]; ok {
			t.Errorf("patch exposes immutable, ceremony-owned or forbidden member %q", forbidden)
		}
	}
}

func TestSAMLProviderInputHasNoJITSurface(t *testing.T) {
	doc, err := api.Doc()
	if err != nil {
		t.Fatal(err)
	}
	schema, ok := doc.Components.Schemas["SamlProviderInput"]
	if !ok || schema.Value == nil {
		t.Fatal("missing SamlProviderInput schema")
	}
	for _, forbidden := range []string{"jit", "jit_policy", "jit_provision"} {
		if _, exists := schema.Value.Properties[forbidden]; exists {
			t.Errorf("SamlProviderInput exposes forbidden SAML JIT field %q", forbidden)
		}
	}
	if _, ok := schema.Value.Properties["entity_id"]; !ok {
		t.Error("SamlProviderInput cannot name the exact entityID selected from aggregate metadata")
	}
	foundRequired := false
	for _, member := range schema.Value.Required {
		foundRequired = foundRequired || member == "entity_id"
	}
	if !foundRequired {
		t.Error("entity_id is optional; aggregate metadata selection would be ambiguous")
	}
}

func TestSAMLProviderWarningsAreRequiredAndClosed(t *testing.T) {
	doc, err := api.Doc()
	if err != nil {
		t.Fatal(err)
	}
	provider := doc.Components.Schemas["SamlProvider"]
	if provider == nil || provider.Value == nil {
		t.Fatal("missing SamlProvider schema")
	}
	if !slices.Contains(provider.Value.Required, "warnings") {
		t.Fatal("SamlProvider warnings are optional; clients could silently hide provider health")
	}
	warning := doc.Components.Schemas["SamlProviderWarning"]
	if warning == nil || warning.Value == nil {
		t.Fatal("missing SamlProviderWarning schema")
	}
	code := warning.Value.Properties["code"]
	if code == nil || code.Value == nil {
		t.Fatal("warning code is not typed")
	}
	want := []any{"metadata_expires_soon", "metadata_expired", "signing_certificate_not_yet_valid", "signing_certificate_expired"}
	if !slices.Equal(code.Value.Enum, want) {
		t.Fatalf("warning codes = %v, want closed %v", code.Value.Enum, want)
	}
}

func TestSAMLACSAcceptsOnlyThePOSTBinding(t *testing.T) {
	doc, err := api.Doc()
	if err != nil {
		t.Fatal(err)
	}
	item := doc.Paths.Find("/api/v1/auth/saml/{provider}/acs")
	if item == nil || item.Post == nil {
		t.Fatal("missing POST ACS operation")
	}
	if item.Get != nil || item.Put != nil || item.Patch != nil || item.Delete != nil {
		t.Fatal("ACS exposes a binding other than HTTP-POST")
	}
	body := item.Post.RequestBody
	if body == nil || body.Value == nil || body.Value.Content.Get("application/x-www-form-urlencoded") == nil {
		t.Fatal("ACS does not consume application/x-www-form-urlencoded")
	}
}

func TestSAMLMetadataUsesTheSAMLMetadataMediaType(t *testing.T) {
	doc, err := api.Doc()
	if err != nil {
		t.Fatal(err)
	}
	item := doc.Paths.Find("/api/v1/auth/saml/{provider}/metadata")
	if item == nil || item.Get == nil {
		t.Fatal("missing GET metadata operation")
	}
	response := item.Get.Responses.Value("200")
	if response == nil || response.Value == nil || response.Value.Content.Get("application/samlmetadata+xml") == nil {
		t.Fatal("metadata response does not use application/samlmetadata+xml")
	}
}

func TestSAMLMetadataMutationsReturnAConfirmationDiff(t *testing.T) {
	doc, err := api.Doc()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/api/v1/instance/saml-providers/{slug}",
		"/api/v1/instance/saml-providers/{slug}/refresh-metadata",
	} {
		item := doc.Paths.Find(path)
		if item == nil {
			t.Fatalf("missing %s", path)
		}
		op := item.Put
		if op == nil {
			op = item.Post
		}
		response := op.Responses.Value("200")
		media := response.Value.Content.Get("application/json")
		if media == nil || media.Schema == nil || media.Schema.Ref != "#/components/schemas/SamlProviderMutationResult" {
			t.Errorf("%s cannot return the typed diff-and-confirm ceremony", path)
		}
	}
}
