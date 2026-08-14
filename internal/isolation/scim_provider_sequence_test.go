package isolation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/scimproto"
	"github.com/Hikyo-Org/hikyo/internal/server"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// The captured-provider-sequence fixtures (#73 SC1).
//
// Everything else in this package asserts one layer. These drive the REAL HTTP
// mount with raw requests shaped the way Okta and Entra actually issue them:
// the discovery trio first, then the probe-before-write pattern both connectors
// follow, then CRUD, filters, paging and the closed refusals. A helper that
// shared code with the server would prove less than a request built the way a
// connector builds one, so the bodies here are literal maps and the paths are
// literal strings — including the URL-encoded filters.
//
// The tables are ordered STEP LISTS rather than independent cases, because a
// provisioning cycle is a conversation: the `displayName eq` probe that returns
// nothing and the create that follows it are one act, and a fixture that ran
// them in isolation would not notice if the probe stopped seeing what the
// create wrote.

// scimCall is one raw request against the provisioning mount.
type scimCall func(method, path string, body any) (int, map[string]any)

// wireOrg is the organisation these fixtures provision into. The harness's own
// `org_a` is a readable short id, and the API contract's `ID` schema requires a
// prefixed UUID — so a raw HTTP request naming `org_a` is refused by the
// contract layer before any SCIM code runs. Below-the-wire fixtures never meet
// that boundary; these ones exist to meet it.
const wireOrg = domain.OrgID("org_0198f000-0000-7000-8000-00000000000a")

// scimWireServer stands the production HTTP server up in front of one live
// binding and hands back the identity provider's view of it: the binding id,
// the mount's base URL (for the one fixture that must present a DIFFERENT
// binding's credential) and a raw-request function carrying this binding's own.
func scimWireServer(t *testing.T, db *store.DB, slug string) (string, string, scimCall) {
	t.Helper()
	return scimWireServerWithSubject(t, db, slug, domain.SubjectSourceExternalID)
}

// scimWireServerWithSubject is the same, with the binding's declared subject
// source chosen — which is also what declares its schema extension (§5.1).
func scimWireServerWithSubject(t *testing.T, db *store.DB, slug, subjectSource string) (string, string, scimCall) {
	t.Helper()
	// ONE Auth, built BEFORE anything else touches the datastore: each call
	// mints a fresh root key and lazily creates the key hierarchy, so a second
	// one cannot open the keyring this datastore already holds.
	auth := authService(t, db)
	svc := &service.SCIM{DB: db, Auth: auth}

	execRaw(t, db, `INSERT INTO orgs (id, name, active, metadata, created_at) VALUES `+
		`('`+string(wireOrg)+`', 'wire-org', TRUE, '{}', `+ts+`)`)
	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
		`VALUES ('g_oa_mm_wire', 'usr_orgadmin', 'manage-members', '`+string(wireOrg)+`', NULL, NULL, `+ts+`)`)
	execRaw(t, db, `INSERT INTO grant_origins (id, grant_id, kind, subject, created_at) `+
		`VALUES ('gor_g_oa_mm_wire', 'g_oa_mm_wire', 'manual', 'usr_orgadmin', `+ts+`)`)
	seedSCIMProvider(t, db, slug, "https://"+slug+".example.test", true)

	binding, err := svc.CreateBinding(t.Context(), service.LocalPrincipal(orgAdmin), wireOrg,
		service.SCIMBindingInput{
			ProviderKind: domain.ProviderOIDC, ProviderSlug: slug,
			SubjectSource: subjectSource,
		})
	if err != nil {
		t.Fatalf("binding create: %v", err)
	}
	mint, err := svc.MintCredential(t.Context(), service.LocalPrincipal(orgAdmin), wireOrg, binding.ID, false, "")
	if err != nil {
		t.Fatalf("credential mint: %v", err)
	}
	bindingID, token := binding.ID, mint.Token
	// The same construction production and the demo flow use: a hand-minimal
	// API would route around middleware the real one runs.
	srv := httptest.NewServer(server.New(&service.System{DB: db}, &server.API{
		Auth:         auth,
		Orgs:         &service.Orgs{DB: db},
		Projects:     &service.Projects{DB: db},
		Environments: &service.Environments{DB: db},
		Folders:      &service.Folders{DB: db},
		Grants:       &service.Grants{DB: db},
		SCIM:         svc,
		SCIMWire:     svc,
		Version:      "scim-sequence",
	}, nil))
	t.Cleanup(srv.Close)

	mount := srv.URL + api.PathPrefix + "/orgs/" + string(wireOrg) + "/scim/v2/"
	base := mount + bindingID
	call := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		return scimRawRequest(t, method, base+path, token, body)
	}
	return bindingID, mount, call
}

// scimRawRequest is one bearer-authenticated SCIM request, built the way a
// connector builds one rather than through a generated client.
func scimRawRequest(t *testing.T, method, url, token string, body any) (int, map[string]any) {
	t.Helper()
	status, _, decoded := scimRawResponse(t, method, url, token, body)
	return status, decoded
}

// scimRawResponse is the same, returning the response BYTES as they came off
// the socket. Comparing re-marshalled maps compares this test's encoder, not
// the server's: key order, whitespace, number formatting and duplicate members
// all vanish in the round trip, and those are exactly what "indistinguishable"
// has to cover.
func scimRawResponse(t *testing.T, method, url, token string, body any) (int, []byte, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		// Raw bytes pass through VERBATIM: the malformed-body fixtures need to
		// send bodies that are not valid JSON at all, which json.Marshal
		// cannot express.
		raw, verbatim := body.([]byte)
		if !verbatim {
			var err error
			raw, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", scimproto.MediaType)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return res.StatusCode, raw, out
}

// scimStep is one request in a captured sequence.
type scimStep struct {
	// Name is the connector's own word for what it is doing at this point.
	Name   string
	Method string
	// Path may name earlier steps' captured ids as {user}, {group}, … — the
	// connector substitutes ids it was handed, and so does this.
	Path string
	Body any
	Want int
	// Capture stores a field of the response under a name later steps can use.
	Capture map[string]string
	// Check is the step's own assertion, run only when the status matched.
	Check func(t *testing.T, body map[string]any, ids map[string]string)
}

// runSCIMSequence plays a captured sequence in order.
func runSCIMSequence(t *testing.T, call scimCall, steps []scimStep) map[string]string {
	t.Helper()
	ids := map[string]string{}
	for i, step := range steps {
		path := step.Path
		for name, value := range ids {
			path = strings.ReplaceAll(path, "{"+name+"}", value)
		}
		if strings.Contains(path, "{") {
			t.Fatalf("step %d (%s): unsubstituted placeholder in %q; known ids %v", i, step.Name, path, ids)
		}
		// Bodies name captured ids too — a connector PATCHes a group with the id
		// the create handed it. Substitution happens on the rendered JSON so the
		// literal maps above stay readable.
		payload := step.Body
		if payload != nil {
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			rendered := string(raw)
			for name, value := range ids {
				rendered = strings.ReplaceAll(rendered, "{"+name+"}", value)
			}
			payload = json.RawMessage(rendered)
		}
		status, body := call(step.Method, path, payload)
		if status != step.Want {
			t.Fatalf("step %d (%s): %s %s = %d, want %d\n  body: %v",
				i, step.Name, step.Method, path, status, step.Want, body)
		}
		for name, field := range step.Capture {
			v, ok := body[field].(string)
			if !ok || v == "" {
				t.Fatalf("step %d (%s): response carries no %q to capture: %v", i, step.Name, field, body)
			}
			ids[name] = v
		}
		if step.Check != nil {
			step.Check(t, body, ids)
		}
	}
	return ids
}

// ---------------------------------------------------------------------------
// Shared assertions
// ---------------------------------------------------------------------------

// wantList asserts the RFC 7644 ListResponse envelope by NAME — every field,
// not just the one the step cares about — plus the expected total and page.
func wantList(total, startIndex, itemsPerPage int) func(*testing.T, map[string]any, map[string]string) {
	return func(t *testing.T, body map[string]any, _ map[string]string) {
		t.Helper()
		schemas, _ := body["schemas"].([]any)
		if len(schemas) != 1 || schemas[0] != scimproto.SchemaListResponse {
			t.Fatalf("a list response must declare exactly the ListResponse schema, got %v", body["schemas"])
		}
		for _, field := range []string{"totalResults", "startIndex", "itemsPerPage", "Resources"} {
			if _, ok := body[field]; !ok {
				t.Fatalf("the ListResponse envelope is missing %q: %v", field, body)
			}
		}
		if got := numberField(t, body, "totalResults"); got != total {
			t.Fatalf("totalResults = %d, want %d: %v", got, total, body)
		}
		if got := numberField(t, body, "startIndex"); got != startIndex {
			t.Fatalf("startIndex = %d, want %d (1-based, per RFC 7644): %v", got, startIndex, body)
		}
		if got := numberField(t, body, "itemsPerPage"); got != itemsPerPage {
			t.Fatalf("itemsPerPage = %d, want %d: %v", got, itemsPerPage, body)
		}
		resources, ok := body["Resources"].([]any)
		if !ok {
			t.Fatalf("Resources is not an array: %v", body["Resources"])
		}
		if len(resources) != itemsPerPage {
			t.Fatalf("Resources holds %d entries but itemsPerPage says %d: %v", len(resources), itemsPerPage, body)
		}
	}
}

func numberField(t *testing.T, body map[string]any, field string) int {
	t.Helper()
	v, ok := body[field].(float64)
	if !ok {
		t.Fatalf("%s is not a number: %v", field, body[field])
	}
	return int(v)
}

// firstResourceID pulls the id of a ListResponse's only resource.
func firstResourceID(t *testing.T, body map[string]any) string {
	t.Helper()
	resources, _ := body["Resources"].([]any)
	if len(resources) == 0 {
		t.Fatalf("no resources to read an id from: %v", body)
	}
	first, _ := resources[0].(map[string]any)
	id, _ := first["id"].(string)
	if id == "" {
		t.Fatalf("the first resource carries no id: %v", resources[0])
	}
	return id
}

// eqFilter builds the URL-encoded `attr eq "value"` query a connector sends.
func eqFilter(attr, value string) string {
	return "?filter=" + url.QueryEscape(attr+` eq "`+value+`"`)
}

// ---------------------------------------------------------------------------
// SC1.a: the discovery trio, against implemented truth
// ---------------------------------------------------------------------------

// assertDiscoveryTrio checks the three documents against what this server
// ACTUALLY does: every `supported: false` is paired with a live refusal at the
// endpoint that would serve it, and the resource and schema sets are exactly
// the closed pair. "Matches implemented truth" is a claim about the pair, so
// asserting the document alone would only prove the document is consistent with
// itself.
func assertDiscoveryTrio(t *testing.T, call scimCall) {
	t.Helper()

	status, spc := call(http.MethodGet, "/ServiceProviderConfig", nil)
	if status != http.StatusOK {
		t.Fatalf("ServiceProviderConfig = %d %v", status, spc)
	}
	if schemas, _ := spc["schemas"].([]any); len(schemas) != 1 || schemas[0] != scimproto.SchemaSPConfig {
		t.Fatalf("ServiceProviderConfig declares %v, want the ServiceProviderConfig schema", spc["schemas"])
	}
	supported := func(feature string) bool {
		t.Helper()
		block, ok := spc[feature].(map[string]any)
		if !ok {
			t.Fatalf("ServiceProviderConfig declares no %q block: %v", feature, spc)
		}
		on, ok := block["supported"].(bool)
		if !ok {
			t.Fatalf("%s.supported is not a boolean: %v", feature, block)
		}
		return on
	}
	// The advertised presences.
	for _, feature := range []string{"patch", "filter"} {
		if !supported(feature) {
			t.Fatalf("ServiceProviderConfig advertises %s as absent, but the endpoints serve it", feature)
		}
	}
	// The advertised absences, each paired with the refusal that makes it true.
	absences := []struct {
		feature string
		method  string
		path    string
		body    any
	}{
		{"bulk", http.MethodPost, "/Bulk", map[string]any{}},
		{"sort", http.MethodGet, "/Users?sortBy=userName", nil},
	}
	for _, a := range absences {
		if supported(a.feature) {
			t.Fatalf("ServiceProviderConfig advertises %s as supported; the endpoint refuses it", a.feature)
		}
		status, body := call(a.method, a.path, a.body)
		if status != http.StatusNotImplemented {
			t.Fatalf("%s %s = %d, want 501 to match the advertised absence of %s: %v",
				a.method, a.path, status, a.feature, body)
		}
		assertSCIM501(t, body)
	}
	// changePassword and etag have no endpoint to probe — provisioning never
	// establishes credentials and this server mints no versions — so the
	// document's own claim is the whole truth and is pinned here.
	for _, feature := range []string{"changePassword", "etag"} {
		if supported(feature) {
			t.Fatalf("ServiceProviderConfig advertises %s as supported; nothing implements it", feature)
		}
	}
	// The credential this fixture presents is a bearer token, which is what the
	// document tells a connector to send.
	schemes, _ := spc["authenticationSchemes"].([]any)
	if len(schemes) != 1 {
		t.Fatalf("want exactly one authentication scheme, got %v", schemes)
	}
	if scheme, _ := schemes[0].(map[string]any); scheme["type"] != "oauthbearertoken" {
		t.Fatalf("the advertised scheme is not the bearer token this mount accepts: %v", schemes[0])
	}

	status, types := call(http.MethodGet, "/ResourceTypes", nil)
	if status != http.StatusOK {
		t.Fatalf("ResourceTypes = %d %v", status, types)
	}
	wantList(2, 1, 2)(t, types, nil)
	gotTypes := map[string]string{}
	for _, raw := range types["Resources"].([]any) {
		row, _ := raw.(map[string]any)
		id, _ := row["id"].(string)
		endpoint, _ := row["endpoint"].(string)
		gotTypes[id] = endpoint
	}
	if len(gotTypes) != 2 || gotTypes["User"] != "/Users" || gotTypes["Group"] != "/Groups" {
		t.Fatalf("ResourceTypes must be exactly User -> /Users and Group -> /Groups, got %v", gotTypes)
	}
	// The endpoints it names are the endpoints that answer.
	for _, endpoint := range []string{"/Users", "/Groups"} {
		if status, body := call(http.MethodGet, endpoint, nil); status != http.StatusOK {
			t.Fatalf("ResourceTypes names %s, which answers %d: %v", endpoint, status, body)
		}
	}

	status, schemasDoc := call(http.MethodGet, "/Schemas", nil)
	if status != http.StatusOK {
		t.Fatalf("Schemas = %d %v", status, schemasDoc)
	}
	wantList(3, 1, 3)(t, schemasDoc, nil)
	ids := []string{}
	for _, raw := range schemasDoc["Resources"].([]any) {
		row, _ := raw.(map[string]any)
		id, _ := row["id"].(string)
		ids = append(ids, id)
		if attrs, _ := row["attributes"].([]any); len(attrs) == 0 {
			t.Fatalf("schema %s carries no attribute definitions; the document is the closed truth, not a URI list", id)
		}
	}
	sort.Strings(ids)
	// The two core schemas plus the enterprise extension ResourceTypes declares
	// on User — a binding may name an extension attribute as its subject source,
	// and this document is the only place a connector can read that it exists.
	want := []string{scimproto.SchemaGroup, scimproto.SchemaUser, scimproto.SchemaEnterpriseExt}
	sort.Strings(want)
	if strings.Join(ids, " ") != strings.Join(want, " ") {
		t.Fatalf("Schemas must be exactly %v, got %v", want, ids)
	}
}

// assertSCIM501 pins the shape of a not-implemented refusal: the RFC error
// schema, status 501 as a STRING (RFC 7644 renders it that way), and NO
// `scimType` — that field is a 400-class discriminator (§8).
func assertSCIM501(t *testing.T, body map[string]any) {
	t.Helper()
	if schemas, _ := body["schemas"].([]any); len(schemas) != 1 || schemas[0] != scimproto.SchemaError {
		t.Fatalf("a 501 must carry the RFC Error schema, got %v", body["schemas"])
	}
	if body["status"] != "501" {
		t.Fatalf("a 501 body must name its status as \"501\", got %v", body["status"])
	}
	if _, has := body["scimType"]; has {
		t.Fatalf("a 501 must carry no scimType — that field discriminates 400s: %v", body)
	}
	if detail, _ := body["detail"].(string); detail == "" {
		t.Fatalf("a 501 must say what is unsupported: %v", body)
	}
}

// ---------------------------------------------------------------------------
// SC1: the Okta-shaped sequence
// ---------------------------------------------------------------------------

// TestSCIMOktaSequence is SC1's captured Okta conversation. Okta reads the
// discovery trio once, then for every user runs `userName eq` before it
// creates, and for every group runs `displayName eq` before it creates or
// updates — so the probe-then-write pairs here are the connector's own control
// flow, not a test's convenience.
func TestSCIMOktaSequenceSQLite(t *testing.T)   { runSCIMOktaSequence(t, seededDB(t, openSQLite)) }
func TestSCIMOktaSequencePostgres(t *testing.T) { runSCIMOktaSequence(t, seededDB(t, openPostgres)) }

func runSCIMOktaSequence(t *testing.T, db *store.DB) {
	_, _, call := scimWireServer(t, db, "okta")
	assertDiscoveryTrio(t, call)

	const userName = "okta.user@example.test"
	const external = "00u1okta"

	runSCIMSequence(t, call, []scimStep{
		{
			Name: "probe for the user before creating it", Method: http.MethodGet,
			Path: "/Users" + eqFilter("userName", userName), Want: http.StatusOK,
			// The probe that finds nothing still returns a truthful, fully
			// shaped envelope: a connector reads totalResults, not the array.
			Check: wantList(0, 1, 0),
		},
		{
			Name: "create the user", Method: http.MethodPost, Path: "/Users",
			Body: map[string]any{
				"schemas":  []string{scimproto.SchemaUser},
				"userName": userName, "externalId": external, "active": true,
				"name": map[string]any{"givenName": "Okta", "familyName": "User"},
			},
			Want: http.StatusCreated, Capture: map[string]string{"user": "id"},
			Check: func(t *testing.T, body map[string]any, _ map[string]string) {
				if body["active"] != true {
					t.Fatalf("a created user is active: %v", body["active"])
				}
				if _, ok := body["groups"]; !ok {
					t.Fatalf("the User response must always carry `groups`: %v", body)
				}
				meta, _ := body["meta"].(map[string]any)
				if meta["resourceType"] != "User" {
					t.Fatalf("meta.resourceType = %v, want User", meta["resourceType"])
				}
			},
		},
		{
			Name: "re-probe by userName, case-insensitively", Method: http.MethodGet,
			// `userName` is `caseExact: false` in the advertised schema, which is
			// why it is refused as a subject source — and why this probe, which
			// Okta issues with whatever case its own directory holds, must match.
			Path: "/Users" + eqFilter("userName", strings.ToUpper(userName)), Want: http.StatusOK,
			Check: func(t *testing.T, body map[string]any, ids map[string]string) {
				wantList(1, 1, 1)(t, body, ids)
				if got := firstResourceID(t, body); got != ids["user"] {
					t.Fatalf("the probe resolved %q, want the created user %q", got, ids["user"])
				}
			},
		},
		{
			Name: "probe by externalId, byte-exactly", Method: http.MethodGet,
			Path: "/Users" + eqFilter("externalId", external), Want: http.StatusOK,
			Check: wantList(1, 1, 1),
		},
		{
			Name: "externalId does NOT fold case", Method: http.MethodGet,
			// The identity-bearing attribute compares byte-exact (§8); a
			// case-folding externalId probe would make two IdP identities one.
			Path: "/Users" + eqFilter("externalId", strings.ToUpper(external)), Want: http.StatusOK,
			Check: wantList(0, 1, 0),
		},
		{
			Name: "probe for the group before creating it", Method: http.MethodGet,
			Path: "/Groups" + eqFilter("displayName", "Okta Everyone"), Want: http.StatusOK,
			Check: wantList(0, 1, 0),
		},
		{
			Name: "create the group", Method: http.MethodPost, Path: "/Groups",
			Body: map[string]any{
				"schemas":     []string{scimproto.SchemaGroup},
				"displayName": "Okta Everyone", "externalId": "00gokta",
			},
			Want: http.StatusCreated, Capture: map[string]string{"group": "id"},
		},
		{
			Name: "add the user to the group", Method: http.MethodPatch, Path: "/Groups/{group}",
			Body: map[string]any{
				"schemas": []string{scimproto.SchemaPatchOp},
				"Operations": []any{map[string]any{
					"op": "add", "path": "members",
					"value": []any{map[string]any{"value": "{user}"}},
				}},
			},
			Want: http.StatusOK,
			Check: func(t *testing.T, body map[string]any, ids map[string]string) {
				if got := memberValues(body); len(got) != 1 || got[0] != ids["user"] {
					t.Fatalf("the group must hold exactly the added member, got %v", got)
				}
			},
		},
		{
			Name: "re-probe the group by displayName", Method: http.MethodGet,
			Path: "/Groups" + eqFilter("displayName", "Okta Everyone"), Want: http.StatusOK,
			Check: func(t *testing.T, body map[string]any, ids map[string]string) {
				wantList(1, 1, 1)(t, body, ids)
				if got := firstResourceID(t, body); got != ids["group"] {
					t.Fatalf("the discovery probe resolved %q, want %q", got, ids["group"])
				}
			},
		},
		{
			Name: "probe the group by externalId", Method: http.MethodGet,
			Path: "/Groups" + eqFilter("externalId", "00gokta"), Want: http.StatusOK,
			Check: wantList(1, 1, 1),
		},
		{
			Name: "the user's membership is visible on the user", Method: http.MethodGet,
			Path: "/Users/{user}", Want: http.StatusOK,
			Check: func(t *testing.T, body map[string]any, ids map[string]string) {
				groups, _ := body["groups"].([]any)
				if len(groups) != 1 {
					t.Fatalf("the user must show its one membership: %v", body["groups"])
				}
			},
		},
		{
			Name: "replace the user wholesale", Method: http.MethodPut, Path: "/Users/{user}",
			Body: map[string]any{
				"schemas": []string{scimproto.SchemaUser}, "userName": userName,
			},
			Want: http.StatusOK,
			Check: func(t *testing.T, body map[string]any, _ map[string]string) {
				if body["externalId"] != external {
					t.Fatalf("the subject source is exempt from replacement: %v", body["externalId"])
				}
				if body["active"] != true {
					t.Fatalf("an omitted `active` reactivates: %v", body["active"])
				}
				if _, present := body["name"]; present {
					t.Fatalf("PUT clears omitted mutable attributes: %v", body)
				}
			},
		},
		{
			Name: "deactivate on offboarding", Method: http.MethodPatch, Path: "/Users/{user}",
			Body: map[string]any{
				"schemas":    []string{scimproto.SchemaPatchOp},
				"Operations": []any{map[string]any{"op": "replace", "path": "active", "value": false}},
			},
			Want: http.StatusOK,
			Check: func(t *testing.T, body map[string]any, _ map[string]string) {
				if body["active"] != false {
					t.Fatalf("the deactivation did not take: %v", body["active"])
				}
			},
		},
		{
			Name: "delete the user", Method: http.MethodDelete, Path: "/Users/{user}",
			Want: http.StatusNoContent,
		},
		{
			Name: "the deleted user is gone", Method: http.MethodGet, Path: "/Users/{user}",
			Want: http.StatusNotFound,
		},
		{
			Name: "the delete scrubbed the membership", Method: http.MethodGet, Path: "/Groups/{group}",
			Want: http.StatusOK,
			Check: func(t *testing.T, body map[string]any, _ map[string]string) {
				if got := memberValues(body); len(got) != 0 {
					t.Fatalf("a deleted user's member reference must be scrubbed, got %v", got)
				}
			},
		},
		{
			Name: "delete the group", Method: http.MethodDelete, Path: "/Groups/{group}",
			Want: http.StatusNoContent,
		},
	})

	// Paging, on a directory big enough to page: 1-based startIndex, a truthful
	// total on every page, and an out-of-range page that is empty rather than
	// clamped to the last one.
	for i := range 3 {
		status, body := call(http.MethodPost, "/Users", map[string]any{
			"schemas":  []string{scimproto.SchemaUser},
			"userName": fmt.Sprintf("page-%d@example.test", i), "externalId": fmt.Sprintf("page-%d", i),
		})
		if status != http.StatusCreated {
			t.Fatalf("paging fixture user %d = %d %v", i, status, body)
		}
	}
	pages := []struct {
		name                            string
		query                           string
		total, startIndex, itemsPerPage int
	}{
		{"first page", "?startIndex=1&count=2", 3, 1, 2},
		{"last, partial page", "?startIndex=3&count=2", 3, 3, 1},
		{"out of range", "?startIndex=99&count=2", 3, 99, 0},
		{"filtered total counts the FILTER, not the directory",
			eqFilter("userName", "page-1@example.test"), 1, 1, 1},
	}
	for _, page := range pages {
		status, body := call(http.MethodGet, "/Users"+page.query, nil)
		if status != http.StatusOK {
			t.Fatalf("%s: GET /Users%s = %d %v", page.name, page.query, status, body)
		}
		wantList(page.total, page.startIndex, page.itemsPerPage)(t, body, nil)
	}
	// RFC 7644 §3.4.2.4: a startIndex below 1 is READ AS 1 — not refused. The
	// contract deliberately declares no `minimum` on this parameter, because
	// contract validation runs before the credential authenticates and a schema
	// refusal there is an unauthenticated answer about the request. Post-auth
	// the protocol layer clamps, exactly as the RFC says.
	if status, body := call(http.MethodGet, "/Users?startIndex=0&count=2", nil); status != http.StatusOK {
		t.Fatalf("startIndex=0 = %d, want the RFC's clamp to 1: %v", status, body)
	} else {
		wantList(3, 1, 2)(t, body, nil)
	}
	// A non-numeric startIndex IS refused — but by the protocol, as an RFC 7644
	// error with a `scimType`, not as a Hikyo contract 400.
	if status, body := call(http.MethodGet, "/Users?startIndex=abc", nil); status != http.StatusBadRequest ||
		body["scimType"] != scimproto.TypeInvalidValue {
		t.Fatalf("startIndex=abc = %d %v, want an RFC invalidValue", status, body)
	}
}

// TestSCIMWireRefusesNothingBeforeAuthenticating is p2#1's invariant: the wire
// authenticates BEFORE it says anything about the shape of a request. A
// contract-layer constraint on a SCIM parameter would answer an unauthenticated
// caller with a Hikyo 400 — telling them their request was malformed before they
// proved they may ask — instead of the uniform 401.
func TestSCIMWireRefusesNothingBeforeAuthenticatingSQLite(t *testing.T) {
	runSCIMWireAuthBeforeValidation(t, seededDB(t, openSQLite))
}
func TestSCIMWireRefusesNothingBeforeAuthenticatingPostgres(t *testing.T) {
	runSCIMWireAuthBeforeValidation(t, seededDB(t, openPostgres))
}

func runSCIMWireAuthBeforeValidation(t *testing.T, db *store.DB) {
	bindingID, mount, call := scimWireServer(t, db, "okta")
	base := mount + bindingID

	// Every request below is malformed in a way that HAS a named post-auth
	// refusal, so a 400 here would be the contract layer answering first.
	malformed := []struct {
		name, path string
	}{
		{"startIndex below the 1-based floor", "/Users?startIndex=0"},
		{"a non-numeric startIndex", "/Users?startIndex=abc"},
		{"a negative count", "/Users?count=-5"},
		{"an over-long filter", "/Users?filter=" + url.QueryEscape(`userName eq "`+strings.Repeat("x", 4096)+`"`)},
		{"an unsupported filter", "/Users?filter=" + url.QueryEscape(`userName sw "a"`)},
		{"an over-long sort parameter", "/Users?sortBy=" + strings.Repeat("s", 4096)},
	}
	// A body that is not a SCIM resource at all. It is refused BY THE
	// TRANSPORT, before any handler binds it — which is exactly why it has to
	// be ranked behind authentication too: contract validation and the
	// generated binder both run before a credential is resolved.
	for _, body := range []any{
		[]byte(`{"userName":`),   // truncated JSON
		[]byte(`[1,2,3]`),        // valid JSON, not an object
		[]byte(`"a string"`),     // valid JSON, not an object
		[]byte(`{"a":1}{"b":2}`), // trailing content
	} {
		status, out := scimRawRequest(t, http.MethodPost, base+"/Users", "hik_1_scim_notatoken", body)
		if status != http.StatusUnauthorized {
			t.Errorf("malformed body, unauthenticated: %d, want 401 — a malformed body must not be "+
				"answered before authentication\n  body: %v", status, out)
		}
		// With a REAL credential the same body gets the RFC 7644 refusal, in
		// the SCIM error shape rather than Hikyo's.
		status, out = call(http.MethodPost, "/Users", body)
		if status != http.StatusBadRequest {
			t.Errorf("malformed body, authenticated: %d, want 400: %v", status, out)
		}
		if schemas, _ := out["schemas"].([]any); len(schemas) != 1 || schemas[0] != scimproto.SchemaError {
			t.Errorf("malformed body, authenticated: not an RFC 7644 error body: %v", out)
		}
		if out["scimType"] != scimproto.TypeInvalidSyntax {
			t.Errorf("malformed body, authenticated: scimType = %v, want %q", out["scimType"], scimproto.TypeInvalidSyntax)
		}
	}

	for _, m := range malformed {
		// No credential at all: the answer must be 401 in every case, never a
		// contract 400 describing what is wrong with the request.
		status, body := scimRawRequest(t, http.MethodGet, base+m.path, "hik_1_scim_notatoken", nil)
		if status != http.StatusUnauthorized {
			t.Errorf("%s, unauthenticated: %d, want 401 — validity must not be answered before authentication\n  body: %v",
				m.name, status, body)
		}
		// And with a REAL credential the same request gets its named protocol
		// answer, so the refusals were not simply deleted.
		if status, _ := call(http.MethodGet, m.path, nil); status == http.StatusUnauthorized {
			t.Errorf("%s, authenticated: still 401; the post-auth handling is missing", m.name)
		}
	}
}

// ---------------------------------------------------------------------------
// SC1: the Entra-shaped sequence
// ---------------------------------------------------------------------------

// TestSCIMEntraSequence is SC1's captured Entra conversation. Entra differs
// from Okta in ways this server names as tolerances: it probes by `externalId`
// rather than `userName`, it sends `active` as the STRINGS "True"/"False", and
// it sends pathless PATCH value objects rather than attribute paths. Each of
// those is a fixture here, driven over the wire.
func TestSCIMEntraSequenceSQLite(t *testing.T)   { runSCIMEntraSequence(t, seededDB(t, openSQLite)) }
func TestSCIMEntraSequencePostgres(t *testing.T) { runSCIMEntraSequence(t, seededDB(t, openPostgres)) }

func runSCIMEntraSequence(t *testing.T, db *store.DB) {
	_, _, call := scimWireServer(t, db, "entra")
	assertDiscoveryTrio(t, call)

	const external = "8f3a1c22-entra"

	runSCIMSequence(t, call, []scimStep{
		{
			Name: "probe by externalId before creating", Method: http.MethodGet,
			Path: "/Users" + eqFilter("externalId", external), Want: http.StatusOK,
			Check: wantList(0, 1, 0),
		},
		{
			Name:   "create with a stringified boolean and an enterprise extension",
			Method: http.MethodPost, Path: "/Users",
			Body: map[string]any{
				"schemas":  []string{scimproto.SchemaUser, scimproto.SchemaEnterpriseExt},
				"userName": "entra.user@example.test", "externalId": external,
				"active":                      "True",
				scimproto.SchemaEnterpriseExt: map[string]any{"department": "Engineering"},
			},
			Want: http.StatusCreated, Capture: map[string]string{"user": "id"},
			Check: func(t *testing.T, body map[string]any, _ map[string]string) {
				if body["active"] != true {
					t.Fatalf(`Entra's "True" must normalize to a boolean true: %v`, body["active"])
				}
			},
		},
		{
			Name: "probe for the group before creating it", Method: http.MethodGet,
			Path: "/Groups" + eqFilter("displayName", "Entra Engineering"), Want: http.StatusOK,
			Check: wantList(0, 1, 0),
		},
		{
			Name: "create the group with its members inline", Method: http.MethodPost, Path: "/Groups",
			Body: map[string]any{
				"schemas": []string{scimproto.SchemaGroup}, "displayName": "Entra Engineering",
				"externalId": "e5b7-group",
				"members":    []any{map[string]any{"value": "{user}"}},
			},
			Want: http.StatusCreated, Capture: map[string]string{"group": "id"},
			Check: func(t *testing.T, body map[string]any, ids map[string]string) {
				if got := memberValues(body); len(got) != 1 || got[0] != ids["user"] {
					t.Fatalf("the inline member set did not take: %v", got)
				}
			},
		},
		{
			Name: "rename the group with a pathless value object", Method: http.MethodPatch,
			Path: "/Groups/{group}",
			Body: map[string]any{
				"schemas": []string{scimproto.SchemaPatchOp},
				"Operations": []any{map[string]any{
					"op": "replace", "value": map[string]any{"displayName": "Entra Engineering EMEA"},
				}},
			},
			Want: http.StatusOK,
			Check: func(t *testing.T, body map[string]any, _ map[string]string) {
				if body["displayName"] != "Entra Engineering EMEA" {
					t.Fatalf("the pathless merge did not take: %v", body["displayName"])
				}
				if got := memberValues(body); len(got) != 1 {
					t.Fatalf("a pathless rename must not disturb membership, got %v", got)
				}
			},
		},
		{
			Name: "the renamed group answers the new discovery probe", Method: http.MethodGet,
			Path: "/Groups" + eqFilter("displayName", "Entra Engineering EMEA"), Want: http.StatusOK,
			Check: wantList(1, 1, 1),
		},
		{
			Name: "deactivate with a pathless stringified boolean", Method: http.MethodPatch,
			Path: "/Users/{user}",
			Body: map[string]any{
				"schemas": []string{scimproto.SchemaPatchOp},
				"Operations": []any{map[string]any{
					"op": "replace", "value": map[string]any{"active": "False"},
				}},
			},
			Want: http.StatusOK,
			Check: func(t *testing.T, body map[string]any, _ map[string]string) {
				if body["active"] != false {
					t.Fatalf(`Entra's pathless "False" must normalize to false: %v`, body["active"])
				}
			},
		},
		{
			Name: "reactivate with the path form", Method: http.MethodPatch, Path: "/Users/{user}",
			Body: map[string]any{
				"schemas":    []string{scimproto.SchemaPatchOp},
				"Operations": []any{map[string]any{"op": "replace", "path": "active", "value": "True"}},
			},
			Want: http.StatusOK,
			Check: func(t *testing.T, body map[string]any, _ map[string]string) {
				if body["active"] != true {
					t.Fatalf(`"True" on the path form must normalize too: %v`, body["active"])
				}
			},
		},
		{
			Name: "remove the member with the filtered path", Method: http.MethodPatch,
			Path: "/Groups/{group}",
			Body: map[string]any{
				"schemas": []string{scimproto.SchemaPatchOp},
				"Operations": []any{map[string]any{
					"op": "remove", "path": `members[value eq "{user}"]`,
				}},
			},
			Want: http.StatusOK,
			Check: func(t *testing.T, body map[string]any, _ map[string]string) {
				if got := memberValues(body); len(got) != 0 {
					t.Fatalf("the filtered removal left %v", got)
				}
			},
		},
		{
			Name: "delete the group", Method: http.MethodDelete, Path: "/Groups/{group}",
			Want: http.StatusNoContent,
		},
		{
			Name: "the user survives its group", Method: http.MethodGet, Path: "/Users/{user}",
			Want: http.StatusOK,
		},
	})
}

// ---------------------------------------------------------------------------
// SC1.e/f/h: the closed PATCH matrix, over the wire
// ---------------------------------------------------------------------------

// TestSCIMPatchMatrixOverTheWire walks EVERY cell of §8's operation x path
// table against both resources, over raw HTTP — accepted cells and refused
// cells, each refusal carrying its exact status and `scimType`. The per-cell
// parse fixtures in internal/scimproto prove the parser; this proves the
// transport carries the parser's verdict out unaltered, which is a different
// claim and the one an identity provider actually experiences.
func TestSCIMPatchMatrixOverTheWireSQLite(t *testing.T) {
	runSCIMPatchMatrixOverTheWire(t, seededDB(t, openSQLite))
}
func TestSCIMPatchMatrixOverTheWirePostgres(t *testing.T) {
	runSCIMPatchMatrixOverTheWire(t, seededDB(t, openPostgres))
}

func runSCIMPatchMatrixOverTheWire(t *testing.T, db *store.DB) {
	_, _, call := scimWireServer(t, db, "okta")

	newUser := func(name string) string {
		t.Helper()
		status, body := call(http.MethodPost, "/Users", map[string]any{
			"schemas":  []string{scimproto.SchemaUser},
			"userName": name + "@example.test", "externalId": name,
		})
		if status != http.StatusCreated {
			t.Fatalf("fixture user %s = %d %v", name, status, body)
		}
		id, _ := body["id"].(string)
		return id
	}
	member := newUser("matrix-member")
	newGroup := func(name string) string {
		t.Helper()
		status, body := call(http.MethodPost, "/Groups", map[string]any{
			"schemas": []string{scimproto.SchemaGroup}, "displayName": name,
			"members": []any{map[string]any{"value": member}},
		})
		if status != http.StatusCreated {
			t.Fatalf("fixture group %s = %d %v", name, status, body)
		}
		id, _ := body["id"].(string)
		return id
	}

	// The matrix, verbatim from §8. Each row is one (op, path) cell against one
	// resource; `want` is 200 for an accepted cell and the exact refusal
	// otherwise. Every cell gets a FRESH resource so an accepted cell's effect
	// cannot make a later cell pass or fail for the wrong reason.
	type cell struct {
		name     string
		resource string // "user" or "group"
		op       map[string]any
		want     int
		scimType string
	}
	ref := []any{map[string]any{"value": member}}
	cells := []cell{
		// --- op x path on USERS -------------------------------------------------
		{"add, pathless", "user", map[string]any{"op": "add", "value": map[string]any{"nickName": "N"}}, 200, ""},
		{"replace, pathless", "user", map[string]any{"op": "replace", "value": map[string]any{"nickName": "N"}}, 200, ""},
		{"remove, pathless", "user", map[string]any{"op": "remove"}, 400, scimproto.TypeInvalidPath},
		{"add, plain", "user", map[string]any{"op": "add", "path": "nickName", "value": "N"}, 200, ""},
		{"replace, plain", "user", map[string]any{"op": "replace", "path": "nickName", "value": "N"}, 200, ""},
		{"remove, plain non-required", "user", map[string]any{"op": "remove", "path": "nickName"}, 200, ""},
		{"remove, plain REQUIRED", "user", map[string]any{"op": "remove", "path": "userName"}, 400, scimproto.TypeInvalidPath},
		{"add, active", "user", map[string]any{"op": "add", "path": "active", "value": true}, 200, ""},
		{"replace, active", "user", map[string]any{"op": "replace", "path": "active", "value": false}, 200, ""},
		{"remove, active", "user", map[string]any{"op": "remove", "path": "active"}, 400, scimproto.TypeInvalidPath},
		{"add, members on a USER", "user", map[string]any{"op": "add", "path": "members", "value": ref}, 400, scimproto.TypeInvalidPath},
		{"replace, members on a USER", "user", map[string]any{"op": "replace", "path": "members", "value": ref}, 400, scimproto.TypeInvalidPath},
		{"remove, members on a USER", "user", map[string]any{"op": "remove", "path": "members"}, 400, scimproto.TypeInvalidPath},
		{"remove, members[value eq] on a USER", "user",
			map[string]any{"op": "remove", "path": `members[value eq "` + member + `"]`}, 400, scimproto.TypeInvalidPath},

		// --- op x path on GROUPS ------------------------------------------------
		{"add, pathless", "group", map[string]any{"op": "add", "value": map[string]any{"externalId": "gx"}}, 200, ""},
		{"replace, pathless", "group", map[string]any{"op": "replace", "value": map[string]any{"externalId": "gx"}}, 200, ""},
		{"remove, pathless", "group", map[string]any{"op": "remove"}, 400, scimproto.TypeInvalidPath},
		{"add, plain", "group", map[string]any{"op": "add", "path": "externalId", "value": "gx"}, 200, ""},
		{"replace, plain", "group", map[string]any{"op": "replace", "path": "externalId", "value": "gx"}, 200, ""},
		{"remove, plain non-required", "group", map[string]any{"op": "remove", "path": "externalId"}, 200, ""},
		{"remove, plain REQUIRED", "group", map[string]any{"op": "remove", "path": "displayName"}, 400, scimproto.TypeInvalidPath},
		{"add, active on a GROUP", "group", map[string]any{"op": "add", "path": "active", "value": true}, 400, scimproto.TypeInvalidPath},
		{"replace, active on a GROUP", "group", map[string]any{"op": "replace", "path": "active", "value": true}, 400, scimproto.TypeInvalidPath},
		{"remove, active on a GROUP", "group", map[string]any{"op": "remove", "path": "active"}, 400, scimproto.TypeInvalidPath},
		{"add, members", "group", map[string]any{"op": "add", "path": "members", "value": []any{}}, 200, ""},
		{"replace, members", "group", map[string]any{"op": "replace", "path": "members", "value": ref}, 200, ""},
		{"remove, members", "group", map[string]any{"op": "remove", "path": "members"}, 200, ""},
		{"remove, members[value eq]", "group",
			map[string]any{"op": "remove", "path": `members[value eq "` + member + `"]`}, 200, ""},
		{"add, members[value eq]", "group",
			map[string]any{"op": "add", "path": `members[value eq "` + member + `"]`, "value": ref},
			400, scimproto.TypeInvalidPath},
		{"replace, members[value eq]", "group",
			map[string]any{"op": "replace", "path": `members[value eq "` + member + `"]`, "value": ref},
			400, scimproto.TypeInvalidPath},

		// --- the named value refusals, which are cells too -----------------------
		{"nested-group member reference", "group",
			map[string]any{"op": "add", "path": "members",
				"value": []any{map[string]any{"value": "scg_nested", "type": "Group"}}},
			400, scimproto.TypeInvalidValue},
		{"unknown member reference", "group",
			map[string]any{"op": "add", "path": "members",
				"value": []any{map[string]any{"value": "scu_does_not_exist"}}},
			400, scimproto.TypeInvalidValue},
		// §8's closed mapping: a PATCH path that resolves to nothing is
		// `noTarget`, which RFC 7644 makes a 400 — not a 404, which would say the
		// GROUP was missing.
		{"members[value eq] naming a non-member", "group",
			map[string]any{"op": "remove", "path": `members[value eq "scu_not_a_member"]`},
			400, scimproto.TypeNoTarget},
		{"active as a non-boolean string", "user",
			map[string]any{"op": "replace", "path": "active", "value": "maybe"}, 400, scimproto.TypeInvalidValue},
		{"a pathless value that is not an object", "user",
			map[string]any{"op": "add", "value": "scalar"}, 400, scimproto.TypeInvalidValue},
		{"members as a non-array", "group",
			map[string]any{"op": "add", "path": "members", "value": "not-an-array"}, 400, scimproto.TypeInvalidValue},
		{"an unknown operation verb", "user",
			map[string]any{"op": "merge", "path": "nickName", "value": "N"}, 400, scimproto.TypeInvalidSyntax},
		{"an add with no value", "user",
			map[string]any{"op": "add", "path": "nickName"}, 400, scimproto.TypeInvalidValue},
		{"password, refused by name", "user",
			map[string]any{"op": "replace", "path": "password", "value": "hunter2"}, 400, scimproto.TypeInvalidValue},
	}

	for i, c := range cells {
		target := "/Users/" + newUser(fmt.Sprintf("matrix-u%d", i))
		if c.resource == "group" {
			target = "/Groups/" + newGroup(fmt.Sprintf("Matrix Group %d", i))
		}
		status, body := call(http.MethodPatch, target, map[string]any{
			"schemas":    []string{scimproto.SchemaPatchOp},
			"Operations": []any{c.op},
		})
		if status != c.want {
			t.Errorf("%s on a %s: status %d, want %d\n  body: %v", c.name, c.resource, status, c.want, body)
			continue
		}
		if c.scimType == "" {
			if got, has := body["scimType"]; has && status != 200 {
				t.Errorf("%s on a %s: unexpected scimType %v", c.name, c.resource, got)
			}
			continue
		}
		if body["scimType"] != c.scimType {
			t.Errorf("%s on a %s: scimType = %v, want %q\n  body: %v",
				c.name, c.resource, body["scimType"], c.scimType, body)
		}
	}

	// Whole-PATCH atomicity, over the wire: a VALID operation followed by an
	// invalid one commits nothing. The valid half is chosen to be observable —
	// a rename — so "nothing committed" is checkable rather than assumed.
	atomic := newGroup("Atomic Group")
	status, body := call(http.MethodPatch, "/Groups/"+atomic, map[string]any{
		"schemas": []string{scimproto.SchemaPatchOp},
		"Operations": []any{
			map[string]any{"op": "replace", "path": "displayName", "value": "Renamed By A Doomed Request"},
			map[string]any{"op": "remove", "path": "members[displayName eq \"x\"]"},
		},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("a PATCH with one invalid operation must fail whole: %d %v", status, body)
	}
	if body["scimType"] != scimproto.TypeInvalidPath {
		t.Fatalf("an unsupported member filter is invalidPath, got %v", body["scimType"])
	}
	if status, after := call(http.MethodGet, "/Groups/"+atomic, nil); status != http.StatusOK {
		t.Fatalf("atomicity target = %d %v", status, after)
	} else if after["displayName"] != "Atomic Group" {
		t.Fatalf("the valid half of a refused PATCH was committed: displayName = %v", after["displayName"])
	}
	// And the mirror: the INVALID operation first, so the refusal cannot be
	// explained by "it stopped before reaching the valid one".
	status, body = call(http.MethodPatch, "/Groups/"+atomic, map[string]any{
		"schemas": []string{scimproto.SchemaPatchOp},
		"Operations": []any{
			map[string]any{"op": "remove", "path": "active"},
			map[string]any{"op": "replace", "path": "displayName", "value": "Also Doomed"},
		},
	})
	if status != http.StatusBadRequest || body["scimType"] != scimproto.TypeInvalidPath {
		t.Fatalf("invalid-first must fail whole with invalidPath: %d %v", status, body)
	}
	if _, after := call(http.MethodGet, "/Groups/"+atomic, nil); after["displayName"] != "Atomic Group" {
		t.Fatalf("the trailing valid operation was committed: %v", after["displayName"])
	}

	// ORDER inside one PATCH. A membership script is a SEQUENCE: the same two
	// operations in opposite orders are different requests and must reach
	// different states. Bucketing them into "adds" and "removes" made both
	// produce the same final membership — and therefore the same final
	// AUTHORIZATION — which is a wrong answer to one of the two.
	second := newUser("matrix-second")
	orderCases := []struct {
		name string
		ops  []any
		want []string
	}{
		{"add then remove the same reference",
			[]any{
				map[string]any{"op": "add", "path": "members",
					"value": []any{map[string]any{"value": second}}},
				map[string]any{"op": "remove", "path": `members[value eq "` + second + `"]`},
			},
			[]string{member}},
		{"remove then add the same reference",
			[]any{
				map[string]any{"op": "remove", "path": `members[value eq "` + member + `"]`},
				map[string]any{"op": "add", "path": "members",
					"value": []any{map[string]any{"value": member}}},
			},
			[]string{member}},
		{"clear then add",
			[]any{
				map[string]any{"op": "remove", "path": "members"},
				map[string]any{"op": "add", "path": "members",
					"value": []any{map[string]any{"value": second}}},
			},
			[]string{second}},
		{"add then clear",
			[]any{
				map[string]any{"op": "add", "path": "members",
					"value": []any{map[string]any{"value": second}}},
				map[string]any{"op": "remove", "path": "members"},
			},
			nil},
	}
	for i, c := range orderCases {
		g := newGroup(fmt.Sprintf("Ordered Group %d", i))
		status, body := call(http.MethodPatch, "/Groups/"+g, map[string]any{
			"schemas": []string{scimproto.SchemaPatchOp}, "Operations": c.ops,
		})
		if status != http.StatusOK {
			t.Errorf("%s: %d %v", c.name, status, body)
			continue
		}
		got := memberValues(body)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: members = %v, want %v — the script was not applied in order", c.name, got, c.want)
		}
	}
	// A filtered removal naming a reference an EARLIER operation in the same
	// request added is a legitimate target, not `noTarget`: the script sees
	// what its predecessors did.
	if status, body := call(http.MethodPatch, "/Groups/"+newGroup("Sequenced Group"), map[string]any{
		"schemas": []string{scimproto.SchemaPatchOp},
		"Operations": []any{
			map[string]any{"op": "add", "path": "members",
				"value": []any{map[string]any{"value": second}}},
			map[string]any{"op": "remove", "path": `members[value eq "` + second + `"]`},
		},
	}); status != http.StatusOK {
		t.Fatalf("a removal targeting a member added earlier in the SAME request must succeed: %d %v", status, body)
	}

	// The routes that exist only to refuse (§8): advertised absent, refused with
	// the RFC error body, 501, and never a scimType.
	for _, route := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/Me", nil},
		{http.MethodPost, "/Users/.search", map[string]any{"filter": `userName eq "x"`}},
		{http.MethodPost, "/Groups/.search", map[string]any{"filter": `displayName eq "x"`}},
		{http.MethodPost, "/Bulk", map[string]any{"Operations": []any{}}},
	} {
		status, body := call(route.method, route.path, route.body)
		if status != http.StatusNotImplemented {
			t.Fatalf("%s %s = %d, want 501: %v", route.method, route.path, status, body)
		}
		assertSCIM501(t, body)
	}
}

// ---------------------------------------------------------------------------
// SC2.e: create and attach are byte-shape identical on the wire
// ---------------------------------------------------------------------------

// TestSCIMWireAttachIsIndistinguishable is the RENDERED-BYTES half of #23's
// oracle criterion. runSCIMCreateIsOneQueryPath compares the ordered query
// trace and runSCIMUserLifecycle compares the service resource; this compares
// the bytes an identity provider actually receives, canonicalized so that
// legitimately-differing VALUES (ids, timestamps, names) collapse to their
// types and any difference in the field SET survives.
func TestSCIMWireAttachIsIndistinguishableSQLite(t *testing.T) {
	runSCIMWireAttachIsIndistinguishable(t, seededDB(t, openSQLite))
}
func TestSCIMWireAttachIsIndistinguishablePostgres(t *testing.T) {
	runSCIMWireAttachIsIndistinguishable(t, seededDB(t, openPostgres))
}

func runSCIMWireAttachIsIndistinguishable(t *testing.T, db *store.DB) {
	_, _, call := scimWireServer(t, db, "okta")

	// The attach leg's identity exists already, invited before SCIM ever saw it.
	execRaw(t, db, `INSERT INTO principals (id, kind, created_at) VALUES ('usr_invited_w', 'human', `+ts+`)`)
	execRaw(t, db, `INSERT INTO accounts (id, principal_id, username, display_name, created_at) `+
		`VALUES ('acc_invited_w', 'usr_invited_w', 'invited-w@example.test', 'W', `+ts+`)`)
	execRaw(t, db, `INSERT INTO external_identities (id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at) `+
		`VALUES ('eid_invited_w', 'acc_invited_w', 'oidc', 'https://okta.example.test', 'attach-w', 'okta', 0, `+ts+`)`)

	create := func(userName, external string) map[string]any {
		t.Helper()
		status, body := call(http.MethodPost, "/Users", map[string]any{
			"schemas":  []string{scimproto.SchemaUser},
			"userName": userName, "externalId": external, "active": true,
		})
		if status != http.StatusCreated {
			t.Fatalf("create %s = %d %v", external, status, body)
		}
		return body
	}
	// The attach leg first, so a fresh create cannot differ merely by running
	// second.
	attach := create("invited-w-scim@example.test", "attach-w")
	fresh := create("fresh-w@example.test", "fresh-w")

	if got, want := jsonShape(attach), jsonShape(fresh); got != want {
		t.Fatalf("a create and an attach render different response shapes — that difference is a "+
			"cross-org oracle:\n  fresh:  %s\n  attach: %s", want, got)
	}
	// The comparison is only meaningful if it would have SEEN a difference, so
	// the two legs must genuinely have taken different branches.
	if accountOf(t, db, attach["id"].(string)) != "acc_invited_w" {
		t.Fatal("the attach leg did not attach; the shape comparison proved nothing")
	}
	if accountOf(t, db, fresh["id"].(string)) == "acc_invited_w" {
		t.Fatal("the fresh leg attached; the shape comparison proved nothing")
	}
}

// jsonShape renders a decoded JSON value as canonical shape bytes: object keys
// sorted, arrays kept with their length, every leaf replaced by its JSON type.
// Comparing shapes rather than values is the point — two different people
// produce different content, and what must be indistinguishable is the FORM of
// the answer.
func jsonShape(v any) string {
	var b strings.Builder
	writeJSONShape(&b, v)
	return b.String()
}

func writeJSONShape(b *strings.Builder, v any) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(k)
			b.WriteByte(':')
			writeJSONShape(b, t[k])
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONShape(b, e)
		}
		b.WriteByte(']')
	case string:
		b.WriteString("string")
	case float64:
		b.WriteString("number")
	case bool:
		b.WriteString("bool")
	default:
		b.WriteString("null")
	}
}

// ---------------------------------------------------------------------------
// SC1.a: discovery is the CLOSED truth, per binding
// ---------------------------------------------------------------------------

// TestSCIMDeclaredExtensionsAreTheClosedTruth is §8's "the content is the
// closed truth of what this server implements", made true rather than claimed.
//
// §5.1 admits `externalId` or "a declared enterprise/custom extension path" as
// a subject source, and DECLARATION is what closes the set: a binding that
// names a custom URN declares it, discovery describes it, ingest accepts it —
// and a binding that declared nothing of the sort refuses that same URN by
// name. Before this, any URN was a valid subject source, discovery advertised
// only the enterprise extension, and the renderer echoed whatever arrived.
func TestSCIMDeclaredExtensionsAreTheClosedTruthSQLite(t *testing.T) {
	runSCIMDeclaredExtensions(t, seededDB(t, openSQLite))
}
func TestSCIMDeclaredExtensionsAreTheClosedTruthPostgres(t *testing.T) {
	runSCIMDeclaredExtensions(t, seededDB(t, openPostgres))
}

func runSCIMDeclaredExtensions(t *testing.T, db *store.DB) {
	const acme = "urn:example:params:scim:schemas:extension:acme:2.0:User"
	const undeclared = "urn:example:params:scim:schemas:extension:other:2.0:User"
	_, mount, call := scimWireServerWithSubject(t, db, "okta", acme+":employeeId")

	// The declared extension is DESCRIBED, with the attribute the binding named.
	status, schemas := call(http.MethodGet, "/Schemas", nil)
	if status != http.StatusOK {
		t.Fatalf("/Schemas = %d %v", status, schemas)
	}
	var described map[string]any
	for _, r := range schemas["Resources"].([]any) {
		if m, _ := r.(map[string]any); m["id"] == acme {
			described = m
		}
	}
	if described == nil {
		t.Fatalf("the binding's declared extension must be described: %v", schemas)
	}
	attrs, _ := described["attributes"].([]any)
	if len(attrs) != 1 || attrs[0].(map[string]any)["name"] != "employeeId" {
		t.Fatalf("the description must carry exactly the declared attribute: %v", attrs)
	}
	// …and ADVERTISED on the User resource type.
	status, types := call(http.MethodGet, "/ResourceTypes", nil)
	if status != http.StatusOK {
		t.Fatalf("/ResourceTypes = %d %v", status, types)
	}
	var advertised bool
	for _, r := range types["Resources"].([]any) {
		m, _ := r.(map[string]any)
		for _, e := range m["schemaExtensions"].([]any) {
			if e.(map[string]any)["schema"] == acme {
				advertised = true
			}
		}
	}
	if !advertised {
		t.Fatalf("the binding's declared extension must be advertised: %v", types)
	}

	// A resource carrying the DECLARED extension is accepted, and its rendered
	// `schemas` names it — the array and the documents come from one list.
	status, created := call(http.MethodPost, "/Users", map[string]any{
		"schemas":  []string{scimproto.SchemaUser, acme},
		"userName": "declared@example.test",
		acme:       map[string]any{"employeeId": "e-1"},
	})
	if status != http.StatusCreated {
		t.Fatalf("a declared extension must be accepted: %d %v", status, created)
	}
	got, _ := created["schemas"].([]any)
	var names []string
	for _, v := range got {
		names = append(names, v.(string))
	}
	sort.Strings(names)
	if len(names) != 2 || names[0] != acme || names[1] != scimproto.SchemaUser {
		t.Fatalf("the rendered schemas must be the core one plus the declared extension, got %v", names)
	}

	// An UNDECLARED extension is refused BY NAME, not stored and echoed.
	status, body := call(http.MethodPost, "/Users", map[string]any{
		"schemas":  []string{scimproto.SchemaUser},
		"userName": "undeclared@example.test",
		// The DECLARED extension is present too, so the request gets past
		// subject derivation and the refusal is unambiguously about the other
		// one.
		acme:       map[string]any{"employeeId": "e-9"},
		undeclared: map[string]any{"anything": "x"},
	})
	if status != http.StatusBadRequest || body["scimType"] != scimproto.TypeInvalidValue {
		t.Fatalf("an undeclared extension must be refused with invalidValue: %d %v", status, body)
	}
	if detail, _ := body["detail"].(string); !strings.Contains(detail, undeclared) {
		t.Fatalf("the refusal must name the schema it refused: %v", body["detail"])
	}
	// The refusal is about DECLARATION, not about the URN being exotic: on a
	// SECOND binding in the same org, declaring only `externalId`, the very
	// same extension is refused — and its own /Schemas does not describe it.
	svc := scimSvc(db)
	seedSCIMProvider(t, db, "entra", "https://entra.example.test", true)
	plain, err := svc.CreateBinding(t.Context(), service.LocalPrincipal(orgAdmin), wireOrg,
		service.SCIMBindingInput{
			ProviderKind: domain.ProviderOIDC, ProviderSlug: "entra",
			SubjectSource: domain.SubjectSourceExternalID,
		})
	if err != nil {
		t.Fatal(err)
	}
	plainMint, err := svc.MintCredential(t.Context(), service.LocalPrincipal(orgAdmin), wireOrg, plain.ID, false, "")
	if err != nil {
		t.Fatal(err)
	}
	plainBase := mount + plain.ID
	if status, body := scimRawRequest(t, http.MethodPost, plainBase+"/Users", plainMint.Token, map[string]any{
		"schemas": []string{scimproto.SchemaUser}, "userName": "plain@example.test",
		"externalId": "plain", acme: map[string]any{"employeeId": "e-2"},
	}); status != http.StatusBadRequest || body["scimType"] != scimproto.TypeInvalidValue {
		t.Fatalf("a binding that declared no custom extension must refuse one: %d %v", status, body)
	}
	status, plainSchemas := scimRawRequest(t, http.MethodGet, plainBase+"/Schemas", plainMint.Token, nil)
	if status != http.StatusOK {
		t.Fatalf("/Schemas on the plain binding = %d %v", status, plainSchemas)
	}
	for _, r := range plainSchemas["Resources"].([]any) {
		if m, _ := r.(map[string]any); m["id"] == acme {
			t.Fatalf("a binding that declared no custom extension must not describe one: %v", plainSchemas)
		}
	}
}

// ---------------------------------------------------------------------------
// SC1.g/SC2.g: presence state, and a request that changes nothing
// ---------------------------------------------------------------------------

// TestSCIMPresenceAndNoOp is two rules a string-only input could not express.
//
// PRESENCE: an explicit `remove externalId` is a different request from
// omitting it. On a subject-source binding it is an identity mutation and is
// refused with `mutability`; on a mutable field it actually clears. Collapsed
// onto `ExternalID == ""`, the first silently succeeded and the second was a
// silent no-op.
//
// NO-OP: an identity provider re-asserting current truth on every
// reconciliation cycle must not bump `meta.lastModified` or emit an update
// event. A trail full of updates that updated nothing is a trail nobody reads.
func TestSCIMPresenceAndNoOpSQLite(t *testing.T) {
	runSCIMPresenceAndNoOp(t, seededDB(t, openSQLite))
}
func TestSCIMPresenceAndNoOpPostgres(t *testing.T) {
	runSCIMPresenceAndNoOp(t, seededDB(t, openPostgres))
}

func runSCIMPresenceAndNoOp(t *testing.T, db *store.DB) {
	_, _, call := scimWireServer(t, db, "okta")

	status, user := call(http.MethodPost, "/Users", map[string]any{
		"schemas":  []string{scimproto.SchemaUser},
		"userName": "presence@example.test", "externalId": "presence-sub", "active": true,
	})
	if status != http.StatusCreated {
		t.Fatalf("create = %d %v", status, user)
	}
	id, _ := user["id"].(string)

	// The binding's subject source IS `externalId`, so removing it is the
	// identity mutation write-once refuses — by REMOVAL, the third route to the
	// same place after PUT-with-a-different-value and PATCH-with-a-value.
	if status, body := call(http.MethodPatch, "/Users/"+id, map[string]any{
		"schemas":    []string{scimproto.SchemaPatchOp},
		"Operations": []any{map[string]any{"op": "remove", "path": "externalId"}},
	}); status != http.StatusBadRequest || body["scimType"] != scimproto.TypeMutability {
		t.Fatalf("removing the subject source must be `mutability`: %d %v", status, body)
	}
	if status, body := call(http.MethodGet, "/Users/"+id, nil); status != http.StatusOK ||
		body["externalId"] != "presence-sub" {
		t.Fatalf("the refused removal must have changed nothing: %d %v", status, body)
	}

	// On a GROUP the same attribute is ordinary display metadata, so an
	// explicit removal genuinely clears it — which omission does not.
	status, group := call(http.MethodPost, "/Groups", map[string]any{
		"schemas": []string{scimproto.SchemaGroup}, "displayName": "Presence",
		"externalId": "grp-presence",
	})
	if status != http.StatusCreated {
		t.Fatalf("group create = %d %v", status, group)
	}
	gid, _ := group["id"].(string)
	// Omission first: a PATCH that never mentions externalId leaves it alone.
	if status, body := call(http.MethodPatch, "/Groups/"+gid, map[string]any{
		"schemas":    []string{scimproto.SchemaPatchOp},
		"Operations": []any{map[string]any{"op": "replace", "path": "displayName", "value": "Presence II"}},
	}); status != http.StatusOK || body["externalId"] != "grp-presence" {
		t.Fatalf("omission must not clear externalId: %d %v", status, body)
	}
	// Then the explicit removal, which must.
	if status, body := call(http.MethodPatch, "/Groups/"+gid, map[string]any{
		"schemas":    []string{scimproto.SchemaPatchOp},
		"Operations": []any{map[string]any{"op": "remove", "path": "externalId"}},
	}); status != http.StatusOK {
		t.Fatalf("an explicit removal = %d %v", status, body)
	} else if _, present := body["externalId"]; present {
		t.Fatalf("an explicit removal must clear the attribute: %v", body)
	}

	// The no-op. `scim.user_updated` specifically: the request still records
	// CONTACT and may still clear a staleness warning, which is correct — what
	// it must not do is claim the resource changed.
	updates := func() int64 {
		return queryInt(t, db,
			`SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'scim.user_updated'`)
	}
	status, before := call(http.MethodGet, "/Users/"+id, nil)
	if status != http.StatusOK {
		t.Fatalf("read-back = %d %v", status, before)
	}
	beforeMeta, _ := before["meta"].(map[string]any)
	countBefore := updates()

	// The identical PUT an idle reconciliation cycle sends.
	if status, body := call(http.MethodPut, "/Users/"+id, map[string]any{
		"schemas": []string{scimproto.SchemaUser}, "userName": "presence@example.test",
	}); status != http.StatusOK {
		t.Fatalf("idempotent PUT = %d %v", status, body)
	}
	status, after := call(http.MethodGet, "/Users/"+id, nil)
	if status != http.StatusOK {
		t.Fatalf("read-back = %d %v", status, after)
	}
	afterMeta, _ := after["meta"].(map[string]any)
	if beforeMeta["lastModified"] != afterMeta["lastModified"] {
		t.Fatalf("a request that changed nothing moved lastModified: %v -> %v",
			beforeMeta["lastModified"], afterMeta["lastModified"])
	}
	if got := updates() - countBefore; got != 0 {
		t.Fatalf("a request that changed nothing emitted %d scim.user_updated events", got)
	}
	// The control: a REAL change does both.
	if status, body := call(http.MethodPatch, "/Users/"+id, map[string]any{
		"schemas":    []string{scimproto.SchemaPatchOp},
		"Operations": []any{map[string]any{"op": "replace", "path": "nickName", "value": "P"}},
	}); status != http.StatusOK {
		t.Fatalf("a real change = %d %v", status, body)
	}
	if got := updates() - countBefore; got != 1 {
		t.Fatalf("a real change must emit exactly one scim.user_updated, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// SC4.c: admission, at the wire
// ---------------------------------------------------------------------------

// TestSCIMWireAdmissionOverHTTP is SC4.c as an identity provider experiences
// it. The service-level fixture compares Go error text; this compares the
// RESPONSES: exact status and exact body bytes for a revoked credential versus
// one that names nothing, the page bound answered as a clamp rather than a
// refusal, and the body bound answered by name.
func TestSCIMWireAdmissionOverHTTPSQLite(t *testing.T) {
	runSCIMWireAdmissionOverHTTP(t, seededDB(t, openSQLite))
}
func TestSCIMWireAdmissionOverHTTPPostgres(t *testing.T) {
	runSCIMWireAdmissionOverHTTP(t, seededDB(t, openPostgres))
}

func runSCIMWireAdmissionOverHTTP(t *testing.T, db *store.DB) {
	bindingID, mount, call := scimWireServer(t, db, "okta")
	base := mount + bindingID
	svc := &service.SCIM{DB: db}

	// A SECOND credential on the same binding, then revoked: a value that was
	// real and is not any more.
	revoked, err := svc.MintCredential(t.Context(), service.LocalPrincipal(orgAdmin), wireOrg, bindingID, false, "")
	if err != nil {
		t.Fatal(err)
	}
	creds, err := svc.ListCredentials(t.Context(), service.LocalPrincipal(orgAdmin), wireOrg, bindingID)
	if err != nil {
		t.Fatal(err)
	}
	var newest string
	for _, c := range creds {
		if c.RevokedAt.IsZero() {
			newest = c.ID
		}
	}
	if err := svc.RevokeCredential(t.Context(), service.LocalPrincipal(orgAdmin), wireOrg, bindingID, newest); err != nil {
		t.Fatal(err)
	}
	// A live credential of this fixture's own, for the legs that need the raw
	// response bytes rather than the decoded map.
	live, err := svc.MintCredential(t.Context(), service.LocalPrincipal(orgAdmin), wireOrg, bindingID, false, "")
	if err != nil {
		t.Fatal(err)
	}

	// A well-formed value of the same artifact type that names nothing.
	unknown, _, err := crypto.NewArtifact(crypto.ArtifactSCIM)
	if err != nil {
		t.Fatal(err)
	}

	deadStatus, deadBytes, _ := scimRawResponse(t, http.MethodGet, base+"/Users", revoked.Token, nil)
	unknownStatus, unknownBytes, _ := scimRawResponse(t, http.MethodGet, base+"/Users", unknown, nil)
	if deadStatus != http.StatusUnauthorized || unknownStatus != http.StatusUnauthorized {
		t.Fatalf("both must be 401: revoked=%d unknown=%d", deadStatus, unknownStatus)
	}
	// THE BYTES OFF THE SOCKET, not a re-marshalled map: key order, whitespace
	// and number formatting are part of what an attacker measures, and a
	// round trip through this test's own encoder would normalize all of them
	// away. A body that differed by one word would let a caller enumerate
	// which credentials once existed.
	if !bytes.Equal(deadBytes, unknownBytes) {
		t.Fatalf("a revoked credential and an unknown one answer differently:\n  revoked: %q\n  unknown: %q",
			deadBytes, unknownBytes)
	}
	// The control: the binding's LIVE credential still works, so the two 401s
	// above are the admission decision and not a broken mount.
	if status, body := call(http.MethodGet, "/Users", nil); status != http.StatusOK {
		t.Fatalf("the live credential must still authenticate: %d %v", status, body)
	}

	// The page bound is a CLAMP (RFC 7644 §3.4.2.4 makes `count` a request),
	// answered with the bound rather than refused.
	bound := svc.PageBound()
	if bound <= 0 {
		t.Fatal("the page bound must be positive for this assertion to mean anything")
	}
	for range 3 {
		if status, body := call(http.MethodPost, "/Users", map[string]any{
			"schemas": []string{scimproto.SchemaUser}, "userName": randomUserName(t), "externalId": randomUserName(t),
		}); status != http.StatusCreated {
			t.Fatalf("admission fixture user = %d %v", status, body)
		}
	}
	// EXACTLY the bound, on both members: a page that reported the bound in
	// `itemsPerPage` while returning a different number of resources would be
	// lying about its own answer, and `<= bound` accepts a server that returns
	// one row and calls it a page.
	for range bound {
		if status, body := call(http.MethodPost, "/Users", map[string]any{
			"schemas":  []string{scimproto.SchemaUser},
			"userName": randomUserName(t), "externalId": randomUserName(t),
		}); status != http.StatusCreated {
			t.Fatalf("admission fixture user = %d %v", status, body)
		}
	}
	status, body := call(http.MethodGet, "/Users?count=999999", nil)
	if status != http.StatusOK {
		t.Fatalf("an over-large count must be CLAMPED, not refused: %d %v", status, body)
	}
	if got := numberField(t, body, "itemsPerPage"); got != bound {
		t.Fatalf("itemsPerPage = %d, want exactly this provider's bound of %d", got, bound)
	}
	if resources, _ := body["Resources"].([]any); len(resources) != bound {
		t.Fatalf("the page carries %d resources but the bound is %d", len(resources), bound)
	}
	if got := numberField(t, body, "totalResults"); got <= bound {
		t.Fatalf("the directory must exceed the bound for the clamp to mean anything, totalResults = %d", got)
	}

	// The body bound is a REFUSAL, by name, with ONE status: 413. An oversized
	// body is an admission decision, not an invalid resource — and, like every
	// other wire refusal, it is ranked behind authentication.
	huge := map[string]any{
		"schemas": []string{scimproto.SchemaUser}, "userName": "huge@example.test",
		"externalId": "huge", "nickName": strings.Repeat("x", (1<<20)+1024),
	}
	if status, _, unauth := scimRawResponse(t, http.MethodPost, base+"/Users", "hik_1_scim_notatoken", huge); status != http.StatusUnauthorized {
		t.Fatalf("an over-bound body, unauthenticated = %d, want 401: %v", status, unauth)
	}
	status, hugeBytes, hugeBody := scimRawResponse(t, http.MethodPost, base+"/Users", live.Token, huge)
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("an over-bound body = %d, want exactly 413: %v", status, hugeBody)
	}
	// The exact body, byte for byte: the ADR names this refusal, so its
	// rendering is pinned rather than merely "an error of some kind".
	wantBytes, err := json.Marshal(scimproto.ErrBodyTooLarge.Body())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(hugeBytes), wantBytes) {
		t.Fatalf("the over-bound refusal body drifted:\n  got:  %s\n  want: %s", hugeBytes, wantBytes)
	}
}

// randomUserName is a unique userName per call; the admission fixture needs
// several users and `userName` is unique within a binding.
func randomUserName(t *testing.T) string {
	t.Helper()
	id, _, err := crypto.NewArtifact(crypto.ArtifactSCIM)
	if err != nil {
		t.Fatal(err)
	}
	return id[len(id)-12:] + "@example.test"
}

// ---------------------------------------------------------------------------
// SC4.j: the discovery annotation
// ---------------------------------------------------------------------------

// TestSCIMDiscoveryIsAnnotatedNotSilent is §10's discovery clause: the
// discovery endpoints "are the one SCIM surface annotated `audited: none`-
// equivalent by explicit registry annotation on their probe class, NOT silence".
//
// Three things have to hold together, and each fails differently:
//
//  1. the registry says so — `scim-discovery.read` declares no event type and
//     carries a reasoned, name-pinned annotation;
//  2. a real discovery request emits nothing;
//  3. and the annotation did not leak: a real directory read still emits its
//     `scim.directory_read`, so this is an exemption for the manual, not for
//     the tenant data beside it.
func TestSCIMDiscoveryIsAnnotatedNotSilentSQLite(t *testing.T) {
	runSCIMDiscoveryIsAnnotatedNotSilent(t, seededDB(t, openSQLite))
}
func TestSCIMDiscoveryIsAnnotatedNotSilentPostgres(t *testing.T) {
	runSCIMDiscoveryIsAnnotatedNotSilent(t, seededDB(t, openPostgres))
}

// TestSCIMWireMismatchOverDiscovery is SC1.l over the WIRE: a credential
// presented against a binding it does not belong to is a named authentication
// failure, audited, never a SCIM 400 (§8) — and it must hold on the discovery
// routes too.
//
// It is a fixture in its own right because discovery is the one operation that
// declares no event types of its own: `scim.credential_refused`, emitted before
// any operation authorizes, is its ENTIRE audit linkage. Nothing else exercises
// the mismatch path over a route whose operation carries no audit declaration,
// so nothing else would notice if narrowing that declaration broke the refusal.
func TestSCIMWireMismatchOverDiscoverySQLite(t *testing.T) {
	runSCIMWireMismatchOverDiscovery(t, seededDB(t, openSQLite))
}
func TestSCIMWireMismatchOverDiscoveryPostgres(t *testing.T) {
	runSCIMWireMismatchOverDiscovery(t, seededDB(t, openPostgres))
}

func runSCIMWireMismatchOverDiscovery(t *testing.T, db *store.DB) {
	bindingID, mount, call := scimWireServer(t, db, "okta")

	// A SECOND live binding in the same org, on its own provider, with its own
	// credential. Both are genuine; only the pairing is wrong.
	svc := scimSvc(db)
	seedSCIMProvider(t, db, "second-idp", "https://second-idp.example.test", true)
	other, err := svc.CreateBinding(t.Context(), service.LocalPrincipal(orgAdmin), wireOrg,
		service.SCIMBindingInput{
			ProviderKind: domain.ProviderOIDC, ProviderSlug: "second-idp",
			SubjectSource: domain.SubjectSourceExternalID,
		})
	if err != nil {
		t.Fatalf("second binding: %v", err)
	}
	otherMint, err := svc.MintCredential(t.Context(), service.LocalPrincipal(orgAdmin), wireOrg, other.ID, false, "")
	if err != nil {
		t.Fatalf("second credential: %v", err)
	}

	// The refusal lands on the INSTANCE trail: it is decided before any org is
	// resolved, so there is no tenant to file it under.
	refused := func() int64 {
		return queryInt(t, db,
			`SELECT COUNT(*) FROM audit_instance_events WHERE type = 'scim.credential_refused'`)
	}
	before := refused()
	status, body := scimRawRequest(t, http.MethodGet,
		mount+bindingID+"/ServiceProviderConfig", otherMint.Token, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("a credential presented against another binding's discovery route = %d, want 401: %v",
			status, body)
	}
	if _, has := body["scimType"]; has {
		t.Fatalf("an authentication failure is never a SCIM 400: %v", body)
	}
	if got := refused() - before; got != 1 {
		t.Fatalf("the mismatch must be audited exactly once, got %d new scim.credential_refused rows", got)
	}
	// The credential is not broken, only mispaired: on its OWN binding it works,
	// and the correct pairing on the probed binding works too.
	if status, body := scimRawRequest(t, http.MethodGet,
		mount+other.ID+"/ServiceProviderConfig", otherMint.Token, nil); status != http.StatusOK {
		t.Fatalf("the same credential on its own binding = %d %v", status, body)
	}
	if status, body := call(http.MethodGet, "/ServiceProviderConfig", nil); status != http.StatusOK {
		t.Fatalf("the probed binding's own credential = %d %v", status, body)
	}
}

func runSCIMDiscoveryIsAnnotatedNotSilent(t *testing.T, db *store.DB) {
	// 1. The registry annotation, in both halves: no declared event, and a
	//    pinned reason. Silence would be the operation simply having no events
	//    and no entry, which the audit-completeness invariant rejects outright —
	//    so the pin IS the annotation.
	const op = "scim-discovery.read"
	mapping, ok := facts.AuditMappings()[authz.Operation(op)]
	if !ok {
		t.Fatalf("%s is not a registered operation", op)
	}
	if len(mapping.Events) != 0 {
		t.Fatalf("%s declares event types %v; §10 annotates the probe class audited-none-equivalent",
			op, mapping.Events)
	}
	reason, pinned := loadAuditExemptions(t).Operations[op]
	if !pinned {
		t.Fatalf("%s carries no explicit annotation — §10 demands annotation, not silence", op)
	}
	if len(reason) < 40 {
		t.Fatalf("%s's annotation is not a reason, it is a placeholder: %q", op, reason)
	}

	// 2. A real probe of all three documents emits nothing.
	_, _, call := scimWireServer(t, db, "okta")
	reads := func() int64 {
		return queryInt(t, db,
			`SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'scim.directory_read'`)
	}
	before := reads()
	for _, doc := range []string{"/ServiceProviderConfig", "/ResourceTypes", "/Schemas"} {
		if status, body := call(http.MethodGet, doc, nil); status != http.StatusOK {
			t.Fatalf("%s = %d %v", doc, status, body)
		}
	}
	if got := reads() - before; got != 0 {
		t.Fatalf("three discovery probes emitted %d scim.directory_read events; the probe class is annotated audited-none-equivalent", got)
	}

	// 3. The positive control: a directory read beside them still records. An
	//    exemption that silenced the reads carrying tenant data would pass (2)
	//    and be exactly the hole §10 forbids.
	before = reads()
	if status, body := call(http.MethodGet, "/Users", nil); status != http.StatusOK {
		t.Fatalf("GET /Users = %d %v", status, body)
	}
	if got := reads() - before; got != 1 {
		t.Fatalf("a directory list must emit exactly one scim.directory_read, got %d", got)
	}
	// And it says WHICH surface it was, so the two are distinguishable in the
	// trail rather than merged.
	kind := queryString(t, db,
		`SELECT payload FROM audit_tenant_events WHERE type = 'scim.directory_read' `+
			`ORDER BY seq DESC LIMIT 1`)
	if !strings.Contains(kind, `"user"`) {
		t.Fatalf("the recorded read does not name its resource type: %s", kind)
	}
}
