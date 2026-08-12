package scimproto

import (
	"net/http"
	"strings"
	"testing"
)

// The closed PATCH operation x path matrix (#73 §8), one fixture PER CELL.
//
// The matrix is per-resource: `active` cells apply to Users only and `members`
// cells to Groups only, so a cross-resource path refuses with `invalidPath`
// rather than being quietly ignored. Every accepted cell and every refused cell
// is named here, because "the matrix is closed" is only true if the closure is
// what is tested.
func TestPatchMatrixCells(t *testing.T) {
	cases := []struct {
		name     string
		res      Resource
		body     string
		wantKind PathKind
		wantErr  string // "" = accepted; otherwise the expected scimType
	}{
		// --- add ---
		{"add/pathless-merge", ResourceUser,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","value":{"userName":"a"}}]}`, PathNone, ""},
		{"add/plain", ResourceUser,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"externalId","value":"x"}]}`, PathPlain, ""},
		{"add/active", ResourceUser,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"active","value":true}]}`, PathActive, ""},
		{"add/members", ResourceGroup,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"value":"u1"}]}]}`, PathMembers, ""},
		{"add/members-filtered-REFUSED", ResourceGroup,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members[value eq \"u1\"]","value":"x"}]}`, 0, TypeInvalidPath},

		// --- replace ---
		{"replace/pathless-merge", ResourceUser,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"userName":"a"}}]}`, PathNone, ""},
		{"replace/plain", ResourceUser,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"externalId","value":"x"}]}`, PathPlain, ""},
		{"replace/active", ResourceUser,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`, PathActive, ""},
		{"replace/members", ResourceGroup,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"members","value":[{"value":"u1"}]}]}`, PathMembers, ""},
		{"replace/members-filtered-REFUSED", ResourceGroup,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"members[value eq \"u1\"]","value":"x"}]}`, 0, TypeInvalidPath},

		// --- remove ---
		{"remove/pathless-REFUSED", ResourceUser,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove"}]}`, 0, TypeInvalidPath},
		{"remove/plain-nonrequired", ResourceUser,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"externalId"}]}`, PathPlain, ""},
		{"remove/plain-required-REFUSED", ResourceUser,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"userName"}]}`, 0, TypeInvalidPath},
		{"remove/active-REFUSED", ResourceUser,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"active"}]}`, 0, TypeInvalidPath},
		{"remove/members-clear", ResourceGroup,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members"}]}`, PathMembers, ""},
		{"remove/members-filtered", ResourceGroup,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members[value eq \"u1\"]"}]}`, PathMemberValue, ""},
		// A members filter outside the matrix is an unaccepted CELL, so §8's
		// closed mapping says `invalidPath` — nothing is wrong with the value.
		{"remove/members-filtered-on-display-REFUSED", ResourceGroup,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members[display eq \"Dee\"]"}]}`, 0, TypeInvalidPath},

		// --- cross-resource: the matrix is PER RESOURCE ---
		{"members-on-a-User-REFUSED", ResourceUser,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[]}]}`, 0, TypeInvalidPath},
		{"active-on-a-Group-REFUSED", ResourceGroup,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":true}]}`, 0, TypeInvalidPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ops, e := ParsePatch([]byte(tc.body), tc.res)
			if tc.wantErr != "" {
				if e == nil {
					t.Fatalf("cell accepted but the matrix refuses it")
				}
				if e.SCIMType != tc.wantErr {
					t.Fatalf("scimType = %q, want %q", e.SCIMType, tc.wantErr)
				}
				if e.Status != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400", e.Status)
				}
				return
			}
			if e != nil {
				t.Fatalf("cell refused but the matrix accepts it: %v", e)
			}
			if len(ops) != 1 || ops[0].Kind != tc.wantKind {
				t.Fatalf("kind = %v, want %v", ops[0].Kind, tc.wantKind)
			}
		})
	}
}

// A PatchOp message must declare its schema; §8's error mapping puts a missing
// required member at `invalidValue`.
func TestPatchRequiresItsSchema(t *testing.T) {
	for _, body := range []string{
		`{"Operations":[{"op":"add","path":"externalId","value":"x"}]}`,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"Operations":[{"op":"add","path":"externalId","value":"x"}]}`,
	} {
		if _, e := ParsePatch([]byte(body), ResourceUser); e == nil || e.SCIMType != TypeInvalidValue {
			t.Fatalf("%s: want invalidValue, got %v", body, e)
		}
	}
}

// The value's SHAPE is part of the matrix cell, not a later concern.
func TestPatchValueShapeIsValidated(t *testing.T) {
	const head = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[`
	for name, body := range map[string]string{
		"pathless scalar": head + `{"op":"add","value":"nope"}]}`,
		"active null":     head + `{"op":"replace","path":"active","value":null}]}`,
		"members scalar":  head + `{"op":"add","path":"members","value":"u1"}]}`,
		"plain null":      head + `{"op":"replace","path":"externalId","value":null}]}`,
	} {
		res := ResourceUser
		if strings.Contains(body, "members") {
			res = ResourceGroup
		}
		if _, e := ParsePatch([]byte(body), res); e == nil || e.SCIMType != TypeInvalidValue {
			t.Fatalf("%s: want invalidValue, got %v", name, e)
		}
	}
}

// A malformed attribute path is `invalidPath`, not an accepted plain cell.
func TestPatchRejectsMalformedAttributePaths(t *testing.T) {
	const head = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[`
	for _, path := range []string{"foo bar", "()", "1abc", "-x", "foo/bar"} {
		body := head + `{"op":"replace","path":"` + path + `","value":"v"}]}`
		if _, e := ParsePatch([]byte(body), ResourceUser); e == nil || e.SCIMType != TypeInvalidPath {
			t.Fatalf("%q: want invalidPath, got %v", path, e)
		}
	}
	// Required attributes are refused case-INSENSITIVELY.
	for _, attr := range []string{"userName", "UserName", "ID"} {
		body := head + `{"op":"remove","path":"` + attr + `"}]}`
		if _, e := ParsePatch([]byte(body), ResourceUser); e == nil || e.SCIMType != TypeInvalidPath {
			t.Fatalf("remove %q: want invalidPath, got %v", attr, e)
		}
	}
	// A recognised members filter naming nothing is `noTarget`, not invalidPath.
	body := head + `{"op":"remove","path":"members[value eq \"\"]"}]}`
	if _, e := ParsePatch([]byte(body), ResourceGroup); e == nil || e.SCIMType != TypeNoTarget {
		t.Fatalf("empty members filter: want noTarget, got %v", e)
	}
}

// A crafted non-ASCII attribute must not panic the length-preserving scan.
func TestFilterScanIsLengthPreserving(t *testing.T) {
	for _, raw := range []string{
		"\u212a eq \"x\"", "K eq \"x\"", "\u0130 eq \"x\"",
		strings.Repeat("\u212a", 40) + ` eq "x"`,
	} {
		// The only requirement is that it does not panic; refusal is expected.
		if _, e := ParseFilter(raw, ResourceUser); e == nil {
			t.Fatalf("%q parsed unexpectedly", raw)
		}
	}
}

// Entra's stringified booleans must survive DECODING, not just normalization:
// a *bool struct tag rejected `"True"` before the tolerance could apply.
func TestDecodeUserAcceptsStringifiedActive(t *testing.T) {
	u, e := DecodeUser([]byte(`{"userName":"a@b.test","active":"False"}`))
	if e != nil {
		t.Fatalf("decode: %v", e)
	}
	if u.Active == nil || *u.Active {
		t.Fatalf("active = %v, want false", u.Active)
	}
	// And every case variant of `password` is still refused.
	for _, k := range []string{"password", "Password", "PASSWORD"} {
		if _, e := DecodeUser([]byte(`{"userName":"a","` + k + `":"x"}`)); e == nil {
			t.Fatalf("%q accepted", k)
		}
	}
}

// A PATCH is ATOMIC: any invalid operation fails the whole request with nothing
// committed, so validation happens for EVERY operation before any is applied.
func TestPatchIsAtomicOnOneInvalidOperation(t *testing.T) {
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"externalId","value":"fine"},
		{"op":"remove","path":"active"}
	]}`
	if _, e := ParsePatch([]byte(body), ResourceUser); e == nil {
		t.Fatal("a request with one invalid operation must fail whole")
	} else if e.SCIMType != TypeInvalidPath {
		t.Fatalf("scimType = %q, want invalidPath", e.SCIMType)
	}
}

// Entra sends stringified booleans for `active`. That is a NAMED tolerance,
// not a general string-to-bool coercion.
func TestNormalizeActiveTolerance(t *testing.T) {
	for _, in := range []any{true, "True", "true", "TRUE "} {
		v, e := NormalizeActive(in)
		if e != nil || !v {
			t.Fatalf("%v: got (%v, %v), want (true, nil)", in, v, e)
		}
	}
	for _, in := range []any{false, "False", "false"} {
		v, e := NormalizeActive(in)
		if e != nil || v {
			t.Fatalf("%v: got (%v, %v), want (false, nil)", in, v, e)
		}
	}
	for _, in := range []any{"yes", "1", 1, nil} {
		if _, e := NormalizeActive(in); e == nil || e.SCIMType != TypeInvalidValue {
			t.Fatalf("%v: want invalidValue, got %v", in, e)
		}
	}
}

// The closed filter grammar: the four probes Okta and Entra actually issue,
// and nothing else.
func TestFilterGrammarIsClosed(t *testing.T) {
	accepted := []struct {
		raw   string
		res   Resource
		shape FilterShape
		value string
	}{
		{``, ResourceUser, FilterNone, ""},
		{`userName eq "a@b.test"`, ResourceUser, FilterUserNameEq, "a@b.test"},
		{`externalId eq "ext-1"`, ResourceUser, FilterExternalIDEq, "ext-1"},
		{`displayName eq "Engineering"`, ResourceGroup, FilterDisplayNameEq, "Engineering"},
		// The value is a JSON string literal, so a group whose NAME contains a
		// logical operator or a paren is a perfectly ordinary discovery probe.
		// A naive substring scan refused these, which broke Okta's and Entra's
		// group discovery for any group called "Sales and Marketing".
		{`displayName eq "Sales and Marketing"`, ResourceGroup, FilterDisplayNameEq, "Sales and Marketing"},
		{`displayName eq "Support or Ops"`, ResourceGroup, FilterDisplayNameEq, "Support or Ops"},
		{`displayName eq "R&D (EU)"`, ResourceGroup, FilterDisplayNameEq, "R&D (EU)"},
		{`displayName eq "not applicable"`, ResourceGroup, FilterDisplayNameEq, "not applicable"},
		{`displayName eq "Say \"hi\""`, ResourceGroup, FilterDisplayNameEq, `Say "hi"`},
		{`userName eq "a and b@example.test"`, ResourceUser, FilterUserNameEq, "a and b@example.test"},
		{`externalId eq "grp-1"`, ResourceGroup, FilterExternalIDEq, "grp-1"},
	}
	for _, tc := range accepted {
		f, e := ParseFilter(tc.raw, tc.res)
		if e != nil {
			t.Fatalf("%q: refused: %v", tc.raw, e)
		}
		if f.Shape != tc.shape || f.Value != tc.value {
			t.Fatalf("%q: got (%v, %q), want (%v, %q)", tc.raw, f.Shape, f.Value, tc.shape, tc.value)
		}
	}
	refused := []struct {
		raw string
		res Resource
	}{
		{`userName sw "a"`, ResourceUser},
		{`userName eq "a" and externalId eq "b"`, ResourceUser},
		{`not (userName eq "a")`, ResourceUser},
		{`emails.value eq "a@b.test"`, ResourceUser},
		{`meta.lastModified gt "2026-01-01T00:00:00Z"`, ResourceUser},
		// displayName is a GROUP attribute; on a User it is not filterable.
		{`displayName eq "Engineering"`, ResourceUser},
		// userName is a USER attribute; on a Group it is not filterable.
		{`userName eq "a"`, ResourceGroup},
		{`userName eq unquoted`, ResourceUser},
		// Quote-awareness must not become quote-blindness: a genuine compound
		// filter is still refused, and so is an unterminated literal.
		{`displayName eq "Sales" and externalId eq "g1"`, ResourceGroup},
		{`displayName eq "unterminated`, ResourceGroup},
		{`(displayName eq "Sales")`, ResourceGroup},
		{`not displayName eq "Sales"`, ResourceGroup},
	}
	for _, tc := range refused {
		if _, e := ParseFilter(tc.raw, tc.res); e == nil || e.SCIMType != TypeInvalidFilter {
			t.Fatalf("%q: want invalidFilter, got %v", tc.raw, e)
		}
	}
}

// RFC 7644 paging: 1-based, bounded, and an out-of-range page yields an empty
// resource list while the caller still reports a truthful total.
func TestPagingIsOneBasedAndBounded(t *testing.T) {
	p, e := ParsePage("", "", 200)
	if e != nil || p.StartIndex != 1 || p.Count != 200 {
		t.Fatalf("defaults = %+v (%v)", p, e)
	}
	// A value below 1 is interpreted as 1, per the RFC.
	if p, _ := ParsePage("0", "", 200); p.StartIndex != 1 {
		t.Fatalf("startIndex 0 must clamp to 1, got %d", p.StartIndex)
	}
	// `count` is a REQUEST; the server's bound is the answer.
	if p, _ := ParsePage("1", "9999", 200); p.Count != 200 {
		t.Fatalf("count must clamp to the bound, got %d", p.Count)
	}
	if _, e := ParsePage("nope", "", 200); e == nil || e.SCIMType != TypeInvalidValue {
		t.Fatalf("non-integer startIndex: want invalidValue, got %v", e)
	}

	all := []int{1, 2, 3, 4, 5}
	if got := Slice(all, Page{StartIndex: 2, Count: 2}); len(got) != 2 || got[0] != 2 {
		t.Fatalf("page 2..3 = %v", got)
	}
	if got := Slice(all, Page{StartIndex: 99, Count: 10}); len(got) != 0 {
		t.Fatalf("out-of-range page must be empty, got %v", got)
	}
	body := ListResponse(5, Page{StartIndex: 99, Count: 10}, nil)
	if body["totalResults"] != 5 {
		t.Fatalf("an out-of-range page must still report the truthful total: %v", body["totalResults"])
	}
	if got := body["Resources"].([]any); len(got) != 0 {
		t.Fatalf("Resources must be an empty array, not null: %v", got)
	}
}

// The named refusals, each with its exact code (§8's closed error mapping).
func TestNamedRefusalsCarryTheirExactCodes(t *testing.T) {
	// `password` is refused BY NAME rather than dropped.
	if _, e := DecodeUser([]byte(`{"userName":"a","password":"hunter2"}`)); e == nil {
		t.Fatal("the password attribute must be refused")
	} else if e.SCIMType != TypeInvalidValue || e.Status != http.StatusBadRequest {
		t.Fatalf("password: got %d/%s, want 400/invalidValue", e.Status, e.SCIMType)
	}
	// Nested-group members and empty references are `invalidValue`.
	if e := CheckMembers([]Member{{Value: "g1", Type: "Group"}}); e == nil || e.SCIMType != TypeInvalidValue {
		t.Fatalf("nested group member: want invalidValue, got %v", e)
	}
	if e := CheckMembers([]Member{{Value: ""}}); e == nil || e.SCIMType != TypeInvalidValue {
		t.Fatalf("empty member reference: want invalidValue, got %v", e)
	}
	// The four unimplemented endpoint classes are HTTP 501 with NO scimType:
	// scimType is a 400-class discriminator, and inventing one for a 501 would
	// name a code the RFC does not define.
	for _, what := range []string{"Bulk", "/Me", "Sorting", ".search"} {
		e := NotImplemented(what)
		if e.Status != http.StatusNotImplemented {
			t.Fatalf("%s: status = %d, want 501", what, e.Status)
		}
		if e.SCIMType != "" {
			t.Fatalf("%s: a 501 must carry no scimType, got %q", what, e.SCIMType)
		}
		if _, ok := e.Body()["scimType"]; ok {
			t.Fatalf("%s: the rendered body must omit scimType entirely", what)
		}
	}
	// A credential-versus-binding mismatch is 401 — never a SCIM 400.
	if e := Unauthorized(); e.Status != http.StatusUnauthorized || e.SCIMType != "" {
		t.Fatalf("authentication failure: got %d/%s, want 401 with no scimType", e.Status, e.SCIMType)
	}
	// The remaining mapped codes exist and render.
	for _, e := range []*Error{
		ErrMutability("write-once"), ErrNoTarget("nothing there"),
		ErrInvalidValue("bad"), Conflict("taken"),
	} {
		body := e.Body()
		if body["schemas"].([]string)[0] != SchemaError {
			t.Fatalf("error body missing the SCIM error schema: %v", body)
		}
		if body["status"] == "" {
			t.Fatal("error body missing status")
		}
	}
}

// IdP-supplied strings are attacker-influencable free text at a trust
// boundary: bounded here, once, and nowhere later.
func TestIdPStringsAreBounded(t *testing.T) {
	long := `{"userName":"` + strings.Repeat("a", 2000) + `"}`
	if _, e := DecodeUser([]byte(long)); e == nil || e.SCIMType != TypeInvalidValue {
		t.Fatalf("an over-long userName must be refused: %v", e)
	}
	huge := make([]byte, (1<<20)+1)
	for i := range huge {
		huge[i] = ' '
	}
	if _, e := DecodeUser(huge); e == nil || e.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("an over-large body must be refused by name: %v", e)
	}
}

// The discovery documents are "the closed truth of what this server
// implements" (§8): every refusal this server makes must be READABLE there
// before a connector pushes anything.
// TestDiscoveryDescribesEverySchemaAResourceCanDeclare closes the loop the
// discovery documents exist to close: a rendered resource may declare only
// schemas `/ResourceTypes` advertises and `/Schemas` describes, and every one
// it advertises must be describable. A resource claiming conformance to a URI
// discovery never mentioned is the half-implemented state §8 forbids by name,
// and it used to be reachable — `SchemasFor` echoed any `urn:`-keyed attribute
// straight into `schemas`.
func TestDiscoveryDescribesEverySchemaAResourceCanDeclare(t *testing.T) {
	described := map[string]bool{}
	for _, r := range Schemas()["Resources"].([]any) {
		described[r.(map[string]any)["id"].(string)] = true
	}
	advertised := map[string]bool{}
	for _, r := range ResourceTypes()["Resources"].([]any) {
		m := r.(map[string]any)
		advertised[m["schema"].(string)] = true
		for _, e := range m["schemaExtensions"].([]any) {
			advertised[e.(map[string]any)["schema"].(string)] = true
		}
	}
	for schema := range advertised {
		if !described[schema] {
			t.Errorf("ResourceTypes advertises %s, which Schemas does not describe", schema)
		}
	}

	// The rendering side: an undeclared extension is STORED and returned as
	// display metadata (this server loses nothing an IdP sends) but never
	// appears in `schemas`.
	rendered := SchemasFor(map[string]any{
		SchemaEnterpriseExt:                      map[string]any{"department": "x"},
		"urn:example:params:scim:schemas:custom": map[string]any{"anything": "y"},
		"nickName":                               "z",
	})
	for _, schema := range rendered {
		if !advertised[schema] {
			t.Errorf("a rendered resource declares %s, which /ResourceTypes does not advertise", schema)
		}
	}
	if len(rendered) != 2 {
		t.Fatalf("want the core schema plus the one DECLARED extension present, got %v", rendered)
	}
}

func TestDiscoveryIsTheClosedTruth(t *testing.T) {
	types := ResourceTypes()
	resources, _ := types["Resources"].([]any)
	if len(resources) != 2 {
		t.Fatalf("the resource set is closed at User and Group, got %d", len(resources))
	}
	var sawUserExtension bool
	for _, r := range resources {
		m := r.(map[string]any)
		exts, ok := m["schemaExtensions"].([]any)
		if !ok {
			t.Fatalf("%v declares no schemaExtensions", m["id"])
		}
		if m["id"] == "User" {
			for _, e := range exts {
				if e.(map[string]any)["schema"] == SchemaEnterpriseExt {
					sawUserExtension = true
				}
			}
		}
	}
	if !sawUserExtension {
		t.Fatal("User must advertise the enterprise extension: a binding's subject source may live there")
	}

	byID := map[string]map[string]any{}
	for _, r := range Schemas()["Resources"].([]any) {
		m := r.(map[string]any)
		byID[m["id"].(string)] = m
	}
	for _, id := range []string{SchemaUser, SchemaGroup, SchemaEnterpriseExt} {
		schema, ok := byID[id]
		if !ok {
			t.Fatalf("/Schemas omits %s", id)
		}
		if attrs, _ := schema["attributes"].([]any); len(attrs) == 0 {
			t.Fatalf("%s carries no attribute definitions", id)
		}
	}
	// The advertised metadata must match the refusals the server actually
	// makes: userName is caseExact:false (which is WHY it is refused as a
	// subject source), externalId is byte-exact, groups is read-only.
	want := map[string]map[string]any{
		"userName":   {"caseExact": false, "required": true},
		"externalId": {"caseExact": true},
		"groups":     {"mutability": "readOnly"},
	}
	for _, a := range byID[SchemaUser]["attributes"].([]any) {
		m := a.(map[string]any)
		expected, tracked := want[m["name"].(string)]
		if !tracked {
			continue
		}
		for k, v := range expected {
			if m[k] != v {
				t.Errorf("User.%s: %s = %v, want %v", m["name"], k, m[k], v)
			}
		}
		delete(want, m["name"].(string))
	}
	if len(want) != 0 {
		t.Fatalf("/Schemas omits attributes this server has refusals about: %v", want)
	}
	// And ServiceProviderConfig's absences are the endpoints' refusals.
	spc := ServiceProviderConfig(200)
	for _, absent := range []string{"bulk", "sort", "etag", "changePassword"} {
		if spc[absent].(map[string]any)["supported"] != false {
			t.Errorf("ServiceProviderConfig advertises %s as supported; the endpoint refuses it", absent)
		}
	}
}
