package schema_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/schema"
)

// Declaration-time refusals. A rule may not be meaningless (schema-model ADR
// § Validation timing), so every one of these fails the SAVE — none of them
// is an advisory, and none of them is silently ignored.

func TestDeclarationRefusals(t *testing.T) {
	cases := []struct {
		name string
		decl schema.Declaration
		// the substring the refusal must name, so "rejected loud BY NAME" is
		// a property of the message and not only of the exit path
		names string
	}{
		{"unknown type", rule(schema.Rule{Type: "float"}), "float"},
		{"no rule at all", schema.Declaration{}, "exactly one"},
		{"rule and any_of together", schema.Declaration{
			Rule:  &schema.Rule{Type: schema.TypeString},
			AnyOf: []schema.Rule{{Type: schema.TypeString}},
		}, "exactly one"},
		{"any_of with one alternative", schema.Declaration{
			AnyOf: []schema.Rule{{Type: schema.TypeString}},
		}, "at least two"},
		{"any_of too many alternatives", schema.Declaration{
			AnyOf: make([]schema.Rule, schema.MaxAnyOfAlternatives+1),
		}, "alternatives"},

		{"backreference rejected", rule(schema.Rule{Type: schema.TypeString, Pattern: `(a)\1`}), "pattern"},
		{"lookahead rejected", rule(schema.Rule{Type: schema.TypeString, Pattern: `(?=a)b`}), "pattern"},
		{"pattern too long", rule(schema.Rule{
			Type: schema.TypeString, Pattern: strings.Repeat("a", schema.MaxPatternBytes+1),
		}), "pattern"},
		{"pattern on a non-string type", rule(schema.Rule{Type: schema.TypeInteger, Pattern: "x"}), "pattern"},

		{"enum without members", rule(schema.Rule{Type: schema.TypeEnum}), "members"},
		{"enum empty member", rule(schema.Rule{Type: schema.TypeEnum, Members: []string{"a", ""}}), "empty"},
		{"enum member empty after trim", rule(schema.Rule{Type: schema.TypeEnum, Members: []string{"a", "  "}}), "empty"},
		{"enum duplicate after trim", rule(schema.Rule{Type: schema.TypeEnum, Members: []string{"a", " a "}}), "distinct"},
		{"enum member with NUL", rule(schema.Rule{Type: schema.TypeEnum, Members: []string{"a", "b\x00c"}}), "NUL"},
		{"enum member not utf-8", rule(schema.Rule{Type: schema.TypeEnum, Members: []string{"a", "b\xffc"}}), "UTF-8"},
		{"too many enum members", rule(schema.Rule{
			Type: schema.TypeEnum, Members: manyMembers(schema.MaxEnumMembers + 1),
		}), "members"},

		{"url without schemes", rule(schema.Rule{Type: schema.TypeURL}), "schemes"},
		{"url empty scheme", rule(schema.Rule{Type: schema.TypeURL, Schemes: []string{""}}), "scheme"},

		{"integer min above max", rule(schema.Rule{
			Type: schema.TypeInteger, Min: i64p(5), Max: i64p(4),
		}), "min"},
		{"string min above max", rule(schema.Rule{
			Type: schema.TypeString, MinLength: intp(5), MaxLength: intp(4),
		}), "min_length"},
		{"negative length bound", rule(schema.Rule{Type: schema.TypeString, MinLength: intp(-1)}), "min_length"},
		{"members on a non-enum type", rule(schema.Rule{
			Type: schema.TypeString, Members: []string{"a"},
		}), "members"},
		{"schemes on a non-url type", rule(schema.Rule{
			Type: schema.TypeString, Schemes: []string{"https"},
		}), "schemes"},
		{"json schema on a non-json type", rule(schema.Rule{
			Type: schema.TypeString, JSONSchema: json.RawMessage(`{}`),
		}), "json_schema"},
		{"nested any_of", schema.Declaration{AnyOf: []schema.Rule{
			{Type: schema.TypeString}, {Type: "any_of"},
		}}, "any_of"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := schema.Compile(tc.decl)
			if err == nil {
				t.Fatalf("Compile accepted %+v", tc.decl)
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Fatalf("refusal %q does not name %q", err, tc.names)
			}
		})
	}
}

func TestSecretDeclarationRefusesValueLiteralsRecursively(t *testing.T) {
	cases := []struct {
		name string
		decl schema.Declaration
		want string
	}{
		{"enum rule", rule(schema.Rule{Type: schema.TypeEnum, Members: []string{"live-value"}}), "members"},
		{"any_of enum alternative", schema.Declaration{AnyOf: []schema.Rule{
			{Type: schema.TypeString},
			{Type: schema.TypeEnum, Members: []string{"live-value"}},
		}}, "members"},
		{"nested json schema const", rule(schema.Rule{Type: schema.TypeJSON, JSONSchema: json.RawMessage(
			`{"properties":{"nested":{"allOf":[{"const":"live-value"}]}}}`)}), "const"},
		{"nested json schema enum", rule(schema.Rule{Type: schema.TypeJSON, JSONSchema: json.RawMessage(
			`{"$defs":{"nested":{"enum":["live-value"]}}}`)}), "enum"},
		{"nested json schema examples", rule(schema.Rule{Type: schema.TypeJSON, JSONSchema: json.RawMessage(
			`{"items":{"examples":["live-value"]}}`)}), "examples"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := schema.CheckDeclarationClassification(schema.Secret, tc.decl)
			if err == nil || !strings.Contains(err.Error(), tc.want) ||
				!strings.Contains(err.Error(), "use `pattern`, or declassify the key") {
				t.Fatalf("secret declaration refusal = %v", err)
			}
		})
	}

	allowed := rule(schema.Rule{Type: schema.TypeJSON, JSONSchema: json.RawMessage(
		`{"properties":{"nested":{"type":"string","pattern":"^[A-Z]+$"}}}`)})
	if err := schema.CheckDeclarationClassification(schema.Secret, allowed); err != nil {
		t.Fatalf("pattern-only secret declaration refused: %v", err)
	}
	if err := schema.CheckDeclarationClassification(schema.Config, cases[0].decl); err != nil {
		t.Fatalf("config enum declaration refused: %v", err)
	}
}

func manyMembers(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, "m"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+itoa(i))
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// The JSON Schema profile is an allowlist, and every exclusion the ADR fixes
// is refused BY NAME rather than ignored — a schema must never appear to
// enforce something it does not.
func TestJSONSchemaProfileRefusals(t *testing.T) {
	cases := []struct {
		name   string
		schema string
		names  string
	}{
		{"format excluded", `{"type":"string","format":"email"}`, "format"},
		// There is no defaulting mechanism in this product at all, so a schema
		// that appears to declare one must be refused rather than accepted as
		// inert annotation data.
		{"default excluded", `{"type":"string","default":"x"}`, "default"},
		{"dynamicRef excluded", `{"$dynamicRef":"#node"}`, "$dynamicRef"},
		{"dynamicAnchor excluded", `{"$dynamicAnchor":"node"}`, "$dynamicAnchor"},
		{"unevaluatedProperties excluded", `{"unevaluatedProperties":false}`, "unevaluatedProperties"},
		{"unevaluatedItems excluded", `{"unevaluatedItems":false}`, "unevaluatedItems"},
		{"contains excluded", `{"contains":{"type":"string"}}`, "contains"},
		// The one remaining allowlisted keyword with superlinear cost. With it
		// out, the declaration-time work budget is a genuine step cap rather
		// than a size bound wearing its name.
		{"uniqueItems excluded", `{"type":"array","uniqueItems":true}`, "uniqueItems"},
		{"unknown keyword refused", `{"wenvSpecial":1}`, "wenvSpecial"},
		{"remote ref refused", `{"$ref":"https://example.test/s.json"}`, "$ref"},
		{"file ref refused", `{"$ref":"file:///etc/passwd"}`, "$ref"},
		{"dangling ref refused", `{"$ref":"#/$defs/missing"}`, "$ref"},
		{"self ref cycle refused", `{"$defs":{"a":{"$ref":"#/$defs/a"}},"$ref":"#/$defs/a"}`, "cycle"},
		{"mutual ref cycle refused", `{"$defs":{"a":{"$ref":"#/$defs/b"},"b":{"$ref":"#/$defs/a"}},"$ref":"#/$defs/a"}`, "cycle"},
		{"recursive containment cycle refused",
			`{"$defs":{"n":{"type":"object","properties":{"child":{"$ref":"#/$defs/n"}}}},"$ref":"#/$defs/n"}`, "cycle"},
		{"foreign dialect refused", `{"$schema":"http://json-schema.org/draft-07/schema#"}`, "$schema"},
		{"duplicate keys refused", `{"type":"object","type":"string"}`, "duplicate"},
		{"not an object or bool", `[1,2]`, "object"},
		{"malformed", `{`, "parse"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := schema.Compile(rule(schema.Rule{
				Type: schema.TypeJSON, JSONSchema: json.RawMessage(tc.schema),
			}))
			if err == nil {
				t.Fatalf("Compile accepted %s", tc.schema)
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Fatalf("refusal %q does not name %q", err, tc.names)
			}
		})
	}
}

func TestJSONSchemaBoundRefusals(t *testing.T) {
	deep := strings.Repeat(`{"properties":{"a":`, schema.MaxJSONSchemaDepth+2) + `{}` +
		strings.Repeat(`}}`, schema.MaxJSONSchemaDepth+2)
	if _, err := schema.Compile(rule(schema.Rule{
		Type: schema.TypeJSON, JSONSchema: json.RawMessage(deep),
	})); err == nil || !strings.Contains(err.Error(), "depth") {
		t.Fatalf("deep schema refusal = %v, want a depth bound", err)
	}

	var defs strings.Builder
	defs.WriteString(`{"$defs":{`)
	for i := range schema.MaxJSONSchemaSubschemas + 2 {
		if i > 0 {
			defs.WriteString(",")
		}
		defs.WriteString(`"d` + itoa(i) + `":{"type":"string"}`)
	}
	defs.WriteString(`}}`)
	_, err := schema.Compile(rule(schema.Rule{
		Type: schema.TypeJSON, JSONSchema: json.RawMessage(defs.String()),
	}))
	if err == nil || !strings.Contains(err.Error(), "subschema") {
		t.Fatalf("wide schema refusal = %v, want a subschema bound", err)
	}
	// The subschema bound IS the evaluation work budget: the refusal names the
	// step cap it derives from, so an operator learns what the number means.
	if !strings.Contains(err.Error(), "evaluation work budget") {
		t.Fatalf("the subschema refusal does not name the work budget: %v", err)
	}

	big := `{"description":"` + strings.Repeat("x", schema.MaxJSONSchemaBytes) + `"}`
	if _, err := schema.Compile(rule(schema.Rule{
		Type: schema.TypeJSON, JSONSchema: json.RawMessage(big),
	})); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("large schema refusal = %v, want a byte bound", err)
	}
}

func TestJSONSchemaProfileAccepts(t *testing.T) {
	for _, s := range []string{
		`true`,
		`{"type":"object","required":["a"],"properties":{"a":{"type":"string","minLength":1}}}`,
		`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"array","prefixItems":[{"type":"string"}],"items":false}`,
		`{"$defs":{"port":{"type":"integer","minimum":1,"maximum":65535}},"type":"object","properties":{"p":{"$ref":"#/$defs/port"}}}`,
		`{"anyOf":[{"type":"string"},{"type":"integer"}]}`,
	} {
		if _, err := schema.Compile(rule(schema.Rule{
			Type: schema.TypeJSON, JSONSchema: json.RawMessage(s),
		})); err != nil {
			t.Fatalf("Compile(%s) refused an in-profile schema: %v", s, err)
		}
	}
}

// The key-name grammar is the delivery surface's grammar, not a preference.
func TestKeyNameGrammar(t *testing.T) {
	for _, ok := range []string{"A", "_A", "DATABASE_URL", "X9", "_"} {
		if err := schema.CheckKeyName(ok); err != nil {
			t.Fatalf("CheckKeyName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a", "9A", "A-B", "A B", "Á", "A.B", strings.Repeat("A", schema.MaxKeyNameBytes+1)} {
		if err := schema.CheckKeyName(bad); err == nil {
			t.Fatalf("CheckKeyName(%q) accepted", bad)
		}
	}
}

// Round-tripping is byte-stable: the stored form is the canonical form, so
// two identical declarations dedupe and a semantic diff is a byte diff.
func TestCanonicalRoundTrip(t *testing.T) {
	d := schema.Declaration{Rule: &schema.Rule{
		Type: schema.TypeEnum, Members: []string{" b ", "a"},
	}}
	raw, err := schema.Canonical(d)
	if err != nil {
		t.Fatal(err)
	}
	back, err := schema.ParseDeclaration(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := schema.Canonical(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(again) {
		t.Fatalf("canonical form is not stable: %s vs %s", raw, again)
	}
	// The write-time trim applies to declared members too, so the stored
	// declaration is the one validation actually uses.
	if back.Rule.Members[0] != "b" && back.Rule.Members[1] != "b" {
		t.Fatalf("members not trimmed in the canonical form: %s", raw)
	}
	if _, err := schema.ParseDeclaration([]byte(`{"rule":{"type":"string"},"nope":1}`)); err == nil {
		t.Fatal("ParseDeclaration accepted an unknown field")
	}
}

// The value-dependent/metadata split is the reveal gate's input, so it is a
// tested property rather than a comment.
func TestValueDependentChange(t *testing.T) {
	base := schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString, MinLength: intp(1)}}
	same := schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString, MinLength: intp(1)}}
	tighter := schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString, MinLength: intp(2)}}
	if schema.ValueDependentChange(base, same) {
		t.Fatal("an identical declaration reported a value-dependent change")
	}
	if !schema.ValueDependentChange(base, tighter) {
		t.Fatal("a tightened minLength is a value-dependent change")
	}
}

// Canonical and Compile must not rewrite the caller's declaration. They are
// called on declarations the caller still holds — the reveal gate diffs both
// sides before anything is written — and a Rule copy shares its slices'
// backing arrays, so an in-place trim would be an invisible side effect.
func TestCanonicalDoesNotMutateItsInput(t *testing.T) {
	d := schema.Declaration{AnyOf: []schema.Rule{
		{Type: schema.TypeEnum, Members: []string{" a ", "b"}},
		{Type: schema.TypeURL, Schemes: []string{"HTTPS", " postgres "}},
	}}
	if _, err := schema.Canonical(d); err != nil {
		t.Fatal(err)
	}
	if _, err := schema.Compile(d); err != nil {
		t.Fatal(err)
	}
	if d.AnyOf[0].Members[0] != " a " {
		t.Fatalf("Canonical/Compile rewrote the caller's members: %q", d.AnyOf[0].Members[0])
	}
	if d.AnyOf[1].Schemes[0] != "HTTPS" || d.AnyOf[1].Schemes[1] != " postgres " {
		t.Fatalf("Canonical/Compile rewrote the caller's schemes: %q", d.AnyOf[1].Schemes)
	}
}
