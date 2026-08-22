package schema_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/schema"
)

// The value-validation engine's fixture table: one row per lexical rule the
// schema-model ADR fixes. Every row is a (declaration, value) pair with the
// verdict the ADR demands, so a rule that quietly changes meaning fails here
// before it reaches a publish.
//
// `want` is the verdict; `keyword` (when set) is the schema location the
// failure must name. Instance-derived text never appears in an expectation,
// because for a `secret` key it never appears in the failure either.

func intp(v int) *int     { return &v }
func i64p(v int64) *int64 { return &v }
func rule(r schema.Rule) schema.Declaration {
	return schema.Declaration{Rule: &r}
}

func compile(t *testing.T, classification schema.Classification, d schema.Declaration) *schema.Compiled {
	t.Helper()
	c, err := schema.CompileWithoutCompatibilityCheckForTest(classification, d)
	if err != nil {
		t.Fatalf("Compile(%+v): %v", d, err)
	}
	return c
}

func TestValueFixtures(t *testing.T) {
	cases := []struct {
		name    string
		decl    schema.Declaration
		value   string
		valid   bool
		keyword string
	}{
		// string
		{"string plain", rule(schema.Rule{Type: schema.TypeString}), "hello", true, ""},
		{"string empty refused by default", rule(schema.Rule{Type: schema.TypeString}), "", false, "allow_empty"},
		{"string empty allowed", rule(schema.Rule{Type: schema.TypeString, AllowEmpty: true}), "", true, ""},
		{"string whitespace-only trims to empty", rule(schema.Rule{Type: schema.TypeString}), "   ", false, "allow_empty"},
		{"string interior newline is data", rule(schema.Rule{Type: schema.TypeString}), "-----BEGIN\nkey\n-----END", true, ""},
		{"string trailing newline trimmed", rule(schema.Rule{Type: schema.TypeString, MaxLength: intp(3)}), "abc\n", true, ""},
		{"string min length", rule(schema.Rule{Type: schema.TypeString, MinLength: intp(4)}), "abc", false, "min_length"},
		{"string max length", rule(schema.Rule{Type: schema.TypeString, MaxLength: intp(2)}), "abc", false, "max_length"},
		{"string NUL refused", rule(schema.Rule{Type: schema.TypeString}), "ab\x00c", false, "nul"},
		{"string invalid utf-8 refused", rule(schema.Rule{Type: schema.TypeString}), "ab\xffc", false, "utf8"},

		// pattern — whole-value anchored, never a substring search
		{"pattern whole value", rule(schema.Rule{Type: schema.TypeString, Pattern: "[a-z]+"}), "abc", true, ""},
		{"pattern rejects substring match", rule(schema.Rule{Type: schema.TypeString, Pattern: "[a-z]+"}), "abc1", false, "pattern"},
		{"pattern anchored against prefix match", rule(schema.Rule{Type: schema.TypeString, Pattern: "A"}), "AB", false, "pattern"},

		// integer
		{"integer plain", rule(schema.Rule{Type: schema.TypeInteger}), "42", true, ""},
		{"integer negative", rule(schema.Rule{Type: schema.TypeInteger}), "-42", true, ""},
		{"integer leading zeros accepted", rule(schema.Rule{Type: schema.TypeInteger}), "007", true, ""},
		{"integer leading plus refused", rule(schema.Rule{Type: schema.TypeInteger}), "+7", false, "type"},
		{"integer underscore refused", rule(schema.Rule{Type: schema.TypeInteger}), "1_0", false, "type"},
		{"integer hex refused", rule(schema.Rule{Type: schema.TypeInteger}), "0x10", false, "type"},
		{"integer exponent refused", rule(schema.Rule{Type: schema.TypeInteger}), "1e3", false, "type"},
		{"integer int64 boundary", rule(schema.Rule{Type: schema.TypeInteger}), "9223372036854775807", true, ""},
		{"integer wider than int64 refused", rule(schema.Rule{Type: schema.TypeInteger}), "9223372036854775808", false, "magnitude"},
		{"integer min", rule(schema.Rule{Type: schema.TypeInteger, Min: i64p(10)}), "9", false, "min"},
		{"integer max", rule(schema.Rule{Type: schema.TypeInteger, Max: i64p(10)}), "11", false, "max"},
		{"integer range with leading zeros", rule(schema.Rule{Type: schema.TypeInteger, Max: i64p(10)}), "0009", true, ""},

		// boolean — canonical only, never coerced
		{"boolean true", rule(schema.Rule{Type: schema.TypeBoolean}), "true", true, ""},
		{"boolean false", rule(schema.Rule{Type: schema.TypeBoolean}), "false", true, ""},
		{"boolean TRUE refused", rule(schema.Rule{Type: schema.TypeBoolean}), "TRUE", false, "type"},
		{"boolean 1 refused", rule(schema.Rule{Type: schema.TypeBoolean}), "1", false, "type"},
		{"boolean yes refused", rule(schema.Rule{Type: schema.TypeBoolean}), "yes", false, "type"},

		// enum
		{"enum member", rule(schema.Rule{Type: schema.TypeEnum, Members: []string{"a", "b"}}), "a", true, ""},
		{"enum non-member", rule(schema.Rule{Type: schema.TypeEnum, Members: []string{"a", "b"}}), "c", false, "members"},

		// url
		{"url absolute in allowlist", rule(schema.Rule{Type: schema.TypeURL, Schemes: []string{"https"}}), "https://example.test/x", true, ""},
		{"url scheme case-insensitive", rule(schema.Rule{Type: schema.TypeURL, Schemes: []string{"https"}}), "HTTPS://example.test/x", true, ""},
		{"url scheme outside allowlist", rule(schema.Rule{Type: schema.TypeURL, Schemes: []string{"https"}}), "http://example.test", false, "schemes"},
		{"url relative refused", rule(schema.Rule{Type: schema.TypeURL, Schemes: []string{"https"}}), "/x/y", false, "absolute"},
		{"url opaque refused", rule(schema.Rule{Type: schema.TypeURL, Schemes: []string{"mailto"}}), "mailto:a@b.test", false, "absolute"},

		// json
		{"json object", rule(schema.Rule{Type: schema.TypeJSON}), `{"a":1}`, true, ""},
		{"json duplicate keys refused", rule(schema.Rule{Type: schema.TypeJSON}), `{"a":1,"a":2}`, false, "duplicate_key"},
		{"json nested duplicate keys refused", rule(schema.Rule{Type: schema.TypeJSON}), `{"o":{"a":1,"a":2}}`, false, "duplicate_key"},
		{"json trailing document refused", rule(schema.Rule{Type: schema.TypeJSON}), `{"a":1} {"b":2}`, false, "type"},
		{"json malformed refused", rule(schema.Rule{Type: schema.TypeJSON}), `{`, false, "type"},
		{"json schema satisfied", rule(schema.Rule{
			Type:       schema.TypeJSON,
			JSONSchema: []byte(`{"type":"object","required":["a"],"properties":{"a":{"type":"integer"}}}`),
		}), `{"a":1}`, true, ""},
		{"json schema violated", rule(schema.Rule{
			Type:       schema.TypeJSON,
			JSONSchema: []byte(`{"type":"object","required":["a"],"properties":{"a":{"type":"integer"}}}`),
		}), `{"b":1}`, false, "json_schema"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := compile(t, schema.Secret, tc.decl)
			v := c.Validate(tc.value)
			if v.Valid != tc.valid {
				t.Fatalf("Validate(%q) valid=%v, want %v (errors: %+v)", tc.value, v.Valid, tc.valid, v.Errors)
			}
			if tc.valid {
				if len(v.Errors) != 0 {
					t.Fatalf("valid verdict carries %d errors", len(v.Errors))
				}
				return
			}
			if len(v.Errors) == 0 {
				t.Fatal("invalid verdict carries no error")
			}
			if tc.keyword != "" {
				found := false
				for _, e := range v.Errors {
					if strings.Contains(e.Keyword, tc.keyword) {
						found = true
					}
				}
				if !found {
					t.Fatalf("no failure names keyword %q; got %+v", tc.keyword, v.Errors)
				}
			}
		})
	}
}

// A secret key's failures carry nothing derived from the instance: the value,
// any prefix of it, its length, and any instance-derived path are all absent.
// The probe value is a distinctive token, so a leak is detectable by search.
func TestSecretFailuresCarryNoInstanceData(t *testing.T) {
	const marker = "AKIALEAKCANARY"
	c := compile(t, schema.Secret, rule(schema.Rule{
		Type:       schema.TypeJSON,
		JSONSchema: []byte(`{"type":"object","additionalProperties":false,"properties":{"declared":{"type":"string"}}}`),
	}))
	v := c.Validate(`{"` + marker + `":"x"}`)
	if v.Valid {
		t.Fatal("additionalProperties:false accepted an undeclared property")
	}
	for _, e := range v.Errors {
		if e.InstancePath != "" {
			t.Fatalf("secret failure carries an instance path %q", e.InstancePath)
		}
		if strings.Contains(e.Keyword+e.Message, marker) {
			t.Fatalf("secret failure echoes instance data: %+v", e)
		}
	}
}

// A config key is readable under ordinary environment read, so its failures
// may carry the instance path the operator needs.
func TestConfigFailuresMayCarryInstancePaths(t *testing.T) {
	c := compile(t, schema.Config, rule(schema.Rule{
		Type:       schema.TypeJSON,
		JSONSchema: []byte(`{"type":"object","properties":{"a":{"type":"integer"}}}`),
	}))
	v := c.Validate(`{"a":"nope"}`)
	if v.Valid {
		t.Fatal("expected a type failure")
	}
	found := false
	for _, e := range v.Errors {
		if e.InstancePath != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("config failure carries no instance path: %+v", v.Errors)
	}
}

// any_of: the value is valid if any alternative accepts it, and a total
// failure enumerates every alternative's own failure — "matched none of 2"
// is not an answer an operator can act on.
func TestAnyOf(t *testing.T) {
	d := schema.Declaration{AnyOf: []schema.Rule{
		{Type: schema.TypeInteger, Min: i64p(1)},
		{Type: schema.TypeEnum, Members: []string{"auto"}},
	}}
	c := compile(t, schema.Secret, d)
	for _, ok := range []string{"4", "auto"} {
		if v := c.Validate(ok); !v.Valid {
			t.Fatalf("Validate(%q) refused: %+v", ok, v.Errors)
		}
	}
	v := c.Validate("banana")
	if v.Valid {
		t.Fatal("banana satisfied neither alternative but was accepted")
	}
	seen := map[int]bool{}
	for _, e := range v.Errors {
		seen[e.Alternative] = true
	}
	if !seen[0] || !seen[1] {
		t.Fatalf("failures do not enumerate every alternative: %+v", v.Errors)
	}
}

// allow_empty lives on the string alternative, never on the union.
func TestAnyOfEmptyRidesTheStringAlternative(t *testing.T) {
	c := compile(t, schema.Secret, schema.Declaration{AnyOf: []schema.Rule{
		{Type: schema.TypeInteger},
		{Type: schema.TypeString, AllowEmpty: true},
	}})
	if v := c.Validate(""); !v.Valid {
		t.Fatalf("empty refused despite an allow_empty string alternative: %+v", v.Errors)
	}
}

// The instance-byte budget fails loud; it never degrades to "assume valid".
func TestInstanceByteBudget(t *testing.T) {
	c := compile(t, schema.Secret, rule(schema.Rule{Type: schema.TypeString}))
	v := c.Validate(strings.Repeat("a", schema.MaxValueBytes+1))
	if v.Valid {
		t.Fatal("an over-budget value was accepted")
	}
	if v.Errors[0].Keyword != "budget.value_bytes" {
		t.Fatalf("budget breach named %q", v.Errors[0].Keyword)
	}
}

// Error count and bytes are capped: a schema that can produce hundreds of
// failures must not turn one validation into a response-sized payload.
func TestErrorCapsHold(t *testing.T) {
	members := make([]string, 0, 64)
	for i := range 64 {
		members = append(members, string(rune('a'+i%26))+strings.Repeat("z", i))
	}
	alts := make([]schema.Rule, 0, schema.MaxAnyOfAlternatives)
	for range schema.MaxAnyOfAlternatives {
		alts = append(alts, schema.Rule{Type: schema.TypeEnum, Members: members})
	}
	c := compile(t, schema.Secret, schema.Declaration{AnyOf: alts})
	v := c.Validate("nothing-matches")
	if v.Valid {
		t.Fatal("expected a total failure")
	}
	if len(v.Errors) > schema.MaxVerdictErrors {
		t.Fatalf("%d errors exceeds the cap of %d", len(v.Errors), schema.MaxVerdictErrors)
	}
	total := 0
	for _, e := range v.Errors {
		total += len(e.Keyword) + len(e.Message) + len(e.InstancePath)
	}
	if total > schema.MaxVerdictErrorBytes {
		t.Fatalf("%d error bytes exceeds the cap of %d", total, schema.MaxVerdictErrorBytes)
	}
}

// The write-time trim is Normalize's job and only Normalize's: the verdict
// never carries the value, so the write path calls this and the reporting path
// cannot.
func TestNormalizeIsTheWriteTimeTrim(t *testing.T) {
	if got := schema.Normalize("  padded\t\n"); got != "padded" {
		t.Fatalf("Normalize = %q, want %q", got, "padded")
	}
	c := compile(t, schema.Config, rule(schema.Rule{Type: schema.TypeString}))
	if v := c.Validate("  padded\t\n"); !v.Valid {
		t.Fatalf("a value valid after the trim was refused: %+v", v.Errors)
	}
}

// The WHOLE verdict is checked for the canary, not only its Errors: a verdict
// is what gets stored on a draft, rendered in a cell, logged and audited, so a
// plaintext field anywhere on it is a leak at every one of those points.
func TestWholeSecretVerdictCarriesNoPlaintext(t *testing.T) {
	const marker = "AKIALEAKCANARY"
	for _, tc := range []struct {
		name string
		decl schema.Declaration
	}{
		{"string pattern", rule(schema.Rule{Type: schema.TypeString, Pattern: "nope"})},
		{"json schema", rule(schema.Rule{
			Type:       schema.TypeJSON,
			JSONSchema: []byte(`{"type":"object","additionalProperties":false,"properties":{"declared":{"type":"string"}}}`),
		})},
		{"enum", rule(schema.Rule{Type: schema.TypeEnum, Members: []string{"a"}})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := compile(t, schema.Secret, tc.decl)
			for _, value := range []string{marker, `{"` + marker + `":"x"}`} {
				v := c.Validate(value)
				if v.Valid {
					continue
				}
				encoded, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(encoded), marker) {
					t.Fatalf("the verdict carries instance plaintext: %s", encoded)
				}
			}
		})
	}
}

// The error-byte cap budgets what the WIRE carries: the COMPLETE verdict
// document, envelope included. Escaping turns one control character into six
// bytes and one non-ASCII rune into as many as twelve, so a cap computed from
// raw string lengths — or from the failure list without its envelope — budgets
// a number nobody sends.
func TestErrorCapIsOnEncodedBytes(t *testing.T) {
	// A pattern whose message is plain, against a member list whose count is
	// what the message reports — the escaping pressure comes from the schema
	// location instead, which is where instance-independent text can grow.
	heavy := strings.Repeat(`\u0001\u2028`, 900)
	c := compile(t, schema.Config, rule(schema.Rule{
		Type:       schema.TypeJSON,
		JSONSchema: []byte(`{"type":"object","required":["` + heavy + `"]}`),
	}))
	v := c.Validate(`{}`)
	if v.Valid {
		t.Fatal("a missing required property was accepted")
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > schema.MaxVerdictErrorBytes {
		t.Fatalf("%d encoded WHOLE-VERDICT bytes exceeds the cap of %d", len(encoded), schema.MaxVerdictErrorBytes)
	}
	if len(v.Errors) == 0 {
		t.Fatal("an invalid verdict carries no errors")
	}
}
