package importer

import (
	"encoding/json"

	"github.com/Hikyo-Org/hikyo/internal/schema"
)

// Deterministic type suggestion for the wizard (import-paths ADR § Typing).
//
// A suggestion NEVER applies on its own — the wizard offers it and it lands only
// on a human accept. The conservative floor is `string`; flag mode declares
// everything `string` and never calls this. The suggestion is computed across
// ALL of a key's mapped values (declarations are project-scoped, so a key that
// is `4` in staging and `auto` in prod suggests nothing but `string`): a type is
// suggested only when EVERY value would satisfy it.

// suggestBoolean and suggestInteger reuse the schema grammar so a suggestion is
// exactly a type the declaration would then accept — an accepted suggestion that
// failed validation would be a decorative flag, the failure this ADR refuses.
var (
	suggestBoolean = mustCompile(schema.TypeBoolean)
	suggestInteger = mustCompile(schema.TypeInteger)
)

func mustCompile(t schema.Type) *schema.Compiled {
	rule := schema.Rule{Type: t}
	c, err := schema.Compile(schema.Declaration{Rule: &rule})
	if err != nil {
		// The rules are compile-time constants; a failure is a build-time bug.
		panic("importer: compiling the " + string(t) + " suggestion rule: " + err.Error())
	}
	return c
}

// SuggestType returns the deterministic type suggestion for a key's values,
// checked in the fixed order boolean → integer → json, falling back to string.
// An empty value set suggests string: there is nothing to narrow from.
func SuggestType(values []string) schema.Type {
	if len(values) == 0 {
		return schema.TypeString
	}
	switch {
	case allSatisfy(values, func(v string) bool { return suggestBoolean.Validate(v, schema.Secret).Valid }):
		return schema.TypeBoolean
	case allSatisfy(values, func(v string) bool { return suggestInteger.Validate(v, schema.Secret).Valid }):
		return schema.TypeInteger
	case allSatisfy(values, isJSONObjectOrArray):
		return schema.TypeJSON
	default:
		return schema.TypeString
	}
}

func allSatisfy(values []string, ok func(string) bool) bool {
	for _, v := range values {
		if !ok(v) {
			return false
		}
	}
	return true
}

// isJSONObjectOrArray reports whether a value is a single well-formed JSON
// object or array. A scalar JSON document (`4`, `true`, `"x"`) is deliberately
// NOT json here — those are the integer/boolean/string cases — so the suggestion
// only fires for genuinely structured leaves, matching the ADR's wording.
func isJSONObjectOrArray(v string) bool {
	trimmed := schema.Normalize(v)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return false
	}
	var doc any
	if err := json.Unmarshal([]byte(v), &doc); err != nil {
		return false
	}
	switch doc.(type) {
	case map[string]any, []any:
		return true
	default:
		return false
	}
}
