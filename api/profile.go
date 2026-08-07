package api

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// The bound OpenAPI 3.1 semantic profile (system-architecture ADR, operative
// amendment banner 2026-08-07). Every rule below is checked against the raw
// document rather than the parsed model, because the parser is exactly what
// would launder a prohibited construct into something that looks fine: a
// loader that silently ignores `nullable` under 3.1 turns "the field is
// nullable" into "the field is required and never null" without a word.
//
// CheckProfile is exported so the oasdiff gate's fixtures run the same rules
// the live contract runs. A tool in the chain that cannot meet its duty on
// 3.1 is a loud blocker to surface, never a silent downgrade to 3.0.3.

// DefaultDialect is the OAS 3.1 default JSON Schema dialect. It is pinned:
// an alternate dialect changes what every keyword in the document means, and
// no consumer in the chain negotiates one.
const DefaultDialect = "https://spec.openapis.org/oas/3.1/dialect/base"

// CheckProfile reports every profile violation in a document, joined, so one
// run names all of them rather than one per iteration.
func CheckProfile(specYAML []byte) error {
	var root map[string]any
	if err := yaml.Unmarshal(specYAML, &root); err != nil {
		return fmt.Errorf("profile: parse: %w", err)
	}

	var problems []error

	version, _ := root["openapi"].(string)
	if !strings.HasPrefix(version, "3.1") {
		problems = append(problems, fmt.Errorf("profile: openapi must be 3.1.x, got %q", version))
	}

	switch dialect := root["jsonSchemaDialect"].(type) {
	case string:
		if dialect != DefaultDialect {
			problems = append(problems, fmt.Errorf(
				"profile: jsonSchemaDialect is pinned to %q, got %q — alternate dialects fail closed",
				DefaultDialect, dialect))
		}
	default:
		problems = append(problems, fmt.Errorf(
			"profile: jsonSchemaDialect must be stated explicitly as %q", DefaultDialect))
	}

	if _, ok := root["webhooks"]; ok {
		problems = append(problems, errors.New(
			"profile: top-level `webhooks` is prohibited in v1 — an unsolicited outbound call is not in the zero-egress posture"))
	}

	problems = append(problems, walkSchemaRules(root)...)
	return errors.Join(problems...)
}

// walkSchemaRules enforces the two per-schema rules: legacy `nullable` is
// prohibited (3.1 spells it `type: [T, "null"]`), and an open enum never
// carries the `enum` keyword — an open enum that also constrains its values
// is closed in fact and would reject a newer server's response.
func walkSchemaRules(node any) []error {
	var problems []error
	var walk func(node any, path string)
	walk = func(node any, path string) {
		switch v := node.(type) {
		case map[string]any:
			if _, bad := v["nullable"]; bad {
				problems = append(problems, fmt.Errorf(
					"profile: %s uses legacy `nullable` — 3.1 spells nullability as `type: [T, \"null\"]`", path))
			}
			_, open := v[ExtOpenEnum]
			_, closed := v["enum"]
			if open && closed {
				problems = append(problems, fmt.Errorf(
					"profile: %s declares %s and `enum` together — an open enum must not constrain its values, or a newer server's value is rejected",
					path, ExtOpenEnum))
			}
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(v[k], path+"."+k)
			}
		case []any:
			for i, item := range v {
				walk(item, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	walk(node, "$")
	return problems
}
