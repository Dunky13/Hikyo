package schema

import (
	"fmt"
	"sort"
)

// checkDeclarationClassification enforces the source-of-truth ADR's
// classification boundary. A secret declaration may constrain a shape with a
// pattern, but it may not carry value literals through enum members or through
// const/enum/examples anywhere in an embedded JSON Schema document.
func checkDeclarationClassification(classification Classification, d Declaration) error {
	if classification != Secret {
		return nil
	}
	for i, rule := range d.alternatives() {
		where := "rule"
		if d.Rule == nil {
			where = fmt.Sprintf("any_of alternative %d", i)
		}
		if rule.Type == TypeEnum || len(rule.Members) > 0 {
			return declErr("secret declaration %s uses value-literal `members`; use `pattern`, or declassify the key", where)
		}
		if len(rule.JSONSchema) == 0 {
			continue
		}
		var doc any
		if err := strictJSON(rule.JSONSchema, &doc); err != nil {
			return declErr("`json_schema`: parse: %v", err)
		}
		if keyword, ok := valueLiteralKeyword(doc); ok {
			return declErr("secret declaration %s uses value-literal JSON Schema keyword `%s`; use `pattern`, or declassify the key", where, keyword)
		}
	}
	return nil
}

func valueLiteralKeyword(node any) (string, bool) {
	switch value := node.(type) {
	case map[string]any:
		for _, keyword := range []string{"const", "enum", "examples"} {
			if _, ok := value[keyword]; ok {
				return keyword, true
			}
		}
		names := make([]string, 0, len(value))
		for name := range value {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			child := value[name]
			if keyword, ok := valueLiteralKeyword(child); ok {
				return keyword, true
			}
		}
	case []any:
		for _, child := range value {
			if keyword, ok := valueLiteralKeyword(child); ok {
				return keyword, true
			}
		}
	}
	return "", false
}
