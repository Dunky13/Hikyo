package importer

import (
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/schema"
)

func TestSuggestType(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		want   schema.Type
	}{
		{"empty suggests string", nil, schema.TypeString},
		{"canonical booleans", []string{"true", "false", "true"}, schema.TypeBoolean},
		{"non-canonical boolean is string", []string{"TRUE"}, schema.TypeString},
		{"integers", []string{"4", "-7", "0"}, schema.TypeInteger},
		{"leading zero integer", []string{"01"}, schema.TypeInteger},
		{"json object", []string{`{"a":1}`}, schema.TypeJSON},
		{"json array", []string{"[1,2,3]"}, schema.TypeJSON},
		{"scalar json is not json", []string{"4"}, schema.TypeInteger},
		{"string scalar json quote is string", []string{`"x"`}, schema.TypeString},
		// Computed across ALL mapped values: a key that disagrees across
		// environments suggests nothing but string.
		{"mixed integer and word", []string{"4", "auto"}, schema.TypeString},
		{"mixed boolean and integer", []string{"true", "4"}, schema.TypeString},
		{"mixed json shapes stays json", []string{`{"a":1}`, "[1]"}, schema.TypeJSON},
		{"one env only", []string{"9000"}, schema.TypeInteger},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SuggestType(tc.values); got != tc.want {
				t.Errorf("SuggestType(%v) = %s, want %s", tc.values, got, tc.want)
			}
		})
	}
}

// TestSuggestionIsAlwaysAcceptedByTheDeclaration is the anti-decoration guard: a
// suggested type must be one the declaration would then accept for every value,
// or accepting it would fail validation later.
func TestSuggestionIsAlwaysAcceptedByTheDeclaration(t *testing.T) {
	sets := [][]string{
		{"true", "false"}, {"4", "-7", "01"}, {`{"a":1}`, "[1,2]"}, {"auto", "4"},
	}
	for _, values := range sets {
		typ := SuggestType(values)
		rule := schema.Rule{Type: typ}
		compiled, err := schema.CompileClassified(schema.Secret, schema.Declaration{Rule: &rule})
		if err != nil {
			t.Fatalf("suggested type %s does not compile: %v", typ, err)
		}
		for _, v := range values {
			if verdict := compiled.Validate(v); !verdict.Valid {
				t.Errorf("suggested %s for %q but the declaration rejects it: %+v", typ, v, verdict.Errors)
			}
		}
	}
}
