package main

import (
	"strings"
	"testing"
)

// TestImportRuleContract is the fail-closed import contract (ADR §3): the
// generator consumes id/regex/keywords, ignores description/tags, and rejects
// by name any verdict-affecting or unknown field, and any regex that does not
// compile under RE2.
func TestImportRuleContract(t *testing.T) {
	clean := map[string]any{
		"id":          "github-pat",
		"description": "non-semantic annotation, ignored",
		"tags":        []any{"key"},
		"regex":       "ghp_[0-9a-zA-Z]{36}",
		"keywords":    []any{"ghp_"},
	}

	t.Run("accepts contract-clean rule", func(t *testing.T) {
		gr, err := importRule("github-pat", clean)
		if err != nil {
			t.Fatalf("clean rule rejected: %v", err)
		}
		if gr.regex != "ghp_[0-9a-zA-Z]{36}" || len(gr.keywords) != 1 || gr.digest == "" {
			t.Fatalf("unexpected imported rule: %+v", gr)
		}
	})

	reject := []struct {
		name  string
		field string
		value any
	}{
		{"entropy", "entropy", 3.5},
		{"allowlist", "allowlist", map[string]any{}},
		{"allowlists", "allowlists", []any{}},
		{"path", "path", "x"},
		{"secretGroup", "secretGroup", 1},
		{"unknown field", "somethingNew", "x"},
	}
	for _, tc := range reject {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			raw := clone(clean)
			raw[tc.field] = tc.value
			_, err := importRule("github-pat", raw)
			if err == nil {
				t.Fatalf("expected rejection for field %q", tc.field)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error should name the field %q: %v", tc.field, err)
			}
		})
	}

	t.Run("rejects uncompilable regex", func(t *testing.T) {
		raw := clone(clean)
		raw["regex"] = "(unclosed"
		if _, err := importRule("bad", raw); err == nil {
			t.Fatal("expected rejection for uncompilable regex")
		}
	})

	t.Run("rejects missing regex", func(t *testing.T) {
		raw := clone(clean)
		delete(raw, "regex")
		if _, err := importRule("bad", raw); err == nil {
			t.Fatal("expected rejection for missing regex")
		}
	})
}

// TestSemanticDigestDeterministic proves generation is deterministic and that
// keyword order does not change the digest (canonical sorted form).
func TestSemanticDigestDeterministic(t *testing.T) {
	a := semanticDigest("id", "re", []string{"b", "a"})
	b := semanticDigest("id", "re", []string{"a", "b"})
	if a != b {
		t.Fatalf("digest not order-invariant: %q vs %q", a, b)
	}
	if semanticDigest("id", "re", []string{"a"}) == semanticDigest("id2", "re", []string{"a"}) {
		t.Fatal("digest must depend on id")
	}
}

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
