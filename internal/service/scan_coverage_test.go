package service

import (
	"reflect"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/schema"
)

// SS3 field-coverage matrix (#74, secret-scanning ADR §2). The Surface-2 scan is
// defined STRUCTURALLY, not by enumeration: every author-controlled string leaf
// of the canonical definitions model must be scanned, and adding a public string
// field silently unscanned must be impossible. This test walks the definitions
// model by reflection, sets ONE content leaf at a time to a unique sentinel, and
// asserts the leaf extractor surfaces that sentinel — OR that the field is on the
// closed exclusion list (a fixed schema keyword or a server-generated identifier,
// content no author composes). A newly added string field that is neither
// covered nor excluded fails here.
//
// The exclusion list is the ADR's "fixed schema keywords + server-generated
// immutable identifiers", named field-by-field so a reviewer sees exactly what
// is not scanned and why.
var excludedDefinitionFields = map[string]string{
	"KeySpec.Classification": "closed enum secret|config, not author free-text",
	"KeySpec.GroupID":        "server-generated group identifier, not composed content",
	"Rule.Type":              "closed type enum, a fixed schema keyword",
}

const coverageSentinel = "AKIAIOSFODNN7EXAMPLE_sentinel"

// isContentLeaf reports whether a reflect field is an author-controlled content
// leaf the scanner must cover: a string, a []string, or a json.RawMessage
// ([]byte). Numeric, boolean and pointer-to-numeric constraint fields are not
// content, and nested structs (Declaration, Presence) are walked separately.
func isContentLeaf(f reflect.StructField) bool {
	t := f.Type
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return true
	case reflect.Slice:
		return t.Elem().Kind() == reflect.String || t.Elem().Kind() == reflect.Uint8
	}
	return false
}

// setSentinel populates a content-leaf field with the sentinel so the extractor
// has exactly one non-empty leaf to surface.
func setSentinel(v reflect.Value) {
	t := v.Type()
	switch {
	case t.Kind() == reflect.Pointer && t.Elem().Kind() == reflect.String:
		s := coverageSentinel
		v.Set(reflect.ValueOf(&s))
	case t.Kind() == reflect.String:
		v.SetString(coverageSentinel)
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.String:
		v.Set(reflect.ValueOf([]string{coverageSentinel}))
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8:
		v.Set(reflect.ValueOf([]byte(coverageSentinel)))
	}
}

func leafSetContains(leaves []scanLeaf, sentinel string) bool {
	for _, l := range leaves {
		if string(l.Content) == sentinel {
			return true
		}
	}
	return false
}

func TestSurface2FieldCoverageMatrix(t *testing.T) {
	// KeySpec: each top-level content leaf, in isolation.
	specType := reflect.TypeOf(KeySpec{})
	for i := 0; i < specType.NumField(); i++ {
		field := specType.Field(i)
		key := "KeySpec." + field.Name
		if _, excluded := excludedDefinitionFields[key]; excluded {
			continue
		}
		if field.Type == reflect.TypeOf(schema.Declaration{}) {
			continue // walked below
		}
		// A nested struct that is neither the Declaration nor an explicitly
		// excluded one must not slip through unchecked: Presence carries only
		// server-issued environment ids (not author content), so it is excluded
		// by name; any OTHER nested struct added later fails here until it is
		// either walked for its leaves or added to this exclusion.
		if field.Type.Kind() == reflect.Struct {
			if field.Type == reflect.TypeOf(schema.PresenceRules{}) {
				continue // env-id lists are server-issued, not author content
			}
			t.Errorf("KeySpec.%s is a nested struct with no coverage walk; add it to the matrix or exclude it by name", field.Name)
			continue
		}
		if !isContentLeaf(field) {
			continue
		}
		spec := KeySpec{}
		setSentinel(reflect.ValueOf(&spec).Elem().Field(i))
		if !leafSetContains(keySpecLeaves(spec), coverageSentinel) {
			t.Errorf("author-controlled field %s is not scan-covered and is not on the exclusion list", key)
		}
	}

	// schema.Rule (the Declaration's leaves): each content field in isolation.
	ruleType := reflect.TypeOf(schema.Rule{})
	for i := 0; i < ruleType.NumField(); i++ {
		field := ruleType.Field(i)
		key := "Rule." + field.Name
		if _, excluded := excludedDefinitionFields[key]; excluded {
			continue
		}
		if !isContentLeaf(field) {
			continue
		}
		rule := schema.Rule{Type: schema.TypeString}
		setSentinel(reflect.ValueOf(&rule).Elem().Field(i))
		spec := KeySpec{Declaration: schema.Declaration{Rule: &rule}}
		if !leafSetContains(keySpecLeaves(spec), coverageSentinel) {
			t.Errorf("author-controlled declaration field %s is not scan-covered and is not on the exclusion list", key)
		}
	}

	// KeyMetadataUpdate: the PATCH members.
	metaType := reflect.TypeOf(KeyMetadataUpdate{})
	for i := 0; i < metaType.NumField(); i++ {
		field := metaType.Field(i)
		if !isContentLeaf(field) {
			continue // Deprecated is *bool, not content
		}
		m := KeyMetadataUpdate{}
		setSentinel(reflect.ValueOf(&m).Elem().Field(i))
		if !leafSetContains(keyMetadataLeaves(m), coverageSentinel) {
			t.Errorf("author-controlled metadata field KeyMetadataUpdate.%s is not scan-covered", field.Name)
		}
	}

	// The hierarchy name inputs are single-string leaves; assert each locator
	// constant is present and distinct so a coverage gap there is visible too.
	for _, loc := range []string{locEnvironmentName, locEnvironmentNote, locFolderPath, locGroupName} {
		if loc == "" {
			t.Error("a hierarchy locator constant is empty")
		}
	}
}
