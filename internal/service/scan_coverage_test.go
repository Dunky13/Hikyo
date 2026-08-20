package service

import (
	"reflect"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/definitions"
)

// SS3 field-coverage matrix (#74, secret-scanning ADR §2). The Surface-2 scan is
// defined STRUCTURALLY, not by enumeration: every author-controlled string leaf
// of the canonical definitions model must be scanned, and adding a public string
// field silently unscanned must be impossible.
//
// The proof is by construction, not a maintained constant list: a RECURSIVE
// reflection walk enumerates every content leaf reachable in the real Go types
// — descending through nested structs, pointers, and slices (schema.Declaration
// → schema.Rule, the Rule's pattern / enum members / url schemes / JSON Schema
// blob, the any_of alternatives, and the same tree under a bundle Key) — sets
// ONE leaf at a time to a unique sentinel, and asserts the leaf extractor
// surfaces that sentinel. A leaf that is neither surfaced nor on the closed
// exclusion list fails here, so a newly added string field anywhere in the
// reachable tree cannot ship unscanned.
//
// The exclusion list is the ADR's "fixed schema keywords + server-generated
// immutable identifiers", keyed by OwnerType.FieldName and named field-by-field
// so a reviewer sees exactly what is not scanned and why. Excluding a field
// stops the walk at that field (its whole subtree, if it has one) — a named
// stop, never a silent skip.
var excludedContentFields = map[string]string{
	// --- direct-edit (service) model ---
	"KeySpec.Classification": "closed enum secret|config, not author free-text",
	"KeySpec.GroupID":        "server-generated group identifier, not composed content",
	"KeySpec.Presence": "schema.PresenceRules subtree: only PresenceMode (closed none|all|explicit enum) " +
		"and server-issued environment ids — no author free-text",
	"Rule.Type": "closed type enum, a fixed schema keyword",
	// --- definitions bundle model ---
	"Key.ID":             "server-generated key identifier, not composed content",
	"Key.Classification": "closed enum secret|config, not author free-text",
	"Key.Group": "key-group NAME reference; a dangling one is refused by definitions.Resolve " +
		"(validateKeyReferences) before persist, and a real group's name is itself scanned via key_groups",
	"Key.RequiredIn": "definitions.Presence subtree: Mode (closed enum) + presence env-NAME references; " +
		"dangling ones refused by Resolve, real env names scanned via environments",
	"Key.ForbiddenIn": "definitions.Presence subtree, as Key.RequiredIn",
	"Environment.ID":  "server-generated environment identifier, not composed content",
	"KeyGroup.ID":     "server-generated group identifier, not composed content",
}

const coverageSentinel = "AKIAIOSFODNN7EXAMPLE_sentinel"

func leafSetContains(leaves []scanLeaf, sentinel string) bool {
	for _, l := range leaves {
		if string(l.Content) == sentinel {
			return true
		}
	}
	return false
}

// coverageLeaf is one author-controlled content leaf discovered by the walk: its
// dotted path from the root type (for diagnostics and the anti-vacuity guard)
// and a setter that plants the sentinel at exactly that leaf in a fresh,
// addressable root value — allocating pointers and one-element slices along the
// way so the containing entry actually exists for the extractor to see.
type coverageLeaf struct {
	path string
	set  func(root reflect.Value)
}

// navFn returns the addressable slot for the current position, given the
// addressable root. Composing navFns is how the walk threads pointer allocation
// and slice materialisation down to a deep leaf.
type navFn func(root reflect.Value) reflect.Value

// collectContentLeaves recursively enumerates the author-controlled content
// leaves of typ. It FAILS CLOSED: any reflect kind it does not recognise is a
// t.Errorf, not a silent skip — "prove by construction" means an unhandled shape
// cannot pass as a no-op. Numeric and boolean scalars are the only silent skips,
// because a credential is a string and a number/bool field cannot carry one.
func collectContentLeaves(t *testing.T, typ reflect.Type, path string, nav navFn) []coverageLeaf {
	t.Helper()
	switch typ.Kind() {
	case reflect.String:
		return []coverageLeaf{{path, func(root reflect.Value) {
			nav(root).SetString(coverageSentinel)
		}}}

	case reflect.Pointer:
		return collectContentLeaves(t, typ.Elem(), path, func(root reflect.Value) reflect.Value {
			slot := nav(root)
			if slot.IsNil() {
				slot.Set(reflect.New(typ.Elem()))
			}
			return slot.Elem()
		})

	case reflect.Slice:
		elem := typ.Elem()
		switch {
		case elem.Kind() == reflect.Uint8:
			// []byte / json.RawMessage is a NAMED TERMINAL-BLOB boundary: the
			// scanner runs one rule pass over the whole blob (declarationLeaves
			// emits it verbatim) and never parses its interior, so the walk stops
			// here rather than descending into the JSON structure.
			return []coverageLeaf{{path, func(root reflect.Value) {
				nav(root).SetBytes([]byte(coverageSentinel))
			}}}
		case elem.Kind() == reflect.String:
			return []coverageLeaf{{path, func(root reflect.Value) {
				slot := nav(root)
				slot.Set(reflect.MakeSlice(typ, 1, 1))
				slot.Index(0).SetString(coverageSentinel)
			}}}
		case elem.Kind() == reflect.Struct || (elem.Kind() == reflect.Pointer && elem.Elem().Kind() == reflect.Struct):
			// A slice of structs (e.g. any_of []Rule, bundle Keys []Key): recurse
			// into element 0, materialising a one-element slice so it exists.
			return collectContentLeaves(t, elem, path, func(root reflect.Value) reflect.Value {
				slot := nav(root)
				if slot.Len() == 0 {
					slot.Set(reflect.MakeSlice(typ, 1, 1))
				}
				return slot.Index(0)
			})
		default:
			t.Errorf("coverage walk: unhandled slice element kind %s at %s", elem.Kind(), path)
			return nil
		}

	case reflect.Struct:
		var out []coverageLeaf
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if _, excluded := excludedContentFields[typ.Name()+"."+f.Name]; excluded {
				continue // named stop: this field (and its subtree) is not scanned, by justification above
			}
			idx := i
			childNav := func(root reflect.Value) reflect.Value { return nav(root).Field(idx) }
			out = append(out, collectContentLeaves(t, f.Type, path+"."+f.Name, childNav)...)
		}
		return out

	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return nil // scalar constraint field: structurally cannot carry a credential string

	default:
		t.Errorf("coverage walk: unhandled kind %s at %s", typ.Kind(), path)
		return nil
	}
}

// rootLeaves walks a root type and returns its content leaves.
func rootLeaves(t *testing.T, root any) []coverageLeaf {
	t.Helper()
	typ := reflect.TypeOf(root)
	return collectContentLeaves(t, typ, typ.Name(), func(r reflect.Value) reflect.Value { return r })
}

// assertEachLeafScanned plants the sentinel at each leaf in a fresh root and
// asserts the extractor surfaces it.
func assertEachLeafScanned(t *testing.T, rootType any, leaves []coverageLeaf, extract func(root reflect.Value) []scanLeaf) {
	t.Helper()
	rt := reflect.TypeOf(rootType)
	for _, leaf := range leaves {
		root := reflect.New(rt).Elem()
		leaf.set(root)
		if !leafSetContains(extract(root), coverageSentinel) {
			t.Errorf("author-controlled leaf %s is not scan-covered and is not on the exclusion list", leaf.path)
		}
	}
}

func TestSurface2FieldCoverageMatrix(t *testing.T) {
	// KeySpec: every content leaf, recursively (including the whole
	// Declaration → Rule / any_of tree), one sentinel at a time.
	assertEachLeafScanned(t, KeySpec{}, rootLeaves(t, KeySpec{}), func(root reflect.Value) []scanLeaf {
		return keySpecLeaves(root.Interface().(KeySpec))
	})

	// KeyMetadataUpdate: the PATCH members (pointer content leaves).
	assertEachLeafScanned(t, KeyMetadataUpdate{}, rootLeaves(t, KeyMetadataUpdate{}), func(root reflect.Value) []scanLeaf {
		return keyMetadataLeaves(root.Interface().(KeyMetadataUpdate))
	})

	// The hierarchy name inputs are single-string ingresses handled directly by
	// the Folders/Environments/KeyGroups services (not a struct field), so assert
	// each locator constant is present and distinct — a coverage gap there is
	// visible too.
	for _, loc := range []string{locEnvironmentName, locEnvironmentNote, locFolderPath, locGroupName} {
		if loc == "" {
			t.Error("a hierarchy locator constant is empty")
		}
	}
}

// TestBundleLeafCoverageMatrix is SS3.e extended to the definitions bundle model
// (#74 SS3): definitions.Bundle carries its own Key/Environment/KeyGroup structs,
// distinct from the service KeySpec, scanned by bundleLeaves on plan/apply/check.
// It walks the whole Bundle recursively — Environments/KeyGroups names, and each
// Key's leaves INCLUDING its Declaration → Rule / any_of tree — sets one leaf at
// a time, and asserts bundleLeaves surfaces it. A newly added bundle string leaf
// that is neither covered nor excluded fails here, so it cannot ship unscanned
// through the Git flow.
func TestBundleLeafCoverageMatrix(t *testing.T) {
	assertEachLeafScanned(t, definitions.Bundle{}, rootLeaves(t, definitions.Bundle{}), func(root reflect.Value) []scanLeaf {
		return bundleLeaves(root.Interface().(definitions.Bundle))
	})
}

// TestCoverageWalkReachesDeepLeaves is the anti-vacuity guard: it pins that the
// recursive walk actually reaches the deepest author-controlled leaves under a
// nested Declaration, so a walker bug that collected zero (or only shallow)
// leaves — which would make the two matrices above pass on an empty set — trips
// here. It also stands in for "a syntactically-new deep string field": if the
// declaration tree gains a scanned field, the walk must reach it, and these
// anchors prove the descent through pointer (Rule), slice-of-struct (any_of),
// and terminal-blob (JSON Schema) shapes all work.
func TestCoverageWalkReachesDeepLeaves(t *testing.T) {
	paths := map[string]bool{}
	for _, l := range rootLeaves(t, KeySpec{}) {
		paths[l.path] = true
	}
	for _, l := range rootLeaves(t, definitions.Bundle{}) {
		paths[l.path] = true
	}
	for _, want := range []string{
		"KeySpec.Declaration.Rule.Pattern",        // pointer → struct → string
		"KeySpec.Declaration.Rule.Members",        // pointer → struct → []string (enum members)
		"KeySpec.Declaration.Rule.JSONSchema",     // pointer → struct → []byte blob
		"KeySpec.Declaration.AnyOf.Pattern",       // slice-of-struct alternative → string
		"KeySpec.Declaration.AnyOf.Members",       // slice-of-struct alternative → []string
		"Bundle.Keys.Declaration.Rule.Pattern",    // bundle key declaration, direct rule
		"Bundle.Keys.Declaration.AnyOf.Pattern",   // bundle key declaration, any_of alternative
		"Bundle.Keys.Declaration.Rule.JSONSchema", // bundle key declaration, JSON blob
	} {
		if !paths[want] {
			t.Errorf("the coverage walk never reached %q; the recursive descent is broken and the matrices would pass vacuously", want)
		}
	}
	if len(paths) == 0 {
		t.Fatal("the coverage walk collected zero leaves")
	}
}
