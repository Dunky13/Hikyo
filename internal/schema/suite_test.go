package schema_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dunky13/wenv/internal/schema"
)

// The JSON Schema conformance baseline.
//
// The ADR requires "a pinned library and version, PLUS A CONFORMANCE-SUITE
// BASELINE": two Wenv installations must accept and reject the same schemas,
// and "some 2020-12 validator" is not a contract. The library and version are
// pinned in go.mod; this is the behavioural half.
//
// Vendored from the official suite at
// json-schema-org/JSON-Schema-Test-Suite@15fe552d6cf76e29cc8165306fb6a72503fd360b,
// tests/draft2020-12, restricted to the files covering keywords the PROFILE
// allows. Refreshing it is a deliberate act: change the commit above, re-fetch
// the same file list, and review the diff.
//
// Two kinds of skip, both automatic and both self-describing rather than a
// hand-curated list that could rot:
//
//   - A group whose SCHEMA the profile refuses is outside the accepted subset
//     by construction. It is skipped and the profile's own refusal is the
//     reason; the counts below assert the profile is neither refusing
//     everything nor refusing nothing.
//   - A group whose INSTANCE is not a thing Wenv can hold — the engine's
//     lexical rules refuse non-UTF-8, NUL bytes and duplicate object keys
//     before any schema runs, and trims edge whitespace — is named in
//     lexicalSkips with the rule that catches it.
//
// The suite's `data` is fed as its ORIGINAL BYTES, because a `json` value in
// Wenv is a string on the wire and re-marshalling would hide exactly the
// duplicate-key and number-precision behaviour the ADR fixes.

// lexicalSkips names every case where Wenv's own value rules — not the schema —
// decide the outcome, so the suite's expectation cannot apply. Keyed
// "file/group/test", each with the rule responsible.
var lexicalSkips = map[string]string{}

type suiteGroup struct {
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
	Tests       []struct {
		Description string          `json:"description"`
		Data        json.RawMessage `json:"data"`
		Valid       bool            `json:"valid"`
	} `json:"tests"`
}

func TestJSONSchemaConformanceBaseline(t *testing.T) {
	dir := filepath.Join("testdata", "jsonschema-suite")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("the vendored conformance suite is empty — the baseline is not pinned")
	}

	var ran, outOfProfile int
	usedSkips := map[string]bool{}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var groups []suiteGroup
		if err := json.Unmarshal(raw, &groups); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		file := strings.TrimSuffix(entry.Name(), ".json")
		for _, group := range groups {
			compiled, err := schema.Compile(schema.Declaration{Rule: &schema.Rule{
				Type: schema.TypeJSON, JSONSchema: group.Schema,
			}})
			if err != nil {
				// Outside the accepted subset. The refusal IS the reason, and
				// it must name what it refused rather than being generic.
				if !strings.Contains(err.Error(), "json_schema") {
					t.Errorf("%s/%s: refused without naming the profile: %v", file, group.Description, err)
				}
				outOfProfile++
				continue
			}
			for _, tc := range group.Tests {
				name := file + "/" + group.Description + "/" + tc.Description
				if _, skipped := lexicalSkips[name]; skipped {
					usedSkips[name] = true
					continue
				}
				ran++
				got := compiled.Validate(string(tc.Data), schema.Config)
				if got.Valid != tc.Valid {
					t.Errorf("%s: valid=%v, suite says %v (errors %+v)", name, got.Valid, tc.Valid, got.Errors)
				}
			}
		}
	}

	// The baseline has to be a baseline: a profile that refused every schema
	// would pass an assertion-free run, and a suite that exercised nothing
	// would too.
	if ran < 500 {
		t.Errorf("only %d suite cases ran — the baseline collapsed; it covered 7xx when pinned", ran)
	}
	if outOfProfile == 0 {
		t.Error("no suite schema was refused — the profile is no longer narrower than 2020-12")
	}
	for name := range lexicalSkips {
		if !usedSkips[name] {
			t.Errorf("lexical skip %q matches no suite case — remove the stale entry", name)
		}
	}
	t.Logf("conformance baseline: %d cases run, %d groups out of profile, %d lexical skips",
		ran, outOfProfile, len(lexicalSkips))
}
