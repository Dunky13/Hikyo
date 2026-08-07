package api_test

import (
	"os"
	"strings"
	"testing"
)

// The system-architecture ADR's amendment banner names oapi-codegen v2.8.0 —
// the 3.1-support release — as the working pin, and says it moves only by
// recorded amendment, never silently. go.mod is where that pin lives; this
// test is what makes "never silently" true, because a dependency bump that
// drags the generator along fails here with the amendment obligation spelled
// out rather than regenerating different code on a quiet Tuesday.
const pinnedGenerator = "github.com/oapi-codegen/oapi-codegen/v2 v2.8.0"

func TestGeneratorPinIsTheAmendedVersion(t *testing.T) {
	mod, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if !strings.Contains(string(mod), pinnedGenerator) {
		t.Fatalf("go.mod no longer pins %q.\n"+
			"Moving the generator requires a recorded amendment to the system-architecture ADR "+
			"(banner 2026-08-07), not a dependency bump: the 3.1 duties — Go strict-server types, "+
			"runtime request validation, CI wire-response validation, TypeScript+Zod generation and "+
			"the oasdiff gate — must each be demonstrated against the same 3.1 document before the "+
			"replacement is adopted.", pinnedGenerator)
	}
}
