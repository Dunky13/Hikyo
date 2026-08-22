package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api/apigen"
)

// TestRevealingDiffIsRefusedBeforeAnyRequestWithoutASink is the CLI half of the
// reveal-triad fix: `values diff --reveal` on a non-terminal stdout with no
// --output-file and no --dangerously-print has nowhere to put the plaintext, so
// it is refused by the print triad BEFORE the request goes out — never
// downgraded to stdout, and never after a round-trip that has already disclosed.
//
// It reaches no server: the refusal is destination preparation, which runs
// ahead of target resolution, so an OpenTerminal that fails (no controlling
// terminal) is enough to prove the ordering.
func TestRevealingDiffIsRefusedBeforeAnyRequestWithoutASink(t *testing.T) {
	ios := IO{
		Stdin:        strings.NewReader(""),
		Stdout:       &bytes.Buffer{},
		Stderr:       &bytes.Buffer{},
		Env:          Env{Getenv: func(k string) string { return statePathFor(t, k) }},
		OpenTerminal: func() (io.WriteCloser, error) { return nil, errors.New("no controlling terminal") },
	}
	err := runValues(context.Background(), ios,
		[]string{"diff", "--left", "dev", "--right", "prod", "--reveal"})
	var ce *Error
	if !asCLIError(err, &ce) || ce.Code != ExitRefused {
		t.Fatalf("err = %v, want an ExitRefused pre-request refusal", err)
	}
	if !strings.Contains(err.Error(), "nowhere to go") {
		t.Fatalf("err = %v, want the print-triad refusal (before any request)", err)
	}
}

func TestPublishProtectedIDsPreservesExactReviewedSet(t *testing.T) {
	got := publishProtectedIDs("env_prod,env_closure")
	if got == nil || len(*got) != 2 || (*got)[0] != "env_prod" || (*got)[1] != "env_closure" {
		t.Fatalf("confirmed protected set = %+v", got)
	}
}

func TestRollbackTableShowsFullImpactPreview(t *testing.T) {
	before, after := "old", "new"
	table := rollbackTable(apigen.RollbackResult{
		Preview: apigen.ImpactPreview{Environments: []apigen.ImpactEnvironment{{
			EnvironmentId: "env_prod", Protected: true,
			Changes: []apigen.ImpactChange{{
				VersionId: "pcv_1", Name: "LOG_LEVEL", Classification: "config",
				Operation: "set", Status: "edited", Before: &before, After: &after,
			}},
		}}},
	})
	if len(table.Rows) != 1 {
		t.Fatalf("rollback preview rows = %+v", table.Rows)
	}
	want := []string{"env_prod", "true", "pcv_1", "LOG_LEVEL", "config", "set", "edited", "old", "new"}
	for i := range want {
		if table.Rows[0][i] != want[i] {
			t.Fatalf("rollback preview row[%d] = %q, want %q: %+v", i, table.Rows[0][i], want[i], table.Rows[0])
		}
	}
}

// statePathFor gives NewState a writable state dir so the test reaches
// destination preparation rather than failing to open state first.
func statePathFor(t *testing.T, key string) string {
	if key == "HIKYO_STATE_DIR" {
		return t.TempDir()
	}
	return ""
}
