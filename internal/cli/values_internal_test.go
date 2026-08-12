package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestRevealingDiffIsRefusedBeforeAnyRequestWithoutASink is the CLI half of the
// reveal-triad fix: `values diff --reveal` on a non-terminal stdout with no
// --output-file and no --dangerously-print has nowhere to put the plaintext, so
// it is refused by the print triad BEFORE the request goes out — never
// downgraded to stdout, and never after a round-trip that has already disclosed.
//
// It reaches no server: the refusal is the "nowhere to go" preflight, which runs
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

// statePathFor gives NewState a writable state dir so the test reaches the
// preflight rather than failing to open state first.
func statePathFor(t *testing.T, key string) string {
	if key == "HIKYO_STATE_DIR" {
		return t.TempDir()
	}
	return ""
}
