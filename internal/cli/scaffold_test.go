package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/cli"
)

// TestDefinitionsScaffoldIsOfflineAndAdditive proves the whole ADR property in
// one test: testIO has NO trust store and NO session, so any client
// construction would refuse — a clean exit is the proof the verb never touched a
// server. The stdout bytes are byte-pinned to a fixture, and every key must be
// config with the TODO marker.
func TestDefinitionsScaffoldIsOfflineAndAdditive(t *testing.T) {
	env := "# a comment\nexport DATABASE_URL=postgres://x\nAPI_KEY=\"s3cr3t\"\nLOG_LEVEL=info\n"
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	ios, stdout, stderr := testIO(t, nil)
	if code := cli.Run(t.Context(), ios, []string{"definitions", "scaffold", "--from", path}); code != cli.ExitOK {
		t.Fatalf("exit %d (a session/client was required?): %s", code, stderr.String())
	}
	golden(t, "definitions-scaffold.json", stdout.Bytes())

	out := stdout.String()
	for _, want := range []string{`"classification": "config"`, `"description": "TODO: classify"`, `"type": "string"`} {
		if !strings.Contains(out, want) {
			t.Errorf("scaffold bundle missing %q:\n%s", want, out)
		}
	}
	// Additive: no base_revision (omitempty pointer absent).
	if strings.Contains(out, "base_revision") {
		t.Errorf("scaffold bundle is not additive — it carries a base_revision:\n%s", out)
	}
	if !strings.Contains(stderr.String(), "3 keys emitted as config") {
		t.Errorf("missing the classify-before-apply stderr line: %s", stderr.String())
	}
}

func TestDefinitionsScaffoldRefusesMalformedEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("lowercase=bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ios, _, stderr := testIO(t, nil)
	if code := cli.Run(t.Context(), ios, []string{"definitions", "scaffold", "--from", path}); code != cli.ExitRefused {
		t.Fatalf("exit %d, want refused", code)
	}
	if !strings.Contains(stderr.String(), "lowercase") {
		t.Errorf("refusal does not name the bad key: %s", stderr.String())
	}
}
