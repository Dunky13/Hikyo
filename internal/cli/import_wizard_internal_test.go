package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/disclose"
	"github.com/Hikyo-Org/hikyo/internal/importer"
)

// nopTerminal backs an injected TerminalSession: its existence is what
// onTerminal checks, nothing is read from or written to it.
type nopTerminal struct{ io.ReadWriter }

func (nopTerminal) Close() error { return nil }

// TestImportOnTerminalEntersWizard is acceptance criterion 3's TTY half: `import`
// with no source arguments on a terminal enters the wizard rather than printing
// the flag-mode usage error. The wizard then fails at target resolution (no
// project resolves in this test), which proves entry: the error is not the
// no-arguments usage refusal.
func TestImportOnTerminalEntersWizard(t *testing.T) {
	var stderr bytes.Buffer
	session, err := disclose.NewTerminalSession(nopTerminal{ReadWriter: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	ios := IO{
		Stdin:           strings.NewReader(""),
		Stdout:          &bytes.Buffer{},
		Stderr:          &stderr,
		Env:             Env{Getenv: func(string) string { return "" }},
		TerminalSession: session,
	}
	err = runImport(context.Background(), ios, nil)
	if err == nil {
		t.Fatal("the wizard entry returned no error despite no resolvable target")
	}
	if strings.Contains(err.Error(), "needs --from or --mapping") {
		t.Fatalf("import on a terminal fell through to the flag-mode usage error: %v", err)
	}
}

// TestImportNoTerminalIsAHardError is the no-TTY half: without a terminal and
// without --from/--mapping, import is a hard usage error, never a hung prompt.
func TestImportNoTerminalIsAHardError(t *testing.T) {
	err := runImport(context.Background(), IO{Stderr: &bytes.Buffer{}}, nil)
	var cliErr *Error
	if !errors.As(err, &cliErr) || cliErr.Code != ExitUsage {
		t.Fatalf("err = %v, want ExitUsage", err)
	}
	if !strings.Contains(err.Error(), "needs --from or --mapping") {
		t.Fatalf("err = %v, want the no-arguments usage refusal", err)
	}
}

// TestValuesImportRefusesOverwriteForCreatedEnvFile: a created-environment
// values file (name-addressed, tokenless) may not be imported with --overwrite —
// the overwrite would bypass skip-by-default with no occurrence review. Refused
// before any server contact.
func TestValuesImportRefusesOverwriteForCreatedEnvFile(t *testing.T) {
	body, err := importer.Encode(importer.ValuesFile{
		FormatVersion: importer.FormatVersion, Project: "prj_x", EnvironmentName: "staging",
		Entries: []importer.ValuesEntry{{Key: "API_KEY", Value: "v"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "values-staging.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	ios := IO{
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
		Env: Env{Getenv: func(k string) string {
			if k == "HIKYO_STATE_DIR" {
				return stateDir
			}
			return ""
		}},
	}
	err = runValuesImport(context.Background(), ios,
		[]string{"--file", path, "--overwrite", "API_KEY", "--env", "env_staging", "--instance", "unknown-ref"})
	var cliErr *Error
	if !errors.As(err, &cliErr) || cliErr.Code != ExitRefused {
		t.Fatalf("err = %v, want ExitRefused", err)
	}
	if !strings.Contains(err.Error(), "tokenless") {
		t.Fatalf("err = %v, want the tokenless-overwrite refusal", err)
	}
}

// TestValuesImportRefusesMismatchedManifestProject: a values file paired with a
// run manifest from a DIFFERENT project is refused before any server contact, so
// the unrelated manifest's phase-completion marker is never corrupted.
func TestValuesImportRefusesMismatchedManifestProject(t *testing.T) {
	dir := t.TempDir()
	valuesBody, err := importer.Encode(importer.ValuesFile{
		FormatVersion: importer.FormatVersion, Project: "prj_P", Environment: "env_staging",
		Entries: []importer.ValuesEntry{{Key: "API_KEY", Value: "v"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	valuesPath := filepath.Join(dir, "values-env_staging.json")
	if err := os.WriteFile(valuesPath, valuesBody, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestBody, err := importer.Encode(importer.Manifest{
		FormatVersion: importer.FormatVersion, ConnectorContractVersion: importer.ConnectorContractVersion,
		Target:          importer.Target{Project: "prj_Q", Environments: []string{"env_staging"}},
		PhaseCompletion: importer.PhaseCompletion{Authored: true, Imported: map[string]bool{"env_staging": false}},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "run-manifest.json")
	if err := os.WriteFile(manifestPath, manifestBody, 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	ios := IO{
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
		Env: Env{Getenv: func(k string) string {
			if k == "HIKYO_STATE_DIR" {
				return stateDir
			}
			return ""
		}},
	}
	err = runValuesImport(context.Background(), ios,
		[]string{"--file", valuesPath, "--manifest", manifestPath, "--env", "env_staging", "--instance", "unknown-ref"})
	var cliErr *Error
	if !errors.As(err, &cliErr) || cliErr.Code != ExitRefused {
		t.Fatalf("err = %v, want ExitRefused", err)
	}
	if !strings.Contains(err.Error(), "same run") {
		t.Fatalf("err = %v, want the mispaired-manifest refusal", err)
	}
}

func TestTerminalPrompter(t *testing.T) {
	newP := func(input string) (*terminalPrompter, *bytes.Buffer) {
		var out bytes.Buffer
		return newTerminalPrompter(IO{Stdin: strings.NewReader(input), Stderr: &out}), &out
	}

	t.Run("confirm defaults on empty", func(t *testing.T) {
		p, _ := newP("\n")
		got, err := p.Confirm("go?", true)
		if err != nil || !got {
			t.Fatalf("got %v, %v; want default true", got, err)
		}
	})
	t.Run("confirm yes", func(t *testing.T) {
		p, _ := newP("y\n")
		got, err := p.Confirm("go?", false)
		if err != nil || !got {
			t.Fatalf("got %v, %v; want true", got, err)
		}
	})
	t.Run("choose one-indexed", func(t *testing.T) {
		p, _ := newP("2\n")
		got, err := p.Choose("pick", []string{"a", "b", "c"}, 0)
		if err != nil || got != 1 {
			t.Fatalf("got %d, %v; want index 1", got, err)
		}
	})
	t.Run("choose out of range refuses", func(t *testing.T) {
		p, _ := newP("9\n")
		if _, err := p.Choose("pick", []string{"a", "b"}, 0); err == nil {
			t.Fatal("an out-of-range choice was accepted")
		}
	})
	t.Run("line falls back to default", func(t *testing.T) {
		p, _ := newP("\n")
		got, err := p.Line("name", "fallback")
		if err != nil || got != "fallback" {
			t.Fatalf("got %q, %v; want fallback", got, err)
		}
	})
	t.Run("eof is a loud error", func(t *testing.T) {
		p, _ := newP("")
		if _, err := p.Line("name", ""); err == nil {
			t.Fatal("end of input was not surfaced as an error")
		}
	})
}
