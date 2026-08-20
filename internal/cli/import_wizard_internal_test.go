package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// nopWriteCloser backs an injected OpenTerminal: its existence is what
// onTerminal checks, nothing is written to it.
type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// TestImportOnTerminalEntersWizard is acceptance criterion 3's TTY half: `import`
// with no source arguments on a terminal enters the wizard rather than printing
// the flag-mode usage error. The wizard then fails at target resolution (no
// project resolves in this test), which proves entry: the error is not the
// no-arguments usage refusal.
func TestImportOnTerminalEntersWizard(t *testing.T) {
	var stderr bytes.Buffer
	ios := IO{
		Stdin:  strings.NewReader(""),
		Stdout: &bytes.Buffer{},
		Stderr: &stderr,
		Env:    Env{Getenv: func(string) string { return "" }},
		OpenTerminal: func() (io.WriteCloser, error) {
			return nopWriteCloser{io.Discard}, nil
		},
	}
	err := runImport(context.Background(), ios, nil)
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
