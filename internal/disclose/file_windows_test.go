//go:build windows

package disclose

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type windowsTestReader struct {
	*strings.Reader
	closeCount int
}

func (r *windowsTestReader) Close() error {
	r.closeCount++
	return nil
}

type windowsTestWriter struct {
	bytes.Buffer
	closeCount int
}

func (w *windowsTestWriter) Close() error {
	w.closeCount++
	return nil
}

func TestWindowsTerminalSessionOwnsSeparateConsoleHandles(t *testing.T) {
	in := &windowsTestReader{Reader: strings.NewReader("y\n")}
	out := &windowsTestWriter{}
	session, err := NewTerminalSession(newWindowsTerminal(in, out))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := session.Confirm("continue?")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("confirmation was declined")
	}
	if err := session.WriteDisclosure("Token", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if in.closeCount != 1 || out.closeCount != 1 {
		t.Fatalf("console close counts = input %d, output %d; want 1 each", in.closeCount, out.closeCount)
	}
	if got := out.String(); !strings.Contains(got, "continue?") || !strings.Contains(got, "secret") {
		t.Fatalf("console output = %q, want prompt and disclosure", got)
	}
}

var _ io.ReadCloser = (*windowsTestReader)(nil)
var _ io.WriteCloser = (*windowsTestWriter)(nil)

func TestWindowsPreparedFileOwnsHandleUntilAbort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	sink, err := Prepare(Options{OutputFile: path}, nil)
	if err != nil {
		t.Fatal(err)
	}

	competing, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err == nil {
		_ = competing.Close()
		t.Fatal("a competing writer opened the prepared Windows destination")
	}
	if err := sink.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unused Windows reservation remains after Abort: %v", err)
	}
}

func TestWindowsPreparedFileWritesThroughReservedHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	sink, err := Prepare(Options{OutputFile: path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink.WriteOnce("Token", "hik_1_bs_secret"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hik_1_bs_secret\n" {
		t.Fatalf("Windows disclosure file = %q", body)
	}
}
