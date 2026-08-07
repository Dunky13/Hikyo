package disclose

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fakeTTY struct {
	bytes.Buffer
	closed bool
}

func (f *fakeTTY) Close() error { f.closed = true; return nil }

func TestNonTTYWithNoFlagIsRefused(t *testing.T) {
	// The whole point of the triad: with no controlling terminal and no
	// explicit destination, the value is refused rather than downgraded to
	// stdout, where a log shipper would collect it.
	var out bytes.Buffer
	dest, err := Emit("Bootstrap token", "ew_1_bs_secret", Options{
		Stdout:       &out,
		OpenTerminal: func() (io.WriteCloser, error) { return nil, errors.New("no controlling terminal") },
	})
	if !errors.Is(err, ErrNoDestination) {
		t.Fatalf("err = %v, want ErrNoDestination", err)
	}
	if dest != "" {
		t.Fatalf("a destination was reported despite the refusal: %q", dest)
	}
	if out.Len() != 0 {
		t.Fatalf("the value reached stdout anyway: %q", out.String())
	}
	if !strings.Contains(err.Error(), "--output-file") || !strings.Contains(err.Error(), "--dangerously-print") {
		t.Fatalf("the refusal does not name the alternatives: %v", err)
	}
}

func TestTerminalPathNeverTouchesStdout(t *testing.T) {
	var out bytes.Buffer
	tty := &fakeTTY{}
	dest, err := Emit("Bootstrap token", "ew_1_bs_secret", Options{
		Stdout:       &out,
		OpenTerminal: func() (io.WriteCloser, error) { return tty, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if dest != DestTerminal {
		t.Fatalf("destination %q, want %q", dest, DestTerminal)
	}
	if out.Len() != 0 {
		t.Fatalf("plaintext went to stdout on the interactive path: %q", out.String())
	}
	if !strings.Contains(tty.String(), "ew_1_bs_secret") {
		t.Fatal("the value did not reach the controlling terminal")
	}
	if !tty.closed {
		t.Fatal("the terminal handle was leaked")
	}
}

func TestDangerouslyPrintIsTheOnlyStdoutPath(t *testing.T) {
	var out bytes.Buffer
	dest, err := Emit("Token", "ew_1_bs_secret", Options{
		Stdout:           &out,
		DangerouslyPrint: true,
		// A terminal IS available; the explicit flag still wins, because the
		// caller asked for the machine-readable path on purpose.
		OpenTerminal: func() (io.WriteCloser, error) { return &fakeTTY{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if dest != DestStdout {
		t.Fatalf("destination %q, want %q", dest, DestStdout)
	}
	if strings.TrimSpace(out.String()) != "ew_1_bs_secret" {
		t.Fatalf("stdout carried %q, want the bare value", out.String())
	}
}

func TestTwoDestinationsIsARefusal(t *testing.T) {
	_, err := Emit("Token", "v", Options{OutputFile: filepath.Join(t.TempDir(), "t"), DangerouslyPrint: true})
	if err == nil {
		t.Fatal("naming two destinations was accepted")
	}
}

func TestOutputFileIsCreatedFreshAt0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	dest, err := Emit("Token", "ew_1_bs_secret", Options{OutputFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if dest != DestFile {
		t.Fatalf("destination %q, want %q", dest, DestFile)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o, want 0600", info.Mode().Perm())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The file holds the value and a newline and nothing else, so a script
	// can read it directly.
	if string(body) != "ew_1_bs_secret\n" {
		t.Fatalf("file holds %q", body)
	}
}

func TestOutputFileIsNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Emit("Token", "new", Options{OutputFile: path}); !errors.Is(err, ErrFileExists) {
		t.Fatalf("err = %v, want ErrFileExists", err)
	}
	body, _ := os.ReadFile(path)
	if string(body) != "previous" {
		t.Fatal("the existing file was modified")
	}
}

func TestOutputFileRefusesASymlinkedTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("O_NOFOLLOW has no Windows equivalent; the limitation is documented in file_windows.go")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Emit("Token", "v", Options{OutputFile: link}); err == nil {
		t.Fatal("a symlinked target was written through")
	}
	body, _ := os.ReadFile(real)
	if string(body) != "x" {
		t.Fatal("the symlink target was overwritten")
	}
}

func TestOutputFileRefusesAWorldWritableParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the parent-ownership check is the unix leg; see file_windows.go")
	}
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	// Mkdir applies the umask, so set the mode explicitly.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	_, err := Emit("Token", "v", Options{OutputFile: filepath.Join(dir, "token")})
	if err == nil {
		t.Fatal("a world-writable parent was accepted — someone else could win the create race")
	}
	if !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("refusal does not name the problem: %v", err)
	}
}
