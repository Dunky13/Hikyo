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
	closed     bool
	closeCount int
}

func (f *fakeTTY) Close() error {
	f.closed = true
	f.closeCount++
	return nil
}

func TestPreparedFileReservesDestinationAndWritesExactlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	sink, err := Prepare(Options{OutputFile: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sink.Abort(); err != nil {
			t.Errorf("cleanup prepared sink: %v", err)
		}
	})
	if sink.Destination() != DestFile {
		t.Fatalf("prepared destination = %q, want %q", sink.Destination(), DestFile)
	}

	competing, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		_ = competing.Close()
		t.Fatal("a competing writer acquired the prepared destination")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("competing create error = %v, want os.ErrExist", err)
	}

	dest, err := sink.WriteOnce("Token", "hik_1_bs_secret")
	if err != nil {
		t.Fatal(err)
	}
	if dest != DestFile {
		t.Fatalf("destination %q, want %q", dest, DestFile)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hik_1_bs_secret\n" {
		t.Fatalf("file holds %q", body)
	}
	if _, err := sink.WriteOnce("Token", "second"); !errors.Is(err, ErrSinkConsumed) {
		t.Fatalf("second write error = %v, want ErrSinkConsumed", err)
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "hik_1_bs_secret\n" {
		t.Fatalf("second write changed file: body=%q err=%v", body, err)
	}
}

func TestPreparedTerminalClosesAfterWriteAndRefusesSecondWrite(t *testing.T) {
	tty := &fakeTTY{}
	sink, err := Prepare(Options{OpenTerminal: func() (io.WriteCloser, error) { return tty, nil }})
	if err != nil {
		t.Fatal(err)
	}
	dest, err := sink.WriteOnce("Token", "hik_1_bs_secret")
	if err != nil {
		t.Fatal(err)
	}
	if dest != DestTerminal {
		t.Fatalf("destination %q, want %q", dest, DestTerminal)
	}
	if tty.closeCount != 1 {
		t.Fatalf("terminal close count = %d, want 1", tty.closeCount)
	}
	if _, err := sink.WriteOnce("Token", "second"); !errors.Is(err, ErrSinkConsumed) {
		t.Fatalf("second write error = %v, want ErrSinkConsumed", err)
	}
	if tty.closeCount != 1 {
		t.Fatalf("second write closed terminal again: count = %d", tty.closeCount)
	}
}

type failingTTY struct {
	closeCount int
}

func (*failingTTY) Write([]byte) (int, error) { return 0, errors.New("terminal disappeared") }
func (f *failingTTY) Close() error {
	f.closeCount++
	return nil
}

func TestPreparedTerminalClosesAfterWriteFailure(t *testing.T) {
	tty := &failingTTY{}
	sink, err := Prepare(Options{OpenTerminal: func() (io.WriteCloser, error) { return tty, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink.WriteOnce("Token", "secret"); err == nil || !strings.Contains(err.Error(), "terminal disappeared") {
		t.Fatalf("write error = %v, want terminal failure", err)
	}
	if tty.closeCount != 1 {
		t.Fatalf("terminal close count = %d, want 1", tty.closeCount)
	}
	if _, err := sink.WriteOnce("Token", "second"); !errors.Is(err, ErrSinkConsumed) {
		t.Fatalf("second write error = %v, want ErrSinkConsumed", err)
	}
}

func TestPreparedTerminalAbortClosesWithoutWriting(t *testing.T) {
	tty := &fakeTTY{}
	sink, err := Prepare(Options{OpenTerminal: func() (io.WriteCloser, error) { return tty, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Abort(); err != nil {
		t.Fatal(err)
	}
	if tty.closeCount != 1 {
		t.Fatalf("terminal close count = %d, want 1", tty.closeCount)
	}
	if tty.Len() != 0 {
		t.Fatalf("abort wrote to terminal: %q", tty.String())
	}
	if err := sink.Abort(); err != nil {
		t.Fatalf("second abort = %v, want idempotent success", err)
	}
	if tty.closeCount != 1 {
		t.Fatalf("second abort closed terminal again: count = %d", tty.closeCount)
	}
}

func TestAbortRemovesOnlyOwnedEmptyReservation(t *testing.T) {
	t.Run("empty reservation", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		sink, err := Prepare(Options{OutputFile: path})
		if err != nil {
			t.Fatal(err)
		}
		if err := sink.Abort(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("reservation remains after abort: %v", err)
		}
		if _, err := sink.WriteOnce("Token", "value"); !errors.Is(err, ErrSinkConsumed) {
			t.Fatalf("write after abort error = %v, want ErrSinkConsumed", err)
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("non-empty reservation", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			sink, err := Prepare(Options{OutputFile: path})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("claimed"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := sink.Abort(); !errors.Is(err, ErrReservationChanged) {
				t.Fatalf("abort error = %v, want ErrReservationChanged", err)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != "claimed" {
				t.Fatalf("abort changed non-empty reservation: %q", body)
			}
		})

		t.Run("replaced reservation", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			sink, err := Prepare(Options{OutputFile: path})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := sink.Abort(); !errors.Is(err, ErrReservationChanged) {
				t.Fatalf("abort error = %v, want ErrReservationChanged", err)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != "replacement" {
				t.Fatalf("abort removed replacement: %q", body)
			}
		})
	}
}

func TestAbortOnReturnPreservesOperationAndCleanupErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows denies competing writes while the reservation handle is open")
	}
	path := filepath.Join(t.TempDir(), "token")
	sink, err := Prepare(Options{OutputFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("claimed"), 0o600); err != nil {
		t.Fatal(err)
	}
	operationErr := errors.New("operation failed")
	result := error(operationErr)
	sink.AbortOnReturn(&result)
	if !errors.Is(result, operationErr) {
		t.Fatalf("result = %v, want operation error preserved", result)
	}
	if !errors.Is(result, ErrReservationChanged) {
		t.Fatalf("result = %v, want cleanup error surfaced", result)
	}
}

func TestNonTTYWithNoFlagIsRefused(t *testing.T) {
	// The whole point of the triad: with no controlling terminal and no
	// explicit destination, the value is refused rather than downgraded to
	// stdout, where a log shipper would collect it.
	var out bytes.Buffer
	sink, err := Prepare(Options{
		Stdout:       &out,
		OpenTerminal: func() (io.WriteCloser, error) { return nil, errors.New("no controlling terminal") },
	})
	if !errors.Is(err, ErrNoDestination) {
		t.Fatalf("err = %v, want ErrNoDestination", err)
	}
	if sink != nil {
		t.Fatal("a sink was returned despite the refusal")
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
	sink, err := Prepare(Options{
		Stdout:       &out,
		OpenTerminal: func() (io.WriteCloser, error) { return tty, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	dest, err := sink.WriteOnce("Bootstrap token", "hik_1_bs_secret")
	if err != nil {
		t.Fatal(err)
	}
	if dest != DestTerminal {
		t.Fatalf("destination %q, want %q", dest, DestTerminal)
	}
	if out.Len() != 0 {
		t.Fatalf("plaintext went to stdout on the interactive path: %q", out.String())
	}
	if !strings.Contains(tty.String(), "hik_1_bs_secret") {
		t.Fatal("the value did not reach the controlling terminal")
	}
	if !tty.closed {
		t.Fatal("the terminal handle was leaked")
	}
}

func TestDangerouslyPrintIsTheOnlyStdoutPath(t *testing.T) {
	var out bytes.Buffer
	sink, err := Prepare(Options{
		Stdout:           &out,
		DangerouslyPrint: true,
		// A terminal IS available; the explicit flag still wins, because the
		// caller asked for the machine-readable path on purpose.
		OpenTerminal: func() (io.WriteCloser, error) { return &fakeTTY{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	dest, err := sink.WriteOnce("Token", "hik_1_bs_secret")
	if err != nil {
		t.Fatal(err)
	}
	if dest != DestStdout {
		t.Fatalf("destination %q, want %q", dest, DestStdout)
	}
	if strings.TrimSpace(out.String()) != "hik_1_bs_secret" {
		t.Fatalf("stdout carried %q, want the bare value", out.String())
	}
}

func TestTwoDestinationsIsARefusal(t *testing.T) {
	_, err := Prepare(Options{OutputFile: filepath.Join(t.TempDir(), "t"), DangerouslyPrint: true})
	if err == nil {
		t.Fatal("naming two destinations was accepted")
	}
}

func TestOutputFileIsCreatedFreshAt0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	sink, err := Prepare(Options{OutputFile: path})
	if err != nil {
		t.Fatal(err)
	}
	dest, err := sink.WriteOnce("Token", "hik_1_bs_secret")
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
	if string(body) != "hik_1_bs_secret\n" {
		t.Fatalf("file holds %q", body)
	}
}

func TestOutputFileIsNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(Options{OutputFile: path}); !errors.Is(err, ErrFileExists) {
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
	if _, err := Prepare(Options{OutputFile: link}); err == nil {
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
	_, err := Prepare(Options{OutputFile: filepath.Join(dir, "token")})
	if err == nil {
		t.Fatal("a world-writable parent was accepted — someone else could win the create race")
	}
	if !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("refusal does not name the problem: %v", err)
	}
}

func TestPrepareReservesBeforeAnythingIsMinted(t *testing.T) {
	// The ordering hazard the triad creates: a caller that mints a
	// display-once secret and only then finds it has nowhere to put it has
	// destroyed the secret and performed the side effect. Prepare refuses or
	// reserves before `admin create` creates an administrator.
	noTerminal := func() (io.WriteCloser, error) { return nil, errors.New("no controlling terminal") }
	if _, err := Prepare(Options{OpenTerminal: noTerminal}); !errors.Is(err, ErrNoDestination) {
		t.Fatalf("err = %v, want ErrNoDestination", err)
	}
	stdoutSink, err := Prepare(Options{DangerouslyPrint: true, OpenTerminal: noTerminal})
	if err != nil {
		t.Fatalf("--dangerously-print refused: %v", err)
	}
	if err := stdoutSink.Abort(); err != nil {
		t.Fatal(err)
	}
	terminalSink, err := Prepare(Options{OpenTerminal: func() (io.WriteCloser, error) { return &fakeTTY{}, nil }})
	if err != nil {
		t.Fatalf("an available terminal refused: %v", err)
	}
	if err := terminalSink.Abort(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	fresh := filepath.Join(dir, "fresh")
	fileSink, err := Prepare(Options{OutputFile: fresh, OpenTerminal: noTerminal})
	if err != nil {
		t.Fatalf("a free path refused: %v", err)
	}
	info, err := os.Stat(fresh)
	if err != nil {
		t.Fatalf("Prepare did not reserve the file: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("prepared reservation size = %d, want 0", info.Size())
	}
	if err := fileSink.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fresh); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Abort left the reservation behind: %v", err)
	}
	taken := filepath.Join(dir, "taken")
	if err := os.WriteFile(taken, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(Options{OutputFile: taken, OpenTerminal: noTerminal}); !errors.Is(err, ErrFileExists) {
		t.Fatalf("an occupied path passed preparation: %v", err)
	}
	if _, err := Prepare(Options{OutputFile: fresh, DangerouslyPrint: true}); err == nil {
		t.Fatal("two destinations passed preparation")
	}
}

// scriptedTTY is a terminal whose reads come from a script and whose writes go
// somewhere else, which is what a real terminal is. fakeTTY cannot serve here:
// it reads back its own prompt.
type scriptedTTY struct {
	in  *strings.Reader
	out bytes.Buffer
}

func (s *scriptedTTY) Read(p []byte) (int, error)  { return s.in.Read(p) }
func (s *scriptedTTY) Write(p []byte) (int, error) { return s.out.Write(p) }
func (s *scriptedTTY) Close() error                { return nil }

func scripted(answer string) (*scriptedTTY, Options) {
	tty := &scriptedTTY{in: strings.NewReader(answer)}
	return tty, Options{OpenTerminal: func() (io.WriteCloser, error) { return tty, nil }}
}

func TestConfirmReadsTheTerminal(t *testing.T) {
	for _, c := range []struct {
		answer string
		want   bool
	}{{"y\n", true}, {"yes\n", true}, {"\n", false}, {"n\n", false}, {"nope\n", false}} {
		tty, o := scripted(c.answer)
		got, err := Confirm("destroy it?", o)
		if err != nil {
			t.Fatalf("%q: %v", c.answer, err)
		}
		if got != c.want {
			t.Errorf("Confirm(%q) = %v, want %v", c.answer, got, c.want)
		}
		if !strings.Contains(tty.out.String(), "destroy it?") {
			t.Errorf("%q: the prompt did not reach the terminal", c.answer)
		}
	}
}

func TestConfirmNameRequiresTheExactName(t *testing.T) {
	// The long name is the regression: the yes/no reader stops after nine
	// bytes, so a name any longer than that could never be typed back.
	const name = "production-eu-west-peer"
	for _, c := range []struct {
		answer string
		want   bool
	}{
		{name + "\n", true},
		{"  " + name + "  \n", true},
		{"production-eu-west-pee\n", false},
		{"PRODUCTION-EU-WEST-PEER\n", false},
		{"y\n", false},
		{"\n", false},
	} {
		tty, o := scripted(c.answer)
		got, err := ConfirmName("removing it destroys the credential.", name, o)
		if err != nil {
			t.Fatalf("%q: %v", c.answer, err)
		}
		if got != c.want {
			t.Errorf("ConfirmName(%q) = %v, want %v", c.answer, got, c.want)
		}
		if !strings.Contains(tty.out.String(), name) {
			t.Errorf("%q: the prompt does not name what has to be typed", c.answer)
		}
	}
}

func TestConfirmNameRefusesWithoutATerminal(t *testing.T) {
	ok, err := ConfirmName("remove it?", "peer-b", Options{
		OpenTerminal: func() (io.WriteCloser, error) { return nil, errors.New("no controlling terminal") },
	})
	if !errors.Is(err, ErrNoDestination) {
		t.Fatalf("err = %v, want ErrNoDestination", err)
	}
	if ok {
		t.Fatal("a destructive act was confirmed with no terminal to confirm it at")
	}
}
