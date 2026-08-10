// Package disclose implements the universal print triad (api-cli-surface ADR
// § Output grammar): every path that can emit secret plaintext sends it to
// exactly one of three destinations, and refuses otherwise.
//
//	(a) the controlling terminal (/dev/tty; CONOUT$ on Windows), after an
//	    in-terminal confirmation;
//	(b) a file the process creates itself via --output-file, with the parent
//	    directory checked and the file created O_EXCL at exactly 0600;
//	(c) ordinary stdout, only under the explicit --dangerously-print flag;
//	    and it is refused otherwise, naming the three options.
//
// Ordinary stdout is NOT a destination even when stdout is a TTY. A PTY is
// allocatable by CI runners, `script`, tmux and service managers, so
// isatty() proves neither presence nor intent — the Compose ADR's locked
// finding about input, applied to output. The controlling terminal is a
// different file: a log-capturing pipe does not receive it.
package disclose

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ErrNoDestination is the refusal. It names all three options because a
// refusal that does not say what to do instead is just an obstacle.
var ErrNoDestination = errors.New(
	"refusing to disclose: no permitted destination. Choose one of:\n" +
		"  * run this from an interactive terminal (the value is written to the terminal, never to stdout)\n" +
		"  * --output-file PATH   (created fresh, 0600, in a directory you own)\n" +
		"  * --dangerously-print  (writes to stdout — and to whatever collects your stdout)")

// ErrFileExists reports that --output-file named something already present.
// The file is never overwritten: an existing path may be a symlink into
// somewhere else, and O_EXCL is what makes that unarguable.
var ErrFileExists = errors.New("refusing to disclose: --output-file already exists (it is never overwritten)")

// Options selects the destination.
type Options struct {
	// OutputFile selects destination (b) when non-empty.
	OutputFile string
	// DangerouslyPrint selects destination (c).
	//
	// The flag's name is the mitigation and this ADR does not pretend there
	// is another: a user who passes it in CI has published the value to their
	// CI system's log retention.
	DangerouslyPrint bool
	// Stdout is where (c) writes. Injectable for tests; nil means os.Stdout.
	Stdout io.Writer
	// OpenTerminal opens the controlling terminal for (a). Injectable for
	// tests; nil means the platform default.
	OpenTerminal func() (io.WriteCloser, error)
}

// Destination names where a value went, for the audit event that records the
// delivery mode — a value that reached a log shipper is a different event
// from one written to a root-owned file.
type Destination string

const (
	DestTerminal Destination = "terminal"
	DestFile     Destination = "file"
	DestStdout   Destination = "stdout"
)

// Preflight checks that a destination is usable WITHOUT writing anything.
//
// It exists because of an ordering hazard the print triad creates on its own:
// a caller that mints a display-once secret and only then discovers it has
// nowhere to put it has destroyed the secret and performed the side effect.
// `admin create` is the sharp case — it would leave an instance bootstrapped
// with an administrator whose establishment authority nobody ever saw, and
// re-running it refuses because the instance now has an account.
//
// Preflight is necessarily approximate for the file leg: it cannot create the
// file (that would consume the O_EXCL that makes the real write safe), so it
// reports what it can — the path is free and the parent is acceptable — and a
// race between the check and the write still lands on Emit's refusal. It
// closes the common failure, not every failure, and says so.
func Preflight(o Options) error {
	switch {
	case o.OutputFile != "" && o.DangerouslyPrint:
		return errors.New("refusing to disclose: --output-file and --dangerously-print name two destinations; choose one")
	case o.DangerouslyPrint:
		return nil
	case o.OutputFile != "":
		return preflightFile(o.OutputFile)
	}
	open := o.OpenTerminal
	if open == nil {
		open = openControllingTerminal
	}
	tty, err := open()
	if err != nil {
		return ErrNoDestination
	}
	return tty.Close()
}

// Emit writes value to exactly one permitted destination and reports which.
// label is the human-facing description printed alongside on the interactive
// path; it is never written to the file, which contains the value and a
// trailing newline and nothing else, so a script can read it directly.
func Emit(label, value string, o Options) (Destination, error) {
	switch {
	case o.OutputFile != "" && o.DangerouslyPrint:
		return "", errors.New("refusing to disclose: --output-file and --dangerously-print name two destinations; choose one")

	case o.OutputFile != "":
		if err := writeExclusive(o.OutputFile, value+"\n"); err != nil {
			return "", err
		}
		return DestFile, nil

	case o.DangerouslyPrint:
		w := o.Stdout
		if w == nil {
			w = os.Stdout
		}
		if _, err := fmt.Fprintln(w, value); err != nil {
			return "", err
		}
		return DestStdout, nil
	}

	open := o.OpenTerminal
	if open == nil {
		open = openControllingTerminal
	}
	tty, err := open()
	if err != nil {
		// No controlling terminal: this is the non-TTY case, and it is
		// refused rather than downgraded to stdout.
		return "", ErrNoDestination
	}
	defer tty.Close()
	if _, err := fmt.Fprintf(tty, "\n%s:\n\n    %s\n\nThis value is shown once and is not retrievable afterwards.\n\n",
		label, value); err != nil {
		return "", err
	}
	return DestTerminal, nil
}

// Redact renders a value for a log or an error message: never the value.
func Redact(string) string { return "[REDACTED:hikyo-artifact]" }

// Confirm reads a yes/no answer from the controlling terminal. The prompt and
// the answer both travel the terminal, so a log-capturing pipe sees neither
// the question nor the intent.
func Confirm(prompt string, o Options) (bool, error) {
	open := o.OpenTerminal
	if open == nil {
		open = openControllingTerminal
	}
	tty, err := open()
	if err != nil {
		return false, ErrNoDestination
	}
	defer tty.Close()
	if _, err := fmt.Fprintf(tty, "%s [y/N]: ", prompt); err != nil {
		return false, err
	}
	r, ok := tty.(io.Reader)
	if !ok {
		return false, ErrNoDestination
	}
	// One byte at a time: the terminal is line-buffered and there is no
	// bufio wrapper to leave holding unread input the caller may still want.
	var answer []byte
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 && buf[0] != '\n' {
			answer = append(answer, buf[0])
		}
		if err != nil || (n > 0 && buf[0] == '\n') {
			break
		}
		if len(answer) > 8 {
			break
		}
	}
	switch strings.ToLower(strings.TrimSpace(string(answer))) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
