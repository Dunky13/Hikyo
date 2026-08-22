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
// isatty() proves neither presence nor intent — the compose-integration ADR's locked
// finding about input, applied to output. The controlling terminal is a
// different file: a log-capturing pipe does not receive it.
package disclose

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
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

// ErrSinkConsumed reports that a prepared destination has already been used
// or aborted. A prepared sink is deliberately single-use: display-once
// material must have exactly one disclosure attempt.
var ErrSinkConsumed = errors.New("refusing to disclose: prepared destination was already consumed")

// ErrReservationChanged reports that Abort found a file reservation that was
// no longer both empty and the exact file Prepare created. Abort leaves that
// path untouched rather than risking deletion of somebody else's file.
var ErrReservationChanged = errors.New("refusing to disclose: prepared file reservation changed; leaving it untouched")

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

// PreparedSink owns one already-selected disclosure destination from Prepare
// until either WriteOnce or Abort consumes it. Keeping the open terminal or
// exclusively-created file here closes the former check-then-reopen window.
type PreparedSink struct {
	mu          sync.Mutex
	destination Destination
	consumed    bool
	write       func(label, value string) error
	abort       func() error
}

// Destination identifies the reserved delivery mode before minting, so audit
// records can describe the exact sink that will receive the value.
func (s *PreparedSink) Destination() Destination {
	if s == nil {
		return ""
	}
	return s.destination
}

// Prepare selects and reserves exactly one destination before display-once
// material is minted. File destinations are created exclusively at 0600;
// terminal destinations are opened now and retained for the eventual write.
func Prepare(o Options) (*PreparedSink, error) {
	switch {
	case o.OutputFile != "" && o.DangerouslyPrint:
		return nil, errors.New("refusing to disclose: --output-file and --dangerously-print name two destinations; choose one")

	case o.OutputFile != "":
		file, err := prepareFile(o.OutputFile)
		if err != nil {
			return nil, err
		}
		return &PreparedSink{
			destination: DestFile,
			write: func(_ string, value string) error {
				return file.write(value + "\n")
			},
			abort: file.abort,
		}, nil

	case o.DangerouslyPrint:
		w := o.Stdout
		if w == nil {
			w = os.Stdout
		}
		return &PreparedSink{
			destination: DestStdout,
			write: func(_ string, value string) error {
				_, err := fmt.Fprintln(w, value)
				return err
			},
			abort: func() error { return nil },
		}, nil
	}

	open := o.OpenTerminal
	if open == nil {
		open = openControllingTerminal
	}
	tty, err := open()
	if err != nil {
		return nil, ErrNoDestination
	}
	return &PreparedSink{
		destination: DestTerminal,
		write: func(label, value string) (writeErr error) {
			defer func() { writeErr = errors.Join(writeErr, tty.Close()) }()
			_, writeErr = fmt.Fprintf(tty, "\n%s:\n\n    %s\n\nThis value is shown once and is not retrievable afterwards.\n\n",
				label, value)
			return writeErr
		},
		abort: tty.Close,
	}, nil
}

// WriteOnce consumes the prepared destination even when the write fails. A
// retry could duplicate a partially-delivered secret, so callers must treat a
// failed attempt as unrecoverable and mint a replacement where supported.
func (s *PreparedSink) WriteOnce(label, value string) (Destination, error) {
	if s == nil {
		return "", ErrSinkConsumed
	}
	s.mu.Lock()
	if s.consumed {
		s.mu.Unlock()
		return "", ErrSinkConsumed
	}
	s.consumed = true
	write := s.write
	destination := s.destination
	s.mu.Unlock()

	if err := write(label, value); err != nil {
		return "", err
	}
	return destination, nil
}

// Abort closes an unused sink. For a file sink it removes the reservation only
// when the path still names the exact empty file Prepare created.
func (s *PreparedSink) Abort() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.consumed {
		s.mu.Unlock()
		return nil
	}
	s.consumed = true
	abort := s.abort
	s.mu.Unlock()
	return abort()
}

// AbortOnReturn lets callers defer cleanup without losing an Abort failure.
// result must point at the caller's named error result.
func (s *PreparedSink) AbortOnReturn(result *error) {
	*result = errors.Join(*result, s.Abort())
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
	answer, err := readLine(tty, 8)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// ConfirmName is the destructive-verb confirmation: the human types the
// SUBJECT'S NAME, not a letter.
//
// A y/N prompt is answered by reflex and by a stray newline in a paste buffer;
// typing the name cannot be. It is reserved for irreversible acts — asking for
// a typed name on a reversible one only teaches people to type names.
//
// The comparison is EXACT: no case folding, no whitespace tolerance beyond the
// surrounding trim, because "close enough to the name of the thing you are
// destroying" is not a property worth having.
func ConfirmName(prompt, want string, o Options) (bool, error) {
	open := o.OpenTerminal
	if open == nil {
		open = openControllingTerminal
	}
	tty, err := open()
	if err != nil {
		return false, ErrNoDestination
	}
	defer tty.Close()
	if _, err := fmt.Fprintf(tty, "%s\ntype %q to confirm: ", prompt, want); err != nil {
		return false, err
	}
	// The cap is generous rather than tight: it exists to stop an unbounded
	// read on a terminal that never sends a newline, not to bound the name.
	answer, err := readLine(tty, 256)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(answer) == want, nil
}

// readLine reads one line from the terminal, one byte at a time: it is
// line-buffered and there is no bufio wrapper to leave holding unread input the
// caller may still want. `limit` bounds the answer so a terminal that never sends
// a newline cannot spin here forever.
func readLine(tty io.WriteCloser, limit int) (string, error) {
	r, ok := tty.(io.Reader)
	if !ok {
		return "", ErrNoDestination
	}
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
		if len(answer) > limit {
			break
		}
	}
	return string(answer), nil
}
