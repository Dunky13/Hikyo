// Package disclose implements the universal print triad (api-cli-surface ADR
// § Output grammar): every path that can emit secret plaintext sends it to
// exactly one of three destinations, and refuses otherwise.
//
//	(a) the controlling terminal (/dev/tty; CONIN$ + CONOUT$ on Windows), after an
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

// ErrTerminalCapabilities reports a controlling-terminal handle that cannot
// both read confirmations and write prompts/disclosures. Construction fails
// before any ceremony starts instead of discovering the missing reader later.
var ErrTerminalCapabilities = errors.New("refusing to use controlling terminal: handle must support read, write, and close")

// ErrTerminalInputTooLong reports an answer that exceeded the bounded input
// accepted by a terminal confirmation.
var ErrTerminalInputTooLong = errors.New("refusing terminal confirmation: input exceeded the allowed length")

// ErrDisclosureDeclined reports that the operator refused the terminal leg of
// the print triad. No plaintext is written after this error.
var ErrDisclosureDeclined = errors.New("refusing to disclose: terminal disclosure was declined")

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

// TerminalSession owns one validated controlling-terminal handle for a
// bounded ceremony. Confirmation and disclosure methods share that handle;
// Close is idempotent so a prepared sink and its command owner can both defer
// cleanup safely.
type TerminalSession struct {
	mu         sync.Mutex
	terminal   io.WriteCloser
	reader     io.Reader
	passwordFD int
	closed     bool
	closeErr   error
}

// NewTerminalSession validates and takes ownership of terminal. A rejected
// handle is closed before the constructor returns.
func NewTerminalSession(terminal io.WriteCloser) (*TerminalSession, error) {
	if terminal == nil {
		return nil, ErrTerminalCapabilities
	}
	reader, ok := terminal.(io.Reader)
	if !ok {
		return nil, errors.Join(ErrTerminalCapabilities, terminal.Close())
	}
	passwordFD := -1
	switch handle := terminal.(type) {
	case interface{ terminalPasswordFD() int }:
		passwordFD = handle.terminalPasswordFD()
	case interface{ Fd() uintptr }:
		passwordFD = int(handle.Fd())
	}
	return &TerminalSession{terminal: terminal, reader: reader, passwordFD: passwordFD}, nil
}

// OpenTerminalSession opens and validates the platform controlling terminal.
func OpenTerminalSession() (*TerminalSession, error) {
	terminal, err := openControllingTerminal()
	if err != nil {
		return nil, errors.Join(ErrNoDestination, err)
	}
	session, err := NewTerminalSession(terminal)
	if err != nil {
		return nil, errors.Join(ErrNoDestination, err)
	}
	return session, nil
}

func (s *TerminalSession) closeLocked() error {
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	s.closeErr = s.terminal.Close()
	return s.closeErr
}

// Close releases the session handle exactly once.
func (s *TerminalSession) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeLocked()
}

func (s *TerminalSession) confirm(prompt string, limit int) (bool, error) {
	if s == nil {
		return false, ErrNoDestination
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrNoDestination
	}
	if _, err := fmt.Fprintf(s.terminal, "%s [y/N]: ", prompt); err != nil {
		return false, errors.Join(err, s.closeLocked())
	}
	answer, err := readLine(s.reader, limit)
	if err != nil {
		return false, errors.Join(err, s.closeLocked())
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, nil
	default:
		return false, s.closeLocked()
	}
}

// Confirm reads one bounded yes/no answer on the session.
func (s *TerminalSession) Confirm(prompt string) (bool, error) {
	return s.confirm(prompt, 8)
}

// ConfirmEnumerated is the explicit seam for confirmations whose prompt
// names the complete affected set. The caller owns domain-specific rendering;
// the session owns bounded input and terminal lifetime.
func (s *TerminalSession) ConfirmEnumerated(prompt string) (bool, error) {
	return s.confirm(prompt, 8)
}

// ConfirmName requires the exact subject name for an irreversible act. The
// comparison is exact after trimming surrounding whitespace: no case folding
// and no reflexive y/N shortcut.
func (s *TerminalSession) ConfirmName(prompt, want string) (bool, error) {
	if s == nil {
		return false, ErrNoDestination
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrNoDestination
	}
	if _, err := fmt.Fprintf(s.terminal, "%s\ntype %q to confirm: ", prompt, want); err != nil {
		return false, errors.Join(err, s.closeLocked())
	}
	answer, err := readLine(s.reader, 256)
	if err != nil {
		return false, errors.Join(err, s.closeLocked())
	}
	if strings.TrimSpace(answer) == want {
		return true, nil
	}
	return false, s.closeLocked()
}

// WriteDisclosure writes display-once material through the session without
// closing it; the prepared sink or command owner closes the session.
func (s *TerminalSession) WriteDisclosure(label, value string) error {
	if s == nil {
		return ErrNoDestination
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrNoDestination
	}
	_, err := fmt.Fprintf(s.terminal, "\n%s:\n\n    %s\n\nThis value is shown once and is not retrievable afterwards.\n\n",
		label, value)
	if err != nil {
		return errors.Join(err, s.closeLocked())
	}
	return nil
}

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
// material is minted. File destinations are created exclusively at 0600. The
// terminal leg only wraps an explicitly constructed command-scoped session;
// this package never reopens it through a callback or implicit fallback.
func Prepare(o Options, session *TerminalSession) (*PreparedSink, error) {
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

	if session == nil {
		return nil, ErrNoDestination
	}
	confirmed, err := session.Confirm("Use the controlling terminal for this disclosure?")
	if err != nil {
		return nil, err
	}
	if !confirmed {
		return nil, ErrDisclosureDeclined
	}
	return &PreparedSink{
		destination: DestTerminal,
		write: func(label, value string) error {
			return errors.Join(session.WriteDisclosure(label, value), session.Close())
		},
		abort: session.Close,
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

// readLine reads one line from the terminal, one byte at a time: it is
// line-buffered and there is no bufio wrapper to leave holding unread input the
// caller may still want. `limit` bounds the answer so a terminal that never sends
// a newline cannot spin here forever.
func readLine(r io.Reader, limit int) (string, error) {
	var answer []byte
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				return string(answer), nil
			}
			if len(answer) >= limit {
				return "", ErrTerminalInputTooLong
			}
			answer = append(answer, buf[0])
		}
		if err != nil {
			return "", fmt.Errorf("reading controlling terminal: %w", err)
		}
		if n == 0 {
			return "", io.ErrNoProgress
		}
	}
}
