// Package cli is the client-side surface: the noun-verb verb table, context
// resolution, the local trust store, and the output grammar.
//
// It holds no policy. Every authorization decision is the server's, evaluated
// at the chokepoint in the request's own transaction; the CLI adds transport
// and the client-local safety properties the api-cli-surface ADR fixes —
// which instance a credential may be presented to, where plaintext may go,
// and what a script may rely on.
package cli

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
)

// The closed exit-code set (api-cli-surface ADR § Output grammar). It is
// scoped to Hikyo's own termination, and it is frozen from the first stable
// release: scripts branch on codes, never on parsing error prose.
const (
	// ExitOK is success.
	ExitOK = 0
	// ExitInternal is an unexpected fault.
	ExitInternal = 1
	// ExitUsage is a malformed invocation: unknown verb, missing argument,
	// bad flag.
	ExitUsage = 2
	// ExitAuth is authentication required or failed.
	ExitAuth = 3
	// ExitRefused covers validation, policy, a declined ceremony, a
	// trust-store refusal and an output-grammar refusal — everything the
	// server or the client declined to do.
	ExitRefused = 4
	// ExitNotFound is not found, WHICH IS ALSO UNAUTHORIZED, indistinguishable
	// by design: unauthorized ≡ nonexistent holds on the CLI exactly as it
	// does on the wire.
	ExitNotFound = 5
	// ExitUnavailable is the server or transport being unreachable — including
	// admission overload, which is a temporary unavailability rather than a
	// refusal of this particular request.
	ExitUnavailable = 6
)

// 126 and 127 are the ONLY exits outside the closed set above, and they are
// used by `hikyo run --` alone (verbs/compose.go). They are NOT hikyo's own
// codes: they are the child-side shell convention that `run` borrows because it
// stands in for the command it execs.
//
//	127  the command named after `--` was not found on PATH (exec.LookPath).
//	126  the command was found but could not be executed (Exec returned).
//
// On a successful exec there is no hikyo process at all (unix syscall.Exec;
// windows spawn-wait-and-exit-with-the-child-code), so the child's own exit
// status and signals are the invocation's, untouched — hikyo never overwrites
// them with a code of its own.
const (
	ExitCommandNotExecutable = 126
	ExitCommandNotFound      = 127
)

// Error carries an exit code out of a verb.
type Error struct {
	Code int
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func failf(code int, format string, args ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

// Report prints an error to stderr and returns its exit code. Diagnostics go
// to stderr without exception, so stdout carries only the requested payload
// and `-o json` output is parseable by construction.
func Report(stderr io.Writer, err error) int {
	if err == nil {
		return ExitOK
	}
	var status *silentExit
	if errors.As(err, &status) {
		return status.Code
	}
	var e *Error
	if errors.As(err, &e) {
		fmt.Fprintln(stderr, "hikyo:", e.Err)
		return e.Code
	}
	fmt.Fprintln(stderr, "hikyo:", err)
	return ExitInternal
}

// silentExit is a successful command outcome with a non-zero status. The
// definitions check contract reserves 1 for "different"; it is not an error
// diagnostic and therefore must not print the ordinary `hikyo:` prefix.
type silentExit struct{ Code int }

func (e *silentExit) Error() string { return fmt.Sprintf("exit %d", e.Code) }

// Verbs is the closed set of client verbs this build serves. main dispatches
// on it, and the classification-totality invariant enumerates it against the
// wire registry: a verb here without a probe class fails the build. Derived
// from the dispatch table so the two can never disagree.
var Verbs = slices.Sorted(maps.Keys(verbHandlers))
