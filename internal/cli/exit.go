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
)

// The closed exit-code set (api-cli-surface ADR § Output grammar). It is
// scoped to Wenv's own termination, and it is frozen from the first stable
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
	var e *Error
	if errors.As(err, &e) {
		fmt.Fprintln(stderr, "wenv:", e.Err)
		return e.Code
	}
	fmt.Fprintln(stderr, "wenv:", err)
	return ExitInternal
}

// Verbs is the closed set of client verbs this build serves. main dispatches
// on it, and the classification-totality invariant enumerates it against the
// wire registry: a verb here without a probe class fails the build.
var Verbs = []string{"login", "logout", "whoami", "account", "context", "org"}
