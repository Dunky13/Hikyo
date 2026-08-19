//go:build !unix

package compose

// DefaultArgMax on Windows: CreateProcess caps the command line at 32767 chars
// (including the terminating NUL). There is no _SC_ARG_MAX; this constant is the
// documented CreateProcess limit.
func DefaultArgMax() int { return 32767 }
