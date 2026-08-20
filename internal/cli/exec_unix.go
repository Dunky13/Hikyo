//go:build !windows

package cli

import "syscall"

// execRun replaces the current process image with argv0 (compose-integration
// ADR § "Two delivery paths": `run` execs, so on success there is no hikyo
// process — the child's exit status and signals are the invocation's,
// untouched). A successful syscall.Exec never returns; a returned error is the
// exec failure the caller maps to 126.
func execRun(argv0 string, argv, env []string) error {
	return syscall.Exec(argv0, argv, env)
}
