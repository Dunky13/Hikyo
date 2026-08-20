//go:build !unix

package compose

import "fmt"

// ExecPreflight is the Windows leg: it checks the command line and the
// environment block SEPARATELY against the 32767 UTF-16-unit CreateProcess cap
// (no margin). argMax is accepted for a uniform call site but ignored — the
// Windows caps are fixed, not derived from _SC_ARG_MAX.
func ExecPreflight(env, argv []string, _ int) (ok bool, detail string) {
	cmdline, envBlock, ok := ExecSizeWindows(env, argv)
	if ok {
		return true, ""
	}
	return false, fmt.Sprintf("command line is %d and environment block %d UTF-16 units; each is capped at %d",
		cmdline, envBlock, windowsMaxUTF16)
}
