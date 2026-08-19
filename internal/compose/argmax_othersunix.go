//go:build unix && !darwin

package compose

import "golang.org/x/sys/unix"

// DefaultArgMax on Linux and the BSDs. There is no cross-platform sysconf in
// golang.org/x/sys/unix (it is Solaris-only there), so this reproduces glibc's
// _SC_ARG_MAX derivation: one quarter of the stack rlimit, which is the kernel
// bound on the combined argv+envp region (MAX_ARG_STRLEN aside). Clamped to a
// conservative 128 KiB floor and a 6 MiB ceiling; a failed lookup uses the
// floor. Stated, not silent: the CLI passes an explicit limit in production and
// this is only the fallback source.
func DefaultArgMax() int {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_STACK, &lim); err != nil || lim.Cur == 0 {
		return conservativeArgMax
	}
	n := int(lim.Cur / 4)
	switch {
	case n < conservativeArgMax:
		return conservativeArgMax
	case n > 6*1024*1024:
		return 6 * 1024 * 1024
	default:
		return n
	}
}
