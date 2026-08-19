//go:build darwin

package compose

import "golang.org/x/sys/unix"

// DefaultArgMax on darwin reads kern.argmax via sysctl — the real _SC_ARG_MAX
// backing value. golang.org/x/sys/unix is already in go.mod (no new
// dependency). A failed read falls back to the conservative floor rather than
// silently passing everything.
func DefaultArgMax() int {
	if n, err := unix.SysctlUint32("kern.argmax"); err == nil && n > 0 {
		return int(n)
	}
	return conservativeArgMax
}
