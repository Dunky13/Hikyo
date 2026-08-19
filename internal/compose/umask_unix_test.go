//go:build unix

package compose

import "syscall"

func setUmask(mask int) int { return syscall.Umask(mask) }
