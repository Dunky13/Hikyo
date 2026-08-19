//go:build !unix

package compose

// setUmask is a no-op on non-unix; the umask tests skip there.
func setUmask(int) int { return 0 }
