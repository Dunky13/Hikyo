//go:build !unix

package compose

// fsyncDir is a no-op on Windows: directory handles cannot be fsynced the way
// POSIX allows, and Windows is a client platform here. Stated, not silent — the
// crash-durability guarantee is the unix leg's.
func fsyncDir(string) error { return nil }
