//go:build !linux

package crypto

// PR_SET_DUMPABLE is Linux-only; other platforms get the core-dump rlimit
// alone, exactly as the encryption ADR scopes it.
func setNotDumpable() error { return nil }
