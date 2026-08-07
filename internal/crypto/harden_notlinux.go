//go:build unix && !linux

package crypto

// PR_SET_DUMPABLE is Linux-only; other Unix platforms get the core-dump
// rlimit alone, exactly as the encryption ADR scopes it.
func setNotDumpable() error { return nil }
