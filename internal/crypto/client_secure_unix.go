//go:build unix

package crypto

import (
	"fmt"
	"os"
	"syscall"
)

// The Unix leg of the client state-directory protection model
// (system-architecture ADR § Client local state): 0700 directory / 0600 file,
// owned by the invoking user. Violations are REFUSED, never chmod-repaired —
// the caller surfaces them as a doctor finding.

// ensureSecureDir creates dir 0700 if absent, else verifies an existing dir is
// a directory, owned by the euid, and not group/other-accessible.
func ensureSecureDir(dir string) error {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("crypto: create state dir %s: %w", dir, err)
		}
		// MkdirAll honours umask, so tighten explicitly to 0700.
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("crypto: chmod state dir %s: %w", dir, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("crypto: stat state dir %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("crypto: state path %s exists but is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("crypto: state dir %s is accessible by group or others (mode %04o); refusing", dir, perm)
	}
	return checkOwner(dir, info)
}

// checkSecureFile verifies an already-open key file is 0600, a regular file,
// and owned by the euid.
func checkSecureFile(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("crypto: stat %s: %w", f.Name(), err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("crypto: %s is not a regular file", f.Name())
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("crypto: local key %s is accessible by group or others (mode %04o); refusing", f.Name(), perm)
	}
	return checkOwner(f.Name(), info)
}

func checkOwner(path string, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("crypto: cannot determine owner of %s", path)
	}
	if uint32(st.Uid) != uint32(os.Geteuid()) {
		return fmt.Errorf("crypto: %s is owned by uid %d, not by you (uid %d); refusing", path, st.Uid, os.Geteuid())
	}
	return nil
}
