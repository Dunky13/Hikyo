//go:build !unix

package crypto

import (
	"fmt"
	"os"
)

// The Windows leg. POSIX mode bits and euid ownership have no direct
// equivalent here, and Windows is a CLIENT platform for Hikyo (the server runs
// on unix), so this leg gives existence/create semantics without the
// owner-and-mode enforcement the unix leg provides — stated, not silent, the
// same way internal/disclose scopes its Windows write. Closing it needs the
// Windows security APIs and belongs with the ticket that ships a supported
// Windows client.

func ensureSecureDir(dir string) error {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("crypto: create state dir %s: %w", dir, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("crypto: stat state dir %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("crypto: state path %s exists but is not a directory", dir)
	}
	return nil
}

func checkSecureFile(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("crypto: stat %s: %w", f.Name(), err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("crypto: %s is not a regular file", f.Name())
	}
	return nil
}
