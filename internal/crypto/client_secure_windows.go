//go:build !unix

package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// The Windows leg. POSIX mode bits and euid ownership have no direct
// equivalent here, and Windows is a CLIENT platform for Hikyo (the server runs
// on unix), so this leg gives existence/create semantics without the
// owner-and-mode enforcement the unix leg provides — stated, not silent, the
// same way internal/disclose scopes its Windows write. Closing it needs the
// Windows security APIs and belongs with the ticket that ships a supported
// Windows client.

func loadOrCreateMasterKey(dir string) ([]byte, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("crypto: create state dir %s: %w", dir, err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("crypto: stat state dir %s: %w", dir, err)
	}
	path := filepath.Join(dir, localKeyName)

	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	switch {
	case err == nil:
		defer f.Close()
		key := make([]byte, KeySize)
		if _, err := io.ReadFull(f, key); err != nil {
			return nil, fmt.Errorf("crypto: read %s: %w", path, err)
		}
		if extra, _ := f.Read(make([]byte, 1)); extra != 0 {
			return nil, fmt.Errorf("crypto: %s is not a %d-byte local key", path, KeySize)
		}
		return key, nil
	case os.IsNotExist(err):
		key := make([]byte, KeySize)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, fmt.Errorf("crypto: randomness unavailable, refusing to create local key: %w", err)
		}
		w, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			Zero(key)
			return nil, fmt.Errorf("crypto: create %s: %w", path, err)
		}
		if _, err := w.Write(key); err != nil {
			w.Close()
			Zero(key)
			return nil, fmt.Errorf("crypto: write %s: %w", path, err)
		}
		if err := w.Sync(); err != nil {
			w.Close()
			Zero(key)
			return nil, fmt.Errorf("crypto: fsync %s: %w", path, err)
		}
		if err := w.Close(); err != nil {
			Zero(key)
			return nil, fmt.Errorf("crypto: close %s: %w", path, err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("crypto: open %s: %w", path, err)
	}
}
