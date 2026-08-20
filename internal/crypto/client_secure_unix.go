//go:build unix

package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// The Unix leg of the client state-directory protection model
// (system-architecture ADR § Client local state): 0700 directory / 0600 file,
// owned by the invoking user, reached only through directory-relative,
// no-symlink-follow descriptors. Violations are REFUSED, never chmod-repaired —
// the caller surfaces them as a doctor finding.
//
// The state dir is opened EXACTLY ONCE, as an os.Root, and every check runs
// through that one descriptor — no validate-a-path-then-reopen-it TOCTOU:
//   - mode and owner are read with root.Stat(".") (fd-relative fstatat), never a
//     path stat a rename could race between check and use.
//   - os.OpenRoot follows a symlinked ROOT path (the root itself is not confined
//     — only lookups WITHIN it are), so after OpenRoot succeeds we os.Lstat the
//     path once and refuse a symlink. That Lstat comes AFTER the open, so a race
//     can only cause a spurious refusal, never a spurious acceptance — the fd we
//     actually use is already pinned.
//   - local.key is opened O_RDONLY|O_NOFOLLOW and its mode/owner/regularity read
//     from that fd (f.Stat()); there is no Lstat→open gap. An escaping symlink is
//     refused by os.Root itself ("path escapes"); an in-root, non-escaping key
//     symlink is platform-dependent (Linux ELOOP on O_NOFOLLOW, darwin follows)
//     and harmless — it can only resolve inside the 0700 dir the euid owns.

// loadOrCreateMasterKey returns the 32-byte local key from dir/local.key,
// creating the directory (0700) and key (0600, O_EXCL) on first use.
func loadOrCreateMasterKey(dir string) ([]byte, error) {
	root, err := openStateDir(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	f, err := root.OpenFile(localKeyName, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	switch {
	case err == nil:
		defer f.Close()
		return readVerifiedKey(f, dir)
	case errors.Is(err, os.ErrNotExist):
		return createKeyFileRoot(root, dir)
	default:
		return nil, fmt.Errorf("crypto: open %s/%s: %w", dir, localKeyName, err)
	}
}

// openStateDir creates dir 0700 if absent (chmod-on-create only, never
// repairing an existing dir's mode), opens it ONCE as an os.Root, refuses a
// symlinked dir with a post-open Lstat, and verifies exact 0700 + euid
// ownership through the root descriptor.
func openStateDir(dir string) (*os.Root, error) {
	// Create parents permissively, then the leaf itself with os.Mkdir so a
	// successful create is distinguishable from a pre-existing dir: only a dir we
	// just created is chmod'd (to counter umask); an existing one is verified and
	// refused if loose, never silently repaired.
	if parent := filepath.Dir(dir); parent != dir {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return nil, fmt.Errorf("crypto: create state dir parents %s: %w", parent, err)
		}
	}
	switch err := os.Mkdir(dir, 0o700); {
	case err == nil:
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("crypto: chmod state dir %s: %w", dir, err)
		}
	case errors.Is(err, os.ErrExist):
		// Pre-existing: verified below, never repaired.
	default:
		return nil, fmt.Errorf("crypto: create state dir %s: %w", dir, err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("crypto: open state root %s: %w", dir, err)
	}
	// os.OpenRoot follows a symlinked root path; refuse a symlinked state dir with
	// a single post-open Lstat (see file header: post-open ⇒ no acceptance race).
	if li, err := os.Lstat(dir); err != nil {
		root.Close()
		return nil, fmt.Errorf("crypto: lstat state dir %s: %w", dir, err)
	} else if li.Mode()&os.ModeSymlink != 0 {
		root.Close()
		return nil, fmt.Errorf("crypto: state dir %s is a symlink; refusing", dir)
	}
	info, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("crypto: stat state dir %s: %w", dir, err)
	}
	if !info.IsDir() {
		root.Close()
		return nil, fmt.Errorf("crypto: state path %s is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		root.Close()
		return nil, fmt.Errorf("crypto: state dir %s has mode %04o, want 0700; refusing", dir, perm)
	}
	if err := checkOwner(dir, info); err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

// readVerifiedKey verifies an already-open local.key (regular, 0600, euid-owned,
// all through its descriptor) and returns its 32 bytes. A short or oversized
// file is corruption, never a shorter key.
func readVerifiedKey(f *os.File, dir string) ([]byte, error) {
	if err := checkSecureFile(f); err != nil {
		return nil, err
	}
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(f, key); err != nil {
		return nil, fmt.Errorf("crypto: read %s/%s: %w", dir, localKeyName, err)
	}
	if extra, _ := f.Read(make([]byte, 1)); extra != 0 {
		return nil, fmt.Errorf("crypto: %s/%s is not a %d-byte local key", dir, localKeyName, KeySize)
	}
	return key, nil
}

// createKeyFileRoot creates local.key relative to root with O_EXCL and 0600,
// fills it with fresh randomness, and fsyncs it before use.
func createKeyFileRoot(root *os.Root, dir string) ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		Zero(key)
		return nil, fmt.Errorf("crypto: randomness unavailable, refusing to create local key: %w", err)
	}
	f, err := root.OpenFile(localKeyName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		Zero(key)
		return nil, fmt.Errorf("crypto: create %s/%s: %w", dir, localKeyName, err)
	}
	// Umask-independent: 0600 exactly whatever the process umask was.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		Zero(key)
		return nil, fmt.Errorf("crypto: chmod %s/%s: %w", dir, localKeyName, err)
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		Zero(key)
		return nil, fmt.Errorf("crypto: write %s/%s: %w", dir, localKeyName, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		Zero(key)
		return nil, fmt.Errorf("crypto: fsync %s/%s: %w", dir, localKeyName, err)
	}
	if err := f.Close(); err != nil {
		Zero(key)
		return nil, fmt.Errorf("crypto: close %s/%s: %w", dir, localKeyName, err)
	}
	return key, nil
}

// checkSecureFile verifies an already-open key file is 0600, a regular file,
// and owned by the euid, all through its descriptor.
func checkSecureFile(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("crypto: stat %s: %w", f.Name(), err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("crypto: %s is not a regular file", f.Name())
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		return fmt.Errorf("crypto: local key %s has mode %04o, want 0600; refusing", f.Name(), perm)
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
