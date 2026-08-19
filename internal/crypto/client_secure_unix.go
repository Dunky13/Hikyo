//go:build unix

package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"syscall"
)

// The Unix leg of the client state-directory protection model
// (system-architecture ADR § Client local state): 0700 directory / 0600 file,
// owned by the invoking user, reached only through directory-relative,
// no-symlink-follow descriptors. Violations are REFUSED, never chmod-repaired —
// the caller surfaces them as a doctor finding.
//
// Two symlink hazards are closed here rather than by a path stat:
//   - a symlinked STATE DIR: the directory is opened with O_NOFOLLOW|O_DIRECTORY,
//     which fails on a symlinked final component, and its mode/owner are then
//     read through that descriptor (f.Stat()), never a separate os.Stat that a
//     rename could race.
//   - a symlinked KEY: local.key is Lstat'd through the directory root before
//     opening, so a symlink in its place is refused (os.Root follows in-root
//     symlinks and ignores O_NOFOLLOW on some platforms, so the Lstat is the
//     real guard).

// loadOrCreateMasterKey returns the 32-byte local key from dir/local.key,
// creating the directory (0700) and key (0600, O_EXCL) on first use.
func loadOrCreateMasterKey(dir string) ([]byte, error) {
	root, err := openStateDirNoFollow(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	fi, err := root.Lstat(localKeyName)
	switch {
	case err == nil:
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("crypto: %s/%s is not a regular file (symlink or special); refusing", dir, localKeyName)
		}
		return readKeyFileRoot(root, dir)
	case os.IsNotExist(err):
		return createKeyFileRoot(root, dir)
	default:
		return nil, fmt.Errorf("crypto: stat %s/%s: %w", dir, localKeyName, err)
	}
}

// openStateDirNoFollow creates dir 0700 if absent, then opens it with
// O_NOFOLLOW|O_DIRECTORY (refusing a symlinked dir), verifies exact 0700 and
// euid ownership through the descriptor, and returns an os.Root confined to it.
func openStateDirNoFollow(dir string) (*os.Root, error) {
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("crypto: create state dir %s: %w", dir, err)
		}
		// MkdirAll honours umask, so tighten explicitly to 0700.
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("crypto: chmod state dir %s: %w", dir, err)
		}
	}

	df, err := os.OpenFile(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("crypto: open state dir %s (symlink or not a directory?): %w", dir, err)
	}
	info, err := df.Stat()
	df.Close()
	if err != nil {
		return nil, fmt.Errorf("crypto: stat state dir %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("crypto: state path %s is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		return nil, fmt.Errorf("crypto: state dir %s has mode %04o, want 0700; refusing", dir, perm)
	}
	if err := checkOwner(dir, info); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("crypto: open state root %s: %w", dir, err)
	}
	return root, nil
}

// readKeyFileRoot opens local.key relative to root, verifies exact 0600 and euid
// ownership through the descriptor, and returns its 32 bytes. A short or
// oversized file is corruption, never a shorter key.
func readKeyFileRoot(root *os.Root, dir string) ([]byte, error) {
	f, err := root.OpenFile(localKeyName, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("crypto: open %s/%s: %w", dir, localKeyName, err)
	}
	defer f.Close()
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
