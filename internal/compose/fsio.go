package compose

import (
	"fmt"
	"os"
	"path/filepath"
)

// Filesystem durability helpers. The compose-integration ADR is explicit about
// fsync ordering: a value must be on disk before anything references it, and a
// directory entry is only durable once the directory itself is fsynced. The
// single atomic-rename stamp file is the commit point; generation directories
// are made durable file-by-file then marked complete.

// writeFileFsync creates path (truncating), writes data, chmods to perm
// explicitly (umask-independent), and fsyncs the file. It does NOT fsync the
// parent — the caller fsyncs the directory once after writing all its files.
func writeFileFsync(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// atomicWrite writes data to a temp file in the same directory, fsyncs it,
// renames it over path (the atomic commit), then fsyncs the directory so the
// rename is durable. perm is applied explicitly.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true
	if err := fsyncDir(dir); err != nil {
		return fmt.Errorf("fsync dir after rename %s: %w", path, err)
	}
	return nil
}
