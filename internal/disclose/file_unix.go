//go:build !windows

package disclose

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// writeExclusive creates the output file the way the ADR fixes it, and the
// order is the security property:
//
//  1. open the PARENT directory with O_DIRECTORY|O_NOFOLLOW and check it —
//     owned by the invoking user, not world- or group-writable;
//  2. create the final component RELATIVE TO THAT DIRECTORY FD with
//     O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW, so the path cannot be swapped
//     between the check and the create;
//  3. fchmod to exactly 0600 (umask-independent — a permissive umask must not
//     be able to widen a file holding a credential);
//  4. fstat the written descriptor and confirm a regular file.
//
// Symlinked or shared-writable parents are refused by these checks rather
// than delegated to caller judgment. Ancestry ABOVE the checked parent stays
// the caller's path choice, which the docs state rather than pretending
// otherwise.
func writeExclusive(path, content string) error {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	if name == "" {
		return fmt.Errorf("refusing to disclose: %q names a directory, not a file", path)
	}

	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("refusing to disclose: cannot open the parent directory %q safely: %w", dir, err)
	}
	defer unix.Close(dirFD)

	var dirStat unix.Stat_t
	if err := unix.Fstat(dirFD, &dirStat); err != nil {
		return fmt.Errorf("refusing to disclose: cannot stat the parent directory %q: %w", dir, err)
	}
	if uint32(dirStat.Uid) != uint32(os.Getuid()) {
		return fmt.Errorf("refusing to disclose: the parent directory %q is owned by uid %d, not by you (uid %d)",
			dir, dirStat.Uid, os.Getuid())
	}
	// Group- or world-writable parents let someone else win the create race
	// or replace the file after it is written.
	if dirStat.Mode&0o022 != 0 {
		return fmt.Errorf("refusing to disclose: the parent directory %q is writable by group or others (mode %04o)",
			dir, dirStat.Mode&0o777)
	}

	fd, err := unix.Openat(dirFD, name,
		unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return ErrFileExists
		}
		return fmt.Errorf("refusing to disclose: cannot create %q: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	// Umask-independent: 0600 exactly, whatever the process umask was when
	// the file came into existence.
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("refusing to disclose: cannot set 0600 on %q: %w", path, err)
	}
	var fileStat unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &fileStat); err != nil {
		return fmt.Errorf("refusing to disclose: cannot stat %q: %w", path, err)
	}
	if fileStat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("refusing to disclose: %q is not a regular file", path)
	}

	if _, err := io.WriteString(f, content); err != nil {
		return err
	}
	// The value must be on disk before the caller is told it was delivered:
	// a crash between write and fsync would leave the operator holding a
	// receipt for a token that does not exist.
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

// openControllingTerminal opens /dev/tty — the controlling terminal, which is
// a different file from stdout. A process with no controlling terminal fails
// here, which is exactly the non-TTY refusal.
func openControllingTerminal() (io.WriteCloser, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}
