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

type preparedFile struct {
	f       *os.File
	dirFD   int
	name    string
	path    string
	created unix.Stat_t
}

func prepareFile(path string) (*preparedFile, error) {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	if name == "" {
		return nil, fmt.Errorf("refusing to disclose: %q names a directory, not a file", path)
	}

	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("refusing to disclose: cannot open the parent directory %q safely: %w", dir, err)
	}
	fail := func(err error) (*preparedFile, error) {
		_ = unix.Close(dirFD)
		return nil, err
	}

	var dirStat unix.Stat_t
	if err := unix.Fstat(dirFD, &dirStat); err != nil {
		return fail(fmt.Errorf("refusing to disclose: cannot stat the parent directory %q: %w", dir, err))
	}
	if uint32(dirStat.Uid) != uint32(os.Getuid()) {
		return fail(fmt.Errorf("refusing to disclose: the parent directory %q is owned by uid %d, not by you (uid %d)",
			dir, dirStat.Uid, os.Getuid()))
	}
	if dirStat.Mode&0o022 != 0 {
		return fail(fmt.Errorf("refusing to disclose: the parent directory %q is writable by group or others (mode %04o)",
			dir, dirStat.Mode&0o777))
	}

	fd, err := unix.Openat(dirFD, name,
		unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fail(ErrFileExists)
		}
		return fail(fmt.Errorf("refusing to disclose: cannot create %q: %w", path, err))
	}
	f := os.NewFile(uintptr(fd), path)
	cleanup := func(err error) (*preparedFile, error) {
		_ = f.Close()
		_ = unix.Unlinkat(dirFD, name, 0)
		_ = unix.Close(dirFD)
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		return cleanup(fmt.Errorf("refusing to disclose: cannot set 0600 on %q: %w", path, err))
	}
	var fileStat unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &fileStat); err != nil {
		return cleanup(fmt.Errorf("refusing to disclose: cannot stat %q: %w", path, err))
	}
	if fileStat.Mode&unix.S_IFMT != unix.S_IFREG {
		return cleanup(fmt.Errorf("refusing to disclose: %q is not a regular file", path))
	}

	return &preparedFile{f: f, dirFD: dirFD, name: name, path: path, created: fileStat}, nil
}

func (p *preparedFile) pathStillOwned() bool {
	var current unix.Stat_t
	if err := unix.Fstatat(p.dirFD, p.name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false
	}
	return current.Dev == p.created.Dev && current.Ino == p.created.Ino
}

func (p *preparedFile) removeOwned() error {
	// The parent was opened without following symlinks and rejected unless it
	// is owned by this uid and not writable by group/others. Therefore an
	// untrusted uid cannot replace this entry between the identity check and
	// unlink; a same-uid process is already inside the owner boundary for this
	// 0600 disclosure file. The inode comparison still prevents stale cleanup
	// from removing a replacement made before Abort starts.
	if !p.pathStillOwned() {
		return ErrReservationChanged
	}
	if err := unix.Unlinkat(p.dirFD, p.name, 0); err != nil {
		return fmt.Errorf("remove unused disclosure reservation %q: %w", p.path, err)
	}
	return nil
}

func (p *preparedFile) write(content string) error {
	_, writeErr := io.WriteString(p.f, content)
	if writeErr == nil {
		writeErr = p.f.Sync()
	}
	writeErr = errors.Join(writeErr, p.f.Close())
	p.f = nil
	if writeErr == nil {
		if err := unix.Fsync(p.dirFD); err == nil {
			_ = unix.Close(p.dirFD)
			p.dirFD = -1
			return nil
		} else {
			writeErr = fmt.Errorf("refusing to disclose: cannot commit the directory entry for %q: %w", p.path, err)
		}
	}

	cleanupErr := p.removeOwned()
	if cleanupErr == nil {
		cleanupErr = unix.Fsync(p.dirFD)
	}
	_ = unix.Close(p.dirFD)
	p.dirFD = -1
	return errors.Join(writeErr, cleanupErr)
}

func (p *preparedFile) abort() error {
	var current unix.Stat_t
	if err := unix.Fstat(int(p.f.Fd()), &current); err != nil || current.Size != 0 || !p.pathStillOwned() {
		closeErr := p.f.Close()
		p.f = nil
		_ = unix.Close(p.dirFD)
		p.dirFD = -1
		return errors.Join(ErrReservationChanged, err, closeErr)
	}

	removeErr := p.removeOwned()
	closeErr := p.f.Close()
	p.f = nil
	if removeErr == nil {
		removeErr = unix.Fsync(p.dirFD)
	}
	_ = unix.Close(p.dirFD)
	p.dirFD = -1
	return errors.Join(removeErr, closeErr)
}

// openControllingTerminal opens /dev/tty — the controlling terminal, which is
// a different file from stdout. A process with no controlling terminal fails
// here, which is exactly the non-TTY refusal.
func openControllingTerminal() (io.WriteCloser, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}
