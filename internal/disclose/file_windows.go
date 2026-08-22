//go:build windows

package disclose

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

type preparedFile struct {
	f    *os.File
	path string
}

// prepareFile uses CREATE_NEW with no sharing, so the reserved handle cannot
// be reopened, replaced, or deleted before WriteOnce/Abort consumes it. The
// owner-only DACL and dirfd-relative parent checks used on Unix still have no
// equivalent here; Windows remains a client platform, not a bootstrap host.
func prepareFile(path string) (*preparedFile, error) {
	pathp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("refusing to disclose: invalid output path %q: %w", path, err)
	}
	handle, err := windows.CreateFile(
		pathp,
		windows.GENERIC_WRITE|windows.DELETE,
		0,
		nil,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return nil, ErrFileExists
		}
		return nil, fmt.Errorf("refusing to disclose: cannot create %q: %w", path, err)
	}
	return &preparedFile{f: os.NewFile(uintptr(handle), path), path: path}, nil
}

func (p *preparedFile) deleteOnClose() error {
	deleteFile := byte(1)
	if err := windows.SetFileInformationByHandle(
		windows.Handle(p.f.Fd()), windows.FileDispositionInfo, &deleteFile, 1,
	); err != nil {
		return fmt.Errorf("remove disclosure reservation %q: %w", p.path, err)
	}
	return nil
}

func (p *preparedFile) write(content string) error {
	_, writeErr := io.WriteString(p.f, content)
	if writeErr == nil {
		writeErr = p.f.Sync()
	}
	if writeErr != nil {
		writeErr = errors.Join(writeErr, p.deleteOnClose())
	}
	writeErr = errors.Join(writeErr, p.f.Close())
	p.f = nil
	return writeErr
}

func (p *preparedFile) abort() error {
	info, err := p.f.Stat()
	if err != nil || info.Size() != 0 {
		closeErr := p.f.Close()
		p.f = nil
		return errors.Join(ErrReservationChanged, err, closeErr)
	}
	err = errors.Join(p.deleteOnClose(), p.f.Close())
	p.f = nil
	return err
}

// openControllingTerminal opens the console output device, the Windows
// counterpart of /dev/tty: a redirected stdout does not reach it.
func openControllingTerminal() (io.WriteCloser, error) {
	return os.OpenFile("CONOUT$", os.O_RDWR, 0)
}
