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

// windowsTerminal presents the console's separate input and output handles as
// one owned read/write/close handle. Windows cannot use one CONOUT$ descriptor
// for both directions; TerminalSession keeps that platform fact private.
type windowsTerminal struct {
	input  io.ReadCloser
	output io.WriteCloser
}

func newWindowsTerminal(input io.ReadCloser, output io.WriteCloser) io.WriteCloser {
	return &windowsTerminal{input: input, output: output}
}

func (t *windowsTerminal) Read(p []byte) (int, error)  { return t.input.Read(p) }
func (t *windowsTerminal) Write(p []byte) (int, error) { return t.output.Write(p) }
func (t *windowsTerminal) terminalPasswordFD() int {
	input, ok := t.input.(*os.File)
	if !ok {
		return -1
	}
	return int(input.Fd())
}
func (t *windowsTerminal) Close() error {
	return errors.Join(t.input.Close(), t.output.Close())
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

// openControllingTerminal owns both Windows console handles behind one
// session handle: CONIN$ for confirmations and CONOUT$ for prompts and
// disclosures. Redirected stdin/stdout never receive either direction.
func openControllingTerminal() (io.WriteCloser, error) {
	input, err := os.OpenFile("CONIN$", os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	output, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		return nil, errors.Join(err, input.Close())
	}
	return newWindowsTerminal(input, output), nil
}
