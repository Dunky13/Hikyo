//go:build windows

package disclose

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// The Windows leg of the triad. CREATE_NEW is expressed as O_CREATE|O_EXCL,
// which the runtime maps to it, so the never-overwrite property holds.
//
// Stated limitation, not a silent one: the owner-only DACL and the
// dirfd-relative create the unix path uses have no direct equivalent here,
// so this leg gives exclusivity but not the parent-directory ownership check.
// Windows is a CLIENT platform for Wenv — the server, and therefore every
// bootstrap and reset disclosure, runs on unix — so the weaker leg is not on
// the bootstrap path. Closing it needs the Windows security APIs and belongs
// with the ticket that ships a supported Windows client.
func writeExclusive(path, content string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrFileExists
		}
		return fmt.Errorf("refusing to disclose: cannot create %q: %w", path, err)
	}
	defer f.Close()
	if _, err := io.WriteString(f, content); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

// openControllingTerminal opens the console output device, the Windows
// counterpart of /dev/tty: a redirected stdout does not reach it.
func openControllingTerminal() (io.WriteCloser, error) {
	return os.OpenFile("CONOUT$", os.O_RDWR, 0)
}
