package crypto

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setNotDumpable() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("crypto: PR_SET_DUMPABLE=0: %w", err)
	}
	return nil
}
