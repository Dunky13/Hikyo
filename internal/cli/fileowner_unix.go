//go:build !windows

package cli

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByEUID reports whether the file is owned by the invoking user. It is the
// unix leg of the ownership check compose doctor renders; the server runs on
// unix, so this is the leg that matters. Windows treats every file as owned
// (the check is a no-op there, like the rest of the crypto protection model).
func ownedByEUID(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	return int(st.Uid) == os.Geteuid()
}
