//go:build unix

package compose

import (
	"os"
	"syscall"
)

// fsyncDir fsyncs a directory so a rename/create within it is durable — on a
// crash an unsynced entry can leave a durable file with no findable name.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// fsyncRootPath fsyncs a directory named relative to root (name "." is the root
// itself), so a create/rename beneath it is durable. Used for the runtime-dir
// generation transaction, which is confined to an os.Root.
func fsyncRootPath(root *os.Root, name string) error {
	d, err := root.Open(name)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ownerOf returns the uid/gid of an existing file so a rewrite can preserve
// them. Returns (-1, -1) when it cannot be determined.
func ownerOf(fi os.FileInfo) (uid, gid int) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1
	}
	return int(st.Uid), int(st.Gid)
}
