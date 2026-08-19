//go:build !unix

package compose

import "os"

// fsyncDir is a no-op on Windows: directory handles cannot be fsynced the way
// POSIX allows, and Windows is a client platform here. Stated, not silent — the
// crash-durability guarantee is the unix leg's.
func fsyncDir(string) error { return nil }

// fsyncRootPath is the Windows no-op leg (see fsyncDir).
func fsyncRootPath(*os.Root, string) error { return nil }

// ownerOf has no POSIX-uid equivalent on Windows, so ownership is not preserved
// on this client platform.
func ownerOf(os.FileInfo) (uid, gid int) { return -1, -1 }
