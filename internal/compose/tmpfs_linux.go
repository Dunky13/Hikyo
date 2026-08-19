//go:build linux

package compose

import "golang.org/x/sys/unix"

// TMPFS_MAGIC / RAMFS_MAGIC identify the in-memory filesystems the ADR allows
// rendered plaintext to live on (compose-integration ADR § Where plaintext
// lives; ops-spec § 6: "plaintext only ever on tmpfs"). x/sys/unix defines
// these constants but the check itself is written here for one place to audit.
const (
	tmpfsMagic = 0x01021994 // TMPFS_MAGIC
	ramfsMagic = 0x858458f6 // RAMFS_MAGIC
)

// IsTmpfs reports whether path is backed by tmpfs (or ramfs) via statfs. The
// caller (the CLI) feeds the result to doctor; the renderer does NOT refuse a
// non-tmpfs path — a default path must be tmpfs, but an explicitly configured
// one is the operator's call. This check is Linux-only; see the non-Linux leg.
func IsTmpfs(path string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false, err
	}
	magic := int64(st.Type)
	return magic == tmpfsMagic || magic == ramfsMagic, nil
}
