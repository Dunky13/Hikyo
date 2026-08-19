//go:build !linux

package compose

// IsTmpfs is Linux-only: TMPFS_MAGIC / RAMFS_MAGIC and statfs's filesystem-type
// field are Linux specifics, and the target deployment for the tmpfs guarantee
// is a Linux box (compose-integration ADR § Where plaintext lives). On every
// other platform this returns (true, nil) so the tmpfs doctor check does not
// fire spuriously; the guarantee is documented as the Linux leg's.
func IsTmpfs(string) (bool, error) { return true, nil }
