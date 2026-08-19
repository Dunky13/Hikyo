//go:build windows

package cli

import "io/fs"

// ownedByEUID is a no-op on Windows: it is a client platform, the server runs
// on unix, and the crypto protection-model ownership checks are documented
// weaker/no-ops there (mirrors internal/disclose and internal/crypto).
func ownedByEUID(_ fs.FileInfo) bool { return true }
