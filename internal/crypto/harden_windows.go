//go:build !unix

package crypto

// Windows builds ship for the client verbs (system-architecture ADR
// § Packaging), which never load the keyring; the ADR's core-dump and
// dumpable hardening is Unix machinery. A Windows-hosted *server* runs
// without it — no equivalent is claimed.
func HardenProcess() error { return nil }
