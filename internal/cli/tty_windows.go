//go:build windows

package cli

// ttyDevice is the Windows console, the counterpart of /dev/tty.
const ttyDevice = "CONIN$"
