//go:build !windows

package cli

// ttyDevice is the controlling terminal, which is a different file from
// stdout: a log-capturing pipe does not receive it.
const ttyDevice = "/dev/tty"
