package cli

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// readTerminalPassword prompts on the CONTROLLING TERMINAL with echo off.
//
// Not stdin, and not stdout: a password read from a pipe would let a
// repository script feed one, and a prompt written to stdout would land in
// whatever collects it. The same reasoning as the output triad, applied to
// input — which is where the ADR got it from.
//
// No secret ever transits argv in either direction, so there is deliberately
// no --password flag for this to fall back to.
func readTerminalPassword(prompt string) (string, error) {
	tty, err := os.OpenFile(ttyDevice, os.O_RDWR, 0)
	if err != nil {
		return "", failf(ExitRefused,
			"a password can only be read from an interactive terminal, and this process has none. "+
				"There is no --password flag: a secret on argv is visible in `ps`, /proc/*/cmdline and shell history")
	}
	defer tty.Close()

	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return "", err
	}
	raw, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", failf(ExitRefused, "reading the password: %v", err)
	}
	// TrimRight only: leading and internal whitespace are legitimate password
	// characters, and silently altering a password is how "my password stopped
	// working" happens.
	return strings.TrimRight(string(raw), "\r\n"), nil
}
