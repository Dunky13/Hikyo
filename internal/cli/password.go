package cli

import (
	"fmt"
	"os"
	"os/signal"
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
	// INTERRUPT-SAFE ECHO RESTORE. term.ReadPassword turns echo off and turns
	// it back on when it returns — and a Ctrl-C while it is blocked kills the
	// process before it returns, leaving the terminal with echo disabled. The
	// user's shell then reads their next keystrokes invisibly, and the next
	// secret they type is invisible too, which is the failure mode that matters:
	// they cannot see that it is not being masked, so they type it anyway.
	//
	// The state is captured before the read and restored from a signal handler,
	// so the terminal is usable whichever way the read ends.
	state, stateErr := term.GetState(int(tty.Fd()))
	if stateErr == nil {
		interrupted := make(chan os.Signal, 1)
		signal.Notify(interrupted, os.Interrupt)
		done := make(chan struct{})
		defer func() {
			signal.Stop(interrupted)
			close(done)
		}()
		go func() {
			select {
			case <-interrupted:
				_ = term.Restore(int(tty.Fd()), state)
				fmt.Fprintln(tty)
				// The command still dies of the interrupt — 130 is the shell's
				// own spelling of "killed by SIGINT". Restoring and exiting is
				// portable where re-raising the signal is not, and this handler
				// exists to leave the terminal usable, not to make the command
				// uninterruptible.
				os.Exit(130)
			case <-done:
			}
		}()
	}
	raw, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		if stateErr == nil {
			_ = term.Restore(int(tty.Fd()), state)
		}
		return "", failf(ExitRefused, "reading the password: %v", err)
	}
	// TrimRight only: leading and internal whitespace are legitimate password
	// characters, and silently altering a password is how "my password stopped
	// working" happens.
	return strings.TrimRight(string(raw), "\r\n"), nil
}
