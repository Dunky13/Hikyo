package disclose

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"golang.org/x/term"
)

// ReadPassword reads one no-echo secret from the same controlling terminal
// handle used by the rest of the session. Platform construction records the
// input descriptor once; no prompt reopens /dev/tty or the Windows console.
func (s *TerminalSession) ReadPassword(prompt string) (string, error) {
	if s == nil {
		return "", ErrNoDestination
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", ErrNoDestination
	}
	if s.passwordFD < 0 {
		return "", errors.Join(ErrTerminalCapabilities, s.closeLocked())
	}
	if _, err := fmt.Fprint(s.terminal, prompt); err != nil {
		return "", errors.Join(err, s.closeLocked())
	}

	state, stateErr := term.GetState(s.passwordFD)
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
				_ = term.Restore(s.passwordFD, state)
				_, _ = fmt.Fprintln(s.terminal)
				os.Exit(130)
			case <-done:
			}
		}()
	}

	raw, err := term.ReadPassword(s.passwordFD)
	_, newlineErr := fmt.Fprintln(s.terminal)
	if err != nil {
		if stateErr == nil {
			_ = term.Restore(s.passwordFD, state)
		}
		return "", errors.Join(fmt.Errorf("reading terminal password: %w", err), newlineErr, s.closeLocked())
	}
	if newlineErr != nil {
		return "", errors.Join(newlineErr, s.closeLocked())
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}
