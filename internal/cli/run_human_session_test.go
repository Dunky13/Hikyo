package cli_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/cli"
	"github.com/Hikyo-Org/hikyo/internal/disclose"
)

// fakeTTY is a controlling terminal: it swallows writes and reads a scripted
// answer for the y/N confirmation.
type fakeTTY struct {
	r          io.Reader
	closeCount int
}

func (f *fakeTTY) Read(p []byte) (int, error)  { return f.r.Read(p) }
func (f *fakeTTY) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeTTY) Close() error {
	f.closeCount++
	return nil
}

func terminalSession(t *testing.T, answer string) (*disclose.TerminalSession, *fakeTTY) {
	t.Helper()
	tty := &fakeTTY{r: strings.NewReader(answer)}
	session, err := disclose.NewTerminalSession(tty)
	if err != nil {
		t.Fatal(err)
	}
	return session, tty
}

func runHumanServer(t *testing.T, windowLive bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/reveal-window"):
			_ = json.NewEncoder(w).Encode(apigen.RevealWindow{Live: windowLive})
		case strings.Contains(r.URL.Path, "/delivery"):
			val := "info"
			_ = json.NewEncoder(w).Encode(apigen.DeliveryResponse{
				Keys: []apigen.DeliveredKey{
					{Name: "LOG_LEVEL", Classification: "config", KeyId: "key_1", Value: &val, Presence: "set"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	})
}

func runArgs(extra ...string) []string {
	base := []string{"run", "--use-human-session"}
	base = append(base, extra...)
	return append(base, "--instance", "local", "--org", "org_70", "--project", "prj_70", "--env", "env_70", "--", "true")
}

func TestRunHumanSessionRefusedWithoutTTY(t *testing.T) {
	// testIO injects no TerminalSession, so the refusal needs no
	// server and comes before any session lookup.
	ios, _, stderr := definitionsTestIO(t, runHumanServer(t, true))
	if code := cli.Run(t.Context(), ios, runArgs()); code != cli.ExitRefused {
		t.Fatalf("exit %d, want refused; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "controlling terminal") {
		t.Errorf("refusal does not name the missing terminal: %s", stderr.String())
	}
}

func TestRunHumanSessionRefusedWhenStderrIsNotATerminal(t *testing.T) {
	// A controlling terminal exists but stderr is captured: the locked condition
	// "stderr-is-a-TTY" refuses before any session lookup.
	ios, _, stderr := definitionsTestIO(t, runHumanServer(t, true))
	var tty *fakeTTY
	ios.TerminalSession, tty = terminalSession(t, "y\n")
	ios.StderrIsTerminal = func() bool { return false }
	if code := cli.Run(t.Context(), ios, runArgs()); code != cli.ExitRefused {
		t.Fatalf("exit %d, want refused; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "stderr to be a terminal") {
		t.Errorf("refusal does not name stderr: %s", stderr.String())
	}
	if tty.closeCount != 1 {
		t.Errorf("terminal close count = %d, want 1", tty.closeCount)
	}
}

func TestRunHumanSessionRefusedWhenDeclined(t *testing.T) {
	ios, _, stderr := definitionsTestIO(t, runHumanServer(t, true))
	ios.StderrIsTerminal = func() bool { return true }
	var tty *fakeTTY
	ios.TerminalSession, tty = terminalSession(t, "n\n")
	if code := cli.Run(t.Context(), ios, runArgs()); code != cli.ExitRefused {
		t.Fatalf("exit %d, want refused; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "declined") {
		t.Errorf("refusal does not report the decline: %s", stderr.String())
	}
	if tty.closeCount != 1 {
		t.Errorf("terminal close count = %d, want 1", tty.closeCount)
	}
}

func TestRunHumanSessionRequiresLiveWindow(t *testing.T) {
	ios, _, stderr := definitionsTestIO(t, runHumanServer(t, false))
	ios.StderrIsTerminal = func() bool { return true }
	ios.TerminalSession, _ = terminalSession(t, "y\n")
	if code := cli.Run(t.Context(), ios, runArgs()); code != cli.ExitAuth {
		t.Fatalf("exit %d, want ExitAuth; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "live disclosure window is required") {
		t.Errorf("refusal is not the disclosure-window message: %s", stderr.String())
	}
}

func TestRunHumanSessionConfigOnlyStillNeedsTheWindow(t *testing.T) {
	// --config-only carries no secrets, but the exception's four conditions are
	// locked as a set: with a dead window the run is refused, with a live one
	// and a "yes" confirmation it reaches exec (captured here).
	dead, _, stderr := definitionsTestIO(t, runHumanServer(t, false))
	dead.StderrIsTerminal = func() bool { return true }
	dead.TerminalSession, _ = terminalSession(t, "y\n")
	if code := cli.Run(t.Context(), dead, runArgs("--config-only")); code != cli.ExitAuth {
		t.Fatalf("config-only with a dead window: exit %d, want ExitAuth; stderr=%s", code, stderr.String())
	}
	live, _, stderr2 := definitionsTestIO(t, runHumanServer(t, true))
	live.StderrIsTerminal = func() bool { return true }
	var liveTTY *fakeTTY
	live.TerminalSession, liveTTY = terminalSession(t, "y\n")
	var execed bool
	live.Exec = func(argv0 string, argv, env []string) error { execed = true; return nil }
	if code := cli.Run(t.Context(), live, runArgs("--config-only")); code != cli.ExitOK {
		t.Fatalf("exit %d, want ok; stderr=%s", code, stderr2.String())
	}
	if !execed {
		t.Error("config-only human-session run did not reach exec")
	}
	if liveTTY.closeCount != 1 {
		t.Errorf("terminal close count = %d, want 1", liveTTY.closeCount)
	}
}
