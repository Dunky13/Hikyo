package cli_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/cli"
)

// fakeTTY is a controlling terminal: it swallows writes and reads a scripted
// answer for the y/N confirmation.
type fakeTTY struct{ r io.Reader }

func (f *fakeTTY) Read(p []byte) (int, error)  { return f.r.Read(p) }
func (f *fakeTTY) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeTTY) Close() error                { return nil }

// openTTY returns an OpenTerminal that yields a fresh terminal each call, so
// onTerminal's open/close does not consume the confirmation answer.
func openTTY(answer string) func() (io.WriteCloser, error) {
	return func() (io.WriteCloser, error) {
		return &fakeTTY{r: strings.NewReader(answer)}, nil
	}
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
	// testIO injects no OpenTerminal, so onTerminal is false: the refusal needs no
	// server and comes before any session lookup.
	ios, _, stderr := definitionsTestIO(t, runHumanServer(t, true))
	if code := cli.Run(t.Context(), ios, runArgs()); code != cli.ExitRefused {
		t.Fatalf("exit %d, want refused; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "controlling terminal") {
		t.Errorf("refusal does not name the missing terminal: %s", stderr.String())
	}
}

func TestRunHumanSessionRefusedWhenDeclined(t *testing.T) {
	ios, _, stderr := definitionsTestIO(t, runHumanServer(t, true))
	ios.OpenTerminal = openTTY("n\n")
	if code := cli.Run(t.Context(), ios, runArgs()); code != cli.ExitRefused {
		t.Fatalf("exit %d, want refused; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "declined") {
		t.Errorf("refusal does not report the decline: %s", stderr.String())
	}
}

func TestRunHumanSessionRequiresLiveWindow(t *testing.T) {
	ios, _, stderr := definitionsTestIO(t, runHumanServer(t, false))
	ios.OpenTerminal = openTTY("y\n")
	if code := cli.Run(t.Context(), ios, runArgs()); code != cli.ExitAuth {
		t.Fatalf("exit %d, want ExitAuth; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "live disclosure window is required") {
		t.Errorf("refusal is not the disclosure-window message: %s", stderr.String())
	}
}

func TestRunHumanSessionConfigOnlySkipsWindow(t *testing.T) {
	// --config-only carries no secrets, so the reveal ceremony does not apply: with
	// a dead window and a "yes" confirmation the run reaches exec (captured here).
	ios, _, stderr := definitionsTestIO(t, runHumanServer(t, false))
	ios.OpenTerminal = openTTY("y\n")
	var execed bool
	ios.Exec = func(argv0 string, argv, env []string) error { execed = true; return nil }
	code := cli.Run(t.Context(), ios, runArgs("--config-only"))
	if code != cli.ExitOK {
		t.Fatalf("exit %d, want ok; stderr=%s", code, stderr.String())
	}
	if !execed {
		t.Error("config-only human-session run did not reach exec")
	}
}
