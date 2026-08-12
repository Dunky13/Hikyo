package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The consumption side of the closed channel set (#61): a workload receives
// its credential through `--token-file` and HIKYO_TOKEN, and nothing else.

func tokenIO(env map[string]string) (IO, *bytes.Buffer) {
	var stderr bytes.Buffer
	return IO{
		Stderr: &stderr,
		Env:    Env{Getenv: func(k string) string { return env[k] }},
	}, &stderr
}

func TestMachineTokenChannels(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("hik_1_wl_fromfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("environment variable", func(t *testing.T) {
		ios, _ := tokenIO(map[string]string{"HIKYO_TOKEN": "hik_1_wl_fromenv"})
		got, err := machineToken(ios, "")
		if err != nil || got != "hik_1_wl_fromenv" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("token file, trailing newline stripped", func(t *testing.T) {
		ios, _ := tokenIO(nil)
		got, err := machineToken(ios, file)
		if err != nil || got != "hik_1_wl_fromfile" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("neither channel is not an error", func(t *testing.T) {
		// An absent machine credential means "use the human session", which
		// is the ordinary case for every interactive verb.
		ios, _ := tokenIO(nil)
		got, err := machineToken(ios, "")
		if err != nil || got != "" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("token file wins, and says so loudly", func(t *testing.T) {
		ios, stderr := tokenIO(map[string]string{"HIKYO_TOKEN": "hik_1_wl_fromenv"})
		got, err := machineToken(ios, file)
		if err != nil || got != "hik_1_wl_fromfile" {
			t.Fatalf("--token-file must win: got %q, %v", got, err)
		}
		// A silent precedence rule on a credential is exactly the quiet
		// ambiguity the fail-loud principle exists to prevent: the operator
		// who set both believes one of them is in use.
		out := stderr.String()
		if !strings.Contains(out, "WARNING") || !strings.Contains(out, "HIKYO_TOKEN") {
			t.Fatalf("the collision must warn loudly, got %q", out)
		}
	})

	t.Run("identical values do not warn", func(t *testing.T) {
		ios, stderr := tokenIO(map[string]string{"HIKYO_TOKEN": "hik_1_wl_fromfile"})
		if _, err := machineToken(ios, file); err != nil {
			t.Fatal(err)
		}
		if stderr.Len() != 0 {
			t.Fatalf("two channels agreeing is not an ambiguity: %q", stderr)
		}
	})

	t.Run("empty token file is a loud failure", func(t *testing.T) {
		empty := filepath.Join(dir, "empty")
		if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		ios, _ := tokenIO(nil)
		if _, err := machineToken(ios, empty); err == nil {
			t.Fatal("an empty --token-file must fail rather than fall back to HIKYO_TOKEN")
		}
	})

	t.Run("missing token file is a loud failure", func(t *testing.T) {
		ios, _ := tokenIO(map[string]string{"HIKYO_TOKEN": "hik_1_wl_fromenv"})
		if _, err := machineToken(ios, filepath.Join(dir, "absent")); err == nil {
			t.Fatal("an unreadable --token-file must fail rather than silently use HIKYO_TOKEN")
		}
	})
}
