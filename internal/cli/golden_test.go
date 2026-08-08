package cli_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dunky13/wenv/internal/cli"
)

// Golden snapshots (api-cli-surface ADR § The CLI is a frozen surface too).
//
// From the first stable release, within the major: no verb or flag is removed
// or repurposed, `-o json` shapes are additive-only, exit-code meanings are
// stable, and `--format` values are never removed. Enforced by committed
// fixtures whose diff is reviewed like a spec change.
//
// Human-oriented `table` output is explicitly NOT frozen and is deliberately
// absent from these fixtures — scripts that parse tables instead of `-o json`
// are outside the promise, and snapshotting table output here would quietly
// extend the promise to cover it.

var update = flag.Bool("update", false, "rewrite the golden fixtures")

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing fixture %s (run `go test ./internal/cli -update` and review the diff): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s drifted from its committed fixture.\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func testIO(t *testing.T, env map[string]string) (cli.IO, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	state := t.TempDir()
	work := t.TempDir()
	var stdout, stderr bytes.Buffer
	get := func(k string) string {
		if v, ok := env[k]; ok {
			return v
		}
		if k == "WENV_STATE_DIR" {
			return state
		}
		return ""
	}
	return cli.IO{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Env:     cli.Env{Getenv: get},
		Workdir: work,
	}, &stdout, &stderr
}

func TestHelpOutputIsFrozen(t *testing.T) {
	var buf bytes.Buffer
	cli.Usage(&buf)
	golden(t, "help.txt", buf.Bytes())
}

func TestExitCodeMatrix(t *testing.T) {
	// The scenario matrix the ops spec calls for: a fixed set of invocations
	// with their committed exit codes. Scripts branch on codes, so a code
	// changing under an unchanged invocation is a breaking change.
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, cli.ExitUsage},
		{"unknown verb", []string{"teleport"}, cli.ExitUsage},
		{"unknown context subverb", []string{"context", "warp"}, cli.ExitUsage},
		{"context show without a name", []string{"context", "show"}, cli.ExitUsage},
		{"context show unknown name", []string{"context", "show", "nope"}, cli.ExitNotFound},
		{"context delete unknown trust entry", []string{"context", "delete", "--instance", "nope"}, cli.ExitNotFound},
		{"login without a target", []string{"login", "--local"}, cli.ExitUsage},
		{"login without --local refuses by name", []string{"login", "https://wenv.example"}, cli.ExitRefused},
		{"device flow refuses by name", []string{"login", "https://wenv.example", "--device"}, cli.ExitRefused},
		{"login against an unestablished reference", []string{"login", "--local", "--as", "u", "unknown-ref"}, cli.ExitRefused},
		{"unknown output format", []string{"context", "list", "-o", "yaml"}, cli.ExitUsage},
		{"org without a subverb", []string{"org"}, cli.ExitUsage},
		{"org list with no session", []string{"org", "list", "--instance", "unknown-ref"}, cli.ExitRefused},
		{"account without the subverb", []string{"account"}, cli.ExitUsage},
		{"passkey enrol refuses by name", []string{"account", "passkey", "enrol"}, cli.ExitRefused},
	}
	var report strings.Builder
	for _, tc := range cases {
		ios, _, _ := testIO(t, nil)
		got := cli.Run(t.Context(), ios, tc.args)
		report.WriteString(strings.Join(append([]string{"wenv"}, tc.args...), " "))
		report.WriteString(" -> ")
		report.WriteString(exitName(got))
		report.WriteString("\n")
		if got != tc.want {
			t.Errorf("%s: exit %d (%s), want %d (%s)", tc.name, got, exitName(got), tc.want, exitName(tc.want))
		}
	}
	golden(t, "exit-codes.txt", []byte(report.String()))
}

func exitName(code int) string {
	switch code {
	case cli.ExitOK:
		return "0 ok"
	case cli.ExitInternal:
		return "1 internal"
	case cli.ExitUsage:
		return "2 usage"
	case cli.ExitAuth:
		return "3 authentication"
	case cli.ExitRefused:
		return "4 refused"
	case cli.ExitNotFound:
		return "5 not found"
	case cli.ExitUnavailable:
		return "6 unavailable"
	default:
		return "unknown"
	}
}

func TestContextJSONShapeIsFrozen(t *testing.T) {
	// `-o json` shapes are part of the promise. The fixture is the machine
	// contract; adding a field to it is additive and fine, removing or
	// renaming one is not.
	ios, stdout, _ := testIO(t, nil)
	if code := cli.Run(t.Context(), ios, []string{"context", "list", "-o", "json"}); code != cli.ExitOK {
		t.Fatalf("exit %d", code)
	}
	golden(t, "context-list-empty.json", stdout.Bytes())
}

func TestAnUnestablishedReferenceIsRefusedNotPrompted(t *testing.T) {
	// The rule with teeth: a pin file or a context may NAME an instance, and
	// if the reference is not in the local trust store the CLI refuses and
	// names the missing provisioning step. It never prompts-to-trust
	// mid-command and never sends a credential toward the origin.
	ios, _, stderr := testIO(t, nil)
	code := cli.Run(t.Context(), ios, []string{"login", "--local", "--as", "admin", "malicious-ref"})
	if code != cli.ExitRefused {
		t.Fatalf("exit %d, want %d", code, cli.ExitRefused)
	}
	msg := stderr.String()
	for _, want := range []string{"not in the local trust store", "--trust-file", "WENV_TRUST_BUNDLE"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not mention %q:\n%s", want, msg)
		}
	}
}

func TestPinFileCanDirectButNeverIntroducesAnOrigin(t *testing.T) {
	// A hostile pin-file edit is bounded to retargeting WITHIN origins this
	// box already trusts. It cannot name an origin at all — the schema has no
	// field for one — and a reference it names that is not established is a
	// refusal, so the credential-exfiltration variant is closed by
	// construction rather than by vigilance.
	ios, _, stderr := testIO(t, nil)
	work := ios.Workdir
	pin := `{"instance":"attacker-controlled","org":"o","project":"p","env":"e"}`
	if err := os.WriteFile(filepath.Join(work, cli.PinFileName), []byte(pin), 0o644); err != nil {
		t.Fatal(err)
	}
	code := cli.Run(t.Context(), ios, []string{"org", "list"})
	if code != cli.ExitRefused {
		t.Fatalf("exit %d, want %d — a pin file reached an unestablished instance", code, cli.ExitRefused)
	}
	if !strings.Contains(stderr.String(), "not in the local trust store") {
		t.Errorf("unexpected refusal:\n%s", stderr.String())
	}
	// And the pin file schema itself has no origin field: a struct field is
	// the only way one could be introduced, and there is none.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(`{"origin":"https://attacker.example"}`), &parsed); err != nil {
		t.Fatal(err)
	}
	var typed cli.PinFile
	if err := json.Unmarshal([]byte(`{"origin":"https://attacker.example"}`), &typed); err != nil {
		t.Fatal(err)
	}
	if typed.Instance != "" {
		t.Error("a pin file introduced an instance through an origin member")
	}
}

func TestCanonicalOriginRefusesWhatIsNotAnOrigin(t *testing.T) {
	for _, bad := range []string{
		"https://wenv.example/some/path",
		"https://user:pass@wenv.example",
		"ftp://wenv.example",
		"https://",
		"https://wenv.example?a=1",
	} {
		if _, err := cli.CanonicalOrigin(bad); err == nil {
			t.Errorf("%q was accepted as an origin", bad)
		}
	}
	got, err := cli.CanonicalOrigin("HTTPS://Wenv.Example:8443/")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://wenv.example:8443" {
		t.Fatalf("canonical origin %q", got)
	}
}

func TestTargetResolutionPrecedence(t *testing.T) {
	// Per dimension, first hit wins: flags, then environment, then the pin
	// file, then the named context. Overriding ONE dimension is legitimate
	// exactly because the others re-resolve within the same chain.
	ios, _, _ := testIO(t, map[string]string{"WENV_PROJECT": "from-env"})
	if err := os.WriteFile(filepath.Join(ios.Workdir, cli.PinFileName),
		[]byte(`{"instance":"pinned","org":"pinned-org","project":"pinned-project","env":"pinned-env"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := cli.NewState(ios.Env)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := cli.Resolve(st, ios.Env, cli.Flags{Env: "from-flag"}, ios.Workdir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[cli.Dimension]struct {
		value  string
		source cli.Source
	}{
		cli.DimEnv:      {"from-flag", cli.SourceFlag},
		cli.DimProject:  {"from-env", cli.SourceEnv},
		cli.DimOrg:      {"pinned-org", cli.SourcePinFile},
		cli.DimInstance: {"pinned", cli.SourcePinFile},
	}
	for dim, w := range want {
		if got := resolved.Get(dim); got != w.value {
			t.Errorf("%s = %q, want %q", dim, got, w.value)
		}
		if got := resolved.Sources[dim]; got != w.source {
			t.Errorf("%s came from %q, want %q", dim, got, w.source)
		}
	}
}

func TestMissingDimensionIsAHardErrorNamingWhereItLooked(t *testing.T) {
	// Ambiguity is a hard error, never a default: no dimension is ever
	// silently assumed.
	ios, _, _ := testIO(t, nil)
	st, err := cli.NewState(ios.Env)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := cli.Resolve(st, ios.Env, cli.Flags{}, ios.Workdir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolved.Require(cli.DimOrg)
	if err == nil {
		t.Fatal("a missing dimension resolved to something")
	}
	for _, want := range []string{"--org", "WENV_ORG", cli.PinFileName, "context"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say it looked at %q: %v", want, err)
		}
	}
}

func TestThereIsNoPersistentActiveContext(t *testing.T) {
	// `context use` was the sticky global the model prohibits, and its absence
	// is a property worth asserting: one forgotten `use` before a disclosure
	// verb is the wrong-environment export this design exists to prevent.
	ios, _, stderr := testIO(t, nil)
	if code := cli.Run(t.Context(), ios, []string{"context", "use", "prod"}); code != cli.ExitUsage {
		t.Fatalf("`context use` exists (exit %d)", code)
	}
	if !strings.Contains(stderr.String(), "create, list, show or delete") {
		t.Errorf("unexpected message:\n%s", stderr.String())
	}
	var help bytes.Buffer
	cli.Usage(&help)
	if strings.Contains(help.String(), "context use") {
		t.Error("help advertises `context use`")
	}
}
