package cli_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/cli"
)

// The machine-identity CLI surface (#61): the delivery matrix, its refusals,
// and the grammar rules the ADR states as absences.

// TestMintDeliveryRefusalMatrix is the closed output-channel set, refusal
// side. Every case here runs BEFORE any network call, because preparation
// deliberately precedes target resolution: a credential minted with nowhere
// to put it has already been destroyed, and the server will never hand it
// back.
func TestMintDeliveryRefusalMatrix(t *testing.T) {
	// A parent directory this test owns, so the file leg's ownership and
	// permission checks pass on their own merits.
	good := t.TempDir()
	taken := filepath.Join(good, "already-there")
	if err := os.WriteFile(taken, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	shared := t.TempDir()
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			// The headline refusal: bare non-TTY output is refused, never
			// silently downgraded to stdout, and the refusal names all three
			// permitted destinations rather than just saying no.
			name: "bare non-tty is refused, not downgraded",
			args: []string{"sa", "credential", "mint", "--sa", "sa_1"},
			want: "no permitted destination",
		},
		{
			name: "two destinations named at once",
			args: []string{"sa", "credential", "mint", "--sa", "sa_1",
				"--output-file", filepath.Join(good, "a"), "--dangerously-print"},
			want: "choose one",
		},
		{
			// The file is never overwritten: an existing path may be a
			// symlink into somewhere else, and O_EXCL is what makes that
			// unarguable.
			name: "output file already exists",
			args: []string{"sa", "credential", "mint", "--sa", "sa_1", "--output-file", taken},
			want: "already exists",
		},
		{
			// A group- or world-writable parent lets someone else win the
			// create race or replace the file after it is written.
			name: "shared-writable parent directory",
			args: []string{"sa", "credential", "mint", "--sa", "sa_1",
				"--output-file", filepath.Join(shared, "token")},
			want: "writable by group or others",
		},
		{
			name: "rotate carries the same matrix",
			args: []string{"sa", "credential", "rotate", "--sa", "sa_1", "--id", "mcr_1"},
			want: "no permitted destination",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ios, _, stderr := testIO(t, nil)
			if got := cli.Run(t.Context(), ios, tc.args); got != cli.ExitRefused {
				t.Fatalf("exit %d, want ExitRefused (%d); stderr: %s", got, cli.ExitRefused, stderr)
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stderr %q does not explain the refusal (want %q)", stderr, tc.want)
			}
		})
	}
}

func TestDisclosurePreparationFailureMakesNoRequest(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	taken := filepath.Join(t.TempDir(), "already-reserved")
	if err := os.WriteFile(taken, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"service-account mint", []string{"sa", "credential", "mint", "--sa", "sa_1"}},
		{"account reset", []string{"account", "reset-credential", "usr_1"}},
		{"TOTP enrolment", []string{"account", "factor", "enrol-totp"}},
		{"recovery codes", []string{"account", "recovery-codes", "regenerate"}},
		{"recovery begin", []string{"account", "recovery", "begin", "--as", "alice"}},
		{"SCIM credential", []string{"scim", "credential", "mint", "scb_1"}},
		{"remote credential", []string{"remote-credential", "create", "--label", "peer"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests.Store(0)
			ios, _, stderr := testIO(t, nil)
			args := append(tc.args,
				"--output-file", taken,
				"--instance", server.URL,
			)
			got := cli.Run(t.Context(), ios, args)
			if got != cli.ExitRefused {
				t.Fatalf("exit %d, want ExitRefused (%d); stderr: %s", got, cli.ExitRefused, stderr)
			}
			if requests.Load() != 0 {
				t.Fatalf("destination preparation failed after %d request(s); want no request", requests.Load())
			}
			body, err := os.ReadFile(taken)
			if err != nil || string(body) != "owned" {
				t.Fatalf("existing destination changed: body=%q err=%v", body, err)
			}
		})
	}
}

// TestMintDeliveryAcceptedChannels is the positive side: each permitted
// destination gets past preparation and fails later, on the network, which
// is how we know the channel itself was accepted. `--dangerously-print` and
// `--output-file` are checkable without a terminal; the controlling-terminal
// leg is the one the refusal matrix above proves by its absence.
func TestMintDeliveryAcceptedChannels(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"explicit stdout opt-in", []string{"sa", "credential", "mint", "--sa", "sa_1",
			"--dangerously-print", "--instance", "unknown-ref"}},
		{"output file", []string{"sa", "credential", "mint", "--sa", "sa_1",
			"--output-file", filepath.Join(dir, "token"), "--instance", "unknown-ref"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ios, _, stderr := testIO(t, nil)
			cli.Run(t.Context(), ios, tc.args)
			if strings.Contains(stderr.String(), "nowhere to go") {
				t.Fatalf("a permitted destination was refused by preparation: %s", stderr)
			}
		})
	}
	// Preparation reserves the file, then deferred Abort removes the still-empty
	// reservation when target resolution fails before the mint.
	if _, err := os.Lstat(filepath.Join(dir, "token")); !os.IsNotExist(err) {
		t.Fatalf("the unused prepared output file remains: %v", err)
	}
}

// TestNoTokenFlagExists is the ADR's rule stated as an absence, so it needs a
// test that fails if the absence ends. A secret in argv is visible in `ps`,
// in /proc/<pid>/cmdline and in shell history; the run-wrapper's one clean
// property holds only while the flag does not exist to be misused.
func TestNoTokenFlagExists(t *testing.T) {
	for _, args := range [][]string{
		{"sa", "credential", "mint", "--sa", "sa_1", "--token", "hik_1_wl_secret"},
		{"sa", "list", "--token", "hik_1_wl_secret"},
		{"access", "grant", "list", "--token", "hik_1_wl_secret"},
		{"env", "list", "--token", "hik_1_wl_secret"},
	} {
		ios, _, _ := testIO(t, nil)
		if got := cli.Run(t.Context(), ios, args); got != cli.ExitUsage {
			t.Fatalf("%v: exit %d, want ExitUsage — a --token flag has appeared", args, got)
		}
	}
	// The help text may — and does — mention the flag's absence in prose, so
	// the assertion is against the shapes a flag is DOCUMENTED in, not
	// against the string.
	var help strings.Builder
	cli.Usage(&help)
	for _, shape := range []string{"--token <", "--token=", "[--token]", "--token TOKEN"} {
		if strings.Contains(help.String(), shape) {
			t.Fatalf("the help text advertises a --token flag (%q)", shape)
		}
	}
}

func TestServiceAccountGrammar(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"sa needs a subverb", []string{"sa"}, cli.ExitUsage},
		{"unknown subverb", []string{"sa", "warp"}, cli.ExitUsage},
		{"create needs a name", []string{"sa", "create", "--kind", "workload"}, cli.ExitUsage},
		{"create needs a kind", []string{"sa", "create", "--name", "deployer"}, cli.ExitUsage},
		{"delete needs an id", []string{"sa", "delete"}, cli.ExitUsage},
		{"credential needs a subverb", []string{"sa", "credential"}, cli.ExitUsage},
		{"credential needs a service account", []string{"sa", "credential", "list"}, cli.ExitUsage},
		{"revoke needs a credential id", []string{"sa", "credential", "revoke", "--sa", "sa_1"}, cli.ExitUsage},
		{"rotate needs a credential id", []string{"sa", "credential", "rotate", "--sa", "sa_1"}, cli.ExitUsage},
		// `indefinite` is a distinct typed value, so naming both it and a
		// duration is two different lifetimes rather than a refinement.
		{"indefinite and lifetime collide", []string{"sa", "credential", "mint", "--sa", "sa_1",
			"--indefinite", "--lifetime", "720h", "--dangerously-print"}, cli.ExitUsage},
		{"lifetime must parse", []string{"sa", "credential", "mint", "--sa", "sa_1",
			"--lifetime", "soon", "--dangerously-print"}, cli.ExitUsage},
		// A service account is project-owned, so an org without a project is
		// a usage error rather than a wider query.
		{"list needs a project", []string{"sa", "list", "--instance", "unknown-ref"}, cli.ExitRefused},
		{"policy needs a subverb", []string{"instance-config", "credential-policy"}, cli.ExitUsage},
		{"policy rejects unknown verb", []string{"instance-config", "credential-policy", "warp"}, cli.ExitUsage},
		{"policy set validates the ceiling", []string{"instance-config", "credential-policy", "set",
			"--max-lifetime", "soon"}, cli.ExitUsage},
		{"policy set validates the opt-in", []string{"instance-config", "credential-policy", "set",
			"--allow-indefinite", "maybe"}, cli.ExitUsage},
		{"policy set validates the cap", []string{"instance-config", "credential-policy", "set",
			"--max-live-credentials", "0"}, cli.ExitUsage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ios, _, stderr := testIO(t, nil)
			if got := cli.Run(t.Context(), ios, tc.args); got != tc.want {
				t.Fatalf("exit %d, want %d; stderr: %s", got, tc.want, stderr)
			}
		})
	}
}

func TestHelpStatesTheConsumptionChannels(t *testing.T) {
	var help strings.Builder
	cli.Usage(&help)
	for _, want := range []string{
		"hikyo sa credential mint --sa <id>",
		"hikyo sa credential rotate --sa <id>",
		"--token-file <path> or HIKYO_TOKEN",
		"never a --token flag",
	} {
		if !strings.Contains(help.String(), want) {
			t.Errorf("help missing %q", want)
		}
	}
}
