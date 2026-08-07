package api_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dunky13/wenv/api"
)

// Negative fixtures for the freeze gate (mvp-boundary S1).
//
// The ADR names three that must fail permanently — deleting a deprecated
// endpoint, removing a response-enum value, and removing a security
// requirement — and the 3.1 amendment adds the profile set: nullable, an
// alternate dialect, and top-level webhooks. Each is a base/revised pair
// differing by exactly one thing, because a fixture that changes two things
// proves neither.
//
// Fixture layout: api/testdata/freeze/<case>/{base.yaml,revised.yaml,verdict}
// where verdict is "pass" or "fail".

func TestFreezeGateFixtures(t *testing.T) {
	root := filepath.Join("testdata", "freeze")
	cases, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no freeze fixtures: the gate would be vacuously green")
	}
	sawFail := false
	for _, c := range cases {
		if !c.IsDir() {
			continue
		}
		t.Run(c.Name(), func(t *testing.T) {
			dir := filepath.Join(root, c.Name())
			base := mustRead(t, filepath.Join(dir, "base.yaml"))
			revised := mustRead(t, filepath.Join(dir, "revised.yaml"))
			verdict := strings.TrimSpace(string(mustRead(t, filepath.Join(dir, "verdict"))))

			violations, err := api.CheckFreeze(base, revised)
			if err != nil {
				t.Fatalf("gate errored: %v", err)
			}
			switch verdict {
			case "pass":
				if len(violations) > 0 {
					t.Fatalf("a permitted addition was refused:\n%s", render(violations))
				}
			case "fail":
				if len(violations) == 0 {
					t.Fatal("a forbidden change passed the gate")
				}
			default:
				t.Fatalf("verdict file says %q, want pass or fail", verdict)
			}
		})
		if strings.Contains(c.Name(), "remove") || strings.Contains(c.Name(), "delete") {
			sawFail = true
		}
	}
	if !sawFail {
		t.Error("no removal fixture present — the gate's whole purpose is unproven")
	}
}

// The gate must be green against the live contract compared with itself: a
// no-op diff producing violations would mean every future change is refused
// for reasons unrelated to the change.
func TestFreezeGateIsGreenAgainstAnIdenticalDocument(t *testing.T) {
	violations, err := api.CheckFreeze(api.SpecYAML, api.SpecYAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) > 0 {
		t.Fatalf("the contract is not equal to itself under the gate:\n%s", render(violations))
	}
}

// The allowlist is the policy, and an empty one would refuse everything —
// which is fail-closed but useless, and would be quietly "fixed" by whoever
// hit it first. Pin that it names the additions the promise actually offers.
func TestAllowlistNamesThePromisedAdditions(t *testing.T) {
	for _, want := range []string{
		"endpoint-added",
		"new-optional-request-property",
		"response-property-added",
		"response-property-enum-value-added",
	} {
		if !api.PermittedChanges[want] {
			t.Errorf("the allowlist does not permit %q, which the version promise offers", want)
		}
	}
	// And the things it must never permit, however oasdiff classifies them.
	for _, forbidden := range []string{
		"api-removed-without-deprecation",
		"api-removed-before-sunset",
		"request-property-became-required",
		"new-required-request-property",
		"api-security-removed",
		"response-property-enum-value-removed",
	} {
		if api.PermittedChanges[forbidden] {
			t.Errorf("the allowlist permits %q, which is a break however oasdiff grades it", forbidden)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func render(vs []api.Violation) string {
	var b strings.Builder
	for _, v := range vs {
		b.WriteString("  " + v.String() + "\n")
	}
	return b.String()
}
