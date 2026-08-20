package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// SS3 CLI-flag namespace sweep (#74, secret-scanning ADR §4). The only
// secret-scanning input the CLI offers is the per-finding `--acknowledge` token
// flag; no blanket "ignore all findings" / "skip scan" / "disable scan" flag
// exists on any verb. This guards the flag namespace at the source: a new flag
// whose name reads as a blanket scan override fails here.
//
// It also asserts the sanctioned per-finding flag IS registered, so the guard
// cannot pass vacuously by the flag disappearing.

var flagRegistration = regexp.MustCompile(`fs\.(?:String|Bool)Var\([^,]+,\s*"([a-z0-9-]+)"`)

func TestNoBlanketScanOverrideFlag(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	bannedSubstrings := []string{"ignore-finding", "ignore-scan", "skip-scan",
		"skip-finding", "no-scan", "disable-scan", "disable-finding",
		"bypass-scan", "suppress-finding", "suppress-scan"}

	sawAcknowledge := false
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range flagRegistration.FindAllStringSubmatch(string(src), -1) {
			name := m[1]
			if name == "acknowledge" {
				sawAcknowledge = true
			}
			for _, banned := range bannedSubstrings {
				if strings.Contains(name, banned) {
					t.Errorf("%s registers a blanket scan-override flag --%s; only the per-finding --acknowledge is permitted", e.Name(), name)
				}
			}
		}
	}
	if !sawAcknowledge {
		t.Fatal("no --acknowledge flag is registered anywhere; the per-finding acknowledgement path is missing")
	}
}
