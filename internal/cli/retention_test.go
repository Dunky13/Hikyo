package cli_test

import (
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/cli"
)

func TestRetentionGrammar(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"org missing mode", []string{"org", "retention", "set"}, cli.ExitUsage},
		{"org conflicting modes", []string{"org", "retention", "set", "--unlimited", "--max-age", "24h", "--last-revisions", "3"}, cli.ExitUsage},
		{"project missing mode", []string{"project", "retention", "set"}, cli.ExitUsage},
		{"project conflicting modes", []string{"project", "retention", "set", "--inherit", "--max-age", "24h", "--last-revisions", "3"}, cli.ExitUsage},
		{"org get reaches auth", []string{"org", "retention", "get", "--instance", "unknown-ref", "--org", "org_a"}, cli.ExitRefused},
		{"project get reaches auth", []string{"project", "retention", "get", "--instance", "unknown-ref", "--org", "org_a", "--project", "prj_a"}, cli.ExitRefused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ios, _, _ := testIO(t, nil)
			if got := cli.Run(t.Context(), ios, tc.args); got != tc.want {
				t.Fatalf("exit %d, want %d", got, tc.want)
			}
		})
	}
}
