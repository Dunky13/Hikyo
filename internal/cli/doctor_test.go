package cli_test

import (
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/cli"
)

func TestDoctorGrammar(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"unknown argument", []string{"doctor", "now"}, cli.ExitUsage},
		{"valid invocation reaches auth", []string{"doctor", "--instance", "unknown-ref"}, cli.ExitRefused},
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

func TestHelpListsDoctor(t *testing.T) {
	var help strings.Builder
	cli.Usage(&help)
	if !strings.Contains(help.String(), "hikyo doctor") {
		t.Fatal("help omits doctor")
	}
}
