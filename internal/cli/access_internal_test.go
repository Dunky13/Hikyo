package cli

import (
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
)

func TestGrantResultRowRendersEveryOutcome(t *testing.T) {
	for _, tc := range []struct {
		outcome api.GrantOutcome
		want    string
	}{
		{outcome: api.GrantOutcomeCreated(), want: "created"},
		{outcome: api.GrantOutcomeOriginAdded(), want: "origin added"},
		{outcome: api.GrantOutcomeUnchanged(), want: "unchanged"},
	} {
		t.Run(tc.outcome.String(), func(t *testing.T) {
			row, err := grantResultRow(apigen.GrantResult{
				GrantId: "grt_1", Capability: "read", Outcome: tc.outcome,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(row, "|"); got != "read|grt_1|"+tc.want {
				t.Fatalf("row = %q", got)
			}
		})
	}
}
