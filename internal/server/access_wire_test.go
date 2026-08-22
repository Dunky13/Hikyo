package server

import (
	"testing"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

func TestWireGrantResultMapsEveryOutcome(t *testing.T) {
	for _, tc := range []struct {
		service service.GrantOutcome
		wire    api.GrantOutcome
	}{
		{service: service.GrantCreated(), wire: api.GrantOutcomeCreated()},
		{service: service.GrantOriginAdded(), wire: api.GrantOutcomeOriginAdded()},
		{service: service.GrantUnchanged(), wire: api.GrantOutcomeUnchanged()},
	} {
		t.Run(tc.service.String(), func(t *testing.T) {
			got, err := wireGrantResult(
				service.GrantResult{GrantID: "grt_1", Outcome: tc.service},
				domain.CapRead,
			)
			if err != nil {
				t.Fatal(err)
			}
			if got.GrantId != "grt_1" || string(got.Capability) != string(domain.CapRead) || got.Outcome != tc.wire {
				t.Fatalf("wire result = %#v", got)
			}
		})
	}
}
