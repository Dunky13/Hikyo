package api_test

import (
	"encoding/json"
	"testing"

	"github.com/Hikyo-Org/hikyo/api"
)

func TestGrantOutcomeJSONIsClosed(t *testing.T) {
	for _, tc := range []struct {
		outcome api.GrantOutcome
		wire    string
	}{
		{outcome: api.GrantOutcomeCreated(), wire: `"created"`},
		{outcome: api.GrantOutcomeOriginAdded(), wire: `"origin_added"`},
		{outcome: api.GrantOutcomeUnchanged(), wire: `"unchanged"`},
	} {
		t.Run(tc.outcome.String(), func(t *testing.T) {
			encoded, err := json.Marshal(tc.outcome)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != tc.wire {
				t.Fatalf("wire outcome = %s, want %s", encoded, tc.wire)
			}
			var decoded api.GrantOutcome
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded != tc.outcome {
				t.Fatalf("decoded outcome = %q, want %q", decoded, tc.outcome)
			}
		})
	}
}

func TestGrantOutcomeZeroValueIsInvalid(t *testing.T) {
	var outcome api.GrantOutcome
	if outcome.Valid() {
		t.Fatal("zero outcome must be invalid")
	}
	if _, err := json.Marshal(outcome); err == nil {
		t.Fatal("zero outcome must fail JSON encoding")
	}
}

func TestGrantOutcomeJSONRejectsUnknownValue(t *testing.T) {
	var outcome api.GrantOutcome
	if err := json.Unmarshal([]byte(`"partly_created"`), &outcome); err == nil {
		t.Fatal("unknown grant outcome decoded")
	}
}
