package service

import (
	"errors"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/remotefetch"
)

func TestFetchGateCoverageCountsOnlyAttemptedResults(t *testing.T) {
	round := map[string]remotefetch.Result{
		"rmt_attempted": &remotefetch.Attempted{ID: "rmt_attempted"},
		"rmt_queued": &remotefetch.NotAttempted{
			ID: "rmt_queued", Reason: remotefetch.NotAttemptedSlotNotAcquired,
		},
	}
	if !covers(round, []string{"rmt_attempted"}) {
		t.Fatal("an attempted target did not count as covered")
	}
	if covers(round, []string{"rmt_attempted", "rmt_queued"}) {
		t.Fatal("a not-attempted target counted as covered and could suppress a later real fetch")
	}
}

func TestAttemptedFetchKeepsFailuresAndRejectsNotAttemptedResults(t *testing.T) {
	wantErr := errors.New("peer refused connection")
	want := &remotefetch.Attempted{
		ID: "rmt_attempted", Outcome: remotefetch.OutcomeUnreachable, Err: wantErr,
	}
	got, ok := attemptedFetch(want)
	if !ok || got.Outcome != remotefetch.OutcomeUnreachable || !errors.Is(got.Err, wantErr) {
		t.Fatalf("attemptedFetch(%+v) = %+v, %v", want, got, ok)
	}

	notAttempted := &remotefetch.NotAttempted{
		ID: "rmt_queued", Reason: remotefetch.NotAttemptedSlotNotAcquired,
	}
	if got, ok := attemptedFetch(notAttempted); ok {
		t.Fatalf("attemptedFetch(%+v) = %+v, true; settlement would persist a local refusal", notAttempted, got)
	}
}

func TestAttemptedFetchFailsLoudForNilVariants(t *testing.T) {
	tests := []struct {
		name   string
		result remotefetch.Result
	}{
		{name: "nil interface"},
		{name: "nil attempted", result: (*remotefetch.Attempted)(nil)},
		{name: "nil not attempted", result: (*remotefetch.NotAttempted)(nil)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid result variant was silently treated as not attempted")
				}
			}()
			attemptedFetch(test.result)
		})
	}
}

func TestConflictingIdentitiesUsesOnlyAttemptedListings(t *testing.T) {
	results := map[string]remotefetch.Result{
		"rmt_a": &remotefetch.Attempted{
			ID: "rmt_a", Outcome: remotefetch.OutcomeOK,
			Listing: remotefetch.Listing{Identity: "ins_shared"},
		},
		"rmt_b": &remotefetch.NotAttempted{
			ID: "rmt_b", Reason: remotefetch.NotAttemptedContextCancelled,
		},
	}
	if conflicts := conflictingIdentities(results); len(conflicts) != 0 {
		t.Fatalf("not-attempted result contributed an identity conflict: %v", conflicts)
	}
}
