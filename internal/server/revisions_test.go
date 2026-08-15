package server

import (
	"context"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/service"
)

func TestEventStreamSuggestsJitteredRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	recorder := httptest.NewRecorder()
	retry := advisoryRetryBase + advisoryRetryRange/2
	stream := eventStream{ctx: ctx, events: make(chan service.AdvisoryEvent), retry: retry}
	if err := stream.VisitWatchProjectEventsResponse(recorder); err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`retry: ([0-9]+)`).FindStringSubmatch(recorder.Body.String())
	if len(match) != 2 {
		t.Fatalf("SSE preamble has no retry field: %q", recorder.Body.String())
	}
	milliseconds, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if milliseconds < advisoryRetryBase.Milliseconds() ||
		milliseconds >= (advisoryRetryBase+advisoryRetryRange).Milliseconds() {
		t.Fatalf("retry = %dms, want [%d,%d)", milliseconds,
			advisoryRetryBase.Milliseconds(), (advisoryRetryBase + advisoryRetryRange).Milliseconds())
	}
}

func TestImpactPreviewWirePreservesProtectedState(t *testing.T) {
	wired := wireImpactPreview(service.ImpactPreview{Environments: []service.ImpactEnvironment{{
		EnvironmentID: "env_prod", Protected: true,
	}}})
	if len(wired.Environments) != 1 || !wired.Environments[0].Protected {
		t.Fatalf("wired preview lost protected state: %+v", wired)
	}
}
