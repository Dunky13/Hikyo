package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/domain"
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

func TestCollectedRevisionRefusalNamesRevisionAndPolicyOnWire(t *testing.T) {
	refusal := &domain.CollectedRevisionError{
		Revision: 7,
		Policy:   "keep-if-either(max_age=2160h0m0s,last_revisions=10)",
	}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/org_a/projects/prj_a/environments/env_a/revisions/7", nil)
	(&API{}).writeHandlerError(recorder, req, refusal)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", recorder.Code)
	}
	var body apigen.Error
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Detail == nil || !strings.Contains(*body.Error.Detail, "revision 7") ||
		!strings.Contains(*body.Error.Detail, "last_revisions=10") {
		t.Fatalf("collected detail = %v, want named revision and policy", body.Error.Detail)
	}
}
