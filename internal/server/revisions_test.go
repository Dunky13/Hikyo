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

func TestLineageWireCarriesTheCollectionBit(t *testing.T) {
	const policy = "keep-if-either(max_age=2160h0m0s,last_revisions=10)"
	api := &API{Revisions: historyRevisionService{history: []service.RevisionView{
		{Revision: 4, PayloadPresent: true},
		{Revision: 1, PayloadPresent: false, CollectedPolicy: policy},
	}}}
	response, err := api.ListRevisions(t.Context(), apigen.ListRevisionsRequestObject{
		Org: "org_a", Project: "prj_a", Environment: "env_a",
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	if err := response.VisitListRevisionsResponse(recorder); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Items) != 2 {
		t.Fatalf("lineage item count = %d, want 2: %s", len(body.Items), recorder.Body.String())
	}
	if present, ok := body.Items[0]["payload_present"]; !ok || present != true {
		t.Errorf("live payload_present = %#v (present %t), want exact true", present, ok)
	}
	if _, ok := body.Items[0]["collected_policy"]; ok {
		t.Errorf("live row carries collected_policy: %s", recorder.Body.String())
	}
	if present, ok := body.Items[1]["payload_present"]; !ok || present != false {
		t.Errorf("collected payload_present = %#v (present %t), want exact false", present, ok)
	}
	if got, ok := body.Items[1]["collected_policy"]; !ok || got != policy {
		t.Errorf("collected_policy = %#v (present %t), want exact %q", got, ok, policy)
	}
}

type historyRevisionService struct {
	history []service.RevisionView
}

func (s historyRevisionService) History(context.Context, service.Actor, domain.Scope) ([]service.RevisionView, error) {
	return s.history, nil
}
func (historyRevisionService) PublishPlanned(context.Context, service.Actor, domain.Scope, service.PublishRequest) (service.PublishResult, error) {
	return service.PublishResult{}, domain.ErrNotFound
}
func (historyRevisionService) Restore(context.Context, service.Actor, domain.Scope, int64, string) (service.RestoreResult, error) {
	return service.RestoreResult{}, domain.ErrNotFound
}
func (historyRevisionService) Show(context.Context, service.Actor, domain.Scope, int64) (service.RevisionDetail, error) {
	return service.RevisionDetail{}, domain.ErrNotFound
}
func (historyRevisionService) Signals(context.Context, service.Actor, domain.Scope) (service.EnvironmentSignals, error) {
	return service.EnvironmentSignals{}, domain.ErrNotFound
}
func (historyRevisionService) PendingDrafts(context.Context, service.Actor, domain.Scope) ([]service.PendingDraft, error) {
	return nil, domain.ErrNotFound
}
func (historyRevisionService) Export(context.Context, service.Actor, domain.Scope, int64, bool) ([]service.ExportedValue, int64, error) {
	return nil, 0, domain.ErrNotFound
}
func (historyRevisionService) Watch(context.Context, service.Actor, domain.Scope) (<-chan service.AdvisoryEvent, error) {
	return nil, domain.ErrNotFound
}
func (historyRevisionService) RotateTokenKey(context.Context, service.Actor) (service.TokenKeyRotation, error) {
	return service.TokenKeyRotation{}, domain.ErrNotFound
}
