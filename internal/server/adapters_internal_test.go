package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/service"
)

func TestAdapterResponseRejectsMalformedStoredTimestamps(t *testing.T) {
	tests := []struct {
		name string
		view service.AdapterView
		want string
	}{
		{name: "created", view: service.AdapterView{Adapter: service.AdapterRecord{CreatedAt: "not-a-time"}}, want: "created_at"},
		{name: "credential set", view: service.AdapterView{Adapter: service.AdapterRecord{CreatedAt: "2026-08-17T00:00:00Z", CredentialSetAt: "not-a-time"}}, want: "credential_set_at"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := adapterResponse(tt.view); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("adapterResponse() error = %v, want %q", err, tt.want)
			}
		})
	}
	if _, err := adapterMoveResponse(service.AdapterMove{CreatedAt: "not-a-time"}); err == nil || !strings.Contains(err.Error(), "created_at") {
		t.Fatalf("adapterMoveResponse() error = %v, want created_at", err)
	}
}

func TestReauthTotpResponseUsesArtifactChannelAndReportsOnlyOpenedWindows(t *testing.T) {
	late := time.Date(2026, 8, 17, 12, 5, 0, 0, time.UTC)
	early := late.Add(-2 * time.Minute)
	results := []service.ReauthResult{
		{SessionToken: "rotated-secret", SessionID: "ses_one", EnvironmentID: "env_nonzero_two", WindowExpires: late},
		{SessionToken: "rotated-secret", SessionID: "ses_one", EnvironmentID: "env_nonzero_one", WindowExpires: early},
	}

	t.Run("bearer body", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reauth/totp", nil)
		request.Header.Set("Authorization", "Bearer old-secret")
		response, err := makeReauthTotpResponse(request, results, true)
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		if err := response.VisitReauthTotpResponse(recorder); err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["session_token"] != "rotated-secret" || body["window_expires"] != early.Format(time.RFC3339) {
			t.Fatalf("body = %v", body)
		}
		environments, _ := body["environment_ids"].([]any)
		if len(environments) != 2 || environments[0] != "env_nonzero_two" || environments[1] != "env_nonzero_one" {
			t.Fatalf("environment_ids = %v; effective-zero members must be absent", environments)
		}
		if len(recorder.Result().Cookies()) != 0 {
			t.Fatal("bearer response set a browser cookie")
		}
	})

	t.Run("browser cookie", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reauth/totp", nil)
		request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "old-secret"})
		response, err := makeReauthTotpResponse(request, results, true)
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		if err := response.VisitReauthTotpResponse(recorder); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(recorder.Body.String(), "rotated-secret") || strings.Contains(recorder.Body.String(), "session_token") {
			t.Fatalf("browser body disclosed bearer: %s", recorder.Body.String())
		}
		cookies := recorder.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != browserSessionCookie || cookies[0].Value != "rotated-secret" || !cookies[0].HttpOnly {
			t.Fatalf("cookies = %+v", cookies)
		}
	})
}

func TestAdapterTargetResponseIncludesConvergedRevisionAndPendingConflicts(t *testing.T) {
	revision := int64(42)
	artifact := service.AdapterConflictArtifact{ID: "acf_one", DestinationID: 77, TargetGeneration: 3, CreatedAt: time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC), Entries: []service.AdapterConflictEntry{{Surface: "variable", EffectiveName: "PROD_MODE"}}}
	out := adapterTargetResponse(service.AdapterTarget{ConvergedRevision: &revision}, artifact)
	if out.ConvergedRevision == nil || *out.ConvergedRevision != revision {
		t.Fatalf("converged_revision = %v, want %d", out.ConvergedRevision, revision)
	}
	if len(out.Conflicts) != 1 || string(out.Conflicts[0].Id) != artifact.ID || len(out.Conflicts[0].Entries) != 1 || out.Conflicts[0].Entries[0].EffectiveName != "PROD_MODE" {
		t.Fatalf("conflicts = %+v", out.Conflicts)
	}
}
