package client

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// caPEM PEM-encodes a TLS test server's self-signed certificate so the client
// can be pointed at it with an explicit CA bundle (the instance-caBundle path).
func caPEM(t *testing.T, srv *httptest.Server) []byte {
	t.Helper()
	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("test server has no certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func TestFetchDecodesAndSendsParams(t *testing.T) {
	var gotAuth, gotUA, gotQuery, gotPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
		gotQuery = r.URL.RawQuery
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		// Include an unknown additive member to prove lenient decoding.
		_, _ = w.Write([]byte(`{
			"current": false,
			"cursor": "v1:abc",
			"change_token": "v1:tok",
			"schema_revision": 7,
			"pin_expired": false,
			"credential_expires_at": "2026-09-01T00:00:00Z",
			"keys": [
				{"name":"API_KEY","classification":"secret","presence":"set","value":"s3cr3t"},
				{"name":"LOG_LEVEL","classification":"config","presence":"set","value":"info"},
				{"name":"DB_PASSWORD","classification":"secret","presence":"set"}
			],
			"some_future_field": {"nested": true}
		}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, caPEM(t, srv), "hikyo-operator/test")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	resp, outcome, err := c.Fetch(context.Background(), FetchRequest{
		Org: "o", Project: "p", Environment: "prod",
		Cursor: "v1:prev", Projection: "config-only",
		AcknowledgedKeys: []string{"PATH", "LD_PRELOAD"},
		Bearer:           "tok-123",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if outcome != OutcomeOK {
		t.Fatalf("outcome = %v, want OutcomeOK", outcome)
	}
	if gotAuth != "Bearer tok-123" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotUA != "hikyo-operator/test" {
		t.Errorf("User-Agent = %q", gotUA)
	}
	if gotPath != "/api/v1/orgs/o/projects/p/environments/prod/delivery" {
		t.Errorf("path = %q", gotPath)
	}
	for _, want := range []string{"cursor=v1%3Aprev", "projection=config-only", "acknowledged_keys=PATH%2CLD_PRELOAD"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query %q missing %q", gotQuery, want)
		}
	}
	if resp.Cursor != "v1:abc" || resp.ChangeToken != "v1:tok" || resp.SchemaRevision != 7 {
		t.Errorf("scalar fields wrong: %+v", resp)
	}
	if resp.CredentialExpiresAt == nil {
		t.Error("credential_expires_at not decoded")
	}
	if len(resp.Keys) != 3 {
		t.Fatalf("keys = %d, want 3", len(resp.Keys))
	}
	// Presence-only key must have a nil Value; delivered ones non-nil.
	if resp.Keys[0].Value == nil || *resp.Keys[0].Value != "s3cr3t" {
		t.Errorf("API_KEY value = %v", resp.Keys[0].Value)
	}
	if resp.Keys[2].Value != nil {
		t.Errorf("DB_PASSWORD should be presence-only (nil value), got %v", *resp.Keys[2].Value)
	}
}

func TestFetchStatusMapping(t *testing.T) {
	cases := []struct {
		status int
		want   Outcome
	}{
		{http.StatusNotFound, OutcomeScrub},
		{http.StatusConflict, OutcomeNotMaterialized},
		{http.StatusUnauthorized, OutcomeFetchFailed},
		{http.StatusTooManyRequests, OutcomeFetchFailed},
		{http.StatusInternalServerError, OutcomeFetchFailed},
		{http.StatusBadGateway, OutcomeFetchFailed},
		{http.StatusTeapot, OutcomeFetchFailed}, // unrecognized → fail-safe retain
	}
	for _, tc := range cases {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
		}))
		c, err := NewClient(srv.URL, caPEM(t, srv), "hikyo-operator/test")
		if err != nil {
			srv.Close()
			t.Fatalf("NewClient: %v", err)
		}
		resp, outcome, err := c.Fetch(context.Background(), FetchRequest{
			Org: "o", Project: "p", Environment: "e", Bearer: "t",
		})
		srv.Close()
		if outcome != tc.want {
			t.Errorf("status %d: outcome = %v, want %v", tc.status, outcome, tc.want)
		}
		if resp != nil {
			t.Errorf("status %d: response should be nil on non-OK", tc.status)
		}
		if err == nil {
			t.Errorf("status %d: expected a descriptive error", tc.status)
		}
	}
}

func TestNewClientRefusesHTTP(t *testing.T) {
	if _, err := NewClient("http://example.test", nil, "ua"); err == nil {
		t.Fatal("expected refusal of a non-https instance url")
	}
}

func TestFetchRefusesRedirect(t *testing.T) {
	// A server that 302s elsewhere must never see the operator follow it with the
	// credential attached.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, "https://evil.test/steal", http.StatusFound)
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, caPEM(t, srv), "ua")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, outcome, err := c.Fetch(context.Background(), FetchRequest{Org: "o", Project: "p", Environment: "e", Bearer: "t"})
	if err == nil {
		t.Fatal("expected a redirect refusal")
	}
	if outcome != OutcomeFetchFailed {
		t.Errorf("redirect refusal outcome = %v, want OutcomeFetchFailed (retain)", outcome)
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Errorf("error %q should mention the redirect refusal", err)
	}
}

func TestFetchRefusesWithoutBearer(t *testing.T) {
	c, err := NewClient("https://example.test", nil, "ua")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, _, err := c.Fetch(context.Background(), FetchRequest{Org: "o", Project: "p", Environment: "e"}); err == nil {
		t.Fatal("expected refusal to fetch without a credential")
	}
}
