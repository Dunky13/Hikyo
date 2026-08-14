package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

type stubSAMLAuth struct {
	startResult service.SAMLStartResult
	acsResult   service.LoginResult
	metadata    []byte
	acsCookie   string
}

func (s *stubSAMLAuth) SAMLStart(context.Context, string, string, string, string, string) (service.SAMLStartResult, error) {
	return s.startResult, nil
}

func (s *stubSAMLAuth) SAMLACS(_ context.Context, _, _, _, initiatorCookie string) (service.LoginResult, error) {
	s.acsCookie = initiatorCookie
	return s.acsResult, nil
}

func (s *stubSAMLAuth) SAMLMetadata(context.Context, string) ([]byte, error) {
	return s.metadata, nil
}

func TestSAMLStartSetsCrossSitePathScopedInitiatorCookie(t *testing.T) {
	stub := &stubSAMLAuth{startResult: service.SAMLStartResult{
		RedirectURL:     "https://idp.example/sso?SAMLRequest=request&RelayState=relay-state",
		InitiatorCookie: "initiator-secret",
	}}
	api := &API{SAMLAuth: stub}
	response, err := api.SamlStart(context.Background(), apigen.SamlStartRequestObject{
		Provider: "corp", Body: &apigen.SamlStartRequest{Purpose: apigen.SamlStartRequestPurposeLogin},
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	if err := response.VisitSamlStartResponse(recorder); err != nil {
		t.Fatal(err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.SameSite != http.SameSiteNoneMode || !cookie.Secure || !cookie.HttpOnly {
		t.Fatalf("cookie attributes = SameSite %v Secure %v HttpOnly %v", cookie.SameSite, cookie.Secure, cookie.HttpOnly)
	}
	if cookie.Path != "/api/v1/auth/saml/corp/acs" || cookie.MaxAge != 600 {
		t.Fatalf("cookie scope = Path %q MaxAge %d", cookie.Path, cookie.MaxAge)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	acs := mustURL(t, "https://hikyo.example/api/v1/auth/saml/corp/acs")
	jar.SetCookies(acs, cookies)
	if got := jar.Cookies(mustURL(t, "https://hikyo.example/api/v1/auth/saml/corp/acs")); len(got) != 1 {
		t.Fatalf("ACS cookies = %d, want 1", len(got))
	}
	if got := jar.Cookies(mustURL(t, "https://hikyo.example/api/v1/whoami")); len(got) != 0 {
		t.Fatalf("unrelated path received %d SAML cookies", len(got))
	}
}

func TestSAMLACSConsumesInitiatorAndMintsOrdinaryBrowserCookie(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	stub := &stubSAMLAuth{acsResult: service.LoginResult{
		SessionToken: "br.session", SessionID: "session", Artifact: service.ArtifactBrowser,
		CreatedAt: now, IdleExpires: now.Add(time.Hour), AbsExpires: now.Add(8 * time.Hour), Principal: "principal",
	}}
	provider, relay := "corp", "relay-state"
	request := httptest.NewRequest(http.MethodPost, "https://hikyo.example"+samlACSPath(provider), nil)
	request.AddCookie(&http.Cookie{Name: samlBindingCookieName(provider, relay), Value: "initiator-secret"})
	ctx := context.WithValue(context.Background(), requestKey{}, request)
	api := &API{SAMLAuth: stub}
	response, err := api.SamlACS(ctx, apigen.SamlACSRequestObject{
		Provider: apigen.ProviderSlug(provider),
		Body:     &apigen.SamlACSRequest{RelayState: relay, SAMLResponse: "response"},
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	if err := response.VisitSamlACSResponse(recorder); err != nil {
		t.Fatal(err)
	}
	if stub.acsCookie != "initiator-secret" {
		t.Fatalf("initiator cookie = %q", stub.acsCookie)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookies = %d, want clear + session", len(cookies))
	}
	if cookies[0].MaxAge >= 0 || cookies[0].SameSite != http.SameSiteNoneMode {
		t.Fatalf("initiator clear cookie = %#v", cookies[0])
	}
	if cookies[1].Name != browserSessionCookie || cookies[1].SameSite != http.SameSiteLaxMode || cookies[1].Path != "/" {
		t.Fatalf("session cookie = %#v", cookies[1])
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, leaked := body["session_token"]; leaked {
		t.Fatal("browser session token leaked in ACS JSON")
	}
}

func TestSAMLMetadataUsesMetadataMediaType(t *testing.T) {
	stub := &stubSAMLAuth{metadata: []byte("<EntityDescriptor/>")}
	response, err := (&API{SAMLAuth: stub}).SamlMetadata(context.Background(), apigen.SamlMetadataRequestObject{Provider: "corp"})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	if err := response.VisitSamlMetadataResponse(recorder); err != nil {
		t.Fatal(err)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/samlmetadata+xml" {
		t.Fatalf("Content-Type = %q", got)
	}
	if strings.TrimSpace(recorder.Body.String()) != "<EntityDescriptor/>" {
		t.Fatalf("body = %q", recorder.Body.String())
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
