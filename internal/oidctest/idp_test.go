package oidctest

import (
	"net/http"
	"net/url"
	"testing"
)

func TestAuthorizeRedirectsOnlyToRegisteredURI(t *testing.T) {
	idp, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)

	client := idp.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	request := func(redirectURI string) *http.Response {
		t.Helper()
		query := url.Values{
			"client_id":    {"client"},
			"redirect_uri": {redirectURI},
			"state":        {"state"},
		}
		response, err := client.Get(idp.Server.URL + "/authorize?" + query.Encode())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { response.Body.Close() })
		return response
	}

	if response := request("https://attacker.example/callback"); response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unregistered redirect status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}

	const callback = "https://hikyo.test/api/v1/auth/oidc/idp/callback"
	if err := idp.RegisterRedirectURI(callback); err != nil {
		t.Fatal(err)
	}
	response := request(callback)
	if response.StatusCode != http.StatusFound {
		t.Fatalf("registered redirect status = %d, want %d", response.StatusCode, http.StatusFound)
	}
	if got := response.Header.Get("Location"); got == "" {
		t.Fatal("registered redirect omitted Location")
	}
}
