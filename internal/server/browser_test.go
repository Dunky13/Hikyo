package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Dunky13/hikyo/api"
	"github.com/Dunky13/hikyo/api/apigen"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/service"
)

// The browser leg's transport contract (#56), completing #54's deferral.
//
// What is asserted here is the TRANSPORT's half: which channel a token leaves
// on, and when the synchronizer token is demanded. The row-verifier half runs
// against a real datastore in internal/isolation; the stub here answers yes so
// these tests isolate the transport decision from the storage one.

const (
	sessionCookieName = "__Host-hikyo"
	csrfCookieName    = "__Host-hikyo-csrf"
	csrfHeaderName    = "X-Hikyo-CSRF"
)

func browserLoginAuth() stubAuth {
	return stubAuth{
		login: func(_ context.Context, _, _ string, artifact service.Artifact) (service.LoginResult, error) {
			out := service.LoginResult{
				SessionID: liveIdentity.SessionID, Artifact: artifact,
				CreatedAt: liveIdentity.CreatedAt, IdleExpires: liveIdentity.IdleExpiresAt,
				AbsExpires: liveIdentity.AbsoluteExpiresAt,
				Principal:  liveIdentity.Principal, DisplayName: "Admin",
				Assurance: liveIdentity.Assurance,
			}
			if artifact == service.ArtifactBrowser {
				out.SessionToken, out.CSRFToken = "hik_1_br_stub", "hik_1_cs_stub"
			} else {
				out.SessionToken = "hik_1_cli_stub"
			}
			return out, nil
		},
		identity: liveIdentityFn,
		logout:   func(context.Context, string) error { return nil },
	}
}

// createsOrgs answers the one mutation these fixtures use. The default stub
// refuses, which would make a CSRF pass indistinguishable from a CSRF refusal.
func createsOrgs() stubOrgs {
	return stubOrgs{
		create: func(_ context.Context, _ service.Actor, name string, active bool, meta json.RawMessage) (service.Org, error) {
			return service.Org{ID: testOrgID, Name: name, Active: active, Metadata: meta, CreatedAt: liveIdentity.CreatedAt}, nil
		},
	}
}

func cookieByName(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// raw issues a request with explicit cookies and headers, bypassing the
// contract-validating helper: these tests are about headers and cookies, and
// several of them deliberately never reach a handler.
func raw(t *testing.T, srv *httptest.Server, method, path string, body any, mutate func(*http.Request)) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if mutate != nil {
		mutate(req)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, payload
}

func TestBrowserLoginDeliversTheTokenOnlyOnCookies(t *testing.T) {
	srv := newTestServer(t, browserLoginAuth(), stubOrgs{})
	resp, payload := call(t, srv, http.MethodPost, api.PathPrefix+"/auth/local/login", "",
		map[string]any{"username": "admin", "password": "correct horse battery staple", "artifact": "browser"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, payload)
	}

	var result apigen.LoginResult
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	// B2: a browser session token in a script-readable body defeats the whole
	// point of the HttpOnly cookie.
	if result.SessionToken != nil {
		t.Fatalf("the browser session token leaked into the body: %q", *result.SessionToken)
	}

	session := cookieByName(resp, sessionCookieName)
	if session == nil {
		t.Fatal("no session cookie")
	}
	switch {
	case session.Value != "hik_1_br_stub":
		t.Fatalf("session cookie value = %q", session.Value)
	case !session.HttpOnly:
		t.Error("the session cookie is readable by script")
	case !session.Secure:
		t.Error("the session cookie is not Secure — the __Host- prefix requires it")
	case session.Path != "/":
		t.Errorf("session cookie path = %q, want /", session.Path)
	case session.Domain != "":
		t.Errorf("session cookie carries a Domain (%q) — the __Host- prefix forbids it", session.Domain)
	}

	csrf := cookieByName(resp, csrfCookieName)
	if csrf == nil {
		t.Fatal("no synchronizer-token cookie")
	}
	switch {
	case csrf.Value != "hik_1_cs_stub":
		t.Fatalf("csrf cookie value = %q", csrf.Value)
	case csrf.HttpOnly:
		t.Error("the synchronizer token is HttpOnly — the SPA could never echo it")
	case !csrf.Secure:
		t.Error("the synchronizer-token cookie is not Secure")
	case csrf.SameSite != http.SameSiteStrictMode:
		t.Errorf("csrf cookie SameSite = %v, want Strict", csrf.SameSite)
	}
}

// The default is unchanged: a CLI caller that says nothing gets a CLI session
// with its token in the body and no cookies at all.
func TestCLILoginIsStillTheDefaultAndSetsNoCookies(t *testing.T) {
	srv := newTestServer(t, browserLoginAuth(), stubOrgs{})
	resp, payload := call(t, srv, http.MethodPost, api.PathPrefix+"/auth/local/login", "",
		map[string]any{"username": "admin", "password": "correct horse battery staple"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, payload)
	}
	var result apigen.LoginResult
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	if result.SessionToken == nil || *result.SessionToken != "hik_1_cli_stub" {
		t.Fatal("the CLI session token is missing from the body")
	}
	if len(resp.Cookies()) != 0 {
		t.Fatalf("a CLI login set cookies: %v", resp.Cookies())
	}
}

func TestUnknownArtifactIsRefusedByTheContract(t *testing.T) {
	srv := newTestServer(t, browserLoginAuth(), stubOrgs{})
	resp, _ := call(t, srv, http.MethodPost, api.PathPrefix+"/auth/local/login", "",
		map[string]any{"username": "admin", "password": "correct horse battery staple", "artifact": "kiosk"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
}

// The CSRF requirement is a transport decision keyed on the LEG the request
// authenticated on (#54 A10), never on the row.
func TestCookieAuthenticatedMutationRequiresTheSynchronizerToken(t *testing.T) {
	srv := newTestServer(t, stubAuth{identity: liveIdentityFn}, createsOrgs())
	body := map[string]any{"name": "acme"}

	t.Run("no header", func(t *testing.T) {
		resp, payload := raw(t, srv, http.MethodPost, api.PathPrefix+"/orgs", body, func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "hik_1_br_stub"})
			r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "hik_1_cs_stub"})
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401: %s", resp.StatusCode, payload)
		}
		if code := decodeError(t, payload).Error.Code; code != apigen.ErrorCodeUnauthenticated {
			t.Fatalf("code %q", code)
		}
	})

	t.Run("header does not match the cookie", func(t *testing.T) {
		resp, _ := raw(t, srv, http.MethodPost, api.PathPrefix+"/orgs", body, func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "hik_1_br_stub"})
			r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "hik_1_cs_stub"})
			r.Header.Set(csrfHeaderName, "hik_1_cs_somethingelse")
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", resp.StatusCode)
		}
	})

	t.Run("no companion cookie", func(t *testing.T) {
		resp, _ := raw(t, srv, http.MethodPost, api.PathPrefix+"/orgs", body, func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "hik_1_br_stub"})
			r.Header.Set(csrfHeaderName, "hik_1_cs_stub")
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", resp.StatusCode)
		}
	})

	t.Run("matching header passes through", func(t *testing.T) {
		resp, payload := raw(t, srv, http.MethodPost, api.PathPrefix+"/orgs", body, func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "hik_1_br_stub"})
			r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "hik_1_cs_stub"})
			r.Header.Set(csrfHeaderName, "hik_1_cs_stub")
		})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status %d, want 201: %s", resp.StatusCode, payload)
		}
	})
}

// A safe method changes nothing and its response is unreadable cross-origin,
// so demanding the token there would only break the SPA's own boot.
func TestCookieAuthenticatedReadNeedsNoSynchronizerToken(t *testing.T) {
	srv := newTestServer(t, stubAuth{identity: liveIdentityFn}, stubOrgs{})
	resp, payload := raw(t, srv, http.MethodGet, api.PathPrefix+"/auth/whoami", nil, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "hik_1_br_stub"})
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", resp.StatusCode, payload)
	}
}

// A bearer caller has no cookie the browser attaches by itself, so it has no
// CSRF contract — demanding a header of the CLI would be theatre.
func TestBearerMutationNeedsNoSynchronizerToken(t *testing.T) {
	srv := newTestServer(t, stubAuth{identity: liveIdentityFn}, createsOrgs())
	resp, payload := call(t, srv, http.MethodPost, api.PathPrefix+"/orgs", "hik_1_cli_x",
		map[string]any{"name": "acme"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d, want 201: %s", resp.StatusCode, payload)
	}
}

// The row-verifier half: the transport compares the header to the cookie, and
// the session row's verifier settles it. A pair that agrees with each other
// but not with the row is refused.
func TestSynchronizerTokenIsCheckedAgainstTheSessionRow(t *testing.T) {
	auth := stubAuth{identity: liveIdentityFn}
	auth.verifyCSRF = func(context.Context, string, string) error { return service.ErrCSRFMismatch }
	srv := newTestServer(t, auth, createsOrgs())
	resp, _ := raw(t, srv, http.MethodPost, api.PathPrefix+"/orgs", map[string]any{"name": "acme"},
		func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "hik_1_br_stub"})
			r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "hik_1_cs_planted"})
			r.Header.Set(csrfHeaderName, "hik_1_cs_planted")
		})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401 — a self-consistent cookie pair was accepted without the row", resp.StatusCode)
	}
}

// A browser session dies server-side (idle expiry, revocation, a generation
// bump) while its cookie is still in the browser. The very next thing the
// human does is sign in again — and that POST carries the dead cookie. If the
// CSRF gate keys on the cookie being PRESENT rather than on it resolving to a
// live session, that login is refused 401 before the handler, nothing clears
// the cookie, and the account is unreachable until the browser is closed.
//
// A dead cookie authorizes nothing, so it is not a cookie leg and there is no
// CSRF contract to enforce.
func TestAStaleSessionCookieDoesNotBlockANewLogin(t *testing.T) {
	auth := browserLoginAuth()
	auth.verifyCSRF = func(context.Context, string, string) error {
		return domain.ErrUnauthenticated // the cookie resolves to nothing
	}
	srv := newTestServer(t, auth, stubOrgs{})

	resp, payload := raw(t, srv, http.MethodPost, api.PathPrefix+"/auth/local/login",
		map[string]any{"username": "admin", "password": "correct horse battery staple", "artifact": "browser"},
		func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "hik_1_br_expired"})
			r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "hik_1_cs_expired"})
		})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200 — a dead cookie blocked a fresh login: %s", resp.StatusCode, payload)
	}
	if c := cookieByName(resp, sessionCookieName); c == nil || c.Value != "hik_1_br_stub" {
		t.Fatalf("the fresh session cookie did not replace the dead one: %+v", c)
	}
}

// The same rule on an ordinary mutation: a dead cookie is not a cookie leg, so
// the request proceeds and is refused (or not) by the chokepoint on its own
// merits rather than by a CSRF gate guarding a session that no longer exists.
func TestAStaleSessionCookieLeavesTheRefusalToTheChokepoint(t *testing.T) {
	auth := stubAuth{identity: liveIdentityFn}
	auth.verifyCSRF = func(context.Context, string, string) error { return domain.ErrUnauthenticated }
	srv := newTestServer(t, auth, createsOrgs())

	resp, payload := raw(t, srv, http.MethodPost, api.PathPrefix+"/orgs",
		map[string]any{"name": "acme"}, func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "hik_1_br_expired"})
		})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d, want 201 — the CSRF gate answered for a session it could not resolve: %s",
			resp.StatusCode, payload)
	}
}

func TestLogoutClearsBothBrowserCookies(t *testing.T) {
	srv := newTestServer(t, browserLoginAuth(), stubOrgs{})
	resp, payload := raw(t, srv, http.MethodPost, api.PathPrefix+"/auth/logout", nil, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "hik_1_br_stub"})
		r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "hik_1_cs_stub"})
		r.Header.Set(csrfHeaderName, "hik_1_cs_stub")
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d, want 204: %s", resp.StatusCode, payload)
	}
	for _, name := range []string{sessionCookieName, csrfCookieName} {
		c := cookieByName(resp, name)
		if c == nil {
			t.Fatalf("logout did not clear %s", name)
		}
		if c.MaxAge >= 0 && c.Value != "" {
			t.Fatalf("%s was not expired: %+v", name, c)
		}
	}
}

// Logout on the bearer leg answers the plain 204 and touches no cookies: a
// CLI caller has none to clear, and emitting Set-Cookie at it would be noise.
func TestBearerLogoutSetsNoCookies(t *testing.T) {
	srv := newTestServer(t, browserLoginAuth(), stubOrgs{})
	resp, _ := call(t, srv, http.MethodPost, api.PathPrefix+"/auth/logout", "hik_1_cli_x", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d, want 204", resp.StatusCode)
	}
	if len(resp.Cookies()) != 0 {
		t.Fatalf("a bearer logout set cookies: %v", resp.Cookies())
	}
}

// Every account-security mutation reissues or rotates the acting session, and
// every one of them owes the browser the same delivery: the replacement token
// on the cookie, never in a body script can read. A browser that got a `cli`
// token in JSON would be simultaneously logged out — its cookie now points at
// a rotated verifier — and holding a long-lived credential in the DOM.
//
// One table, because the bug is one bug: it was introduced by the operation
// that forgot, not by the operation that is special.
func TestEveryReissuingOperationDeliversOnTheActingChannel(t *testing.T) {
	ops := []struct {
		name   string
		method string
		path   string
		body   map[string]any
	}{
		{"totp enrol confirm", http.MethodPost, "/auth/totp/enrol/confirm", map[string]any{"code": "123456"}},
		{"totp step-up", http.MethodPost, "/auth/totp/step-up", map[string]any{"code": "123456"}},
		{"totp remove", http.MethodDelete, "/auth/totp", map[string]any{"password": "correct horse battery staple"}},
		{"recovery codes", http.MethodPost, "/auth/recovery-codes/regenerate", map[string]any{"proof": "correct horse battery staple"}},
		{"identity unlink", http.MethodDelete, "/auth/identities/eid_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f33", map[string]any{"proof": "correct horse battery staple"}},
	}

	for _, op := range ops {
		t.Run(op.name+" browser", func(t *testing.T) {
			auth := stubAuth{identity: liveIdentityFn, reissue: func() (service.LoginResult, error) {
				return reissuedResult(service.ArtifactBrowser), nil
			}}
			srv := newTestServer(t, auth, stubOrgs{})
			resp, payload := raw(t, srv, op.method, api.PathPrefix+op.path, op.body, browserCaller)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d, want 200: %s", resp.StatusCode, payload)
			}
			session := cookieByName(resp, sessionCookieName)
			if session == nil || session.Value != "hik_1_br_reissued" {
				t.Fatalf("the reissued browser token did not travel on the cookie: %+v", session)
			}
			if csrf := cookieByName(resp, csrfCookieName); csrf == nil || csrf.Value != "hik_1_cs_reissued" {
				t.Fatalf("the rotated synchronizer token did not travel on its cookie: %+v", csrf)
			}
			if strings.Contains(string(payload), "hik_1_br_") {
				t.Fatalf("a browser session token leaked into the body: %s", payload)
			}
		})

		t.Run(op.name+" cli", func(t *testing.T) {
			auth := stubAuth{identity: liveIdentityFn, reissue: func() (service.LoginResult, error) {
				return reissuedResult(service.ArtifactCLI), nil
			}}
			srv := newTestServer(t, auth, stubOrgs{})
			resp, payload := raw(t, srv, op.method, api.PathPrefix+op.path, op.body, func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer hik_1_cli_x")
			})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d, want 200: %s", resp.StatusCode, payload)
			}
			// A bearer caller must NOT be handed a browser cookie: its next
			// request would carry both legs and trip the A10 refusal.
			if len(resp.Cookies()) != 0 {
				t.Fatalf("a CLI caller received cookies: %v", resp.Cookies())
			}
			if !strings.Contains(string(payload), "hik_1_cli_reissued") {
				t.Fatalf("the CLI token is missing from the body: %s", payload)
			}
		})
	}
}

// browserCaller presents a complete, valid cookie leg.
func browserCaller(r *http.Request) {
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "hik_1_br_stub"})
	r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "hik_1_cs_stub"})
	r.Header.Set(csrfHeaderName, "hik_1_cs_stub")
}

func reissuedResult(artifact service.Artifact) service.LoginResult {
	out := service.LoginResult{
		SessionID: liveIdentity.SessionID, Artifact: artifact,
		CreatedAt: liveIdentity.CreatedAt, IdleExpires: liveIdentity.IdleExpiresAt,
		AbsExpires: liveIdentity.AbsoluteExpiresAt,
		Principal:  liveIdentity.Principal, Assurance: liveIdentity.Assurance,
	}
	if artifact == service.ArtifactBrowser {
		out.SessionToken, out.CSRFToken = "hik_1_br_reissued", "hik_1_cs_reissued"
		return out
	}
	out.SessionToken = "hik_1_cli_reissued"
	return out
}

// The rail's endpoint. It is a self-projection, so the properties the
// transport owes it are narrow and all negative: it never refuses on
// authorization, it returns identity only, and an unresolvable session is
// indistinguishable from one whose grants name no org.
func TestListMyOrgsIsASelfProjection(t *testing.T) {
	t.Run("returns the caller's orgs", func(t *testing.T) {
		srv := newTestServer(t, stubAuth{identity: liveIdentityFn}, stubOrgs{
			mine: func(context.Context, service.Actor) ([]service.MyOrg, error) {
				return []service.MyOrg{{ID: testOrgID, Name: "acme"}}, nil
			},
		})
		resp, payload := call(t, srv, http.MethodGet, api.PathPrefix+"/me/orgs", "hik_1_cli_x", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, payload)
		}
		var got apigen.MyOrgList
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatal(err)
		}
		if got.Count != 1 || len(got.Items) != 1 || got.Items[0].Name != "acme" {
			t.Fatalf("body = %s", payload)
		}
		// Identity only: metadata and the active flag are operator-set state
		// and belong to getOrg, which authorizes. If they ever appear here the
		// contract test above would already have failed — this pins the intent.
		if strings.Contains(string(payload), "metadata") || strings.Contains(string(payload), "active") {
			t.Fatalf("the navigation surface leaked operator-set org state: %s", payload)
		}
	})

	t.Run("no orgs is an empty list, not a refusal", func(t *testing.T) {
		srv := newTestServer(t, stubAuth{identity: liveIdentityFn}, stubOrgs{})
		resp, payload := call(t, srv, http.MethodGet, api.PathPrefix+"/me/orgs", "hik_1_cli_x", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, payload)
		}
		var got apigen.MyOrgList
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatal(err)
		}
		if got.Count != 0 || len(got.Items) != 0 {
			t.Fatalf("body = %s", payload)
		}
	})

	t.Run("an unresolvable session is the uniform 401", func(t *testing.T) {
		srv := newTestServer(t, stubAuth{}, stubOrgs{
			mine: func(context.Context, service.Actor) ([]service.MyOrg, error) {
				return nil, domain.ErrUnauthenticated
			},
		})
		resp, payload := call(t, srv, http.MethodGet, api.PathPrefix+"/me/orgs", "hik_1_cli_x", nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", resp.StatusCode)
		}
		if code := decodeError(t, payload).Error.Code; code != apigen.ErrorCodeUnauthenticated {
			t.Fatalf("code %q", code)
		}
	})

	// The cookie leg reaches it without a synchronizer token: it is a GET.
	t.Run("a browser session reaches it without stepping up", func(t *testing.T) {
		srv := newTestServer(t, stubAuth{identity: liveIdentityFn}, stubOrgs{
			mine: func(context.Context, service.Actor) ([]service.MyOrg, error) {
				return []service.MyOrg{{ID: testOrgID, Name: "acme"}}, nil
			},
		})
		resp, payload := raw(t, srv, http.MethodGet, api.PathPrefix+"/me/orgs", nil, func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "hik_1_br_stub"})
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200: %s", resp.StatusCode, payload)
		}
	})
}
