package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The two rules that make the allowlist mean something at the transport, and
// the one that makes the CSP a closed list rather than an escape hatch.

func corsHandler(allowed ...string) http.Handler {
	set := map[string]bool{}
	for _, o := range allowed {
		set[o] = true
	}
	return workspaceCORS(func(_ context.Context, origin string) bool {
		return set[origin]
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func TestCORSEchoesExactlyOneAllowlistedOriginAndNeverCredentials(t *testing.T) {
	h := corsHandler("https://shell.example", "https://other.example")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs", nil)
	req.Header.Set("Origin", "https://shell.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://shell.example" {
		t.Errorf("Allow-Origin = %q, want the single matching origin echoed", got)
	}
	if strings.Contains(rec.Header().Get("Access-Control-Allow-Origin"), "*") {
		t.Error("a wildcard origin was emitted; the allowlist is a closed list by construction")
	}
	// Non-credentials mode is load-bearing: the workspace bearer rides an
	// Authorization header, and admitting cookies here would re-open CSRF for
	// a design that deliberately has nothing ambient to forge.
	if rec.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Error("Allow-Credentials was sent; workspace CORS is non-credentials mode")
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Origin") {
		t.Error("Vary: Origin is missing — a shared cache could serve one origin's headers to another")
	}
}

func TestCORSGivesANonAllowlistedOriginNoHeadersAtAll(t *testing.T) {
	h := corsHandler("https://shell.example")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs", nil)
	req.Header.Set("Origin", "https://hostile.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	for _, header := range []string{
		"Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers", "Access-Control-Allow-Credentials",
	} {
		if got := rec.Header().Get(header); got != "" {
			t.Errorf("%s = %q for a non-allowlisted origin; the answer is no headers at all", header, got)
		}
	}

	// And the preflight: still a 204, so a non-allowlisted origin cannot tell
	// "not allowlisted" from "no such path" — the browser refuses it on the
	// missing headers either way.
	pre := httptest.NewRequest(http.MethodOptions, "/api/v1/orgs", nil)
	pre.Header.Set("Origin", "https://hostile.example")
	pre.Header.Set("Access-Control-Request-Method", "GET")
	prec := httptest.NewRecorder()
	h.ServeHTTP(prec, pre)
	if prec.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", prec.Code)
	}
	if prec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("a preflight from a non-allowlisted origin was granted headers")
	}
}

func TestCSPConnectSrcIsExtendedWithAClosedListNeverAWildcard(t *testing.T) {
	base := policyWithRemotes(nil)
	if base != contentSecurityPolicy {
		t.Errorf("with no remotes the policy must be the untouched baseline, got %q", base)
	}

	got := policyWithRemotes([]string{"https://b.example", "https://c.example", "https://b.example"})
	if !strings.Contains(got, "connect-src 'self' https://b.example https://c.example") {
		t.Errorf("connect-src was not extended with the configured origins: %q", got)
	}
	if strings.Contains(got, "connect-src 'self' https://b.example https://c.example https://b.example") {
		t.Error("a duplicate origin was emitted twice")
	}
	if strings.Contains(got, "*") {
		t.Errorf("the policy contains a wildcard: %q", got)
	}
	if !strings.Contains(got, "frame-ancestors 'none'") {
		t.Error("frame-ancestors 'none' must stand everywhere; the workspace never iframes a remote")
	}

	// A stored value carrying CSP punctuation is DROPPED, not emitted: the
	// directive is space-separated, so emitting one would be directive
	// injection through a configuration row.
	injected := policyWithRemotes([]string{"https://ok.example", "https://x.example; script-src *"})
	if strings.Contains(injected, "script-src *") {
		t.Errorf("a malformed stored origin reached the header: %q", injected)
	}
	if !strings.Contains(injected, "https://ok.example") {
		t.Error("the well-formed origin beside a malformed one was dropped too")
	}
}

// `Vary: Origin` is a cache-control statement, not an allowlist grant, and it
// has to be on EVERY branch. Without it on the denied and no-Origin branches a
// shared cache stores the header-free response and later serves it to an
// allowlisted workspace, whose live meta read then fails on a missing
// Access-Control-Allow-Origin — which reads as withdrawn consent and is not.
func TestVaryOriginIsSetOnEveryBranch(t *testing.T) {
	mw := workspaceCORS(func(_ context.Context, o string) bool { return o == "https://shell.example" })
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))

	for _, c := range []struct{ name, origin, method, acrm string }{
		{"no Origin at all", "", http.MethodGet, ""},
		{"a denied origin", "https://hostile.example", http.MethodGet, ""},
		{"a denied origin's preflight", "https://hostile.example", http.MethodOptions, "GET"},
		{"an allowlisted origin", "https://shell.example", http.MethodGet, ""},
		{"an allowlisted preflight", "https://shell.example", http.MethodOptions, "GET"},
	} {
		req := httptest.NewRequest(c.method, "/api/v1/meta", nil)
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		if c.acrm != "" {
			req.Header.Set("Access-Control-Request-Method", c.acrm)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if !strings.Contains(rec.Header().Get("Vary"), "Origin") {
			t.Errorf("%s: Vary: Origin missing", c.name)
		}
	}
}

// The connect-src extension promises EXACT ORIGINS, never `*`. A character
// filter cannot keep that promise: a wildcard host contains no forbidden
// character.
func TestCSPConnectSrcAdmitsOnlyExactHTTPSOrigins(t *testing.T) {
	for _, bad := range []string{
		"https://*.example.test", // the wildcard the filter missed
		"https:",                 // a scheme source
		"*",
		"'unsafe-eval'",
		"http://peer.example",                // plaintext is not a remote origin
		"http://127.0.0.1.evil.example:8080", // loopback-looking, not loopback
		"https://peer.example/api",
		"https://peer.example?x=1",
		"https://user:pw@peer.example",
		"data:",
		"//peer.example",
		"",
	} {
		if got := policyWithRemotes([]string{bad}); strings.Contains(got, bad) && bad != "" {
			t.Errorf("%q reached connect-src: %s", bad, got)
		}
	}
	// http is admitted on LOOPBACK only, for the two-instance browser harness.
	if got := policyWithRemotes([]string{"http://localhost:45790"}); !strings.Contains(got, "http://localhost:45790") {
		t.Errorf("a loopback http origin was dropped: %s", got)
	}
	got := policyWithRemotes([]string{"https://peer.example", "https://peer.example:8443/", "https://peer.example"})
	want := "connect-src 'self' https://peer.example https://peer.example:8443;"
	if !strings.Contains(got, want) {
		t.Errorf("connect-src = %q, want it to contain %q (deduplicated, canonical, port kept)", got, want)
	}
}
