package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Hikyo-Org/hikyo/internal/server"
)

// Embedded-serving rules (#56, system-architecture ADR § Frontend).
//
// The ADR fixes the rules; `embed.FS` supplies none of them, so they are
// asserted here against the REAL router with a synthetic asset tree. Using
// `fstest.MapFS` rather than the embedded build output is deliberate: the
// rules are a property of the handler, not of whatever the frontend build
// last emitted, and a Go test must stay green for someone who has never run
// pnpm.

const indexHTML = `<!doctype html><html><head><link rel="stylesheet" href="/assets/app-deadbeef.css"></head>` +
	`<body><div id="root"></div><script type="module" src="/assets/app-deadbeef.js"></script></body></html>`

func testUI() fstest.MapFS {
	return fstest.MapFS{
		"index.html":               {Data: []byte(indexHTML)},
		"assets/app-deadbeef.js":   {Data: []byte("export const a = 1;\n")},
		"assets/app-deadbeef.css":  {Data: []byte(":root{--bg:#000}\n")},
		"assets/font-cafe.woff2":   {Data: []byte("woff2")},
		"favicon.svg":              {Data: []byte("<svg/>")},
		"nested/deep/thing.txt":    {Data: []byte("not an asset")},
		"assets/sub/nested-aa.map": {Data: []byte("{}")},
	}
}

func uiServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(server.New(stubReady{}, nil, testUI()))
	t.Cleanup(srv.Close)
	return srv
}

// get issues a raw request without following redirects and returns the
// response plus its body.
func get(t *testing.T, srv *httptest.Server, method, path, accept string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

const htmlAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

func TestSPAFallbackServesIndexForApplicationRoutes(t *testing.T) {
	srv := uiServer(t)
	for _, path := range []string{"/", "/login", "/org/acme/projects", "/deep/nested/route"} {
		t.Run(path, func(t *testing.T) {
			resp, body := get(t, srv, http.MethodGet, path, htmlAccept)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if body != indexHTML {
				t.Fatalf("body is not index.html:\n%s", body)
			}
			if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
				t.Fatalf("content-type = %q, want text/html", got)
			}
		})
	}
}

func TestIndexAlwaysRevalidates(t *testing.T) {
	srv := uiServer(t)
	resp, _ := get(t, srv, http.MethodGet, "/", htmlAccept)
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("index Cache-Control = %q, want no-cache", got)
	}
}

func TestHeadOnASPARouteCarriesTheHeadersWithoutABody(t *testing.T) {
	srv := uiServer(t)
	resp, body := get(t, srv, http.MethodHead, "/login", htmlAccept)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body != "" {
		t.Fatalf("HEAD returned a body: %q", body)
	}
}

func TestHashedAssetsAreImmutable(t *testing.T) {
	srv := uiServer(t)
	for _, path := range []string{"/assets/app-deadbeef.js", "/assets/app-deadbeef.css", "/assets/font-cafe.woff2"} {
		t.Run(path, func(t *testing.T) {
			resp, _ := get(t, srv, http.MethodGet, path, "")
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			cc := resp.Header.Get("Cache-Control")
			if !strings.Contains(cc, "immutable") {
				t.Fatalf("Cache-Control = %q, want immutable", cc)
			}
		})
	}
}

// A missing hashed asset is a build error, not a route: it must 404 rather
// than hand the browser index.html, which would arrive as a JavaScript parse
// error twenty frames from the actual mistake.
func TestMissingHashedAssetDoesNotFallBackToTheSPA(t *testing.T) {
	srv := uiServer(t)
	for _, accept := range []string{"", htmlAccept} {
		resp, body := get(t, srv, http.MethodGet, "/assets/app-00000000.js", accept)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("accept %q: status = %d, want 404", accept, resp.StatusCode)
		}
		if strings.Contains(body, "<html") {
			t.Fatalf("accept %q: the SPA leaked into an asset 404:\n%s", accept, body)
		}
	}
}

func TestAssetDirectoryListingIsRefused(t *testing.T) {
	srv := uiServer(t)
	for _, path := range []string{"/assets/", "/assets/sub", "/assets/sub/"} {
		resp, body := get(t, srv, http.MethodGet, path, htmlAccept)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404", path, resp.StatusCode)
		}
		if strings.Contains(body, "<html") {
			t.Fatalf("%s: served the SPA for a directory", path)
		}
	}
}

// Reserved prefixes are the API's, the probes' and the metrics surface's. A
// path under one of them that routes nowhere answers in that surface's own
// vocabulary — never the SPA — so a probe cannot tell an unrouted API path
// from an application route.
func TestReservedPrefixesNeverFallBackToTheSPA(t *testing.T) {
	srv := uiServer(t)
	for _, path := range []string{
		"/api/v1/does-not-exist",
		"/api/",
		"/api/v1/orgs/../../etc/passwd",
		"/metrics/anything",
		"/healthz/sub",
		"/readyz/sub",
	} {
		t.Run(path, func(t *testing.T) {
			resp, body := get(t, srv, http.MethodGet, path, htmlAccept)
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", resp.StatusCode)
			}
			if strings.Contains(body, "<html") {
				t.Fatalf("a reserved prefix fell back to the SPA:\n%s", body)
			}
		})
	}
}

// The probes themselves keep working: reserving the prefix must not shadow
// the real handlers.
func TestProbesStillAnswer(t *testing.T) {
	srv := uiServer(t)
	for _, path := range []string{"/healthz", "/readyz"} {
		resp, body := get(t, srv, http.MethodGet, path, htmlAccept)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", path, resp.StatusCode)
		}
		if strings.Contains(body, "<html") {
			t.Fatalf("%s: served the SPA", path)
		}
	}
	resp, body := get(t, srv, http.MethodGet, "/metrics", htmlAccept)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/metrics: status = %d, want 503 without a health source", resp.StatusCode)
	}
	if strings.Contains(body, "<html") {
		t.Fatal("/metrics served the SPA")
	}
}

// Fallback is for navigations. A non-GET/HEAD method, or a client that did
// not ask for HTML, gets the contract's own 404 — otherwise a fetch() typo
// would receive an HTML document and fail at JSON.parse instead of at the
// status code.
func TestFallbackOnlyForHTMLNavigations(t *testing.T) {
	srv := uiServer(t)
	t.Run("non-html accept", func(t *testing.T) {
		resp, body := get(t, srv, http.MethodGet, "/some/route", "application/json")
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
		if strings.Contains(body, "<html") {
			t.Fatal("served the SPA to a JSON client")
		}
	})
	t.Run("no accept header", func(t *testing.T) {
		resp, body := get(t, srv, http.MethodGet, "/some/route", "")
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
		if strings.Contains(body, "<html") {
			t.Fatal("served the SPA to a client that asked for nothing")
		}
	})
	t.Run("post", func(t *testing.T) {
		resp, body := get(t, srv, http.MethodPost, "/some/route", htmlAccept)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
		if strings.Contains(body, "<html") {
			t.Fatal("served the SPA to a POST")
		}
	})
}

// Non-hashed root files the build emits (favicon and friends) are served, but
// they are not immutable: their names carry no hash.
func TestRootFilesAreServedWithoutImmutableCaching(t *testing.T) {
	srv := uiServer(t)
	resp, body := get(t, srv, http.MethodGet, "/favicon.svg", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body != "<svg/>" {
		t.Fatalf("body = %q", body)
	}
	// No content hash and no modification time to revalidate against (embedded
	// files have a zero modtime), so the only honest answer is no-cache.
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("unhashed root file Cache-Control = %q, want no-cache", got)
	}
}

// The security baseline the ADR fixes in v1. The exact directive values are
// the ops spec's to tune; that the baseline EXISTS, forbids inline script,
// defaults to self and refuses framing is fixed here — and it constrains the
// Vite build, which must therefore emit no inline script or style.
func TestSecurityBaselineOnEveryResponse(t *testing.T) {
	srv := uiServer(t)
	for _, path := range []string{"/", "/assets/app-deadbeef.js", "/healthz", "/api/v1/nope"} {
		t.Run(path, func(t *testing.T) {
			resp, _ := get(t, srv, http.MethodGet, path, htmlAccept)
			csp := resp.Header.Get("Content-Security-Policy")
			switch {
			case csp == "":
				t.Fatal("no Content-Security-Policy")
			case !strings.Contains(csp, "default-src 'self'"):
				t.Fatalf("CSP does not default to self: %q", csp)
			case !strings.Contains(csp, "frame-ancestors 'none'"):
				t.Fatalf("CSP permits framing: %q", csp)
			case strings.Contains(csp, "unsafe-inline"), strings.Contains(csp, "unsafe-eval"):
				t.Fatalf("CSP relaxes script execution: %q", csp)
			}
			if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
			}
			if got := resp.Header.Get("Referrer-Policy"); got == "" {
				t.Fatal("no Referrer-Policy")
			}
		})
	}
}

// Without the `ui` build tag the binary carries no assets. It must still be a
// working API server — the frontend is an addition, never a prerequisite —
// and every path answers in the contract's vocabulary.
func TestNoEmbeddedUIStillServesTheAPI(t *testing.T) {
	srv := httptest.NewServer(server.New(stubReady{}, nil, nil))
	t.Cleanup(srv.Close)

	resp, body := get(t, srv, http.MethodGet, "/", htmlAccept)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if strings.Contains(body, "<html") {
		t.Fatalf("a UI-less build served HTML:\n%s", body)
	}
	if resp, _ := get(t, srv, http.MethodGet, "/healthz", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
	}
}

// Accept is a preference list with weights, not a substring. A client that
// explicitly refuses HTML must not be handed a document — and `*/*`, which is
// what fetch and curl send by default, is not a navigation.
func TestFallbackHonoursAcceptQuality(t *testing.T) {
	srv := uiServer(t)
	cases := []struct {
		accept string
		want   int
	}{
		{"text/html", http.StatusOK},
		{"text/html;q=0.9, application/json;q=0.8", http.StatusOK},
		{"text/*", http.StatusOK},
		{"application/json, text/html;q=0.001", http.StatusOK},
		{"text/html;q=0, application/json", http.StatusNotFound},
		{"text/html;q=0.0", http.StatusNotFound},
		{"text/html;q=0.000", http.StatusNotFound},
		{"text/html;q=1", http.StatusOK},
		{"text/html;q=1.0", http.StatusOK},
		{"text/html;q=1.000", http.StatusOK},
		// RFC 9110 12.4.2: a qvalue is 0..1 with at most three decimals.
		// Anything else is a client whose weight cannot be believed, and a
		// document is not what to hand it on a guess.
		{"text/html;q=2", http.StatusNotFound},
		{"text/html;q=-1", http.StatusNotFound},
		{"text/html;q=1.5", http.StatusNotFound},
		{"text/html;q=0.5000", http.StatusNotFound},
		{"text/html;q=abc", http.StatusNotFound},
		{"text/html;q=", http.StatusNotFound},
		{"text/html;q=.5", http.StatusNotFound},
		{"text/html;q=1e0", http.StatusNotFound},
		{"*/*", http.StatusNotFound},
		{"application/json", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.accept, func(t *testing.T) {
			resp, body := get(t, srv, http.MethodGet, "/some/route", tc.accept)
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d (body %q)", resp.StatusCode, tc.want, body)
			}
		})
	}
}

// Only ROOT files are served by name. A build that starts emitting a sourcemap
// or a manifest into a subdirectory must not make it publicly readable by
// accident — hashed assets have their own reserved prefix, and everything else
// the browser fetches by name lives at the root.
func TestNonRootEmbeddedFilesAreNotServedByName(t *testing.T) {
	srv := uiServer(t)
	for _, path := range []string{"/nested/deep/thing.txt", "/nested/deep"} {
		resp, body := get(t, srv, http.MethodGet, path, "")
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404 — a nested embedded file is publicly readable", path, resp.StatusCode)
		}
		if strings.Contains(body, "not an asset") {
			t.Fatalf("%s: served the embedded file's contents", path)
		}
	}
}
