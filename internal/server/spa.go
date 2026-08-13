package server

import (
	"context"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/Dunky13/hikyo/api/apigen"
)

// Embedded single-page-application serving (#56).
//
// `embed.FS` has no SPA semantics of its own, so the system-architecture ADR
// § Frontend specifies them and this file is where they live:
//
//   - reserved prefixes (the contract, the probes, the metrics surface and the
//     hashed-asset directory) NEVER fall back to the document;
//   - fallback applies only to a GET/HEAD that asks for HTML, so a mistyped
//     fetch() fails at its status code rather than at JSON.parse;
//   - a missing hashed asset is a build error, so it 404s;
//   - hashed assets are immutable, `index.html` is never cached.
//
// The asset tree arrives as an `fs.FS` rather than being embedded here. That
// keeps the rules testable against a synthetic tree — and keeps `go build` and
// `go test` green for someone who has never run the frontend build, because
// the embed itself sits behind the `ui` tag in internal/webui.

// assetPrefix is the hashed-asset directory. It is reserved: Vite writes every
// content-hashed file under it, so a 404 there is always a build error.
const assetPrefix = "/assets/"

// indexPath is the document served for every application route.
const indexPath = "index.html"

// contentSecurityPolicy is the v1 baseline the ADR fixes. Self-only by
// default, no inline script or style (which constrains the frontend build,
// deliberately), no framing, no plugin content, no base-tag rewriting.
// Tuning belongs to the ops spec; the baseline's existence does not.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; " +
	"connect-src 'self'; base-uri 'none'; object-src 'none'; form-action 'self'; " +
	"frame-ancestors 'none'"

// connectSrcSelf is the token the remote origins extend (#71). It is spelled
// once so the extension below cannot drift from the baseline above.
const connectSrcSelf = "connect-src 'self'"

// policyWithRemotes extends the baseline's `connect-src` with exactly the
// origins of the configured remote entries.
//
// The workspace tier is the BROWSER talking to a remote directly, so the shell
// must be permitted to reach those origins — and only those. It stays a CLOSED
// LIST, never `*`: an origin that is not a configured remote is not reachable
// from this instance's UI, which is the whole point of naming them.
//
// `frame-ancestors 'none'` is untouched and stays everywhere: the popup is a
// top-level navigation and the workspace never iframes a remote.
//
// Each stored value is PARSED AND RECONSTRUCTED as a canonical https origin,
// and anything that does not survive that round trip is dropped. Character
// filtering is what this replaced, and it was the wrong shape: a filter has to
// enumerate everything a CSP source expression can be, and it missed the most
// important one — `https://*.example.test` contains no forbidden character and
// broadens connect-src to every matching subdomain, in a directive whose whole
// promise is "exact origins, never `*`". Reconstruction cannot miss a form,
// because only `scheme://host[:port]` is ever emitted, and only when the parse
// produced exactly that.
func policyWithRemotes(origins []string) string {
	extra := make([]string, 0, len(origins))
	seen := map[string]bool{}
	for _, o := range origins {
		canonical, ok := cspOrigin(o)
		if !ok || seen[canonical] {
			continue
		}
		seen[canonical] = true
		extra = append(extra, canonical)
	}
	if len(extra) == 0 {
		return contentSecurityPolicy
	}
	return strings.Replace(contentSecurityPolicy, connectSrcSelf,
		connectSrcSelf+" "+strings.Join(extra, " "), 1)
}

// cspOrigin reconstructs one canonical https origin, or reports that the stored
// value is not one.
//
// The host is checked character by character against the DNS/IPv6 alphabet
// rather than trusted from url.Parse: a wildcard, a scheme-relative form, a
// path, a query, userinfo and a CSP keyword all fail here, and a value that
// parses but round-trips to something else fails the final comparison. `https`
// only — the remote URL grammar refuses plaintext, so an http entry in this
// list is a stored value that was never a remote.
func cspOrigin(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", false
	}
	host, port := u.Hostname(), u.Port()
	if host == "" {
		return "", false
	}
	// https, or http on LOOPBACK and nothing else. The remote URL grammar
	// refuses plaintext, so an http entry is never a remote a human added
	// through the API — but the two-instance browser harness repoints an entry
	// at a loopback http origin at the store layer, deliberately, because what
	// the browser leg proves (popup origin, CORS, noopener, header-borne
	// bearer, both kill switches) is origin-shaped rather than pin-shaped. A
	// loopback origin cannot be intercepted, so admitting it here narrows
	// nothing that matters, and it is the same asymmetry
	// service.CanonicalOrigin already codifies for allowlist entries.
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1"):
	default:
		return "", false
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == ':': // ':' for a bracketed IPv6 literal
		default:
			return "", false
		}
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	out := u.Scheme + "://" + u.Host
	// The round trip: the emitted value must be exactly what the stored value
	// meant, with nothing dropped in normalisation.
	if trimmed := strings.TrimSuffix(raw, "/"); trimmed != out {
		return "", false
	}
	return out, true
}

// reservedRoots are the surfaces that own their own vocabulary. Each covers
// itself and everything beneath it. `/api` subsumes ContractPrefix, so the
// version prefix needs no entry of its own.
var reservedRoots = []string{"/api", "/metrics", "/healthz", "/readyz",
	strings.TrimSuffix(assetPrefix, "/")}

// reservedFromFallback reports whether a path is withheld from the SPA
// fallback. It is a prefix partition, not a route lookup: an unrouted path
// under /api/ is the contract's 404, not an application route the browser
// should try to render.
func reservedFromFallback(p string) bool {
	for _, root := range reservedRoots {
		if p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}

// securityHeaders applies the baseline to every response, API answers
// included: `nosniff` on a JSON error body is as load-bearing as it is on the
// document, and a single writer means no surface can be forgotten.
func securityHeaders(remoteOrigins func(context.Context) []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			policy := contentSecurityPolicy
			if remoteOrigins != nil {
				policy = policyWithRemotes(remoteOrigins(r.Context()))
			}
			h.Set("Content-Security-Policy", policy)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
			next.ServeHTTP(w, r)
		})
	}
}

// wantsHTML reports whether the client asked for a document. A navigation says
// so; `fetch` with no Accept header does not.
//
// The rule, stated because "contains text/html" is not it: the fallback needs
// an explicit `text/html` (or `text/*`) range with a POSITIVE q-value.
// `Accept: text/html;q=0, application/json` is a client saying it will NOT
// take HTML, and handing it a document anyway is the same failure as ignoring
// Accept entirely. `*/*` deliberately does NOT qualify — a bare wildcard is
// what `fetch` and curl send, and treating it as a navigation is how a typo'd
// API call ends up parsed as JSON three frames from the mistake.
func wantsHTML(r *http.Request) bool {
	for part := range strings.SplitSeq(r.Header.Get("Accept"), ",") {
		media, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		media = strings.TrimSpace(media)
		if !strings.EqualFold(media, "text/html") && !strings.EqualFold(media, "text/*") {
			continue
		}
		if quality(params) > 0 {
			return true
		}
	}
	return false
}

// qvaluePattern is RFC 9110 §12.4.2's qvalue grammar, exactly: zero or one,
// with at most three decimal places. Nothing else is a weight.
var qvaluePattern = regexp.MustCompile(`^(?:0(?:\.[0-9]{0,3})?|1(?:\.0{0,3})?)$`)

// quality reads the q parameter of one Accept range.
//
// An ABSENT q means 1 — that is the RFC's default. A PRESENT but malformed or
// out-of-range one (`q=2`, `q=abc`, `q=0.5000`) means the range does not
// qualify, and that is a decision rather than a reading of the spec: RFC 9110
// gives no default for a malformed weight, so the choice is between guessing
// the client meant 1 and refusing to guess. A client that sent a weight the
// grammar forbids has told us something is wrong with it, and serving an HTML
// document to something that may be a JSON client on the strength of a guess
// is the failure this whole predicate exists to avoid.
func quality(params string) float64 {
	for param := range strings.SplitSeq(params, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(param), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "q") {
			continue
		}
		value = strings.TrimSpace(value)
		if !qvaluePattern.MatchString(value) {
			return 0
		}
		q, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return 0
		}
		return q
	}
	return 1
}

// serveAsset answers from the hashed-asset directory. Nothing here falls back:
// the caller has already established that the path is under the reserved
// asset prefix, and a name that is not in the build is a build error.
func serveAsset(ui fs.FS, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if !fs.ValidPath(name) || !strings.HasPrefix(name, strings.Trim(assetPrefix, "/")+"/") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	info, err := fs.Stat(ui, name)
	if err != nil || info.IsDir() {
		// Plain text, not the contract's error shape: this is not a contract
		// surface, and the reader is a browser console.
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// Every name under the asset directory carries a content hash, so the bytes
	// behind a URL never change and the browser never needs to ask again.
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.ServeFileFS(w, r, ui, name)
}

// serveSPA is the not-found leg once assets exist: an HTML navigation to a
// non-reserved path renders the application, anything else gets the
// contract's uniform nonexistent answer.
func serveSPA(ui fs.FS, w http.ResponseWriter, r *http.Request) {
	if reservedFromFallback(r.URL.Path) ||
		(r.Method != http.MethodGet && r.Method != http.MethodHead) {
		writeError(w, apigen.ErrorCodeNotFound, "")
		return
	}
	// A root-relative file the build emitted (favicon, manifest) is served as
	// itself, whatever the client asked for — it is a real file, not a route.
	// Its name carries no content hash, and an embedded file has a zero
	// modification time, so there is no validator to revalidate against
	// either: `no-cache` is the only honest answer, the same one index.html
	// gets and for the same reason.
	//
	// ONE segment, deliberately. `fs.ValidPath` accepts `some/dir/file`, so a
	// future build emitting a sourcemap or a manifest into a subdirectory
	// would become publicly readable at its own URL without anyone deciding
	// that. Hashed assets have their own reserved prefix; everything else the
	// browser is meant to fetch by name sits at the root.
	if name := strings.TrimPrefix(path.Clean(r.URL.Path), "/"); name != "" && name != indexPath &&
		fs.ValidPath(name) && !strings.Contains(name, "/") {
		if info, err := fs.Stat(ui, name); err == nil && !info.IsDir() {
			w.Header().Set("Cache-Control", "no-cache")
			http.ServeFileFS(w, r, ui, name)
			return
		}
	}
	// Everything past here is the application's own routing, and only a
	// navigation should receive a document.
	if !wantsHTML(r) {
		writeError(w, apigen.ErrorCodeNotFound, "")
		return
	}
	body, err := fs.ReadFile(ui, indexPath)
	if err != nil {
		// An asset tree without a document is a broken build, not a route.
		writeError(w, apigen.ErrorCodeNotFound, "")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The document names the hashed assets, so it is the one file that must
	// never be served from cache without revalidation — a stale index points at
	// bundles a deploy has already removed.
	w.Header().Set("Cache-Control", "no-cache")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
