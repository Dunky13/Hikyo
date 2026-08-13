package server

import (
	"context"
	"net/http"
)

// Cross-origin access for the workspace tier (#71, multi-instance ADR §
// Consent: the origin allowlist).
//
// WHAT THIS DOES AND DOES NOT DO, stated precisely because the ADR is
// emphatic about it: CORS controls what a BROWSER may read. It is not bearer
// authorization. Anyone who exfiltrates a workspace bearer can replay it from
// a non-browser client until it expires or is revoked, exactly as the
// human-auth ADR states for bearer artifacts generally. The server-side
// controls carry the rest — workspace session rows are bound to their
// requesting origin, and removing an origin from the allowlist atomically
// revokes every session bound to it.
//
// Three rules, all normative:
//
//  1. EXACTLY ONE ORIGIN IS ECHOED, and only if it matches an allowlist entry
//     exactly. Never `*`, never a reflected unknown origin, never a list.
//  2. NON-CREDENTIALS MODE. `Access-Control-Allow-Credentials` is never sent,
//     because the workspace bearer rides an `Authorization` header and cookies
//     must not cross origins here. That is also why this instance's CSRF
//     posture is untouched: there is nothing ambient to forge.
//  3. A NON-ALLOWLISTED ORIGIN GETS NO CORS HEADERS AT ALL. Not an error body,
//     not a partial set — the browser's own default refusal is the answer, and
//     adding headers to say "no" would leak that the endpoint exists to
//     script that cannot read it anyway.
//
// It covers `/api/v1` as a whole, which includes the handoff endpoints and the
// pre-auth meta endpoint. Meta must be CORS-readable for allowlisted origins
// because the shell performs a LIVE meta read for the version-skew check
// before establishing or resuming a workspace, cross-origin.

// corsAllowedHeaders is the closed request-header set a workspace client may
// send. `Authorization` is the transport; `Content-Type` is needed for JSON
// bodies. Nothing else — a wildcard here would let script probe for
// header-triggered behaviour.
const corsAllowedHeaders = "Authorization, Content-Type"

// corsAllowedMethods is the contract's own verb set.
const corsAllowedMethods = "GET, POST, PUT, PATCH, DELETE, OPTIONS"

// corsMaxAge caps preflight caching. Ten minutes: long enough that a workspace
// session is not preflighting every call, short enough that de-allowlisting an
// origin stops new preflights promptly. It bounds only the PREFLIGHT — the
// session kill switch is immediate and does not wait for this.
const corsMaxAge = "600"

// workspaceCORS answers preflights and decorates responses for allowlisted
// origins.
//
// `allowed` is consulted per request rather than snapshotted at startup, so
// removing an origin from the allowlist takes effect on the next request
// without a restart. A read error answers FALSE: a database hiccup must close
// the door, never open it.
func workspaceCORS(allowed func(context.Context, string) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// VARY IS SET ON EVERY BRANCH, BEFORE THE DECISION. It is a
			// cache-control statement, not an allowlist grant: it says "this
			// response depends on the Origin header", which is true whether the
			// answer was yes or no. Setting it only on the accepted branch let
			// a shared cache store the header-free response produced for a
			// request with no Origin (or a denied one) and then serve that
			// generic response to an allowlisted workspace — whose live
			// pre-auth meta read would then fail on a missing
			// Access-Control-Allow-Origin, looking exactly like withdrawn
			// consent and not being it.
			w.Header().Add("Vary", "Origin")
			origin := r.Header.Get("Origin")
			if origin == "" || allowed == nil || !allowed(r.Context(), origin) {
				// No headers at all. A preflight from an unknown origin still
				// gets its 204 — the browser refuses it on the missing
				// headers, and answering 403 would distinguish "not
				// allowlisted" from "no such path" to script that can read
				// neither.
				if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			// Deliberately absent: Access-Control-Allow-Credentials. See the
			// package comment — cookies never cross origins in this design.
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h.Set("Access-Control-Allow-Methods", corsAllowedMethods)
				h.Set("Access-Control-Allow-Headers", corsAllowedHeaders)
				h.Set("Access-Control-Max-Age", corsMaxAge)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// workspaceOriginCheck adapts the workspace service to the middleware. Nil when
// no workspace surface is wired, which leaves the server exactly as
// same-origin-only as it was.
func workspaceOriginCheck(a *API) func(context.Context, string) bool {
	if a == nil || a.Workspace == nil {
		return nil
	}
	return func(ctx context.Context, origin string) bool {
		ok, err := a.Workspace.OriginAllowed(ctx, origin)
		return err == nil && ok
	}
}
