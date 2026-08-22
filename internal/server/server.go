// Package server is the HTTP layer: chi router, health surfaces, and the
// generated API. It never imports internal/store — enforced by the
// import-boundary test — so a handler cannot reach data except through the
// service layer, which authorizes inside a transaction.
package server

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
)

// ReadyChecker reports whether a request would actually work.
type ReadyChecker interface {
	Ready(ctx context.Context) error
}

// New builds the router.
//
// Route partitioning, and why it is a partition rather than one stack:
//
//   - /healthz and /readyz are operational probes with no principal and no
//     contract entry. They deliberately sit OUTSIDE the API middleware: a
//     liveness probe that could be refused by the admission budget would turn
//     a login flood into a restart loop.
//   - /api/v1/* is the contract. Every request there is validated against
//     api/openapi.yaml before a handler sees it, carries wire metadata for the
//     audit trail, and renders refusals through one uniform writer.
//
// Anything not matching either is a 404 in the contract's own error shape,
// so a probe cannot tell an unrouted path from a path it may not reach —
// unless `ui` carries an embedded single-page application, in which case the
// rules in spa.go decide, and only for an HTML navigation to a non-reserved
// path. A nil `ui` is an API-only binary, which is what a plain `go build`
// produces.
// remoteOriginSource adapts the directory service to the SPA document writer.
// It swallows the read error deliberately and answers the BASELINE: a database
// hiccup must tighten the policy, never loosen it, and a document served with
// `connect-src 'self'` is a workspace that cannot connect — visible and safe —
// where a document served with no CSP at all would be neither.
//
// It is handed to serveSPA rather than to the header middleware (#211): only a
// served document consumes the extension, so only a served document pays for
// the read.
func remoteOriginSource(a *API) func(context.Context) []string {
	if a == nil || a.Remotes == nil {
		return nil
	}
	return func(ctx context.Context) []string {
		origins, err := a.Remotes.RemoteOrigins(ctx)
		if err != nil {
			return nil
		}
		return origins
	}
}

func New(ready ReadyChecker, a *API, ui fs.FS) http.Handler {
	r := chi.NewRouter()
	// The static security baseline, on every response including refusals. The
	// dynamic part — `connect-src` extended with the configured remotes'
	// origins (#71), a closed list read per DOCUMENT so an added or removed
	// remote takes effect without a restart — belongs to the SPA writer below,
	// which is the only response that can use it.
	r.Use(securityHeaders())
	// Cross-origin readability for allowlisted workspace origins (#71), at the
	// TOP of the chain rather than inside the API group, and that placement is
	// load-bearing rather than tidy.
	//
	// A CORS PREFLIGHT MUST BE ANSWERED WHETHER OR NOT IT MATCHES A ROUTE. The
	// contract declares no OPTIONS operations — correctly, it describes the API
	// and not the browser's transport protocol — so an `OPTIONS
	// /api/v1/auth/workspace/start` matches nothing and, from inside a route
	// group, never reaches that group's middleware at all: it falls through to
	// the router's not-found handler, which knows nothing about CORS and
	// answers with no headers. The browser reports that as a missing
	// `Access-Control-Allow-Origin`, which reads like an allowlist problem and
	// is not — and it made every cross-origin POST of the workspace tier
	// unreachable while the GETs worked.
	//
	// Router-level middleware runs on every request, matched or not. It is also
	// OUTSIDE the artifact middleware, which is what a preflight needs: a
	// preflight carries no credential by definition, so it must be answered
	// before anything tries to resolve one. Requests without an `Origin` header
	// pass through untouched, so nothing else on the router changes.
	r.Use(workspaceCORS(workspaceOriginCheck(a)))
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	r.Get("/readyz", func(w http.ResponseWriter, req *http.Request) {
		if err := ready.Ready(req.Context()); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	r.Get("/metrics", func(w http.ResponseWriter, req *http.Request) {
		if a == nil || a.RetentionHealth == nil {
			http.Error(w, "retention health unavailable", http.StatusServiceUnavailable)
			return
		}
		health, err := a.RetentionHealth.OperationalHealth(req.Context())
		if err != nil {
			http.Error(w, "retention health unavailable", http.StatusServiceUnavailable)
			return
		}
		last := int64(0)
		if health.Recorded {
			last = health.LastSuccess.Unix()
		}
		stale := 0
		if health.Stale {
			stale = 1
		}
		storageWarn := 0
		if health.StorageWarn {
			storageWarn = 1
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "# TYPE hikyo_last_prune_success_timestamp_seconds gauge\n"+
			"hikyo_last_prune_success_timestamp_seconds %d\n"+
			"# TYPE hikyo_prune_stale gauge\n"+
			"hikyo_prune_stale %d\n"+
			"# TYPE hikyo_project_storage_peak_bytes gauge\n"+
			"hikyo_project_storage_peak_bytes %d\n"+
			"# TYPE hikyo_project_storage_warn gauge\n"+
			"hikyo_project_storage_warn %d\n", last, stale, health.PeakProjectBytes, storageWarn)
	})

	if a != nil {
		r.Group(func(g chi.Router) {
			for _, mw := range a.Middleware() {
				g.Use(mw)
			}
			g.Use(a.SlideSessionClocks)
			// The strict server's own error legs go through the SAME uniform
			// writer as every handler. Left at their defaults they emit
			// `http.Error` plain text, which is neither the contract's error
			// shape nor uniform — and it is the leg a handler takes when it
			// returns a bare domain error rather than building one of twenty
			// near-identical per-operation refusal objects.
			apigen.HandlerFromMux(apigen.NewStrictHandlerWithOptions(a, nil, apigen.StrictHTTPServerOptions{
				RequestErrorHandlerFunc:  a.writeRequestError,
				ResponseErrorHandlerFunc: a.writeHandlerError,
			}), g)
		})
	}

	if ui != nil {
		r.Handle(assetPrefix+"*", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			serveAsset(ui, w, req)
		}))
		origins := remoteOriginSource(a)
		r.NotFound(func(w http.ResponseWriter, req *http.Request) {
			serveSPA(ui, origins, w, req)
		})
	} else {
		r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
			writeError(w, wirePolicyForCode(apigen.ErrorCodeNotFound), "")
		})
	}
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		// A method the contract does not describe on a path it does is,
		// from outside, the same fact as a path that is not there.
		writeError(w, wirePolicyForCode(apigen.ErrorCodeNotFound), "")
	})
	return r
}

// ContractPrefix re-exports the version prefix so callers building URLs read
// it from the contract rather than restating it.
const ContractPrefix = api.PathPrefix
