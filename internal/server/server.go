// Package server is the HTTP layer: chi router, health surfaces, and the
// generated API. It never imports internal/store — enforced by the
// import-boundary test — so a handler cannot reach data except through the
// service layer, which authorizes inside a transaction.
package server

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Dunky13/wenv/api"
	"github.com/Dunky13/wenv/api/apigen"
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
// so a probe cannot tell an unrouted path from a path it may not reach.
func New(ready ReadyChecker, a *API) http.Handler {
	r := chi.NewRouter()
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

	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, apigen.ErrorCodeNotFound, "")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		// A method the contract does not describe on a path it does is,
		// from outside, the same fact as a path that is not there.
		writeError(w, apigen.ErrorCodeNotFound, "")
	})
	return r
}

// ContractPrefix re-exports the version prefix so callers building URLs read
// it from the contract rather than restating it.
const ContractPrefix = api.PathPrefix
