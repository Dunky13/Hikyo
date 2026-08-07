// Package server is the HTTP layer: chi router, health surfaces. It never
// imports internal/store — enforced by the import-boundary test.
package server

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// ReadyChecker reports whether a request would actually work.
type ReadyChecker interface {
	Ready(ctx context.Context) error
}

// New builds the router. /healthz = process alive; /readyz = datastore
// reachable + migrations current (the latter holds by construction: boot
// refuses to serve on pending migrations).
func New(ready ReadyChecker) http.Handler {
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
	return r
}
