package compose

import (
	"sort"

	"github.com/Hikyo-Org/hikyo/internal/delivery"
)

// The loader-control baseline has a SINGLE home in internal/delivery
// (loadercontrol.go), shared by both delivery paths — #63 (Compose) here and
// #64 (the Kubernetes operator). This file keeps the compose-facing spellings
// (IsLoaderControl / RefuseUnacknowledged) but backs them by that one table so
// the ADR's "may extend, never silently shrink" invariant is pinned in exactly
// one place.

// IsLoaderControl reports whether name is a loader-control variable. Matching is
// CASE-SENSITIVE: environment variable names are case-sensitive on Linux, so
// `path` is not `PATH`. It re-exports delivery.IsLoaderControlKey.
func IsLoaderControl(name string) bool {
	return delivery.IsLoaderControlKey(name)
}

// RefuseUnacknowledged returns, sorted, the loader-control names in names that
// are NOT in acknowledged. A non-empty result is a delivery failure naming the
// keys (never a silent drop, per the ADR: "a silent drop is a delivery that
// quietly did not happen").
func RefuseUnacknowledged(names []string, acknowledged []string) []string {
	ack := make(map[string]struct{}, len(acknowledged))
	for _, a := range acknowledged {
		ack[a] = struct{}{}
	}
	var refused []string
	for _, n := range names {
		if !IsLoaderControl(n) {
			continue
		}
		if _, ok := ack[n]; ok {
			continue
		}
		refused = append(refused, n)
	}
	sort.Strings(refused)
	return refused
}
