package compose

import (
	"sort"
	"strings"
)

// Loader-control baseline (compose-integration ADR § "Loader-control keys —
// defence in depth, not a boundary", amendment 1). Environment variables that
// redirect what the consuming runtime EXECUTES: a principal holding edit ∧
// publish could otherwise obtain code execution inside every workload without
// holding reveal. This is DEFENCE IN DEPTH, not a boundary — a name list cannot
// catch an application's own configuration keys — and both delivery paths
// refuse by default to deliver a loader-control key unless the target
// explicitly acknowledges it by name.
//
// The list is fixed here verbatim from the ADR. Downstream (#25/stream C) MAY
// extend it; it MUST NOT shrink it silently — loaderControlPinned pins it so a
// deletion fails a test.

// loaderControlExact is the exact-match baseline.
var loaderControlExact = map[string]struct{}{
	"PATH":                {},
	"IFS":                 {},
	"ENV":                 {},
	"BASH_ENV":            {},
	"SHELLOPTS":           {},
	"NODE_OPTIONS":        {},
	"PYTHONSTARTUP":       {},
	"PYTHONPATH":          {},
	"PERL5OPT":            {},
	"PERL5LIB":            {},
	"RUBYOPT":             {},
	"RUBYLIB":             {},
	"JAVA_TOOL_OPTIONS":   {},
	"_JAVA_OPTIONS":       {},
	"JDK_JAVA_OPTIONS":    {},
	"CLASSPATH":           {},
	"SSL_CERT_FILE":       {},
	"SSL_CERT_DIR":        {},
	"CURL_CA_BUNDLE":      {},
	"REQUESTS_CA_BUNDLE":  {},
	"NODE_EXTRA_CA_CERTS": {},
}

// loaderControlPrefixes is the prefix baseline: any name starting with one of
// these is loader-control (LD_PRELOAD, LD_LIBRARY_PATH, GIT_SSH, …).
var loaderControlPrefixes = []string{"LD_", "GIT_"}

// IsLoaderControl reports whether name is a loader-control variable. Matching is
// CASE-SENSITIVE: environment variable names are case-sensitive on Linux, so
// `path` is not `PATH`.
func IsLoaderControl(name string) bool {
	if _, ok := loaderControlExact[name]; ok {
		return true
	}
	for _, p := range loaderControlPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
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
