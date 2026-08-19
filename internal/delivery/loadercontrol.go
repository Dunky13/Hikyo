package delivery

import (
	"slices"
	"strings"
)

// Loader-control baseline (compose-integration ADR § Loader-control keys,
// propagated to the k8s ADR; #64 handoff § 0.6). Environment variables the
// loader/interpreter reads before user code runs: delivering one is an integrity
// capability (`LD_PRELOAD`, `NODE_OPTIONS`, `PATH` in a Secret consumed via
// `envFrom` is code execution in every consuming pod). A mapping whose
// destination `secretKey` matches the baseline is refused unless the CR
// acknowledges EXACTLY those keys.
//
// The list is verbatim from the Compose ADR. #25 (API & CLI) MAY extend it,
// never silently shrink it. It lives here because #63 (Compose) shares the same
// enforcement; the operator (#64) is the first consumer.

// loaderControlPrefixes are matched as prefixes: any variable beginning with one
// is a loader-control key. `LD_*` covers the whole dynamic-linker family
// (LD_PRELOAD, LD_LIBRARY_PATH, …); `GIT_*` covers git's many
// execution-influencing variables (GIT_SSH, GIT_EXTERNAL_DIFF, …).
var loaderControlPrefixes = []string{"LD_", "GIT_"}

// loaderControlExact are matched by exact name.
var loaderControlExact = map[string]bool{
	"PATH":                true,
	"IFS":                 true,
	"ENV":                 true,
	"BASH_ENV":            true,
	"SHELLOPTS":           true,
	"NODE_OPTIONS":        true,
	"PYTHONSTARTUP":       true,
	"PYTHONPATH":          true,
	"PERL5OPT":            true,
	"PERL5LIB":            true,
	"RUBYOPT":             true,
	"RUBYLIB":             true,
	"JAVA_TOOL_OPTIONS":   true,
	"_JAVA_OPTIONS":       true,
	"JDK_JAVA_OPTIONS":    true,
	"CLASSPATH":           true,
	"SSL_CERT_FILE":       true,
	"SSL_CERT_DIR":        true,
	"CURL_CA_BUNDLE":      true,
	"REQUESTS_CA_BUNDLE":  true,
	"NODE_EXTRA_CA_CERTS": true,
}

// IsLoaderControlKey reports whether name is on the loader-control baseline —
// either an exact match or under a controlled prefix.
func IsLoaderControlKey(name string) bool {
	if loaderControlExact[name] {
		return true
	}
	for _, p := range loaderControlPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Unacknowledged applies the § 0.6 rule against a mapping's destination keys.
// The acknowledgement is EXACT, not a wildcard:
//
//   - refused: mapped keys that are on the baseline but NOT acknowledged. A
//     sync carrying any of these fails (`LoaderControlUnacknowledged`).
//   - extraAcks: acknowledged names that are NOT among the mapped keys. An
//     over-broad acknowledgement is itself a refusal — acknowledging `PATH`
//     without mapping it is a latent grant that must not stand.
//
// Both slices empty ⇒ the mapping satisfies the baseline. mapped is the list of
// destination `secretKey`s the mapping delivers; acknowledged is
// `spec.acknowledgedLoaderKeys`. Order-stable and de-duplicated so the caller's
// condition message and the `acknowledged_keys` request parameter are
// deterministic.
func Unacknowledged(mapped, acknowledged []string) (refused, extraAcks []string) {
	ackSet := make(map[string]bool, len(acknowledged))
	for _, a := range acknowledged {
		ackSet[a] = true
	}
	mappedSet := make(map[string]bool, len(mapped))

	seenRefused := make(map[string]bool)
	for _, m := range mapped {
		mappedSet[m] = true
		if IsLoaderControlKey(m) && !ackSet[m] && !seenRefused[m] {
			seenRefused[m] = true
			refused = append(refused, m)
		}
	}

	seenExtra := make(map[string]bool)
	for _, a := range acknowledged {
		if !mappedSet[a] && !seenExtra[a] {
			seenExtra[a] = true
			extraAcks = append(extraAcks, a)
		}
	}

	slices.Sort(refused)
	slices.Sort(extraAcks)
	return refused, extraAcks
}
