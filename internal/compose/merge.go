package compose

import (
	"fmt"
	"sort"
	"strings"
)

// Merge rule for `hikyo run --` (compose-integration ADR § "Merge, collisions,
// and loader-control keys").
//
// FETCHED VALUES WIN over the inherited environment — forced, not chosen: if
// inherited won, a stale `export DATABASE_URL` in a shell profile would
// silently shadow the managed value and the workload would run on the wrong
// secret, invisibly. But a collision whose values DIFFER is a HARD ERROR, not a
// scroll-past warning during `docker compose up`; identical values are a no-op.
// The escape hatch names the colliding keys explicitly (allowOverride) — there
// is no blanket override flag.

// Collision reports, by KEY NAME ONLY, a key present in both sources with
// differing values that was permitted by allowOverride (informational;
// hard-error collisions come back as the error). It carries NO values: a
// value in a result or error string reaches a `docker compose up` warning or a
// structured `%v` log and discloses a secret, and only the colliding name is
// needed.
type Collision struct {
	Key string
}

// MergeEnv merges fetched values into the inherited environment. inherited is a
// slice of "K=V" entries (os.Environ() shape); fetched is the delivered map.
// Inherited order is kept stable; fetched-only keys are appended sorted.
//
// A key in both whose values differ is an error UNLESS listed in allowOverride,
// in which case it is a reported Collision (fetched still wins). Identical
// values are a silent no-op.
func MergeEnv(inherited []string, fetched map[string]string, allowOverride []string) ([]string, []Collision, error) {
	allow := make(map[string]struct{}, len(allowOverride))
	for _, k := range allowOverride {
		allow[k] = struct{}{}
	}

	var collisions []Collision
	var hardErrors []string
	seen := make(map[string]struct{}, len(inherited))
	out := make([]string, 0, len(inherited)+len(fetched))

	for _, kv := range inherited {
		key, val, ok := cutEnv(kv)
		if !ok {
			// Preserve malformed inherited entries verbatim (e.g. a bare name);
			// they are not ours to normalize.
			out = append(out, kv)
			continue
		}
		seen[key] = struct{}{}
		fv, collide := fetched[key]
		if !collide {
			out = append(out, kv)
			continue
		}
		// Fetched wins in all non-error cases.
		out = append(out, key+"="+fv)
		if fv == val {
			continue // identical: no-op
		}
		if _, allowed := allow[key]; allowed {
			collisions = append(collisions, Collision{Key: key})
			continue
		}
		hardErrors = append(hardErrors, key)
	}

	// Fetched-only keys, appended sorted for a stable child environment.
	var extra []string
	for k := range fetched {
		if _, ok := seen[k]; !ok {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		out = append(out, k+"="+fetched[k])
	}

	if len(hardErrors) > 0 {
		sort.Strings(hardErrors)
		return nil, nil, fmt.Errorf("refusing to run: inherited environment and fetched values disagree on %s; "+
			"the values differ. Add each key to --allow-override to accept the fetched value",
			strings.Join(hardErrors, ", "))
	}
	return out, collisions, nil
}

// cutEnv splits a "K=V" entry on its first '='. A entry with no '=' is not a
// well-formed assignment.
func cutEnv(kv string) (key, val string, ok bool) {
	i := strings.IndexByte(kv, '=')
	if i < 0 {
		return "", "", false
	}
	return kv[:i], kv[i+1:], true
}
