package schema

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The JSON Schema profile (schema-model ADR § JSON Schema for `json`-typed
// keys — a pinned, bounded profile).
//
// "We accept JSON Schema 2020-12" is not implementable as stated: a schema
// well inside every size limit can drive combinatorial evaluation through
// nested applicators, and independent Go libraries disagree on formats,
// vocabularies and reference resolution. v1 therefore accepts a pinned,
// profiled, budgeted subset:
//
//   - PINNED library and version — github.com/santhosh-tekuri/jsonschema/v6
//     v6.0.2, pinned in go.mod. Two Hikyo installations must accept and reject
//     the same schemas; "some 2020-12 validator" is not a contract. The
//     conformance-suite baseline is the ops spec's to name (disposition item).
//   - ONE pinned dialect — 2020-12, declared, no negotiation.
//   - A PROFILE that is an explicit keyword ALLOWLIST, never a denylist: a
//     denylist silently admits every keyword a future dialect or library
//     version adds. Anything outside it is rejected loud at declaration, and
//     the exclusions the ADR fixes are rejected BY NAME so an operator learns
//     which rule caught them rather than "unsupported".
//   - BOUNDS checked before compilation: document bytes, nesting depth,
//     subschema count — which together ARE the step cap, because every keyword
//     that survives the allowlist costs at most LINEAR time in the instance per
//     subschema:
//   - `type`, `enum`, `const`, `required`, `dependentRequired`, the length
//     and count bounds and `multipleOf` inspect the instance once (or, for
//     `enum`, once per declared member, which is itself bounded).
//   - `pattern` and `patternProperties` are RE2, which is linear in the
//     subject and carries no backtracking.
//   - `properties`, `additionalProperties`, `propertyNames`, `items`,
//     `prefixItems`, `allOf`, `anyOf`, `oneOf`, `not`, `if`/`then`/`else`,
//     `dependentSchemas` and `$ref` apply SUBSCHEMAS to instance positions,
//     which is exactly the subschemas × instance-bytes product the bound
//     already counts.
//     Every SUPERLINEAR keyword is excluded by name: `uniqueItems` (quadratic
//     element comparison), `contains` (unbounded repetition),
//     `unevaluatedProperties`/`unevaluatedItems` (cost not statically
//     boundable), `$dynamicRef`/`$dynamicAnchor` (meaning not statically
//     determinable at all).
//
// This pre-pass is Hikyo's own, run over the parsed document BEFORE the library
// ever sees it. Delegating the profile to the library would make the profile
// whatever that library's next version decides.
const schemaResourceURL = "https://schema.hikyo.invalid/declaration"

// keywordKind says how a keyword's value is shaped, which is what the walk
// needs in order to know where the subschemas are.
type keywordKind int

const (
	kindData        keywordKind = iota // assertion or annotation; no subschema
	kindSchema                         // one subschema
	kindSchemaArray                    // an array of subschemas
	kindSchemaMap                      // an object whose values are subschemas
)

// allowedKeywords IS the profile. Growing it is a deliberate, reviewable act;
// widening later is additive, whereas accepting arbitrary 2020-12 schemas and
// restricting afterwards would break stored declarations.
var allowedKeywords = map[string]keywordKind{
	// Core, minus every construct that would make meaning depend on anything
	// but this document's own text.
	"$schema":  kindData,
	"$comment": kindData,
	"$ref":     kindData,
	"$defs":    kindSchemaMap,

	// Assertions.
	"type":              kindData,
	"enum":              kindData,
	"const":             kindData,
	"multipleOf":        kindData,
	"maximum":           kindData,
	"exclusiveMaximum":  kindData,
	"minimum":           kindData,
	"exclusiveMinimum":  kindData,
	"maxLength":         kindData,
	"minLength":         kindData,
	"pattern":           kindData,
	"maxItems":          kindData,
	"minItems":          kindData,
	"maxProperties":     kindData,
	"minProperties":     kindData,
	"required":          kindData,
	"dependentRequired": kindData,

	// Applicators whose cost is bounded by the instance and the subschema
	// count, both of which this package bounds.
	"properties":           kindSchemaMap,
	"patternProperties":    kindSchemaMap,
	"dependentSchemas":     kindSchemaMap,
	"additionalProperties": kindSchema,
	"propertyNames":        kindSchema,
	"items":                kindSchema,
	"prefixItems":          kindSchemaArray,
	"allOf":                kindSchemaArray,
	"anyOf":                kindSchemaArray,
	"oneOf":                kindSchemaArray,
	"not":                  kindSchema,
	"if":                   kindSchema,
	"then":                 kindSchema,
	"else":                 kindSchema,

	// Annotations. They assert nothing, so they cost nothing.
	"title":       kindData,
	"description": kindData,
	"examples":    kindData,
	"deprecated":  kindData,
	"readOnly":    kindData,
	"writeOnly":   kindData,
}

// excludedKeywords are the exclusions the ADR fixes by name. They are refused
// with their reason rather than falling through the allowlist's generic
// message, because "unsupported keyword" teaches an operator nothing about why
// the profile will not grow to include it.
var excludedKeywords = map[string]string{
	"$dynamicRef":           "its resolution depends on the dynamic scope, so a schema's meaning stops being statically determinable",
	"$dynamicAnchor":        "its resolution depends on the dynamic scope, so a schema's meaning stops being statically determinable",
	"unevaluatedProperties": "its cost is not statically boundable, so the declaration-time work bound could not hold",
	"unevaluatedItems":      "its cost is not statically boundable, so the declaration-time work bound could not hold",
	"contains":              "an unbounded `contains` has no statically boundable cost; the profile excludes `contains` outright, which is the reversible direction",
	"uniqueItems":           "comparing every array element against every other is QUADRATIC in the instance, so it is not boundable at linear cost per subschema — and the declaration-time work budget is only a step cap while every surviving keyword is at most linear. Widening later is additive, on the same ground as `contains`",
	"minContains":           "`contains` is excluded from the profile, so its bounds have nothing to bound",
	"maxContains":           "`contains` is excluded from the profile, so its bounds have nothing to bound",
	"default":               "there is no defaulting mechanism in this product at all (flat-model ADR): a declared `default` would be an invisible source of values, and a schema must never appear to supply something it does not",
	"format":                "JSON Schema makes `format` an annotation by default, so an asserted-looking `format` may validate nothing, and format assertion is the single largest source of cross-library divergence — use `pattern`",
	"$id":                   "the profile resolves `$ref` as an in-document JSON pointer only, so base-URI machinery is excluded",
	"$anchor":               "the profile resolves `$ref` as an in-document JSON pointer only, so anchors are excluded",
	"$vocabulary":           "one pinned dialect, with no vocabulary negotiation",
	"contentEncoding":       "content keywords are annotations by default, so an asserted-looking one may validate nothing",
	"contentMediaType":      "content keywords are annotations by default, so an asserted-looking one may validate nothing",
	"contentSchema":         "content keywords are annotations by default, so an asserted-looking one may validate nothing",
}

const dialect2020 = "https://json-schema.org/draft/2020-12/schema"

// compileJSONSchema runs the profile pre-pass and then compiles. The order is
// the point: the library never sees a document the profile has not cleared.
func compileJSONSchema(raw []byte) (*jsonschema.Schema, error) {
	if len(raw) > MaxJSONSchemaBytes {
		return nil, declErr("`json_schema` exceeds %d bytes", MaxJSONSchemaBytes)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, declErr("`json_schema`: parse: %v", err)
	}
	if err := checkProfile(doc); err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	if err := c.AddResource(schemaResourceURL, doc); err != nil {
		return nil, declErr("`json_schema`: %v", err)
	}
	sch, err := c.Compile(schemaResourceURL)
	if err != nil {
		return nil, declErr("`json_schema`: compile: %v", err)
	}
	return sch, nil
}

// profileWalk carries the state the three declaration bounds and the cycle
// check need. Nodes are keyed by RFC 6901 JSON pointer, which is also the only
// reference form the profile admits, so the reference graph and the
// containment graph share one vocabulary.
type profileWalk struct {
	nodes map[string]bool
	edges map[string][]string
	count int
}

func checkProfile(doc any) error {
	w := &profileWalk{nodes: map[string]bool{}, edges: map[string][]string{}}
	if err := w.schema(doc, "", 1); err != nil {
		return err
	}
	// References are resolved after the walk because a reference may point
	// forward: `$ref: #/$defs/x` above the `$defs` that declares it is legal.
	for from, targets := range w.edges {
		for _, to := range targets {
			if !w.nodes[to] {
				return declErr("`json_schema`: `$ref` at %q does not resolve to a subschema in this document", pointerName(from))
			}
		}
	}
	if err := w.checkAcyclic(); err != nil {
		return err
	}
	return w.checkWorkBudget()
}

// checkWorkBudget is the declaration-time STEP CAP.
//
// The DECLARED subschema count is NOT a bound on evaluation work, and assuming
// it was is a real hole: `$ref` reuse expands. `allOf: [$ref X, $ref X]`
// evaluates X twice, and nesting that pattern doubles per level, so a document
// with a few dozen declared subschemas can drive millions of evaluations while
// every structural bound reports it as small. The graph is acyclic (checked
// above), so the expansion is finite — but finite is not bounded.
//
// The true static bound is the number of EVALUATION PATHS: how many times a
// subschema is entered when the root is applied once, counting each `$ref`
// traversal separately. Memoized DP over the reference graph already built
// here computes it in one pass, and the cut-off stops the arithmetic long
// before it could overflow.
//
// With every superlinear keyword excluded from the profile (see the audit
// above), each entered subschema costs at most linear time in the instance, so
// expandedPaths × MaxValidatedInstanceBytes is a sound upper bound on
// evaluation steps — which is what makes the runtime budget a backstop rather
// than the only control.
func (w *profileWalk) checkWorkBudget() error {
	limit := MaxEvaluationWork / MaxValidatedInstanceBytes
	if paths := w.expandedPaths(limit); paths > limit {
		return declErr("`json_schema`: `$ref` reuse expands to more than %d evaluation paths, which exceeds the %d-step evaluation work budget at %d validated instance bytes",
			limit, MaxEvaluationWork, MaxValidatedInstanceBytes)
	}
	return nil
}

// expandedPaths counts evaluation paths from the document root, memoized per
// node and saturating at limit+1 so a doubling chain cannot make the counter
// itself the expensive part. Cycle-free by construction, so a node is never
// re-entered while its own count is still being computed.
func (w *profileWalk) expandedPaths(limit int) int {
	memo := make(map[string]int, len(w.nodes))
	var count func(node string) int
	count = func(node string) int {
		if n, ok := memo[node]; ok {
			return n
		}
		total := 1 // the node itself is entered once
		for _, child := range w.edges[node] {
			total += count(child)
			if total > limit {
				total = limit + 1
				break
			}
		}
		memo[node] = total
		return total
	}
	return count("")
}

// schema walks one subschema node, enforcing the depth and subschema bounds,
// the keyword allowlist, and the reference form.
func (w *profileWalk) schema(node any, ptr string, depth int) error {
	if depth > MaxJSONSchemaDepth {
		return declErr("`json_schema`: nesting depth exceeds %d", MaxJSONSchemaDepth)
	}
	w.count++
	// The STRUCTURAL node bound. It is not the work bound — see expandedPaths —
	// but it is what keeps the reference graph small enough for the work bound
	// to be computed over it at all.
	if w.count > MaxJSONSchemaSubschemas {
		return declErr("`json_schema`: subschema count %d exceeds the %d the %d-step evaluation work budget allows at %d validated instance bytes",
			w.count, MaxJSONSchemaSubschemas, MaxEvaluationWork, MaxValidatedInstanceBytes)
	}
	w.nodes[ptr] = true

	obj, ok := node.(map[string]any)
	if !ok {
		if _, isBool := node.(bool); isBool {
			return nil // `true` / `false` are legal schemas and hold nothing
		}
		return declErr("`json_schema`: the value at %q must be a JSON object or boolean schema", pointerName(ptr))
	}

	// Sorted so a document with several violations always names the same one:
	// a refusal that changes between runs is a refusal nobody can test.
	names := make([]string, 0, len(obj))
	for name := range obj {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		value := obj[name]
		if reason, excluded := excludedKeywords[name]; excluded {
			return declErr("`json_schema`: keyword %q is excluded from the supported profile — %s", name, reason)
		}
		kind, allowed := allowedKeywords[name]
		if !allowed {
			return declErr("`json_schema`: keyword %q is not in the supported profile (the profile is an allowlist, so an unknown keyword is refused rather than ignored)", name)
		}
		child := ptr + "/" + escapePointer(name)
		switch kind {
		case kindData:
			if err := w.dataKeyword(ptr, name, value); err != nil {
				return err
			}
		case kindSchema:
			w.edges[ptr] = append(w.edges[ptr], child)
			if err := w.schema(value, child, depth+1); err != nil {
				return err
			}
		case kindSchemaArray:
			items, ok := value.([]any)
			if !ok {
				return declErr("`json_schema`: keyword %q must hold an array of schemas", name)
			}
			for i, item := range items {
				sub := child + "/" + strconv.Itoa(i)
				w.edges[ptr] = append(w.edges[ptr], sub)
				if err := w.schema(item, sub, depth+1); err != nil {
					return err
				}
			}
		case kindSchemaMap:
			members, ok := value.(map[string]any)
			if !ok {
				return declErr("`json_schema`: keyword %q must hold an object of schemas", name)
			}
			memberNames := make([]string, 0, len(members))
			for member := range members {
				memberNames = append(memberNames, member)
			}
			sort.Strings(memberNames)
			for _, member := range memberNames {
				sub := child + "/" + escapePointer(member)
				w.edges[ptr] = append(w.edges[ptr], sub)
				if err := w.schema(members[member], sub, depth+1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// dataKeyword handles the two data keywords whose VALUE the profile
// constrains: the dialect declaration and the reference form.
func (w *profileWalk) dataKeyword(ptr, name string, value any) error {
	switch name {
	case "$schema":
		declared, ok := value.(string)
		if !ok || declared != dialect2020 {
			return declErr("`json_schema`: `$schema` must be %q — one pinned dialect, no negotiation", dialect2020)
		}
	case "$ref":
		ref, ok := value.(string)
		if !ok {
			return declErr("`json_schema`: `$ref` must be a string")
		}
		// In-document only. A remote `$ref` makes the validator an SSRF
		// primitive and puts a third party in the publish path; a file `$ref`
		// reads the host's disk. Neither is a rule this product can own.
		if ref != "#" && !strings.HasPrefix(ref, "#/") {
			return declErr("`json_schema`: `$ref` %q must be an in-document JSON pointer (`#/…`) — remote and file references are excluded", ref)
		}
		w.edges[ptr] = append(w.edges[ptr], unescapeRefTarget(ref))
	}
	return nil
}

// checkAcyclic refuses reference cycles, even in-document. A recursive schema
// terminates on a finite instance, but its cost stops being statically
// boundable, which is exactly what the declaration bounds exist to establish.
// Containment edges cannot themselves cycle, so any cycle found here runs
// through at least one `$ref`.
func (w *profileWalk) checkAcyclic() error {
	const (
		white = 0
		grey  = 1
		black = 2
	)
	colour := map[string]int{}
	var visit func(node string) error
	visit = func(node string) error {
		switch colour[node] {
		case grey:
			return declErr("`json_schema`: reference cycle through %q — cycles are rejected at declaration", pointerName(node))
		case black:
			return nil
		}
		colour[node] = grey
		targets := append([]string(nil), w.edges[node]...)
		sort.Strings(targets)
		for _, target := range targets {
			if err := visit(target); err != nil {
				return err
			}
		}
		colour[node] = black
		return nil
	}
	nodes := make([]string, 0, len(w.nodes))
	for node := range w.nodes {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	for _, node := range nodes {
		if err := visit(node); err != nil {
			return err
		}
	}
	return nil
}

// escapePointer is RFC 6901 token escaping, so a property literally named
// `a/b` cannot forge a pointer into a different node.
func escapePointer(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

// unescapeRefTarget turns `#/a/b` into the walk's pointer form. `#` alone is
// the document root, whose pointer is the empty string.
func unescapeRefTarget(ref string) string {
	return strings.TrimPrefix(ref, "#")
}

// pointerName renders a node for a message: the document root reads as `#`
// rather than as an empty string.
func pointerName(ptr string) string {
	if ptr == "" {
		return "#"
	}
	return fmt.Sprintf("#%s", ptr)
}
