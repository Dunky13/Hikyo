package importer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Dunky13/hikyo/internal/schema"
)

// The rename rules (import-paths ADR § Renames), run against the canonical key
// grammar the schema package owns.
//
// The asymmetry is the whole design: a name that is ALREADY valid is preserved
// byte-for-byte, because a transform applied to an already-valid name is a
// silent rename; a name that is invalid goes through one documented transform;
// and anything that transform cannot resolve is a HARD STOP, not a guess.

// TransformKind records how a target name was reached, for the mapping
// template's `renames` entries.
type TransformKind string

const (
	// TransformAuto is the documented transform.
	TransformAuto TransformKind = "auto"
	// TransformManual is an explicit rename carried by the mapping template.
	TransformManual TransformKind = "manual"
)

// Rename is one source-name → target-name mapping, surfaced in output and
// recorded in the template. Nothing is renamed invisibly.
type Rename struct {
	From      string        `json:"from"`
	To        string        `json:"to"`
	Transform TransformKind `json:"transform"`
}

// TransformName maps a source name onto the canonical grammar.
//
// The documented transform, in full, and it covers the common classes only:
//
//   - lowercase ASCII letters uppercase (`a`-`z` → `A`-`Z`);
//   - `-`, `.`, `/` and `\` become `_`;
//   - a leading digit takes one leading `_`, because the grammar forbids one.
//
// Everything else — a space, `=`, `:`, any non-ASCII rune — is outside the
// mapping and is a hard stop requiring an explicit rename in the mapping
// template. There is no suffixing, no stripping and no transliteration: the
// invisible rename is exactly the mis-route the review gate exists to catch.
//
// The returned bool reports whether the name was already valid, so the caller
// can tell a byte-preserved name from a transformed one without comparing
// strings (they can be equal for an all-uppercase name that merely needed no
// work, and the distinction matters to the template).
func TransformName(source string) (target string, wasValid bool, err error) {
	if schema.CheckKeyName(source) == nil {
		return source, true, nil
	}
	if source == "" {
		return "", false, failure("import", CodeUnmappableName, "",
			"a source name is empty; the canonical grammar has no empty name")
	}
	if len(source) > schema.MaxKeyNameBytes {
		return "", false, failure("import", CodeBound, quoteName(source),
			"source name exceeds the %d-byte key-name bound", schema.MaxKeyNameBytes)
	}
	var b strings.Builder
	b.Grow(len(source) + 1)
	for i := 0; i < len(source); i++ {
		c := source[i]
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteByte(c - 'a' + 'A')
		case c >= 'A' && c <= 'Z', c == '_':
			b.WriteByte(c)
		case c >= '0' && c <= '9':
			if i == 0 {
				// A leading digit cannot open a name. One underscore is the
				// documented resolution; it is deterministic and it is visible
				// in the surfaced rename.
				b.WriteByte('_')
			}
			b.WriteByte(c)
		case c == '-', c == '.', c == '/', c == '\\':
			b.WriteByte('_')
		default:
			return "", false, failure("import", CodeUnmappableName, quoteName(source),
				"the documented transform does not cover byte %#02x; name it explicitly in the mapping template's `renames`", c)
		}
	}
	target = b.String()
	if err := schema.CheckKeyName(target); err != nil {
		// Unreachable for every byte the loop admits; kept because a silent
		// disagreement between this transform and the grammar it targets is
		// exactly the class of bug that ships an invalid declaration.
		return "", false, failure("import", CodeUnmappableName, quoteName(source),
			"the documented transform produced a name the canonical grammar refuses; name it explicitly in the mapping template's `renames`")
	}
	return target, false, nil
}

// MaxShownNameBytes caps how much of a foreign name any message renders. A key
// name is bounded by the grammar once it is a TARGET name, but a SOURCE name is
// foreign bytes and a megabyte of them in a refusal is its own denial of
// service — of the operator's terminal, and of the log that keeps it.
const MaxShownNameBytes = 128

// quoteName renders a foreign name for an error message or a rename table.
//
// This is the ONLY way foreign text is ever rendered by this package. Go quoting
// escapes control bytes, DEL and non-ASCII, so a hostile key name cannot smuggle
// terminal escape sequences into an operator's stderr — the class of attack where
// a source key is literally named "\x1b[2J\x1b]0;pwned\x07". The length cap runs
// after quoting so the budget is on what is PRINTED, not on what was parsed.
//
// Values never reach here. Names do, because the ADR requires errors to name
// keys; that requirement is what makes escaping load-bearing rather than tidy.
func quoteName(s string) string {
	quoted := fmt.Sprintf("%q", s)
	if len(quoted) <= MaxShownNameBytes {
		return quoted
	}
	return quoted[:MaxShownNameBytes] + `..."`
}

// QuoteName exposes the package's one safe foreign-name renderer to the CLI,
// which owns success output while connectors own refusals.
func QuoteName(s string) string { return quoteName(s) }

// NearMiss is one advisory: an imported name within a small edit distance of a
// key the project already declares (schema-model ADR § "Near-miss advisory").
// Non-blocking by that ADR's own words — it closes the residual case where the
// typo happens at declaration rather than at value write.
type NearMiss struct {
	Imported string `json:"imported"`
	Declared string `json:"declared"`
}

// nearMissDistance is the "small edit distance" the schema ADR leaves to the
// implementation. One edit: a transposition, a dropped letter, a doubled
// letter — the accident classes. Two would fire on genuinely distinct short
// names (`DB_HOST` vs `DB_PORT` is distance 2) and an advisory that cries wolf
// is one people learn to ignore.
const nearMissDistance = 1

// NearMisses reports every imported name within nearMissDistance of a declared
// name it is not equal to. Deterministic order: imported name, then declared.
func NearMisses(imported, declared []string) []NearMiss {
	declaredSet := make(map[string]bool, len(declared))
	for _, d := range declared {
		declaredSet[d] = true
	}
	var out []NearMiss
	for _, imp := range imported {
		if declaredSet[imp] {
			continue
		}
		for _, dec := range declared {
			if editDistanceWithin(imp, dec, nearMissDistance) {
				out = append(out, NearMiss{Imported: imp, Declared: dec})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Imported != out[j].Imported {
			return out[i].Imported < out[j].Imported
		}
		return out[i].Declared < out[j].Declared
	})
	return out
}

// editDistanceWithin answers "is the Levenshtein distance between a and b at
// most max?" without computing the full distance. The length gate rejects most
// pairs in constant time, which matters because this runs over
// imported × declared and a project may declare a thousand keys.
func editDistanceWithin(a, b string, max int) bool {
	if a == b {
		return true
	}
	if abs(len(a)-len(b)) > max {
		return false
	}
	// Full DP over bytes. Both operands are canonical key names (ASCII by the
	// grammar) by the time this runs, so bytes are runes.
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		best := cur[0]
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			best = min(best, cur[j])
		}
		if best > max {
			return false
		}
		prev, cur = cur, prev
	}
	return prev[len(b)] <= max
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// recordPath renders a record's structural location for an error. Folder
// segments and the source name are quoted, so hostile bytes cannot escape.
func recordPath(r Record) string {
	if len(r.Folder) == 0 {
		return quoteName(r.SourceName)
	}
	parts := make([]string, 0, len(r.Folder)+1)
	for _, seg := range r.Folder {
		parts = append(parts, seg)
	}
	parts = append(parts, r.SourceName)
	return quoteName(strings.Join(parts, "/"))
}

// checkUTF8 is the uniform value rule: valid UTF-8, no NUL. It returns an error
// rather than a bool only so callers read as checks; the CALLER collects the
// offenders, because the refusal names every one of them at once.
func checkUTF8(value string) error {
	if !utf8.ValidString(value) {
		return errNotUTF8
	}
	if strings.ContainsRune(value, 0) {
		return errNotUTF8
	}
	return nil
}

var errNotUTF8 = &Error{Source: "import", Code: CodeBinaryValue, Detail: "the value is not UTF-8 text"}

// canonicalJSON is THE deterministic conversion for non-scalar leaves
// (import-paths ADR § Per-source structural mapping: "one canonical
// serialization, fixture-pinned at implementation"). One function, used by
// every connector, so a SOPS array and an Infisical object serialize
// identically:
//
//   - object members are ordered by key (encoding/json sorts map keys);
//   - HTML escaping is OFF, so `<`, `>` and `&` survive as themselves;
//   - no indentation, no trailing newline.
//
// A non-string map key (YAML admits integer and boolean keys) is refused by
// name rather than coerced: a coercion is a silent rename of the key one level
// down, which is the thing this ADR refuses everywhere else.
func canonicalJSON(b *Budget, where string, v any) (string, error) {
	normalized, err := normalizeTree(b, where, v, 0)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(normalized); err != nil {
		// The tree came from a parsed document and holds only JSON-expressible
		// values by construction; a failure here is a bug, and the error is
		// dropped rather than wrapped because encoding/json echoes content.
		return "", failure(b.source, CodeMalformed, where,
			"the leaf cannot be serialized as JSON")
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// normalizeTree rewrites a decoded document into JSON-expressible shapes,
// refusing what cannot be expressed rather than coercing it.
func normalizeTree(b *Budget, where string, v any, depth int) (any, error) {
	if err := b.Depth(where, depth); err != nil {
		return nil, err
	}
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			normalized, err := normalizeTree(b, where, child, depth+1)
			if err != nil {
				return nil, err
			}
			out[k] = normalized
		}
		return out, nil
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			name, ok := k.(string)
			if !ok {
				return nil, failure(b.source, CodeMalformed, where,
					"a nested map uses a non-string key; only string keys can be serialized deterministically")
			}
			normalized, err := normalizeTree(b, where, child, depth+1)
			if err != nil {
				return nil, err
			}
			out[name] = normalized
		}
		return out, nil
	case []any:
		out := make([]any, 0, len(t))
		for _, child := range t {
			normalized, err := normalizeTree(b, where, child, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, normalized)
		}
		return out, nil
	default:
		return v, nil
	}
}
