// Package schema is the key catalogue's declaration vocabulary and its
// value-validation engine (#49, schema-model ADR as amended by the flat-model
// ADR). It is a pure library: no store, no authorization, no clock — a
// declaration in, a verdict out — so #50's value saves and #51's publish
// pipeline consume exactly the rules this package's fixtures pin.
//
// Two authorities live here and nowhere else:
//
//   - Compile() is the DECLARATION authority. Saving a declaration blocks on
//     well-formedness: a value may be wrong, a rule may not be meaningless
//     (ADR § Validation timing). Every refusal names what it refused, because
//     a rule that appears to enforce something and does not is worse than no
//     rule at all.
//   - Compiled.Validate() is the VALUE authority: one declaration against one
//     string, with the ADR's fixed lexical semantics and its error-disclosure
//     rules. Everything Hikyo delivers is a string on the wire, so a type is a
//     parse-and-reject rule, never a storage format.
//
// The contract layer carries shape only (a type name is a string, a bound is a
// number); every rule below is enforced here, because an internal caller — a
// future import, a job, the isolation harness — never passes through request
// validation.
package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Classification is the key's `secret | config` classification (#7). It is an
// INPUT to validation because it decides what a failure may say: a `config`
// value is readable under ordinary environment read, a `secret` one is not,
// and the ADR's error-disclosure rule turns on exactly that.
type Classification string

const (
	Config Classification = "config"
	Secret Classification = "secret"
)

// Valid reports whether c is one of the two declared classifications. There is
// no third, and no default: a caller holding an unrecognised string has a bug,
// not a preference.
func (c Classification) Valid() bool { return c == Config || c == Secret }

// Type is one of the six primitives. `float`/`number`, `email`, `duration`,
// `ip`, `port` and `date` are deliberately absent — each is `string` + pattern
// or `integer` + range, and every type costs a validator, a UI affordance and
// a documentation entry (ADR § Declaration vocabulary).
type Type string

const (
	TypeString  Type = "string"
	TypeInteger Type = "integer"
	TypeBoolean Type = "boolean"
	TypeEnum    Type = "enum"
	TypeURL     Type = "url"
	TypeJSON    Type = "json"
)

// TypeExpression is the compact textual form used by the key catalogue's
// table output and by import presence reads. A declaration with one primitive
// is that primitive; a union preserves its canonical alternative order.
func TypeExpression(types []Type) string {
	if len(types) == 0 {
		return ""
	}
	if len(types) == 1 {
		return string(types[0])
	}
	parts := make([]string, 0, len(types))
	for _, typ := range types {
		parts = append(parts, string(typ))
	}
	return "any_of(" + strings.Join(parts, "|") + ")"
}

// Bounds. Declaration and validation are attacker-triggerable work (threat
// model § Availability), so every one of them is a named constant with a loud
// named refusal rather than a number buried in a comparison. The concrete
// values are this slice's, chosen for the ops spec's Pi-4 floor and recorded
// as disposition items — the ops spec owns them once it exists.
const (
	// MaxKeysPerProject bounds the catalogue itself. The positioning envelope
	// is ≤10k entries across an installation (#3); a single project holding a
	// thousand keys is already past the point where a matrix is readable.
	MaxKeysPerProject = 1000
	// MaxKeyGroupsPerProject bounds the coupling vocabulary. A group is a
	// co-publish unit, not a tag: hundreds of them means something else was
	// wanted.
	MaxKeyGroupsPerProject = 100
	// MaxKeyNameBytes is the ops-catalogue key-name bound (domain model
	// § Canonical key grammar). Bytes, not code points: the grammar is ASCII.
	MaxKeyNameBytes = 128
	// MaxDescriptionBytes bounds the free-text description, which may hold a
	// URL — there is no separate docs field.
	MaxDescriptionBytes = 4096
	// MaxEnumMembers, MaxPatternBytes, MaxAnyOfAlternatives are the ADR's
	// declaration-size bounds. `any_of` validation is linear in the number of
	// alternatives and every alternative's failure is enumerated, so the
	// alternative count bounds both the work and the error payload.
	MaxEnumMembers       = 256
	MaxEnumMemberBytes   = 512
	MaxPatternBytes      = 512
	MaxAnyOfAlternatives = 8
	// The JSON Schema declaration bounds. Bytes bound the document, depth
	// bounds nesting, and the subschema count bounds the applicator graph —
	// none of the three implies the others, so all three are enforced. Values
	// are the ops-spec § 8 "Schema & validation" bounds verbatim (≤ 64 KiB
	// declaration, `$ref` nesting ≤ 32) — the operations spec owns the
	// enumeration (schema-model ADR § profile).
	//
	MaxJSONSchemaBytes = 65536
	MaxJSONSchemaDepth = 32
	// MaxEvaluationWork is the ADR's STEP CAP, enforced where it is decidable:
	// at declaration. It IS a step cap and not merely a size bound, because the
	// profile admits no keyword that costs more than LINEAR time in the
	// instance per subschema — `uniqueItems` and `contains`, the two that do,
	// are excluded by name (internal/schema/jsonschema.go carries the per-
	// keyword audit). With every superlinear keyword out, worst-case evaluation
	// is bounded by subschemas × validated instance bytes: one product, checked
	// once, before anything can be evaluated against it.
	//
	// The product's first factor is the EXPANDED evaluation-path count, not the
	// declared subschema count: `$ref` reuse expands, so a document declaring a
	// few dozen subschemas can drive millions of evaluations. See
	// profileWalk.checkWorkBudget.
	//
	// MaxJSONSchemaSubschemas is DERIVED from this budget rather than invented
	// beside it: two independently chosen numbers is how a "bound" stops
	// bounding the thing it names. It bounds the graph STRUCTURALLY, which is
	// what makes the expansion computable over it.
	MaxValidatedInstanceBytes = MaxValueBytes
	MaxEvaluationWork         = 16 << 20
	MaxJSONSchemaSubschemas   = MaxEvaluationWork / MaxValidatedInstanceBytes
	// MaxValueBytes is the evaluation budget's instance-size half: the largest
	// value the engine will validate at all. Beyond it the verdict is a loud
	// budget failure, never "assume valid".
	MaxValueBytes = 65536
	// MaxVerdictErrors and MaxVerdictErrorBytes cap what one verdict may
	// report. Error multiplicity leaks structure for a secret key and is a
	// response-amplification lever for any key — but the leak is closed by the
	// disclosure rule (schema locations only, never instance paths, locked #12),
	// so the ops-spec § 8 values (≤ 100 errors / 64 KiB per verdict) govern the
	// count and size, and the byte cap bounds the amplification.
	MaxVerdictErrors     = 100
	MaxVerdictErrorBytes = 65536
	// EvaluationDeadline is the per-validation wall-clock budget. RE2 is
	// linear so the primitives cannot exceed it; it exists for the JSON Schema
	// leg, whose cost the profile bounds statically and this bounds
	// dynamically. Exceeding it fails the operation loud.
	EvaluationDeadline = 250 * time.Millisecond
	// MaxConcurrentJSONSchemaEvaluations bounds how many JSON Schema
	// evaluations may be in flight at once, ACROSS THE PROCESS.
	//
	// It exists because the wall-clock budget abandons the wait, not the work:
	// the library call is synchronous and cannot be cancelled, so an overrun
	// leaves a goroutine running that nothing is waiting for. Without a
	// ceiling, a caller who can trigger overruns can accumulate them, and the
	// deadline that was meant to bound the damage becomes the thing that
	// multiplies it. A slot is released when the EVALUATION finishes, never
	// when its waiter gives up, so abandoned work still counts against the
	// bound. Admission never queues at all: a full set of slots is an immediate
	// refusal, because a queue of waiters is the unbounded work this ceiling
	// exists to stop. Concrete value is this slice's; the ops spec owns it.
	MaxConcurrentJSONSchemaEvaluations = 8
)

// keyNameRe is the canonical key grammar, restated from the domain model:
// uppercase ASCII, digits and underscore, no leading digit. It is the
// environment-variable-safe grammar every delivery surface assumes — an
// `execve` environment block, a Kubernetes Secret data key, an adapter
// effective name — so it is a delivery constraint, not a style preference.
var keyNameRe = regexp.MustCompile(`\A[A-Z_][A-Z0-9_]*\z`)

// ErrInvalidDeclaration classifies every declaration-time refusal, so the
// service layer maps one sentinel rather than matching messages.
var ErrInvalidDeclaration = errors.New("invalid declaration")

func declErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidDeclaration, fmt.Sprintf(format, args...))
}

// CheckKeyName enforces the canonical grammar and the name bound. Names are
// unique among live keys per project — that half is the store's constraint,
// because uniqueness is a property of the set, not of the string.
func CheckKeyName(name string) error {
	switch {
	case name == "":
		return declErr("key name must not be empty")
	case len(name) > MaxKeyNameBytes:
		return declErr("key name exceeds %d bytes", MaxKeyNameBytes)
	case !keyNameRe.MatchString(name):
		return declErr("key name %q does not match the canonical grammar [A-Z_][A-Z0-9_]*", name)
	}
	return nil
}

// CheckGroupName bounds a key group's name. A group is a project-level label
// on a coupling, so it takes the free-text entity rules rather than the
// delivery grammar — nothing is ever delivered under a group name.
func CheckGroupName(name string) error {
	switch {
	case name == "":
		return declErr("key group name must not be empty")
	case len(name) > MaxKeyNameBytes:
		return declErr("key group name exceeds %d bytes", MaxKeyNameBytes)
	case strings.TrimSpace(name) != name:
		return declErr("key group name has leading or trailing whitespace")
	case !utf8.ValidString(name):
		return declErr("key group name is not valid UTF-8")
	case strings.ContainsRune(name, 0):
		return declErr("key group name contains a NUL byte")
	}
	return nil
}

// CheckDescription bounds the free-text description and refuses the two byte
// classes no Hikyo-held string may carry.
func CheckDescription(what, s string) error {
	switch {
	case len(s) > MaxDescriptionBytes:
		return declErr("%s exceeds %d bytes", what, MaxDescriptionBytes)
	case !utf8.ValidString(s):
		return declErr("%s is not valid UTF-8", what)
	case strings.ContainsRune(s, 0):
		return declErr("%s contains a NUL byte", what)
	}
	return nil
}

// Rule is one primitive type declaration with its constraints. Fields belong
// to exactly one type; a constraint set on the wrong type is a refusal, not an
// ignored field, because a silently ignored `pattern` on an integer key is the
// "appears to enforce something and does not" failure the ADR rejects
// everywhere.
type Rule struct {
	Type Type `json:"type"`

	// string
	MinLength  *int   `json:"min_length,omitempty"`
	MaxLength  *int   `json:"max_length,omitempty"`
	Pattern    string `json:"pattern,omitempty"`
	AllowEmpty bool   `json:"allow_empty,omitempty"`

	// integer
	Min *int64 `json:"min,omitempty"`
	Max *int64 `json:"max,omitempty"`

	// enum
	Members []string `json:"members,omitempty"`

	// url
	Schemes []string `json:"schemes,omitempty"`

	// json
	JSONSchema json.RawMessage `json:"json_schema,omitempty"`
}

// Declaration is a key's value-dependent rule set: exactly one primitive
// Rule, or an `any_of` union of at least two of them. Named `any_of` and never
// `oneOf`: JSON Schema — embedded verbatim for `json` keys — defines `oneOf`
// as exactly-one, and two meanings for one word inside one product is a trap
// for operators and implementers alike. Overlapping alternatives are fine and
// never an error.
type Declaration struct {
	Rule  *Rule  `json:"rule,omitempty"`
	AnyOf []Rule `json:"any_of,omitempty"`
}

// alternatives returns the rules to try, in declared order. A single rule is
// the one-alternative case, so the engine has one loop rather than two paths.
func (d Declaration) alternatives() []Rule {
	if d.Rule != nil {
		return []Rule{*d.Rule}
	}
	return d.AnyOf
}

// ParseDeclaration reads a stored declaration. Unknown fields are refused
// rather than dropped: a declaration written by a newer version and silently
// truncated by an older one would deliver a key under rules nobody declared.
func ParseDeclaration(raw []byte) (Declaration, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var d Declaration
	if err := dec.Decode(&d); err != nil {
		return Declaration{}, declErr("parse declaration: %v", err)
	}
	if dec.More() {
		return Declaration{}, declErr("parse declaration: trailing content after the document")
	}
	return d, nil
}

// Canonical renders the declaration's byte-stable storage form: normalized
// (members and schemes trimmed and lower-cased where the semantics are
// case-insensitive, the JSON Schema re-encoded from its parsed form) and
// deterministically ordered, because Go's encoder emits struct fields in
// declaration order and object keys sorted.
//
// Byte stability is load-bearing three times over: it is the schema export's
// requirement (ADR § Authority), it makes canonical-form deduplication of
// identical declarations a byte comparison, and it makes "did a
// value-dependent rule change?" — the reveal gate's input — a byte diff rather
// than a field-by-field walk that a new field could silently escape.
func Canonical(d Declaration) ([]byte, error) {
	n, err := normalize(d)
	if err != nil {
		return nil, err
	}
	return json.Marshal(n)
}

// normalize applies the write-time trim to every declared string and
// re-encodes the JSON Schema through the parser, so the canonical form is the
// form validation actually uses.
func normalize(d Declaration) (Declaration, error) {
	out := Declaration{}
	norm := func(r Rule) (Rule, error) {
		// CLONE before rewriting. A Rule copy shares its slices' backing
		// arrays, so trimming in place would rewrite the CALLER's declaration
		// as a side effect of asking for its canonical form — and Canonical is
		// called on declarations the caller still holds (the reveal gate's diff
		// runs on both sides before anything is written).
		r.Members = slices.Clone(r.Members)
		r.Schemes = slices.Clone(r.Schemes)
		for i, m := range r.Members {
			r.Members[i] = strings.TrimSpace(m)
		}
		for i, s := range r.Schemes {
			r.Schemes[i] = strings.ToLower(strings.TrimSpace(s))
		}
		if len(r.JSONSchema) > 0 {
			// The byte bound is checked before the parse, so an oversized
			// document is refused rather than parsed and then refused.
			if len(r.JSONSchema) > MaxJSONSchemaBytes {
				return Rule{}, declErr("`json_schema` exceeds %d bytes", MaxJSONSchemaBytes)
			}
			var doc any
			if err := strictJSON(r.JSONSchema, &doc); err != nil {
				return Rule{}, declErr("`json_schema`: parse: %v", err)
			}
			enc, err := json.Marshal(doc)
			if err != nil {
				return Rule{}, declErr("json_schema: re-encode: %v", err)
			}
			r.JSONSchema = enc
		}
		return r, nil
	}
	if d.Rule != nil {
		r, err := norm(*d.Rule)
		if err != nil {
			return Declaration{}, err
		}
		out.Rule = &r
	}
	for _, alt := range d.AnyOf {
		r, err := norm(alt)
		if err != nil {
			return Declaration{}, err
		}
		out.AnyOf = append(out.AnyOf, r)
	}
	return out, nil
}

// ValueDependentChange reports whether the move from `before` to `after`
// changes a rule that must be EVALUATED against an existing value — type,
// min/max, minLength/maxLength, pattern, enum members, url schemes,
// allow_empty, any_of alternatives, and the JSON Schema (ADR § Changing a
// value-dependent rule on a secret key is a disclosure).
//
// The whole Declaration is value-dependent by construction: metadata
// (description, deprecated, deprecation_note, folder path) and presence rules
// live outside it, on the key row. So the answer is a canonical-byte
// comparison — which is also why a new constraint field cannot escape the
// reveal gate by being forgotten in a field list.
//
// An unrenderable declaration is reported as a change: refusing to evaluate is
// the fail-closed direction for a gate.
func ValueDependentChange(before, after Declaration) bool {
	a, errA := Canonical(before)
	b, errB := Canonical(after)
	if errA != nil || errB != nil {
		return true
	}
	return string(a) != string(b)
}
