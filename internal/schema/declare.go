package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Compile is the declaration authority. It performs every declaration-time
// check the ADR fixes and returns the artifact the value engine runs against —
// so "was this declaration well-formed?" and "what do I validate with?" cannot
// drift apart, because they are the same call.
//
// Compilation is per schema revision, not per validation: patterns and JSON
// Schemas are compiled once here and reused by every Validate (ADR § Bounds:
// "compiled once per schema revision and cached, never recompiled per
// validation, so a fetch storm cannot be amplified into CPU").
func Compile(d Declaration) (*Compiled, error) {
	switch {
	case (d.Rule == nil) == (len(d.AnyOf) == 0):
		return nil, declErr("a declaration carries exactly one of `rule` or `any_of`")
	case d.Rule == nil && len(d.AnyOf) < 2:
		return nil, declErr("an `any_of` union carries at least two alternatives")
	case len(d.AnyOf) > MaxAnyOfAlternatives:
		return nil, declErr("an `any_of` union carries at most %d alternatives", MaxAnyOfAlternatives)
	}
	norm, err := normalize(d)
	if err != nil {
		return nil, err
	}
	c := &Compiled{decl: norm}
	for i, r := range norm.alternatives() {
		cr, err := compileRule(r)
		if err != nil {
			if norm.Rule == nil {
				return nil, fmt.Errorf("%w (alternative %d)", err, i)
			}
			return nil, err
		}
		c.alts = append(c.alts, cr)
	}
	return c, nil
}

// Compiled is one key's ready-to-run rule set. It is immutable and safe for
// concurrent use: compiled regexps and compiled JSON Schemas are, and the
// engine writes nothing back.
type Compiled struct {
	decl Declaration
	alts []compiledRule
}

// Declaration returns the normalized declaration this artifact was built from
// — the canonical form, so a caller storing it stores what validation used.
func (c *Compiled) Declaration() Declaration { return c.decl }

type compiledRule struct {
	rule    Rule
	pattern *regexp.Regexp
	schema  *jsonschema.Schema
}

// compileRule enforces the per-type constraint grammar. Every branch refuses
// rather than ignores: a constraint declared on a type that does not have it
// is the "appears to enforce something and does not" failure mode, and it is
// the reason this is a switch over the declared type rather than a set of
// independent field checks.
func compileRule(r Rule) (compiledRule, error) {
	out := compiledRule{rule: r}

	// Cross-type refusals first, so `pattern` on an integer is answered as
	// "pattern belongs to string" rather than as a silently unused field.
	if r.Type == "any_of" {
		return out, declErr("an `any_of` alternative may not itself be an `any_of` (no nesting)")
	}
	if r.Type != TypeString {
		switch {
		case r.Pattern != "":
			return out, declErr("`pattern` is declared on a `string`, not on %q", r.Type)
		case r.MinLength != nil:
			return out, declErr("`min_length` is declared on a `string`, not on %q", r.Type)
		case r.MaxLength != nil:
			return out, declErr("`max_length` is declared on a `string`, not on %q", r.Type)
		case r.AllowEmpty:
			return out, declErr("`allow_empty` is declared on a `string`, not on %q", r.Type)
		}
	}
	if r.Type != TypeInteger && (r.Min != nil || r.Max != nil) {
		return out, declErr("`min`/`max` are declared on an `integer`, not on %q", r.Type)
	}
	if r.Type != TypeEnum && len(r.Members) > 0 {
		return out, declErr("`members` are declared on an `enum`, not on %q", r.Type)
	}
	if r.Type != TypeURL && len(r.Schemes) > 0 {
		return out, declErr("`schemes` are declared on a `url`, not on %q", r.Type)
	}
	if r.Type != TypeJSON && len(r.JSONSchema) > 0 {
		return out, declErr("`json_schema` is declared on a `json` key, not on %q", r.Type)
	}

	switch r.Type {
	case TypeString:
		if r.MinLength != nil && *r.MinLength < 0 {
			return out, declErr("`min_length` must not be negative")
		}
		if r.MaxLength != nil && *r.MaxLength < 0 {
			return out, declErr("`max_length` must not be negative")
		}
		if r.MinLength != nil && r.MaxLength != nil && *r.MinLength > *r.MaxLength {
			return out, declErr("`min_length` %d exceeds `max_length` %d", *r.MinLength, *r.MaxLength)
		}
		if r.Pattern != "" {
			re, err := compilePattern(r.Pattern)
			if err != nil {
				return out, err
			}
			out.pattern = re
		}
	case TypeInteger:
		if r.Min != nil && r.Max != nil && *r.Min > *r.Max {
			return out, declErr("`min` %d exceeds `max` %d", *r.Min, *r.Max)
		}
	case TypeBoolean:
		// Canonical `true`/`false` only; there is nothing to declare.
	case TypeEnum:
		if err := checkEnumMembers(r.Members); err != nil {
			return out, err
		}
	case TypeURL:
		if err := checkSchemes(r.Schemes); err != nil {
			return out, err
		}
	case TypeJSON:
		if len(r.JSONSchema) > 0 {
			sch, err := compileJSONSchema(r.JSONSchema)
			if err != nil {
				return out, err
			}
			out.schema = sch
		}
	default:
		return out, declErr("type %q is not one of the six primitives (string, integer, boolean, enum, url, json)", r.Type)
	}
	return out, nil
}

// compilePattern applies the ADR's anchoring rule: a declared pattern is
// implicitly `\A(?:…)\z` and is never a substring search. An unanchored regex
// that appears to constrain a value while matching a fragment of it is the
// classic validation bypass, and making anchoring the default removes the
// entire class — so the anchors are added here, once, rather than being a rule
// each caller must remember.
//
// RE2 has no backreferences and no lookaround; Go's compiler refuses both, and
// that refusal is surfaced verbatim rather than swallowed. A pattern that
// appears to enforce something and does not is worse than no pattern at all.
func compilePattern(p string) (*regexp.Regexp, error) {
	if len(p) > MaxPatternBytes {
		return nil, declErr("`pattern` exceeds %d bytes", MaxPatternBytes)
	}
	re, err := regexp.Compile(`\A(?:` + p + `)\z`)
	if err != nil {
		return nil, declErr("`pattern` is not a valid RE2 expression (RE2 has no backreferences and no lookaround): %v", err)
	}
	return re, nil
}

// checkEnumMembers: members are non-empty and distinct AFTER the write-time
// trim, because that trim is what a value will have had applied to it by the
// time it is compared. A member of "" is refused because zero-length values
// are governed solely by `string`'s `allow_empty`, and a second path to legal
// emptiness would contradict it.
func checkEnumMembers(members []string) error {
	switch {
	case len(members) == 0:
		return declErr("an `enum` declares at least one member in `members`")
	case len(members) > MaxEnumMembers:
		return declErr("an `enum` declares at most %d `members`", MaxEnumMembers)
	}
	seen := make(map[string]bool, len(members))
	for _, m := range members {
		switch {
		case m == "":
			return declErr("an `enum` member must not be empty after the write-time trim")
		case len(m) > MaxEnumMemberBytes:
			return declErr("an `enum` member exceeds %d bytes", MaxEnumMemberBytes)
		case !utf8.ValidString(m):
			return declErr("an `enum` member is not valid UTF-8")
		case strings.ContainsRune(m, 0):
			return declErr("an `enum` member contains a NUL byte")
		case seen[m]:
			return declErr("`enum` members must be distinct after the write-time trim (%q repeats)", m)
		}
		seen[m] = true
	}
	return nil
}

// schemeRe is RFC 3986's scheme production, which is also what `url.Parse`
// will accept — declaring a scheme it could never produce would be a rule that
// matches nothing.
var schemeRe = regexp.MustCompile(`\A[a-z][a-z0-9+.-]*\z`)

func checkSchemes(schemes []string) error {
	if len(schemes) == 0 {
		return declErr("a `url` declares at least one allowed scheme in `schemes`")
	}
	seen := make(map[string]bool, len(schemes))
	for _, s := range schemes {
		if !schemeRe.MatchString(s) {
			return declErr("`schemes` entry %q is not a valid URL scheme", s)
		}
		if seen[s] {
			return declErr("`schemes` entries must be distinct (%q repeats)", s)
		}
		seen[s] = true
	}
	return nil
}

// errDuplicateKey is the one JSON parse failure the engine reports under its
// own name, because the ADR fixes duplicate object keys as a REJECTION rather
// than last-wins — and an operator whose config was silently halved deserves
// to be told which rule caught it.
var errDuplicateKey = errors.New("duplicate object key")

// strictJSON parses exactly one JSON document, rejecting trailing content and
// duplicate object keys anywhere in it. Numbers are kept as json.Number so a
// re-encode is lossless: the ADR requires numeric values to be validated as
// JSON numbers but delivered as the original bytes.
func strictJSON(raw []byte, out *any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing content after the JSON document")
	}
	return checkNoDuplicateKeys(raw)
}

// checkNoDuplicateKeys walks the token stream keeping one seen-set per open
// object. encoding/json itself is last-wins, so this is the only place the
// rejection can happen.
func checkNoDuplicateKeys(raw []byte) error {
	type frame struct {
		object    bool
		seen      map[string]bool
		expectKey bool
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var stack []*frame
	top := func() *frame {
		if len(stack) == 0 {
			return nil
		}
		return stack[len(stack)-1]
	}
	// fillSlot records that a VALUE was just consumed, so an enclosing object
	// expects a key next.
	fillSlot := func() {
		if f := top(); f != nil && f.object {
			f.expectKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				fillSlot()
				stack = append(stack, &frame{object: true, seen: map[string]bool{}, expectKey: true})
			case '[':
				fillSlot()
				stack = append(stack, &frame{})
			default: // '}' or ']'
				stack = stack[:len(stack)-1]
			}
			continue
		}
		f := top()
		if f != nil && f.object && f.expectKey {
			name, ok := tok.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if f.seen[name] {
				return fmt.Errorf("%w %q", errDuplicateKey, name)
			}
			f.seen[name] = true
			f.expectKey = false
			continue
		}
		fillSlot()
	}
}
