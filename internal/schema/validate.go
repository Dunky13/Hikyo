package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The value-validation engine. One declaration, one string, one verdict.
//
// Everything Wenv delivers is a string on the wire, so a type is a
// parse-and-reject rule plus a UI affordance, never a storage format — which
// is why this file parses and refuses, and never rewrites a value beyond the
// one trim the ADR mandates.

// Failure is one rule violation. It carries the SCHEMA LOCATION that failed
// and never an instance-derived pointer, because for a `secret`-classified key
// the instance is the thing being protected: a JSON value of
// `{"AKIA…credential…":"x"}` failing `additionalProperties:false` would, under
// a naive implementation, put the plaintext in the error message, the log and
// the audit record.
//
// InstancePath is populated ONLY for a `config`-classified key, which is
// readable under ordinary environment read anyway. It is not "redacted
// afterwards": for a secret key the instance-derived text never enters the
// Failure at all, so there is no path by which a later refactor could leak it.
type Failure struct {
	// Alternative indexes the failing `any_of` alternative, or -1 for a
	// single-rule declaration. A total `any_of` failure enumerates every
	// alternative's own failure — a bare "matched none of 2 alternatives" is
	// useless to an operator.
	Alternative int `json:"alternative"`
	// Keyword is the schema location that failed: the declared constraint's
	// name, or `json_schema` with the failing keyword path.
	Keyword string `json:"keyword"`
	// Message is schema-derived prose, safe to show for any classification.
	Message string `json:"message"`
	// InstancePath is the JSON pointer into the value; `config` keys only.
	InstancePath string `json:"instance_path,omitempty"`
}

// Verdict is the engine's answer.
//
// It carries NO VALUE and no fragment of one, by construction. A verdict is
// the thing that gets stored on a draft, rendered in a matrix cell, logged and
// audited; a plaintext field on it would put a `secret` value in every one of
// those places, and no amount of care at each call site is a substitute for the
// value not being there. The write-time normalization the caller needs is
// Normalize, which the WRITE path calls and the reporting path never does.
type Verdict struct {
	Valid bool `json:"valid"`
	// Errors is empty exactly when Valid.
	Errors []Failure `json:"errors,omitempty"`
}

// Normalize is the write-time trim, and the only place it lives: leading and
// trailing whitespace is removed on every write path, for every type, using
// Unicode whitespace semantics. It runs BEFORE validation, so a whitespace-only
// value becomes empty and is then refused by `allow_empty` rather than stored.
//
// It is separate from Validate because its RESULT is plaintext: the write path
// needs the normalized bytes, and nothing else does.
func Normalize(value string) string { return strings.TrimSpace(value) }

// integerRe is the ADR's integer grammar: no leading `+`, no underscores, no
// hex, no exponent. Leading zeros are accepted and preserved verbatim on
// delivery — the value is a string, so `01` is not normalized to `1`.
var integerRe = regexp.MustCompile(`\A-?[0-9]+\z`)

// Validate runs the declaration against one value.
//
// The classification is an input because it decides what a failure may say,
// not whether the value is valid: the same value gets the same verdict either
// way, and only the reporting narrows.
func (c *Compiled) Validate(value string, cls Classification) Verdict {
	trimmed := Normalize(value)
	var v Verdict

	// Budget and lexical checks are declaration-independent: they hold for
	// every type, so they run once rather than inside each alternative.
	switch {
	case len(trimmed) > MaxValueBytes:
		return v.fail(Failure{Alternative: -1, Keyword: "budget.value_bytes",
			Message: fmt.Sprintf("value exceeds the %d-byte validation budget", MaxValueBytes)})
	case !utf8.ValidString(trimmed):
		return v.fail(Failure{Alternative: -1, Keyword: "lexical.utf8",
			Message: "value is not valid UTF-8"})
	case strings.ContainsRune(trimmed, 0):
		// NUL is not a fussy restriction: the Compose delivery path is an
		// execve environment block, which cannot carry one, so a value Wenv
		// called valid would be undeliverable.
		return v.fail(Failure{Alternative: -1, Keyword: "lexical.nul",
			Message: "value contains a NUL byte"})
	}

	single := c.decl.Rule != nil
	var all []Failure
	for i, alt := range c.alts {
		index := i
		if single {
			index = -1
		}
		failures := alt.validate(trimmed, cls, index)
		if len(failures) == 0 {
			// At least one alternative accepts, so the value is valid.
			// Overlapping alternatives are explicitly fine and never an error;
			// there is no XOR semantic anywhere in Wenv's own vocabulary.
			return Verdict{Valid: true}
		}
		all = append(all, failures...)
	}
	v.Errors = capFailures(all)
	return v
}

func (v Verdict) fail(f Failure) Verdict {
	v.Errors = []Failure{f}
	return v
}

// evaluationDeadline is EvaluationDeadline behind a variable so the internal
// test can drive the abandon path deterministically instead of racing a sleep.
var evaluationDeadline = EvaluationDeadline

// evaluationSlots is the process-wide concurrency bound. Its capacity is the
// number of evaluations that may be in flight, and a slot returns only when
// the evaluation itself finishes — see MaxConcurrentJSONSchemaEvaluations.
var evaluationSlots = make(chan struct{}, MaxConcurrentJSONSchemaEvaluations)

// evalOutcome is how an evaluation ended, which is three things and not two:
// it finished, it overran the deadline, or it was never admitted.
type evalOutcome int

const (
	evalCompleted evalOutcome = iota
	evalOverran
	evalRefused
)

// runWithDeadline admits one evaluation against the concurrency bound, runs it,
// and ABANDONS THE WAIT if it overruns.
//
// Three properties, each load-bearing:
//
//   - Admission NEVER QUEUES AT ALL: a free slot is taken, a full set is an
//     immediate loud refusal. Waiting for a slot — even bounded by the
//     deadline — is itself a queue, and a queue of waiters is unbounded work
//     the concurrency ceiling was supposed to stop.
//   - The slot is released by the GOROUTINE, on completion. Releasing it when
//     the waiter gives up would let abandoned work escape the bound entirely,
//     which is the one thing the bound exists to prevent.
//   - The result channel is buffered, so an abandoned goroutine always
//     completes its send and exits rather than blocking forever.
func runWithDeadline(run func() error, d time.Duration) (error, evalOutcome) {
	// Try-acquire, and nothing else: the clock is never consulted here. A
	// caller that waits for a slot IS the queue this bound exists to prevent,
	// and it makes admission race the timer besides.
	select {
	case evaluationSlots <- struct{}{}:
	default:
		return nil, evalRefused
	}

	done := make(chan error, 1)
	go func() {
		defer func() { <-evaluationSlots }()
		done <- run()
	}()

	timer := time.NewTimer(d)
	defer timer.Stop()
	// A budget that has already elapsed is an overrun, decided before the
	// wait rather than raced against it: `select` picks at random among ready
	// cases, so without this a zero deadline would sometimes report success.
	select {
	case <-timer.C:
		return nil, evalOverran
	default:
	}
	select {
	case err := <-done:
		return err, evalCompleted
	case <-timer.C:
		return nil, evalOverran
	}
}

// capFailures collapses repeats and enforces the count and byte caps. Error
// multiplicity leaks structure and length for a secret key the same way a
// value does, and it is a response-amplification lever for any key.
//
// An invalid verdict ALWAYS keeps at least one failure, truncating its message
// to fit rather than dropping it: "Errors is empty exactly when Valid" is this
// package's own contract, and a caps rule that could produce an invalid verdict
// with nothing in it would make every consumer's `len(Errors) == 0` check a
// silent accept.
// The cap is on the ENCODED WHOLE VERDICT, not on the raw string lengths and
// not on the failure list alone: JSON escaping turns one control character into
// six bytes and one non-ASCII rune into as many as twelve, and the envelope's
// own field names, braces and commas are real response bytes too. Anything less
// than the complete document budgets a number no consumer ever sends.
func capFailures(in []Failure) []Failure {
	seen := make(map[Failure]bool, len(in))
	out := make([]Failure, 0, len(in))
	for _, f := range in {
		if seen[f] {
			continue
		}
		seen[f] = true
		if len(out) >= MaxVerdictErrors {
			break
		}
		if encodedSize(append(out, f)) > MaxVerdictErrorBytes {
			break
		}
		out = append(out, f)
	}
	if len(out) == 0 && len(in) > 0 {
		out = append(out, truncateFailure(in[0]))
	}
	return out
}

// encodedSize measures what the wire actually carries: the COMPLETE verdict,
// envelope included. Encoding at this size (at most MaxVerdictErrors small
// structs) costs nothing worth optimising, and it is the only measurement that
// cannot drift from the encoder.
func encodedSize(failures []Failure) int {
	encoded, err := json.Marshal(Verdict{Errors: failures})
	if err != nil {
		// Unreachable: every field is a string or an int. Reported as
		// over-budget so the caps fail CLOSED rather than open.
		return MaxVerdictErrorBytes + 1
	}
	return len(encoded)
}

// truncateFailure fits one failure inside the encoded byte cap. The KEYWORD is
// kept whole — it is the schema location, the part an operator acts on — and
// the message is shrunk until the encoding fits. Shrinking is a loop rather
// than a subtraction because escaping expansion is not a constant.
func truncateFailure(f Failure) Failure {
	f.InstancePath = ""
	for encodedSize([]Failure{f}) > MaxVerdictErrorBytes {
		switch {
		case len(f.Message) > 0:
			f.Message = trimRunes(f.Message, (len(f.Message)+1)/2)
		case len(f.Keyword) > 0:
			f.Keyword = trimRunes(f.Keyword, (len(f.Keyword)+1)/2)
		default:
			return f // nothing left to shrink; the cap is smaller than an envelope
		}
	}
	return f
}

// trimRunes cuts a string to at most n bytes without splitting a rune — a half
// rune would be invalid UTF-8, which is the one thing every value in this
// package is guaranteed not to be.
func trimRunes(s string, n int) string {
	if n >= len(s) {
		n = len(s) - 1
	}
	for n > 0 && !utf8.ValidString(s[:n]) {
		n--
	}
	if n < 0 {
		n = 0
	}
	return s[:n]
}

// validate runs one alternative. It returns every failure that alternative
// produced, so an `any_of` can enumerate them per branch.
func (cr compiledRule) validate(value string, cls Classification, alt int) []Failure {
	fail := func(keyword, format string, args ...any) []Failure {
		return []Failure{{Alternative: alt, Keyword: keyword, Message: fmt.Sprintf(format, args...)}}
	}
	r := cr.rule
	switch r.Type {
	case TypeString:
		var out []Failure
		if value == "" {
			if !r.AllowEmpty {
				return fail("allow_empty", "value is empty and `allow_empty` is not declared")
			}
			// An empty value satisfies nothing else: length bounds and the
			// pattern below still apply, deliberately, so `allow_empty` with a
			// `min_length` is a contradiction the operator can see rather than
			// one this engine papers over.
		}
		length := utf8.RuneCountInString(value)
		if r.MinLength != nil && length < *r.MinLength {
			out = append(out, Failure{Alternative: alt, Keyword: "min_length",
				Message: fmt.Sprintf("value is shorter than the declared `min_length` of %d", *r.MinLength)})
		}
		if r.MaxLength != nil && length > *r.MaxLength {
			out = append(out, Failure{Alternative: alt, Keyword: "max_length",
				Message: fmt.Sprintf("value is longer than the declared `max_length` of %d", *r.MaxLength)})
		}
		if cr.pattern != nil && !cr.pattern.MatchString(value) {
			out = append(out, Failure{Alternative: alt, Keyword: "pattern",
				Message: "value does not match the declared `pattern` over its whole length"})
		}
		return out

	case TypeInteger:
		if !integerRe.MatchString(value) {
			return fail("type", "value is not an integer (`-?[0-9]+`: no leading `+`, no underscores, no hex, no exponent)")
		}
		n, err := strconv.ParseInt(canonicalInteger(value), 10, 64)
		if err != nil {
			// Anything wider than signed 64-bit is refused rather than
			// silently truncated or promoted to a float.
			return fail("magnitude", "integer magnitude does not fit signed 64-bit")
		}
		var out []Failure
		if r.Min != nil && n < *r.Min {
			out = append(out, Failure{Alternative: alt, Keyword: "min",
				Message: fmt.Sprintf("value is below the declared `min` of %d", *r.Min)})
		}
		if r.Max != nil && n > *r.Max {
			out = append(out, Failure{Alternative: alt, Keyword: "max",
				Message: fmt.Sprintf("value is above the declared `max` of %d", *r.Max)})
		}
		return out

	case TypeBoolean:
		if value != "true" && value != "false" {
			// `1`, `yes`, `TRUE` are rejected loud, never coerced: coercion
			// would make Wenv's truthiness differ from each consuming
			// language's, so a value that validated here could mean the
			// opposite there.
			return fail("type", "value is not the canonical `true` or `false`")
		}
		return nil

	case TypeEnum:
		for _, m := range r.Members {
			if value == m {
				return nil
			}
		}
		// The count rather than the list: declared members are schema and may
		// be listed, but a 64-member list in every failure would blow the
		// error-byte cap that exists to bound the response.
		return fail("members", "value is not one of the %d declared `enum` members", len(r.Members))

	case TypeURL:
		u, err := url.Parse(value)
		if err != nil || !u.IsAbs() || u.Opaque != "" {
			return fail("absolute", "value is not an absolute hierarchical URL")
		}
		scheme := strings.ToLower(u.Scheme)
		for _, s := range r.Schemes {
			if scheme == s {
				return nil
			}
		}
		return fail("schemes", "URL scheme is not in the declared `schemes` allowlist")

	case TypeJSON:
		var doc any
		if err := strictJSON([]byte(value), &doc); err != nil {
			if errors.Is(err, errDuplicateKey) {
				// Named separately because the ADR fixes duplicate keys as a
				// rejection rather than last-wins, and the message must not
				// echo the key: an instance key name on a secret key is
				// exactly the disclosure the path rule forbids.
				return fail("duplicate_key", "value contains a duplicate object key")
			}
			return fail("type", "value is not a single well-formed JSON document")
		}
		if cr.schema == nil {
			return nil
		}
		return jsonSchemaFailures(cr.schema, doc, cls, alt)

	default:
		// Unreachable: compileRule refuses an unknown type. Reported as a
		// failure rather than a panic so a malformed stored declaration cannot
		// take the process down.
		return fail("type", "declaration carries an unsupported type")
	}
}

// canonicalInteger strips the leading zeros the declaration preserves, so
// ParseInt sees a form it accepts while the stored value stays byte-exact.
func canonicalInteger(v string) string {
	sign := ""
	if strings.HasPrefix(v, "-") {
		sign, v = "-", v[1:]
	}
	v = strings.TrimLeft(v, "0")
	if v == "" {
		v = "0"
	}
	return sign + v
}

// jsonSchemaFailures renders the library's error tree under the disclosure
// rules. For a `secret` key nothing derived from the instance is read at all —
// not the localized message (the library's `additionalProperties` message
// names the offending instance properties), not the instance location.
func jsonSchemaFailures(sch *jsonschema.Schema, doc any, cls Classification, alt int) []Failure {
	err, outcome := runWithDeadline(func() error { return sch.Validate(doc) }, evaluationDeadline)
	switch outcome {
	case evalOverran:
		// Loud, never "assume valid".
		return []Failure{{Alternative: alt, Keyword: "budget.deadline",
			Message: fmt.Sprintf("validation exceeded the %s evaluation deadline", evaluationDeadline)}}
	case evalRefused:
		return []Failure{{Alternative: alt, Keyword: "budget.concurrency",
			Message: fmt.Sprintf("more than %d JSON Schema evaluations are already in flight",
				MaxConcurrentJSONSchemaEvaluations)}}
	}
	if err == nil {
		return nil
	}
	var verr *jsonschema.ValidationError
	if !errors.As(err, &verr) {
		return []Failure{{Alternative: alt, Keyword: "json_schema", Message: "value failed the declared JSON Schema"}}
	}
	leaves := make([]*jsonschema.ValidationError, 0, 8)
	flattenValidationError(verr, &leaves)
	out := make([]Failure, 0, len(leaves))
	for _, leaf := range leaves {
		f := Failure{
			Alternative: alt,
			Keyword:     "json_schema" + keywordSuffix(leaf),
			Message:     "value failed the declared JSON Schema at " + schemaLocation(leaf),
		}
		if cls == Config {
			// `config` keys report full instance paths and values under
			// ordinary environment read.
			f.InstancePath = instancePointer(leaf.InstanceLocation)
			f.Message = leaf.Error()
		}
		out = append(out, f)
	}
	return out
}

func flattenValidationError(e *jsonschema.ValidationError, out *[]*jsonschema.ValidationError) {
	if len(e.Causes) == 0 {
		*out = append(*out, e)
		return
	}
	for _, cause := range e.Causes {
		flattenValidationError(cause, out)
	}
}

// keywordSuffix renders the failing keyword path — schema text, never
// instance text.
func keywordSuffix(e *jsonschema.ValidationError) string {
	path := e.ErrorKind.KeywordPath()
	if len(path) == 0 {
		return ""
	}
	return "/" + strings.Join(path, "/")
}

// schemaLocation renders the failing subschema's own pointer. Property names
// appearing in it are statically declared IN THE SCHEMA, which the disclosure
// rule permits; dynamic instance keys never reach it.
func schemaLocation(e *jsonschema.ValidationError) string {
	loc := strings.TrimPrefix(e.SchemaURL, schemaResourceURL)
	if loc == "" {
		return "#"
	}
	return loc
}

func instancePointer(tokens []string) string {
	if len(tokens) == 0 {
		return ""
	}
	var b bytes.Buffer
	for _, t := range tokens {
		b.WriteString("/")
		b.WriteString(escapePointer(t))
	}
	return b.String()
}
