package audit

import (
	"fmt"
	"slices"
)

// Payload carries the per-type fields, validated against the type's
// registered schema at write time. Values are restricted to the schema
// kinds below; an unregistered field, a missing required field or a
// kind-mismatched value fails validation and therefore fails the emitting
// operation (fail-closed).
type Payload map[string]any

// FieldKind is the closed set of payload value kinds.
type FieldKind int

const (
	// KindString is a schema-typed identifier or enum value — trusted
	// vocabulary (operation names, ids, class names), never caller free text.
	KindString FieldKind = iota
	// KindFreeText is attacker-influencable caller text. The emitter MUST
	// pass it through SanitizeFreeText before write; validation refuses a
	// value that is over-bound, non-UTF-8-clean or still matching the token
	// grammar.
	KindFreeText
	// KindInt is an integer count or bound.
	KindInt
	// KindBool is a boolean fact.
	KindBool
	// KindStringList is an ordered or set-like collection of trusted
	// identifiers. Keeping it structured avoids lossy delimiter encoding.
	KindStringList
	// KindObject is a nested, closed-schema object.
	KindObject
)

// FieldSpec declares one payload field.
type FieldSpec struct {
	Kind         FieldKind
	Required     bool
	ObjectSchema Schema
	// Enum closes a KindString field to a fixed value set, validated at WRITE
	// time. A registry that declares a closed enum and then accepts anything is
	// a closed enum in prose only — which is what §10's typing rules are not.
	Enum []string
	// NonNegative bounds a KindInt field below at zero. It is a FLAG, not a
	// `Min int`: the zero value of an int cannot distinguish "bound at 0" from
	// "unbounded", and a silent Min:0 on every field rejects the legitimate -1
	// that `previous_configured_seconds` uses for "inherits".
	NonNegative bool
	// AtLeast bounds a KindInt field below at a stated value; ignored when zero.
	AtLeast int
	// MaxLen bounds a KindStringList's length; MaxBytes bounds each entry.
	// MaxBytes also bounds a KindFreeText or KindString scalar, which is how
	// #73 §10's 256-byte SCIM bound is stated at the write boundary rather than
	// inherited from the trail-wide 512-byte one — a per-surface bound the
	// registry declares is a bound; a comment about it is not.
	MaxLen, MaxBytes int
	// Digest closes a KindString field to lowercase SHA-256 hex. §10 states
	// "the subject never appears in plaintext — `subject digest` is its
	// SHA-256 hex", and a field that accepts any string cannot tell a digest
	// from the subject itself, which is the exact leak the rule prevents.
	Digest bool
}

// sha256HexLen is the length of a SHA-256 digest in lowercase hex.
const sha256HexLen = 64

// Schema is one event type's closed payload field set.
type Schema map[string]FieldSpec

func (s Schema) validate(t EventType, p Payload) error {
	for name := range p {
		if _, ok := s[name]; !ok {
			return fmt.Errorf("audit: %s: payload field %q is not in the registered schema", t, name)
		}
	}
	for name, spec := range s {
		v, present := p[name]
		if !present {
			if spec.Required {
				return fmt.Errorf("audit: %s: payload missing required field %q", t, name)
			}
			continue
		}
		if spec.Kind == KindObject {
			object, ok := objectPayload(v)
			if !ok {
				return fmt.Errorf("audit: %s: payload field %q: want object, got %T", t, name, v)
			}
			if spec.ObjectSchema == nil {
				return fmt.Errorf("audit: %s: payload field %q: object schema is missing", t, name)
			}
			if err := spec.ObjectSchema.validate(t, object); err != nil {
				return fmt.Errorf("audit: %s: payload field %q: %w", t, name, err)
			}
			continue
		}
		if err := checkKind(spec.Kind, v); err != nil {
			return fmt.Errorf("audit: %s: payload field %q: %w", t, name, err)
		}
		if err := checkConstraints(spec, v); err != nil {
			return fmt.Errorf("audit: %s: payload field %q: %w", t, name, err)
		}
	}
	return nil
}

// checkConstraints applies the per-field bounds §10's typing rules describe:
// closed enums, non-negative counts, and list caps.
func checkConstraints(spec FieldSpec, v any) error {
	if len(spec.Enum) > 0 {
		s, _ := v.(string)
		if !slices.Contains(spec.Enum, s) {
			return fmt.Errorf("value %q is outside the closed set %v", s, spec.Enum)
		}
	}
	switch t := v.(type) {
	case string:
		if spec.Digest {
			if len(t) != sha256HexLen {
				return fmt.Errorf("digest is %d characters, want %d hex characters", len(t), sha256HexLen)
			}
			for i := range len(t) {
				c := t[i]
				if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
					return fmt.Errorf("digest is not lowercase hex")
				}
			}
		}
		if spec.MaxBytes > 0 && len(t) > spec.MaxBytes {
			return fmt.Errorf("value exceeds %d bytes", spec.MaxBytes)
		}
	case int:
		return checkInt(spec, int64(t))
	case int64:
		return checkInt(spec, t)
	case []string:
		if spec.MaxLen > 0 && len(t) > spec.MaxLen {
			return fmt.Errorf("list has %d entries, bound is %d", len(t), spec.MaxLen)
		}
		for _, entry := range t {
			if spec.MaxBytes > 0 && len(entry) > spec.MaxBytes {
				return fmt.Errorf("list entry exceeds %d bytes", spec.MaxBytes)
			}
			if err := checkSanitized(entry); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkInt(spec FieldSpec, n int64) error {
	if spec.NonNegative && n < 0 {
		return fmt.Errorf("value %d is negative", n)
	}
	if spec.AtLeast != 0 && n < int64(spec.AtLeast) {
		return fmt.Errorf("value %d is below the bound %d", n, spec.AtLeast)
	}
	return nil
}

func checkKind(k FieldKind, v any) error {
	switch k {
	case KindString:
		if _, ok := v.(string); !ok {
			return fmt.Errorf("want string, got %T", v)
		}
	case KindFreeText:
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("want string, got %T", v)
		}
		if err := checkSanitized(s); err != nil {
			return err
		}
	case KindInt:
		switch v.(type) {
		case int, int64:
		default:
			return fmt.Errorf("want int, got %T", v)
		}
	case KindBool:
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("want bool, got %T", v)
		}
	case KindStringList:
		if _, ok := v.([]string); !ok {
			return fmt.Errorf("want []string, got %T", v)
		}
	case KindObject:
		return fmt.Errorf("object kind requires a nested schema")
	default:
		return fmt.Errorf("unknown field kind %d", k)
	}
	return nil
}

func objectPayload(v any) (Payload, bool) {
	switch object := v.(type) {
	case Payload:
		return object, true
	case map[string]any:
		return Payload(object), true
	default:
		return nil, false
	}
}
