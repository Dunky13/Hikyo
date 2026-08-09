package audit

import (
	"fmt"
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
}

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
