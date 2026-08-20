package definitions

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
)

// Strict JSON decoding shared by every closed artifact schema. It lives here
// because internal/importer already depends on this package (the canonical
// bundle type), so the dependency direction forces these neutral helpers down
// rather than duplicating the token walk. They return typed, taxonomy-free
// errors; each caller maps them to its own refusal vocabulary (this package to
// domain sentinels with caller-safe detail, the importer to its Code set).

// DuplicateMemberError names an object member that appeared more than once.
// encoding/json otherwise accepts duplicates with last-one-wins semantics,
// which is unsafe for a reviewed artifact.
type DuplicateMemberError struct{ Member string }

func (e *DuplicateMemberError) Error() string {
	return "object member " + e.Member + " appears more than once"
}

// UnknownFieldError names a field the target schema does not know — for a
// closed, versioned artifact that always means a version mismatch.
type UnknownFieldError struct{ Field string }

func (e *UnknownFieldError) Error() string { return "unknown field " + e.Field }

// ErrMalformed is a JSON syntax or shape failure; ErrTrailing is content after
// the top-level document. Both are content-free on purpose.
var (
	ErrMalformed = errors.New("not a well-formed document")
	ErrTrailing  = errors.New("trailing content after the document")
)

// DecodeStrict rejects duplicate object members and unknown fields, decodes
// into `into`, and refuses trailing content. It is the closed-schema decode
// every artifact parser funnels through.
func DecodeStrict(raw []byte, into any) error {
	if err := RejectDuplicateMembers(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		if field, ok := unknownField(err); ok {
			return &UnknownFieldError{Field: field}
		}
		return ErrMalformed
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrTrailing
	}
	return nil
}

// unknownField extracts the field name from encoding/json's unknown-field
// error, whose message is `json: unknown field "x"`.
func unknownField(err error) (string, bool) {
	msg := err.Error()
	const marker = "unknown field "
	i := strings.Index(msg, marker)
	if i < 0 {
		return "", false
	}
	return strings.Trim(msg[i+len(marker):], `"`), true
}

// RejectDuplicateMembers walks the raw token stream before any decode.
func RejectDuplicateMembers(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := walkJSONValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrTrailing
	}
	return nil
}

func walkJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return ErrMalformed
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			member, err := dec.Token()
			if err != nil {
				return ErrMalformed
			}
			key, ok := member.(string)
			if !ok {
				return ErrMalformed
			}
			folded := foldJSONMember(key)
			if _, dup := seen[folded]; dup {
				return &DuplicateMemberError{Member: key}
			}
			seen[folded] = struct{}{}
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
		if end, err := dec.Token(); err != nil || end != json.Delim('}') {
			return ErrMalformed
		}
	case '[':
		for dec.More() {
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
		if end, err := dec.Token(); err != nil || end != json.Delim(']') {
			return ErrMalformed
		}
	default:
		return ErrMalformed
	}
	return nil
}

// foldJSONMember mirrors encoding/json's case-insensitive struct-field match, so
// exact and case-variant spellings occupy one logical member slot before the
// struct decode can apply last-value-wins to them.
func foldJSONMember(name string) string {
	return strings.Map(func(r rune) rune {
		for {
			next := unicode.SimpleFold(r)
			if next <= r {
				return next
			}
			r = next
		}
	}, name)
}
