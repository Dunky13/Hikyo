package definitions

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Encode renders a validated canonical bundle: sorted object keys at every
// depth (including any JSON Schema document embedded in a declaration),
// two-space indentation, HTML escaping off, and exactly one trailing newline.
// Byte-stability is what makes the digest a meaningful apply pin and a PR diff
// legible.
//
// Parse and Canonicalize are the only producers of an encodable bundle, so
// every successful result parses back to the same canonical model.
func Encode(b CanonicalBundle) ([]byte, error) {
	if !b.valid {
		return nil, invalidDetail("canonical bundle was not produced by Parse or Canonicalize")
	}
	return bytes.Clone(b.encoded), nil
}

// canonicalize serializes any value with sorted keys and stable integers. The
// round-trip through `any` with UseNumber sorts every object member (Go's
// encoder sorts map keys) while preserving int64 exactly as its literal digits,
// which a float64 round-trip would not.
func canonicalize(v any) ([]byte, error) {
	raw, err := marshalNoEscape(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("definitions: canonicalize decode: %w", err)
	}
	sorted, err := marshalNoEscape(generic)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, sorted, "", "  "); err != nil {
		return nil, fmt.Errorf("definitions: canonicalize indent: %w", err)
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// marshalNoEscape marshals without HTML escaping and without the trailing
// newline json.Encoder appends, so `<`, `>` and `&` in a pattern or description
// survive verbatim.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("definitions: marshal: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Digest is the SHA-256 of the canonical encoding, hex-encoded and unprefixed.
// It is computed over canonical bytes, never the raw file bytes, so a
// whitespace-only edit does not move the apply pin while any content change
// does. (This deliberately differs from internal/importer.Digest, whose
// "sha256:"-prefixed form is a template-reference spelling.)
func Digest(b CanonicalBundle) (string, error) {
	canonical, err := Encode(b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
