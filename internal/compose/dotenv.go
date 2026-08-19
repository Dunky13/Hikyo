package compose

import (
	"bytes"
	"regexp"
	"strings"
)

// Raw dotenv encoding for Compose `env_file: { format: raw }`
// (compose-integration ADR § "Dotenv encoding and the Compose version floor").
//
// Compose's DEFAULT env_file parsing interpolates `$`, processes `\n \r \t \\`
// escapes inside double quotes, strips surrounding whitespace, and treats
// single quotes as literal — so a secret containing `$`, a quote, or a
// backslash is SILENTLY TRANSFORMED. `format: raw` (docker/compose#12179, 2.30)
// passes the value as-is. The canonical rendered encoding is therefore: one
// `NAME=value\n` line per key, VALUE byte-for-byte, NO quoting, NO escaping,
// surrounding whitespace PRESERVED.
//
// The representable domain is every UTF-8 sequence the schema admits (NUL
// already excluded by #12) EXCEPT a value carrying `\n` or `\r`: a raw line
// cannot carry a line break, so that value is refused BY NAME rather than
// delivered truncated. Refusals are DATA so the caller can report them as a
// delivery failure naming the keys; a non-empty refusal list means NO file is
// written (compose ADR: the refusal "is reported as a delivery failure, not a
// warning").

// Row is one raw-dotenv entry.
type Row struct {
	Name  string
	Value string
}

// Refusal names a key that cannot be represented as a raw line and why.
type Refusal struct {
	Key    string
	Reason string
}

// nameGrammar is the POSIX-ish env name form. A name outside it cannot be a
// dotenv key (it would not round-trip on `first =`), so it is refused.
var nameGrammar = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// EncodeRaw renders rows to raw dotenv bytes. When any row is unrepresentable
// it returns (nil, refusals, nil): a partial file is never written. Row order
// is preserved.
func EncodeRaw(rows []Row) ([]byte, []Refusal, error) {
	var refusals []Refusal
	for _, r := range rows {
		if !nameGrammar.MatchString(r.Name) {
			refusals = append(refusals, Refusal{Key: r.Name, Reason: "invalid name"})
			continue
		}
		switch {
		case strings.ContainsAny(r.Value, "\n\r"):
			refusals = append(refusals, Refusal{Key: r.Name, Reason: "embedded newline"})
		case strings.IndexByte(r.Value, 0) >= 0:
			// Belt-and-braces: #12 already rejects NUL at publish, but a raw
			// line MUST NOT carry one either.
			refusals = append(refusals, Refusal{Key: r.Name, Reason: "NUL byte"})
		}
	}
	if len(refusals) > 0 {
		return nil, refusals, nil
	}

	var buf bytes.Buffer
	for _, r := range rows {
		buf.WriteString(r.Name)
		buf.WriteByte('=')
		buf.WriteString(r.Value)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil, nil
}
