// Package dotenv parses a standard `.env` file into ordered key/value entries.
//
// This is the STANDARD dotenv grammar an operator's existing `.env` uses — the
// onboarding source the source-of-truth ADR fixes as the scaffold path and the
// import path's dotenv leg. It is deliberately NOT the inverse of
// compose.EncodeRaw: that encoder emits Compose's `format: raw` (no quoting, no
// escaping), whereas a hand-written `.env` uses quotes and backslash escapes, so
// the two are different grammars and live in different packages.
//
// The parser is pure and fail-loud: a malformed line, a duplicate key, or a
// name outside the canonical grammar is refused BY NAME rather than parsed into
// something the operator did not write. `#` begins a comment only at the start
// of a line (after optional leading whitespace); a `#` after an unquoted value
// is part of the value, never a silently stripped inline comment — silently
// truncating a value that legitimately contains ` #` is exactly the
// transformation a secrets tool must not perform. Quote the value to carry a
// leading `#` or surrounding whitespace.
package dotenv

import (
	"fmt"
	"strings"

	"github.com/Hikyo-Org/hikyo/internal/schema"
)

// Entry is one parsed `KEY=value` pair, in file order.
type Entry struct {
	Key   string
	Value string
}

// Parse reads a dotenv document into ordered entries. It refuses — naming the
// offending line and key — on a malformed line, an invalid key name, a bad
// quote/escape, or a duplicate key.
func Parse(data []byte) ([]Entry, error) {
	var entries []Entry
	seen := map[string]struct{}{}
	for n, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// `export KEY=value` is the shell-sourceable form; the prefix is not part
		// of the name.
		if rest, ok := cutExportPrefix(trimmed); ok {
			trimmed = rest
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: not a KEY=value assignment: %q", n+1, line)
		}
		key := strings.TrimRight(trimmed[:eq], " \t")
		if err := schema.CheckKeyName(key); err != nil {
			return nil, fmt.Errorf("line %d: %v", n+1, err)
		}
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate key %q", n+1, key)
		}
		value, err := parseValue(strings.TrimLeft(trimmed[eq+1:], " \t"))
		if err != nil {
			return nil, fmt.Errorf("line %d: key %q: %v", n+1, key, err)
		}
		seen[key] = struct{}{}
		entries = append(entries, Entry{Key: key, Value: value})
	}
	return entries, nil
}

// cutExportPrefix strips a leading `export` followed by whitespace.
func cutExportPrefix(s string) (string, bool) {
	if !strings.HasPrefix(s, "export") {
		return s, false
	}
	rest := s[len("export"):]
	if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
		return s, false // `exportKEY=…` is a name, not the keyword
	}
	return strings.TrimLeft(rest, " \t"), true
}

// parseValue interprets the right-hand side after the `=`, leading whitespace
// already trimmed.
func parseValue(v string) (string, error) {
	switch {
	case v == "":
		return "", nil
	case v[0] == '"':
		return parseDoubleQuoted(v)
	case v[0] == '\'':
		return parseSingleQuoted(v)
	default:
		// Unquoted: the value is the rest of the line with surrounding
		// whitespace trimmed. `#` is NOT an inline comment here (see package
		// doc) — quote the value to carry one.
		return strings.TrimRight(v, " \t"), nil
	}
}

// parseSingleQuoted returns the literal content between single quotes; no escape
// processing, per the shell single-quote convention.
func parseSingleQuoted(v string) (string, error) {
	end := strings.IndexByte(v[1:], '\'')
	if end < 0 {
		return "", fmt.Errorf("unterminated single-quoted value")
	}
	if err := onlyTrailingBlank(v[1+end+1:]); err != nil {
		return "", err
	}
	return v[1 : 1+end], nil
}

// parseDoubleQuoted processes the usual backslash escapes inside double quotes.
func parseDoubleQuoted(v string) (string, error) {
	var b strings.Builder
	for i := 1; i < len(v); i++ {
		c := v[i]
		switch c {
		case '"':
			if err := onlyTrailingBlank(v[i+1:]); err != nil {
				return "", err
			}
			return b.String(), nil
		case '\\':
			if i+1 >= len(v) {
				return "", fmt.Errorf("dangling backslash in double-quoted value")
			}
			i++
			switch v[i] {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '\\':
				b.WriteByte('\\')
			case '"':
				b.WriteByte('"')
			case '\'':
				b.WriteByte('\'')
			default:
				return "", fmt.Errorf("unknown escape \\%c in double-quoted value", v[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", fmt.Errorf("unterminated double-quoted value")
}

// onlyTrailingBlank refuses anything but whitespace after a closing quote, so a
// value that ends its quote early and continues is caught rather than truncated.
func onlyTrailingBlank(s string) error {
	if strings.TrimLeft(s, " \t") != "" {
		return fmt.Errorf("unexpected content after the closing quote")
	}
	return nil
}

// Refusal names one entry Encode could not represent.
type Refusal struct {
	Key    string
	Reason string
}

// Encode renders entries as a dotenv document that Parse reads back
// byte-exact. Values that the unquoted grammar would alter - surrounding
// whitespace (Parse trims it), a leading quote, a `#`, a backslash, a control
// character or a newline - are double-quoted with the escapes parseDoubleQuoted
// understands; every other value is written bare. This is deliberately NOT the
// Compose renderer's raw encoding: that one is consumed by Compose's
// `format: raw`, which performs no unquoting, whereas a document written for
// humans and for `values import --from-dotenv` must survive the round trip.
// A NUL byte cannot be carried by either grammar and is refused by name.
func Encode(entries []Entry) ([]byte, []Refusal, error) {
	var refusals []Refusal
	for _, e := range entries {
		if err := schema.CheckKeyName(e.Key); err != nil {
			refusals = append(refusals, Refusal{Key: e.Key, Reason: "invalid name"})
			continue
		}
		if strings.IndexByte(e.Value, 0) >= 0 {
			refusals = append(refusals, Refusal{Key: e.Key, Reason: "NUL byte"})
		}
	}
	if len(refusals) > 0 {
		return nil, refusals, nil
	}
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Key)
		b.WriteByte('=')
		if needsQuoting(e.Value) {
			b.WriteByte('"')
			for i := 0; i < len(e.Value); i++ {
				switch c := e.Value[i]; c {
				case '\\':
					b.WriteString(`\\`)
				case '"':
					b.WriteString(`\"`)
				case '\n':
					b.WriteString(`\n`)
				case '\r':
					b.WriteString(`\r`)
				case '\t':
					b.WriteString(`\t`)
				default:
					b.WriteByte(c)
				}
			}
			b.WriteByte('"')
		} else {
			b.WriteString(e.Value)
		}
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil, nil
}

// needsQuoting reports whether a bare value would not parse back to itself.
func needsQuoting(v string) bool {
	if v == "" {
		return false
	}
	if v != strings.TrimSpace(v) {
		return true
	}
	if v[0] == '"' || v[0] == '\'' {
		return true
	}
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '#', c == '\\', c == '"', c == '\n', c == '\r', c == '\t', c < 0x20, c == 0x7f:
			return true
		}
	}
	return false
}
