package audit

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Free-text hygiene (audit-model ADR § The event envelope): every
// caller-originated string landing in a durable audit record is
// length-bounded, UTF-8-sanitized, stored as data and never interpreted,
// and passed through the token-grammar redaction filter. Envelope fields
// included, not just payloads.

// FreeTextBound is the byte bound on any single free-text field. The
// concrete value is the operations spec's to tune (#32); this is the
// fail-closed default under the threat model's bounded-payload baseline.
const FreeTextBound = 512

// RedactionMarker replaces any substring matching the wenv token grammar.
const RedactionMarker = "[REDACTED:wenv-token]"

// tokenGrammarRe matches the machine-identity ADR's bearer-token grammar
// `ew_<version>_<type>_<body><checksum>` — deliberately tolerant on the
// version and type fields (any future closed-list widening still redacts)
// and requiring enough base62 body that ordinary prose cannot trip it. The
// scannability of the grammar is a designed-in property; this filter is its
// consumer.
var tokenGrammarRe = regexp.MustCompile(`ew_[0-9A-Za-z]{1,8}_[a-z]{2,8}_[0-9A-Za-z]{16,}`)

// RedactTokens replaces every token-grammar match in s with the redaction
// marker. What this cannot catch is stated in the ADR: an arbitrary secret
// value in free text has no recognizable grammar; the bound and the
// schema-typed fields limit the blast.
func RedactTokens(s string) string {
	return tokenGrammarRe.ReplaceAllString(s, RedactionMarker)
}

// SanitizeFreeText applies the full free-text hygiene: strip invalid UTF-8
// and control characters, truncate to the bound (on a rune boundary), and
// redact token-grammar matches. Emitters call this once at capture; the
// write boundary re-checks with checkSanitized and refuses rather than
// silently re-cleaning.
func SanitizeFreeText(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1 // drop control characters; stored as data, never interpreted
		}
		return r
	}, s)
	s = RedactTokens(s)
	if len(s) > FreeTextBound {
		cut := FreeTextBound
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return s
}

// checkSanitized is the write-boundary re-check: a free-text value that
// SanitizeFreeText would change is refused, because an emitter that skipped
// sanitization is a bug, not something to paper over silently.
func checkSanitized(s string) error {
	if s != SanitizeFreeText(s) {
		return fmt.Errorf("free-text value was not sanitized before the write boundary")
	}
	return nil
}
