package dotenv

import "testing"

// Encode and Parse are each other's inverse for every value the format can
// carry - including the ones a bare line would alter (surrounding whitespace,
// quotes, #, backslashes, newlines). An export that re-imports as a different
// secret is a credential corruption, which is why this is property-shaped.
func TestEncodeParseRoundTrip(t *testing.T) {
	values := []string{
		"", "plain", " leading", "trailing ", " both ", "with # hash", `back\slash`, `dq"inside`, `'single'`,
		"\"starts-with-quote", "tab\tinside", "multi\nline", "cr\rlf\n", "unicode ✓ ok", "equals=inside", "export=word",
	}
	var entries []Entry
	for i, v := range values {
		entries = append(entries, Entry{Key: "KEY_" + string(rune('A'+i)), Value: v})
	}
	out, refusals, err := Encode(entries)
	if err != nil || len(refusals) != 0 {
		t.Fatalf("encode: err=%v refusals=%v", err, refusals)
	}
	back, err := Parse(out)
	if err != nil {
		t.Fatalf("parse own output: %v\n%s", err, out)
	}
	if len(back) != len(entries) {
		t.Fatalf("round trip lost entries: %d -> %d", len(entries), len(back))
	}
	for i := range entries {
		if back[i] != entries[i] {
			t.Errorf("entry %d: %q -> %q", i, entries[i].Value, back[i].Value)
		}
	}
}

func TestEncodeRefusesNULAndBadNames(t *testing.T) {
	_, refusals, err := Encode([]Entry{{Key: "OK", Value: "x\x00y"}, {Key: "bad-name", Value: "v"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(refusals) != 2 {
		t.Fatalf("refusals = %v, want NUL and invalid name", refusals)
	}
}

func TestEncodeWritesBareValuesBare(t *testing.T) {
	out, _, err := Encode([]Entry{{Key: "LOG_LEVEL", Value: "debug"}, {Key: "URL", Value: "postgres://u:p@db/app"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "LOG_LEVEL=debug\nURL=postgres://u:p@db/app\n" {
		t.Fatalf("unexpected encoding:\n%s", out)
	}
}
