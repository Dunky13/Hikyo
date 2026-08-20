package dotenv

import "testing"

func TestParseTable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		in    string
		want  []Entry
		wantK string // if non-empty, the value the refusal must name
	}{
		{name: "plain", in: "FOO=bar", want: []Entry{{"FOO", "bar"}}},
		{name: "export prefix", in: "export FOO=bar", want: []Entry{{"FOO", "bar"}}},
		{name: "spaces around eq", in: "FOO = bar", want: []Entry{{"FOO", "bar"}}},
		{name: "empty value", in: "FOO=", want: []Entry{{"FOO", ""}}},
		{name: "double quoted", in: `FOO="a b"`, want: []Entry{{"FOO", "a b"}}},
		{name: "double quote escapes", in: `FOO="a\nb\t\\\"c"`, want: []Entry{{"FOO", "a\nb\t\\\"c"}}},
		{name: "single quoted literal", in: `FOO='a\nb'`, want: []Entry{{"FOO", `a\nb`}}},
		{name: "hash after unquoted is literal", in: "FOO=bar # x", want: []Entry{{"FOO", "bar # x"}}},
		{name: "full-line comment skipped", in: "# a comment\nFOO=bar", want: []Entry{{"FOO", "bar"}}},
		{name: "indented comment skipped", in: "  # c\nFOO=bar", want: []Entry{{"FOO", "bar"}}},
		{name: "blank lines skipped", in: "\n\nFOO=bar\n\n", want: []Entry{{"FOO", "bar"}}},
		{name: "crlf", in: "FOO=bar\r\nBAZ=qux\r\n", want: []Entry{{"FOO", "bar"}, {"BAZ", "qux"}}},
		{name: "order preserved", in: "B=2\nA=1", want: []Entry{{"B", "2"}, {"A", "1"}}},
		{name: "underscore digit name", in: "_A0=v", want: []Entry{{"_A0", "v"}}},

		{name: "duplicate key refused", in: "FOO=a\nFOO=b", wantK: "FOO"},
		{name: "lowercase name refused", in: "foo=bar", wantK: "foo"},
		{name: "dash name refused", in: "FO-O=bar", wantK: "FO-O"},
		{name: "leading digit name refused", in: "0FOO=bar", wantK: "0FOO"},
		{name: "no equals refused", in: "FOO", wantK: "not a KEY=value"},
		{name: "unterminated double quote", in: `FOO="a`, wantK: "unterminated"},
		{name: "unterminated single quote", in: `FOO='a`, wantK: "unterminated"},
		{name: "unknown escape refused", in: `FOO="a\x"`, wantK: "unknown escape"},
		{name: "content after quote refused", in: `FOO="a"b`, wantK: "after the closing quote"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse([]byte(tc.in))
			if tc.wantK != "" {
				if err == nil {
					t.Fatalf("expected refusal, got %v", got)
				}
				if !contains(err.Error(), tc.wantK) {
					t.Fatalf("refusal %q does not name %q", err.Error(), tc.wantK)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("entry %d = %#v, want %#v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
