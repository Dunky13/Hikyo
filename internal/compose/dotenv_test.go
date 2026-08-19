package compose

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decodeRaw is the reference `format: raw` reader: split the file on '\n', and
// split each non-final line on its FIRST '='. This is the semantics the CI
// round-trip asserts stored bytes survive. It is intentionally minimal — the
// encoder guarantees no value carries '\n', so every entry is exactly one line.
func decodeRaw(b []byte) map[string]string {
	out := map[string]string{}
	s := string(b)
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i < 0 {
			continue
		}
		out[line[:i]] = line[i+1:]
	}
	return out
}

type corpusFile struct {
	Name           string    `json:"name"`
	Rows           []Row     `json:"rows"`
	ExpectRefusals []Refusal `json:"expectRefusals"`
}

func loadCorpus(t *testing.T) []corpusFile {
	t.Helper()
	dir := filepath.Join("testdata", "roundtrip")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read corpus dir: %v", err)
	}
	var out []corpusFile
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var cf corpusFile
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cf); err != nil {
			t.Fatalf("decode %s: %v", e.Name(), err)
		}
		if cf.Name == "" {
			cf.Name = e.Name()
		}
		out = append(out, cf)
	}
	if len(out) == 0 {
		t.Fatal("empty corpus")
	}
	return out
}

func TestEncodeRawCorpus(t *testing.T) {
	for _, cf := range loadCorpus(t) {
		t.Run(cf.Name, func(t *testing.T) {
			b, refusals, err := EncodeRaw(cf.Rows)
			if err != nil {
				t.Fatalf("EncodeRaw error: %v", err)
			}
			if len(cf.ExpectRefusals) > 0 {
				if b != nil {
					t.Errorf("refusal case wrote a file (%d bytes); want none", len(b))
				}
				if !equalRefusals(refusals, cf.ExpectRefusals) {
					t.Errorf("refusals = %v, want %v", refusals, cf.ExpectRefusals)
				}
				return
			}
			if len(refusals) != 0 {
				t.Fatalf("unexpected refusals: %v", refusals)
			}
			// Stored bytes == delivered bytes over the whole corpus.
			got := decodeRaw(b)
			if len(got) != len(cf.Rows) {
				t.Fatalf("decoded %d entries, want %d", len(got), len(cf.Rows))
			}
			for _, r := range cf.Rows {
				if got[r.Name] != r.Value {
					t.Errorf("key %s: round-trip %q != stored %q", r.Name, got[r.Name], r.Value)
				}
			}
		})
	}
}

func equalRefusals(a, b []Refusal) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestEncodeRawEmptyInput(t *testing.T) {
	b, refusals, err := EncodeRaw(nil)
	if err != nil || refusals != nil || len(b) != 0 {
		t.Fatalf("empty input: b=%q refusals=%v err=%v", b, refusals, err)
	}
}

func FuzzEncodeRawRoundTrip(f *testing.F) {
	f.Add("FOO", "bar")
	f.Add("A_B", "$do${llar}")
	f.Add("WS", "  spaced\t")
	f.Add("Q", "'\"\\")
	f.Add("BAD", "has\nnewline")
	f.Add("1bad", "x")
	f.Fuzz(func(t *testing.T, name, value string) {
		b, refusals, err := EncodeRaw([]Row{{Name: name, Value: value}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(refusals) > 0 {
			if b != nil {
				t.Fatalf("refused but wrote a file")
			}
			// A refused row is exactly a bad name, or a value with \n/\r/NUL.
			badName := !nameGrammar.MatchString(name)
			badValue := strings.ContainsAny(value, "\n\r") || strings.IndexByte(value, 0) >= 0
			if !badName && !badValue {
				t.Fatalf("refused a representable row: name=%q value=%q reason=%q", name, value, refusals[0].Reason)
			}
			return
		}
		got := decodeRaw(b)
		if got[name] != value {
			t.Fatalf("round-trip mismatch: name=%q stored=%q got=%q", name, value, got[name])
		}
	})
}
