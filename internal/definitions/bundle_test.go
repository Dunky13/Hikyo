package definitions

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
)

func strp(s string) *string { return &s }

func rev(n int64) *int64 { return &n }

func stringRule() schema.Declaration {
	return schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}}
}

func sampleBundle() Bundle {
	return Bundle{
		FormatVersion: FormatVersion,
		BaseRevision:  rev(12),
		Environments: []Environment{
			{ID: "env_prod", Name: "production"},
			{ID: "env_stg", Name: "staging"},
		},
		KeyGroups: []KeyGroup{{ID: "kg_db", Name: "database"}},
		Keys: []Key{
			{
				ID: "key_url", Name: "DB_URL", FolderPath: "db", Classification: "secret",
				Description: "the <db> url & port", Deprecated: false, DeprecationNote: "",
				Group: "database", Declaration: stringRule(),
				RequiredIn:  Presence{Mode: "explicit", Environments: []string{"production"}},
				ForbiddenIn: Presence{Mode: "none"},
			},
			{
				ID: "key_flag", Name: "FEATURE_FLAG", FolderPath: "", Classification: "config",
				Description: "", Deprecated: true, DeprecationNote: "use the new one",
				Group: "", Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeBoolean}},
				RequiredIn:  Presence{Mode: "none"},
				ForbiddenIn: Presence{Mode: "all"},
			},
		},
	}
}

func TestEncodeParseRoundTrip(t *testing.T) {
	norm, err := Canonicalize(sampleBundle())
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	canonical, err := Encode(norm)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Trailing LF and 2-space indent.
	if !strings.HasSuffix(string(canonical), "\n") {
		t.Fatal("canonical bundle must end in a newline")
	}
	if !strings.Contains(string(canonical), "\n  \"format_version\"") {
		t.Fatalf("canonical bundle not 2-space indented:\n%s", canonical)
	}
	// Every list field is present as [] not null; group emitted even when empty.
	for _, want := range []string{`"environments"`, `"key_groups"`, `"keys"`, `"group": ""`, `"required_in"`, `"forbidden_in"`} {
		if !strings.Contains(string(canonical), want) {
			t.Fatalf("canonical bundle missing %s:\n%s", want, canonical)
		}
	}
	// HTML-unsafe characters survive verbatim.
	if !strings.Contains(string(canonical), "the <db> url & port") {
		t.Fatalf("HTML escaping leaked into canonical bundle:\n%s", canonical)
	}

	parsed, err := Parse(canonical)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(parsed.WireBundle(), norm.WireBundle()) {
		t.Fatalf("Parse(Encode(b)) != b\n got: %+v\nwant: %+v", parsed.WireBundle(), norm.WireBundle())
	}
	reEncoded, err := Encode(parsed)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if string(reEncoded) != string(canonical) {
		t.Fatalf("Encode(Parse(bytes)) != canonical\n got:\n%s\nwant:\n%s", reEncoded, canonical)
	}
}

func TestParseCompiledCarriesClassifiedDeclarations(t *testing.T) {
	norm := mustCanonicalize(t, sampleBundle())
	raw, err := Encode(norm)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCompiled(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed.WireBundle(), norm.WireBundle()) {
		t.Fatalf("ParseCompiled bundle differs\n got: %+v\nwant: %+v", parsed.WireBundle(), norm.WireBundle())
	}
	compiled, ok := parsed.CompiledDeclaration("DB_URL")
	if !ok {
		t.Fatal("ParseCompiled omitted DB_URL's compiled declaration")
	}
	if verdict := compiled.Validate("postgres://db.example.test/app"); !verdict.Valid {
		t.Fatalf("compiled DB_URL declaration refused a string: %+v", verdict.Errors)
	}
	if _, ok := parsed.CompiledDeclaration("MISSING"); ok {
		t.Fatal("ParseCompiled returned an artifact for an absent key")
	}
}

func TestDigestStableOverCanonical(t *testing.T) {
	norm, _ := Canonicalize(sampleBundle())
	d1, err := Digest(norm)
	if err != nil {
		t.Fatal(err)
	}
	if len(d1) != 64 {
		t.Fatalf("digest not 64 hex chars: %q", d1)
	}
	// Re-parsing the canonical form yields the same digest.
	canonical, _ := Encode(norm)
	parsed, _ := Parse(canonical)
	d2, _ := Digest(parsed)
	if d1 != d2 {
		t.Fatalf("digest not stable across parse: %s vs %s", d1, d2)
	}
}

func TestParseUnknownFieldNamesFieldAndVersion(t *testing.T) {
	raw := `{"format_version":1,"environments":[],"key_groups":[],"keys":[],"gremlin":true}`
	_, err := Parse([]byte(raw))
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "gremlin") || !strings.Contains(msg, "version mismatch") {
		t.Fatalf("error must name field and version: %q", msg)
	}
}

func TestParseBaseFieldRejectedByName(t *testing.T) {
	raw := `{"format_version":1,"environments":[],"key_groups":[],"keys":[{"name":"X","folder_path":"","classification":"config","description":"","deprecated":false,"deprecation_note":"","group":"","declaration":{"rule":{"type":"string"}},"required_in":{"mode":"none","environments":[]},"forbidden_in":{"mode":"none","environments":[]},"base":"prod"}]}`
	_, err := Parse([]byte(raw))
	if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "flat-model amendment") {
		t.Fatalf("base field must be rejected by name: %v", err)
	}
}

func TestParseIDsWithoutBaseRejected(t *testing.T) {
	b := sampleBundle()
	b.BaseRevision = nil // ids remain
	_, err := Canonicalize(b)
	if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "ids without base revision") {
		t.Fatalf("ids-without-base canonicalization must be rejected: %v", err)
	}
}

func TestCanonicalizeRunsEveryPreEncodeBundleValidation(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Bundle)
		want error
	}{
		{
			name: "wrong format version",
			edit: func(b *Bundle) { b.FormatVersion = FormatVersion + 1 },
			want: domain.ErrInvalid,
		},
		{
			name: "too many entries",
			edit: func(b *Bundle) {
				b.Environments = make([]Environment, MaxBundleEntries+1)
			},
			want: domain.ErrLimitExceeded,
		},
		{
			name: "canonical bytes exceed parse limit",
			edit: func(b *Bundle) {
				b.Keys[0].Description = strings.Repeat("x", MaxBundleBytes)
			},
			want: domain.ErrLimitExceeded,
		},
		{
			name: "invalid classification",
			edit: func(b *Bundle) { b.Keys[0].Classification = "public" },
			want: domain.ErrInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := sampleBundle()
			tt.edit(&b)
			_, err := Canonicalize(b)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Canonicalize error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestCanonicalBundleReturnsDetachedModel(t *testing.T) {
	bundle := mustCanonicalize(t, sampleBundle())
	want, err := Encode(bundle)
	if err != nil {
		t.Fatal(err)
	}

	detached := bundle.WireBundle()
	detached.Keys[0].Name = "MUTATED"
	detached.Keys[0].Declaration.Rule.Type = schema.TypeInteger
	got, err := Encode(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mutating Bundle() copy changed canonical bytes\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestCanonicalBundleZeroValueRejected(t *testing.T) {
	zero := CanonicalBundle{}
	if _, err := Encode(zero); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("Encode zero CanonicalBundle error = %v, want ErrInvalid", err)
	}
	for _, tt := range []struct {
		name string
		call func()
	}{
		{name: "WireBundle", call: func() { zero.WireBundle() }},
		{name: "Additive", call: func() { zero.Additive() }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				tt.call()
			}()
			if !panicked {
				t.Fatalf("%s accepted zero CanonicalBundle", tt.name)
			}
		})
	}
}

func FuzzCanonicalBundleRoundTrip(f *testing.F) {
	seed, err := Encode(mustCanonicalize(f, sampleBundle()))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, raw []byte) {
		first, err := Parse(raw)
		if err != nil {
			return
		}
		encoded, err := Encode(first)
		if err != nil {
			t.Fatalf("Encode(Parse(raw)): %v", err)
		}
		second, err := Parse(encoded)
		if err != nil {
			t.Fatalf("Parse(Encode(Parse(raw))): %v\n%s", err, encoded)
		}
		if !reflect.DeepEqual(second.WireBundle(), first.WireBundle()) {
			t.Fatalf("canonical model changed across round trip\n got: %+v\nwant: %+v", second.WireBundle(), first.WireBundle())
		}
	})
}

func TestParseDuplicateMemberRejected(t *testing.T) {
	raw := `{"format_version":1,"format_version":1,"environments":[],"key_groups":[],"keys":[]}`
	_, err := Parse([]byte(raw))
	if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicate member must be rejected: %v", err)
	}
}

func TestParseBoundsRefused(t *testing.T) {
	big := make([]byte, MaxBundleBytes+1)
	_, err := Parse(big)
	if !errors.Is(err, domain.ErrLimitExceeded) {
		t.Fatalf("oversized bundle must be ErrLimitExceeded, got %v", err)
	}
}

func TestParseRefusesNestedLiteralOnSecretKey(t *testing.T) {
	b := sampleBundle()
	b.Keys[0].Declaration = schema.Declaration{Rule: &schema.Rule{
		Type:       schema.TypeJSON,
		JSONSchema: []byte(`{"properties":{"password":{"const":"live-value"}}}`),
	}}
	_, err := Canonicalize(b)
	if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "DB_URL") ||
		!strings.Contains(err.Error(), "use `pattern`, or declassify the key") {
		t.Fatalf("secret literal canonicalization refusal = %v", err)
	}
}

func mustCanonicalize(t testing.TB, b Bundle) CanonicalBundle {
	t.Helper()
	n, err := Canonicalize(b)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	return n
}
