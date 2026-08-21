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
	norm, err := Normalize(sampleBundle())
	if err != nil {
		t.Fatalf("normalize: %v", err)
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
	if !reflect.DeepEqual(parsed, norm) {
		t.Fatalf("Parse(Encode(b)) != b\n got: %+v\nwant: %+v", parsed, norm)
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
	norm := mustNormalize(t, sampleBundle())
	raw, err := Encode(norm)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCompiled(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed.Bundle, norm) {
		t.Fatalf("ParseCompiled bundle differs\n got: %+v\nwant: %+v", parsed.Bundle, norm)
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
	norm, _ := Normalize(sampleBundle())
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
	canonical, err := Encode(mustNormalize(t, b))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(canonical)
	if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "ids without base revision") {
		t.Fatalf("ids-without-base must be rejected: %v", err)
	}
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
	raw, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(raw)
	if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "DB_URL") ||
		!strings.Contains(err.Error(), "use `pattern`, or declassify the key") {
		t.Fatalf("secret literal parse refusal = %v", err)
	}
}

func mustNormalize(t *testing.T, b Bundle) Bundle {
	t.Helper()
	n, err := Normalize(b)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return n
}
