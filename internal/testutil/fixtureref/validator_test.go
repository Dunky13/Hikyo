package fixtureref

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAcceptsQualifiedExecutableReferences(t *testing.T) {
	root := fixtureModule(t)

	err := Validate(root, []FixtureRef{
		{Package: "example.test/fixtures/alpha", TestName: "TestTop", Kind: KindTest},
		{Package: "example.test/fixtures/alpha", TestName: "fixtureHelper", Kind: KindHelper},
		{Package: "example.test/fixtures/alpha", TestName: "TestTop/nested/leaf", Kind: KindSubtest},
		{Package: "example.test/fixtures/alpha", TestName: "TestTagged", Kind: KindTest},
	})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsInvalidReferences(t *testing.T) {
	root := fixtureModule(t)
	tests := []struct {
		name string
		refs []FixtureRef
		want string
	}{
		{
			name: "missing or renamed",
			refs: []FixtureRef{{Package: "example.test/fixtures/alpha", TestName: "TestRenamed", Kind: KindTest}},
			want: "not found",
		},
		{
			name: "same name in wrong package",
			refs: []FixtureRef{{Package: "example.test/fixtures/beta", TestName: "TestTop", Kind: KindTest}},
			want: "not found",
		},
		{
			name: "wrong kind",
			refs: []FixtureRef{{Package: "example.test/fixtures/alpha", TestName: "fixtureHelper", Kind: KindTest}},
			want: "exists as helper",
		},
		{
			name: "test-shaped helper with wrong signature",
			refs: []FixtureRef{{Package: "example.test/fixtures/alpha", TestName: "TestWrongSignature", Kind: KindTest}},
			want: "exists as helper",
		},
		{
			name: "duplicate reference",
			refs: []FixtureRef{
				{Package: "example.test/fixtures/alpha", TestName: "TestTop", Kind: KindTest},
				{Package: "example.test/fixtures/alpha", TestName: "TestTop", Kind: KindTest},
			},
			want: "duplicate fixture reference",
		},
		{
			name: "dynamic subtest",
			refs: []FixtureRef{{Package: "example.test/fixtures/alpha", TestName: "TestTop/dynamic", Kind: KindSubtest}},
			want: "not found",
		},
		{
			name: "unrelated run method",
			refs: []FixtureRef{{Package: "example.test/fixtures/alpha", TestName: "TestTop/not-a-subtest", Kind: KindSubtest}},
			want: "not found",
		},
		{
			name: "shadowed testing receiver",
			refs: []FixtureRef{{Package: "example.test/fixtures/alpha", TestName: "TestTop/shadowed", Kind: KindSubtest}},
			want: "not found",
		},
		{
			name: "invalid lowercase test name",
			refs: []FixtureRef{{Package: "example.test/fixtures/alpha", TestName: "Testlowercase", Kind: KindTest}},
			want: "exists as helper",
		},
		{
			name: "test with results",
			refs: []FixtureRef{{Package: "example.test/fixtures/alpha", TestName: "TestWithResult", Kind: KindTest}},
			want: "exists as helper",
		},
		{
			name: "test with grouped parameters",
			refs: []FixtureRef{{Package: "example.test/fixtures/alpha", TestName: "TestGroupedParameters", Kind: KindTest}},
			want: "exists as helper",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(root, tt.refs)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func fixtureModule(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFixtureFile(t, root, "go.mod", "module example.test/fixtures\n\ngo 1.25\n")
	writeFixtureFile(t, root, "alpha/alpha.go", "package alpha\n")
	writeFixtureFile(t, root, "alpha/alpha_test.go", `package alpha

import (
	"fmt"
	"testing"
)

func TestTop(t *testing.T) {
	t.Run("nested", func(t *testing.T) {
		t.Run("leaf", func(t *testing.T) {})
	})
	var runner customRunner
	runner.Run("not-a-subtest", func(t *testing.T) {})
	{
		t := customRunner{}
		t.Run("shadowed", func(t *testing.T) {})
	}
	for i := range 1 {
		t.Run(fmt.Sprintf("dynamic-%d", i), func(t *testing.T) {})
	}
}

func fixtureHelper(t *testing.T) { t.Helper() }

type customRunner struct{}

func (customRunner) Run(string, func(*testing.T)) {}
`)
	writeFixtureFile(t, root, "alpha/tagged_test.go", `//go:build fixturetag

package alpha

import "testing"

func TestTagged(t *testing.T) {}

type T struct{}

func TestWrongSignature(t *T) {}

func Testlowercase(t *testing.T) {}

func TestWithResult(t *testing.T) bool { return true }

func TestGroupedParameters(a, b *testing.T) {}
`)
	writeFixtureFile(t, root, "beta/beta.go", "package beta\n")
	writeFixtureFile(t, root, "beta/beta_test.go", `package beta

import "testing"

func TestTopElsewhere(t *testing.T) {}
`)
	return root
}

func writeFixtureFile(t *testing.T, root, name, contents string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}
