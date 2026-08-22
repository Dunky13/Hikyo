package fixtureref

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAcceptsQualifiedExecutableFixtures(t *testing.T) {
	root := fixtureRepository(t, map[string]string{
		"internal/example/example.go": `package example
`,
		"internal/example/example_test.go": `package example

import "testing"

func TestTopLevel(t *testing.T) {
	t.Run("child", func(t *testing.T) {
		t.Run("grandchild", func(t *testing.T) {})
	})
	name := "dynamic"
	t.Run(name, func(t *testing.T) {})
}

func BenchmarkExample(b *testing.B) {}
func runExample(t *testing.T, value string) {}
`,
		"web/e2e/flows/example.spec.ts": `import { test } from '@playwright/test';

test.describe('example', () => {
  test('exact static title', async ({ page }) => {});
});
`,
	})

	refs := []FixtureRef{
		{Package: "internal/example", TestName: "TestTopLevel", Kind: GoTest},
		{Package: "internal/example", TestName: "BenchmarkExample", Kind: GoBenchmark},
		{Package: "internal/example", TestName: "runExample", Kind: GoHelper},
		{Package: "internal/example", TestName: "TestTopLevel/child/grandchild", Kind: GoSubtest},
		{Package: "web", File: "e2e/flows/example.spec.ts", TestName: "exact static title", Kind: PlaywrightTest},
	}

	for _, ref := range refs {
		if err := Validate(root, ref); err != nil {
			t.Errorf("Validate(%+v) returned %v", ref, err)
		}
	}
}

func TestValidateRejectsStaleOrMisqualifiedReferences(t *testing.T) {
	root := fixtureRepository(t, map[string]string{
		"internal/expected/expected.go": `package expected
`,
		"internal/expected/actual_test.go": `package expected

import "testing"

func TestRenamed(t *testing.T) {
	name := "dynamic"
	t.Run(name, func(t *testing.T) {})
}
func helperOnly(t *testing.T) {}
`,
		"internal/expected/external_test.go": `package expected_test

import "testing"

func TestExternalOnly(t *testing.T) {}
`,
		"internal/elsewhere/elsewhere.go": `package elsewhere
`,
		"internal/elsewhere/same_test.go": `package elsewhere

import "testing"

func TestMissing(t *testing.T) {}
`,
		"web/e2e/flows/actual.spec.ts": `import { test } from '@playwright/test';
test('same title', async () => {});
`,
		"web/e2e/flows/expected.spec.ts": `import { test } from '@playwright/test';
test('different title', async () => {});
`,
	})

	tests := []struct {
		name string
		ref  FixtureRef
		want string
	}{
		{
			name: "renamed function",
			ref:  FixtureRef{Package: "internal/expected", TestName: "TestOldName", Kind: GoTest},
			want: "not found",
		},
		{
			name: "same name in wrong package",
			ref:  FixtureRef{Package: "internal/expected", TestName: "TestMissing", Kind: GoTest},
			want: "internal/expected",
		},
		{
			name: "same directory external test package",
			ref:  FixtureRef{Package: "internal/expected", TestName: "TestExternalOnly", Kind: GoTest},
			want: "not found",
		},
		{
			name: "same function in wrong file",
			ref:  FixtureRef{Package: "internal/expected", File: "expected_test.go", TestName: "TestRenamed", Kind: GoTest},
			want: "expected_test.go",
		},
		{
			name: "helper referenced as test",
			ref:  FixtureRef{Package: "internal/expected", TestName: "helperOnly", Kind: GoTest},
			want: "wrong kind",
		},
		{
			name: "dynamic Go subtest title",
			ref:  FixtureRef{Package: "internal/expected", TestName: "TestRenamed/dynamic", Kind: GoSubtest},
			want: "not found",
		},
		{
			name: "same title in wrong Playwright file",
			ref:  FixtureRef{Package: "web", File: "e2e/flows/expected.spec.ts", TestName: "same title", Kind: PlaywrightTest},
			want: "not found",
		},
		{
			name: "missing Playwright file qualification",
			ref:  FixtureRef{Package: "web", TestName: "same title", Kind: PlaywrightTest},
			want: "requires File",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(root, tt.ref)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate(%+v) error = %v, want substring %q", tt.ref, err, tt.want)
			}
		})
	}
}

func TestValidateRejectsDynamicPlaywrightTitles(t *testing.T) {
	root := fixtureRepository(t, map[string]string{
		"web/e2e/flows/dynamic.spec.ts": "import { test } from '@playwright/test';\ntest(`case ${variant}`, async () => {});\n",
	})

	err := Validate(root, FixtureRef{
		Package:  "web",
		File:     "e2e/flows/dynamic.spec.ts",
		TestName: "case dark",
		Kind:     PlaywrightTest,
	})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("Validate(dynamic title) error = %v, want not found", err)
	}
}

func TestValidateRejectsNonPlaywrightAndNonExecutableTitleLookalikes(t *testing.T) {
	root := fixtureRepository(t, map[string]string{
		"web/e2e/flows/lookalikes.spec.ts": `import { test } from '@playwright/test';

const pattern = /test('regex ghost')/;
if (ready) /test('control regex ghost')/.test(value);
const text = "test('string ghost')";
// test('comment ghost', async () => {});
test.skip('skipped ghost', async () => {});
`,
		"web/e2e/flows/local.spec.ts": `function test(title: string, body: () => void) {
  body();
}
test('local ghost', () => {});
`,
		"web/e2e/flows/shadowed.spec.ts": `import { test } from '@playwright/test';

function helper() {
  const test = localTest;
  test('shadowed ghost', () => {});
}
`,
	})

	tests := []struct {
		file  string
		title string
		want  string
	}{
		{file: "e2e/flows/lookalikes.spec.ts", title: "regex ghost", want: "not found"},
		{file: "e2e/flows/lookalikes.spec.ts", title: "control regex ghost", want: "not found"},
		{file: "e2e/flows/lookalikes.spec.ts", title: "string ghost", want: "not found"},
		{file: "e2e/flows/lookalikes.spec.ts", title: "comment ghost", want: "not found"},
		{file: "e2e/flows/lookalikes.spec.ts", title: "skipped ghost", want: "not found"},
		{file: "e2e/flows/local.spec.ts", title: "local ghost", want: "does not import"},
		{file: "e2e/flows/shadowed.spec.ts", title: "shadowed ghost", want: "shadowed"},
	}

	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			err := Validate(root, FixtureRef{Package: "web", File: tt.file, TestName: tt.title, Kind: PlaywrightTest})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate(%q) error = %v, want substring %q", tt.title, err, tt.want)
			}
		})
	}
}

func fixtureRepository(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, contents := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("creating fixture directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("writing fixture %s: %v", name, err)
		}
	}
	return root
}
