package fixtureref

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAcceptsQualifiedPlaywrightReference(t *testing.T) {
	root := playwrightFixtureRepository(t, map[string]string{
		"web/e2e/flows/example.spec.ts": `import { test as scenario } from '@playwright/test';

scenario.describe('example', () => {
  scenario('exact static title', async ({ page }) => {});
});
`,
	})

	err := Validate(root, []FixtureRef{{
		Package:  "web",
		File:     "e2e/flows/example.spec.ts",
		TestName: "exact static title",
		Kind:     KindPlaywrightTest,
	}})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsMisqualifiedPlaywrightReferences(t *testing.T) {
	root := playwrightFixtureRepository(t, map[string]string{
		"web/e2e/flows/actual.spec.ts": `import { test } from '@playwright/test';
test('same title', async () => {});
`,
		"web/e2e/flows/expected.spec.ts": `import { test } from '@playwright/test';
test('different title', async () => {});
`,
		"web/e2e/flows/dynamic.spec.ts": `import { test } from '@playwright/test';
test(` + "`case ${variant}`" + `, async () => {});
`,
	})

	tests := []struct {
		name string
		ref  FixtureRef
		want string
	}{
		{
			name: "same title in wrong file",
			ref:  FixtureRef{Package: "web", File: "e2e/flows/expected.spec.ts", TestName: "same title", Kind: KindPlaywrightTest},
			want: "not found",
		},
		{
			name: "missing file qualification",
			ref:  FixtureRef{Package: "web", TestName: "same title", Kind: KindPlaywrightTest},
			want: "requires File",
		},
		{
			name: "dynamic title",
			ref:  FixtureRef{Package: "web", File: "e2e/flows/dynamic.spec.ts", TestName: "case dark", Kind: KindPlaywrightTest},
			want: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(root, []FixtureRef{tt.ref})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate(%+v) error = %v, want substring %q", tt.ref, err, tt.want)
			}
		})
	}
}

func TestValidateRejectsPlaywrightSourceLookalikes(t *testing.T) {
	root := playwrightFixtureRepository(t, map[string]string{
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
			err := Validate(root, []FixtureRef{{Package: "web", File: tt.file, TestName: tt.title, Kind: KindPlaywrightTest}})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate(%q) error = %v, want substring %q", tt.title, err, tt.want)
			}
		})
	}
}

func playwrightFixtureRepository(t *testing.T, files map[string]string) string {
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
