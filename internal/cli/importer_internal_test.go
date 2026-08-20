package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/importer"
	"github.com/Hikyo-Org/hikyo/internal/schema"
)

func TestImportCommandsRemainRoutable(t *testing.T) {
	ios := IO{
		Stderr: &bytes.Buffer{},
		Env: Env{Getenv: func(key string) string {
			if key == "HIKYO_STATE_DIR" {
				return t.TempDir()
			}
			return ""
		}},
	}

	if code := Run(t.Context(), ios, []string{"import"}); code != ExitUsage {
		t.Fatalf("hikyo import exit = %d, want %d", code, ExitUsage)
	}
	if got := ios.Stderr.(*bytes.Buffer).String(); strings.Contains(got, "unknown command") {
		t.Fatalf("hikyo import is not routed: %s", got)
	}

	ios.Stderr.(*bytes.Buffer).Reset()
	if code := Run(t.Context(), ios, []string{"values", "import"}); code != ExitUsage {
		t.Fatalf("hikyo values import exit = %d, want %d", code, ExitUsage)
	}
	if got := ios.Stderr.(*bytes.Buffer).String(); strings.Contains(got, "unknown values verb") {
		t.Fatalf("hikyo values import is not routed: %s", got)
	}
}

func TestNewStateAcceptsDoubleDotsInsidePathComponents(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hikyo..prod", "state")
	state, err := NewState(Env{Getenv: func(key string) string {
		if key == "HIKYO_STATE_DIR" {
			return dir
		}
		return ""
	}})
	if err != nil {
		t.Fatalf("valid state directory rejected: %v", err)
	}
	if state.Dir() != dir {
		t.Fatalf("state directory = %q, want %q", state.Dir(), dir)
	}
}

func TestHostileImportNamesAreEscapedOnSuccess(t *testing.T) {
	hostile := "bad\x1b[2J\x07name"
	plan := &importer.Plan{
		Renames:         []importer.Rename{{From: hostile, To: "SAFE_NAME", Transform: importer.TransformManual}},
		SkippedBySource: []string{hostile},
		Values:          importer.ValuesFile{Environment: "env_prod"},
	}
	var stdout, stderr bytes.Buffer
	err := reportImport(IO{Stdout: &stdout, Stderr: &stderr}, plan,
		"address=BAO_ADDR, token=BAO_TOKEN", "source.yaml", "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	output := stdout.String() + stderr.String()
	for _, raw := range []string{"\x1b", "\x07"} {
		if strings.Contains(output, raw) {
			t.Fatalf("success output contains raw control byte %q: %q", raw, output)
		}
	}
	if !strings.Contains(output, importer.QuoteName(hostile)) {
		t.Fatalf("success output does not contain the escaped hostile name: %q", output)
	}
	if !strings.Contains(output, "source resolution: address=BAO_ADDR, token=BAO_TOKEN") {
		t.Fatalf("success output omits live source resolution: %q", output)
	}
}

func TestFlagImportRequiresBothExplicitTargetFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"project", []string{"--from", "k8s", "--environment", "env_explicit", "--file", "export.yaml"}, "--project"},
		{"environment", []string{"--from", "k8s", "--project", "prj_explicit", "--file", "export.yaml"}, "--environment"},
		{"both", []string{"--from", "k8s", "--file", "export.yaml"}, "--project and --environment"},
		{"both before file", []string{"--from", "k8s"}, "--project and --environment"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			ios := IO{
				Stderr: &stderr,
				Env: Env{Getenv: func(key string) string {
					switch key {
					case "HIKYO_PROJECT":
						return "prj_ambient"
					case "HIKYO_ENV":
						return "env_ambient"
					}
					return ""
				}},
			}
			err := runImport(context.Background(), ios, tc.args)
			var cliErr *Error
			if !errors.As(err, &cliErr) || cliErr.Code != ExitRefused {
				t.Fatalf("err = %v, want ExitRefused", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want missing flag %q", err, tc.want)
			}
		})
	}
}

func TestLiveImportValidatesConnectorSelectorsBeforeSourceRead(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			"file and live are exclusive",
			[]string{"--from", "k8s", "--live", "--file", "export.yaml", "--project", "prj", "--environment", "env", "--namespace", "demo"},
			"either --file or --live",
		},
		{
			"sops is file only",
			[]string{"--from", "sops", "--live", "--project", "prj", "--environment", "env"},
			"file-only",
		},
		{
			"k8s requires namespace",
			[]string{"--from", "k8s", "--live", "--project", "prj", "--environment", "env"},
			"--namespace",
		},
		{
			"vault requires mount",
			[]string{"--from", "vault", "--live", "--project", "prj", "--environment", "env"},
			"--mount",
		},
		{
			"vault version is closed",
			[]string{"--from", "vault", "--live", "--project", "prj", "--environment", "env", "--mount", "secret", "--kv-version", "3"},
			"--kv-version",
		},
		{
			"k8s refuses vault selector",
			[]string{"--from", "k8s", "--live", "--project", "prj", "--environment", "env", "--namespace", "demo", "--mount", "secret"},
			"does not take",
		},
		{
			"file mode refuses live selector",
			[]string{"--from", "vault", "--file", "capture.jsonl", "--project", "prj", "--environment", "env", "--mount", "secret"},
			"file mode does not take",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := runImport(context.Background(), IO{Stderr: &bytes.Buffer{}}, tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want selector refusal containing %q", err, tc.want)
			}
		})
	}
}

func TestReplayInfersLiveModeAndSelectorsFromMapping(t *testing.T) {
	mapping := importer.Template{
		FormatVersion:            importer.FormatVersion,
		ConnectorContractVersion: importer.ConnectorContractVersion,
		Source:                   "k8s",
		Scope:                    importer.Scope{Namespace: "demo", Names: []string{"app"}},
		Project:                  "prj_reviewed",
		Environments: []importer.EnvironmentMapping{{
			Target: "env_reviewed",
		}},
		Folders:              []importer.FolderMapping{},
		Renames:              []importer.Rename{},
		Classifications:      []importer.ClassificationChoice{},
		Types:                []importer.TypeChoice{},
		Overwrites:           []importer.KeyEnvironment{},
		TrimAcknowledgements: []importer.KeyEnvironment{},
	}
	raw, err := importer.Encode(mapping)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mapping.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing-kubeconfig"))

	err = runImport(t.Context(), IO{Stderr: &bytes.Buffer{}}, []string{"--mapping", path})
	if err == nil || !strings.Contains(err.Error(), "kubeconfig") {
		t.Fatalf("err = %v, want live kubeconfig read from mapping selectors", err)
	}
	if strings.Contains(err.Error(), "--file") {
		t.Fatalf("live replay incorrectly required a file: %v", err)
	}
}

func TestReplayMappingUsesBoundedFileReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mapping.json")
	if err := os.WriteFile(path, make([]byte, importer.MaxFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runImport(context.Background(), IO{Stderr: &bytes.Buffer{}},
		[]string{"--mapping", path, "--file", "export.yaml"})
	var cliErr *Error
	if !errors.As(err, &cliErr) || cliErr.Code != ExitUsage {
		t.Fatalf("err = %v, want ExitUsage", err)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d-byte per-file cap", importer.MaxFileBytes)) {
		t.Fatalf("mapping refusal does not name the bound: %v", err)
	}
}

func TestWriteArtifactsRefusesValuesFilePhaseTwoCannotRead(t *testing.T) {
	outDir := t.TempDir()
	entries := make([]importer.ValuesEntry, 0, 65)
	for i := 0; i < cap(entries); i++ {
		entries = append(entries, importer.ValuesEntry{
			Key: fmt.Sprintf("KEY_%d", i), Value: strings.Repeat("x", importer.MaxValueBytes),
		})
	}
	plan := &importer.Plan{
		HasValues: true,
		Values: importer.ValuesFile{
			FormatVersion: importer.FormatVersion, Project: "prj_1", Environment: "env_1", Entries: entries,
		},
	}
	_, err := writeArtifacts(IO{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}, outDir, "env_1", plan)
	var cliErr *Error
	if !errors.As(err, &cliErr) || cliErr.Code != ExitRefused {
		t.Fatalf("err = %v, want ExitRefused", err)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d-byte", importer.MaxFileBytes)) {
		t.Fatalf("refusal does not name phase-2 file cap: %v", err)
	}
	for _, name := range []string{bundleFile, mappingFile, manifestFile, "values-env_1.json"} {
		if _, statErr := os.Stat(filepath.Join(outDir, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s survived refused artifact run: %v", name, statErr)
		}
	}
}

func TestWriteArtifactsEmitsCanonicalDefinitionsBundle(t *testing.T) {
	bundle, err := definitions.Normalize(definitions.Bundle{
		FormatVersion: definitions.FormatVersion,
		Environments:  []definitions.Environment{},
		KeyGroups:     []definitions.KeyGroup{},
		Keys: []definitions.Key{{
			Name: "DATABASE_URL", Classification: string(schema.Secret),
			Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}},
			RequiredIn: definitions.Presence{
				Mode: string(schema.PresenceNone), Environments: []string{},
			},
			ForbiddenIn: definitions.Presence{
				Mode: string(schema.PresenceNone), Environments: []string{},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	if _, err := writeArtifacts(IO{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}, outDir, "env_1", &importer.Plan{Bundle: bundle}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(outDir, bundleFile))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := definitions.Parse(raw)
	if err != nil {
		t.Fatalf("emitted definitions-bundle.json is not canonical bundle input: %v\n%s", err, raw)
	}
	if !parsed.Additive() || len(parsed.Keys) != 1 || parsed.Keys[0].Name != "DATABASE_URL" {
		t.Fatalf("emitted bundle = %+v", parsed)
	}
	want, err := definitions.Encode(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatalf("emitted bundle is not canonical:\n%s\nwant:\n%s", raw, want)
	}
}

func TestValuesImportBindsArtifactToProjectAndEnvironment(t *testing.T) {
	values := importer.ValuesFile{Project: "prj_reviewed", Environment: "env_reviewed"}
	for _, tc := range []struct {
		name    string
		project string
		env     string
		want    string
	}{
		{name: "project", project: "prj_other", env: "env_reviewed", want: "project"},
		{name: "environment", project: "prj_reviewed", env: "env_other", want: "environment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateImportArtifactTargets(values, tc.project, tc.env)
			var cliErr *Error
			if !errors.As(err, &cliErr) || cliErr.Code != ExitRefused {
				t.Fatalf("err = %v, want ExitRefused", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal does not name %s mismatch: %v", tc.want, err)
			}
		})
	}
}

func TestMarkImportedReplacesSymlinkWithoutTouchingTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("atomic symlink replacement is a POSIX contract")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "reviewed.json")
	link := filepath.Join(dir, "run-manifest.json")
	original := testManifest(t)
	if err := os.WriteFile(target, original, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := markImported(link, "env_prod"); err != nil {
		t.Fatal(err)
	}

	targetAfter, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(targetAfter, original) {
		t.Fatal("the symlink target was overwritten")
	}
	linkInfo, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if !linkInfo.Mode().IsRegular() {
		t.Fatalf("manifest entry mode = %s, want a regular replacement", linkInfo.Mode())
	}
	if linkInfo.Mode().Perm() != 0o640 {
		t.Fatalf("replacement mode = %o, want 640", linkInfo.Mode().Perm())
	}
	replacement, err := importer.ReadFile(link)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := importer.ParseManifest(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.PhaseCompletion.Imported["env_prod"] {
		t.Fatal("replacement manifest does not record the completed import")
	}
}

func TestMarkImportedWriteFailureLeavesOriginalIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run-manifest.json")
	original := testManifest(t)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	err := markImportedWithWriter(path, "env_prod", func(*os.File, []byte) error {
		return errors.New("simulated temp write failure")
	})
	if err == nil || !strings.Contains(err.Error(), "simulated temp write failure") {
		t.Fatalf("err = %v, want simulated write failure", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("failed temp write changed the original manifest")
	}
}

func testManifest(t *testing.T) []byte {
	t.Helper()
	raw, err := importer.Encode(importer.Manifest{
		FormatVersion:            importer.FormatVersion,
		ConnectorContractVersion: importer.ConnectorContractVersion,
		Target: importer.Target{
			Project:      "prj_test",
			Environments: []string{"env_prod"},
		},
		PhaseCompletion: importer.PhaseCompletion{Imported: map[string]bool{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
