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

	"github.com/Dunky13/hikyo/internal/importer"
)

func TestHostileImportNamesAreEscapedOnSuccess(t *testing.T) {
	hostile := "bad\x1b[2J\x07name"
	plan := &importer.Plan{
		Renames:         []importer.Rename{{From: hostile, To: "SAFE_NAME", Transform: importer.TransformManual}},
		SkippedBySource: []string{hostile},
		Values:          importer.ValuesFile{Environment: "env_prod"},
	}
	var stdout, stderr bytes.Buffer
	err := reportImport(IO{Stdout: &stdout, Stderr: &stderr}, plan,
		"source.yaml", "", t.TempDir())
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
