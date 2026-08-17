package pathutil

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWithinUsesPathComponentBoundaries(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	if !Within(root, filepath.Join(root, "..prod", "file.sql")) {
		t.Fatal("ordinary double dots inside a child component were rejected")
	}
	if Within(root, filepath.Join(root, "..", "outside", "file.sql")) {
		t.Fatal("parent traversal escaped the root")
	}
	if Within(root, root+"-sibling") {
		t.Fatal("sibling sharing the root's string prefix was accepted")
	}
}

func TestReadFileWithinRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not reliably available on Windows")
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.sql")
	if err := os.WriteFile(outside, []byte("SELECT 1;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "inside.sql")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFileWithin(root, link); err == nil {
		t.Fatal("symlink target outside the root was read")
	}
}

func TestReadFileWithinAcceptsDoubleDotsInsideComponents(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root..prod")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "..safe.sql")
	want := []byte("SELECT 1;\n")
	if err := os.WriteFile(target, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFileWithin(root, target)
	if err != nil {
		t.Fatalf("valid dotted path rejected: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("read %q, want %q", got, want)
	}
}

func TestReadFileWithinPreservesErrorCauseAndOperation(t *testing.T) {
	root := t.TempDir()
	missingRoot := filepath.Join(t.TempDir(), "missing")
	tests := []struct {
		name       string
		root       string
		target     string
		wantCause  error
		wantDetail string
	}{
		{
			name:       "root open",
			root:       missingRoot,
			target:     filepath.Join(missingRoot, "query.sql"),
			wantCause:  os.ErrNotExist,
			wantDetail: "open root",
		},
		{
			name:       "target read",
			root:       root,
			target:     filepath.Join(root, "missing.sql"),
			wantCause:  os.ErrNotExist,
			wantDetail: "read target",
		},
		{
			name:       "lexical escape",
			root:       root,
			target:     filepath.Join(root, "..", "outside.sql"),
			wantCause:  os.ErrInvalid,
			wantDetail: "escapes root",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadFileWithin(tt.root, tt.target)
			if !errors.Is(err, tt.wantCause) {
				t.Fatalf("error = %v, want cause %v", err, tt.wantCause)
			}
			if !strings.Contains(err.Error(), tt.wantDetail) {
				t.Fatalf("error = %q, want operation %q", err, tt.wantDetail)
			}
		})
	}
}

func TestReadFileWithinPreservesPermissionError(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits are not enforceable in this environment")
	}
	root := t.TempDir()
	target := filepath.Join(root, "private.sql")
	if err := os.WriteFile(target, []byte("SELECT 1;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(target, 0o600) })

	_, err := ReadFileWithin(root, target)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("error = %v, want permission cause", err)
	}
	if !strings.Contains(err.Error(), "read target") {
		t.Fatalf("error = %q, want read operation", err)
	}
}
