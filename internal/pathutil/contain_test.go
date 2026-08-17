package pathutil

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestResolveWithinRejectsSymlinkEscape(t *testing.T) {
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
	if _, ok := ResolveWithin(root, link); ok {
		t.Fatal("symlink target outside the root was accepted")
	}
}
