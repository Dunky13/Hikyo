package migrate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalPathResolvesSymlinkAliases(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.db")
	if err := os.WriteFile(real, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias.db")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	cReal, err := canonicalPath(real)
	if err != nil {
		t.Fatal(err)
	}
	cAlias, err := canonicalPath(alias)
	if err != nil {
		t.Fatal(err)
	}
	if cReal != cAlias {
		t.Fatalf("alias and real path must contend on one lock: %q vs %q", cAlias, cReal)
	}
}

func TestCanonicalPathWorksForMissingFile(t *testing.T) {
	dir := t.TempDir()
	got, err := canonicalPath(filepath.Join(dir, "not-yet.db"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "not-yet.db" {
		t.Fatalf("got %q", got)
	}
}
