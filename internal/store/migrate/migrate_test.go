package migrate

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Dunky13/hikyo/internal/store"
)

func TestEmbeddedMigrationVersionsAreUnique(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			dir := "migrations/" + dialect
			entries, err := fs.ReadDir(store.MigrationsFS, dir)
			if err != nil {
				t.Fatal(err)
			}

			versions := make(map[int64]string, len(entries))
			for _, entry := range entries {
				prefix, _, ok := strings.Cut(entry.Name(), "_")
				if !ok {
					t.Fatalf("migration %q has no numeric version prefix", entry.Name())
				}
				version, err := strconv.ParseInt(prefix, 10, 64)
				if err != nil {
					t.Fatalf("migration %q has invalid version: %v", entry.Name(), err)
				}
				if previous, exists := versions[version]; exists {
					t.Fatalf("duplicate migration version %d: %s and %s", version, previous, entry.Name())
				}
				versions[version] = entry.Name()
			}
		})
	}
}

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
