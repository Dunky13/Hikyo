package v1alpha1_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCRDManifestsAreFresh regenerates the CRD YAML into a temp dir with the
// pinned controller-gen and diffs it against the committed chart/hikyo/crds.
// Drift fails a normal `go test`, so a marker change that is not re-generated is
// caught without waiting for the CI `generated` job (which runs the same
// scripts/gen-crds.sh and a git-diff). controller-gen is the `go tool` pin, so
// the version is reproducible.
func TestCRDManifestsAreFresh(t *testing.T) {
	root := repoRoot(t)
	committed := filepath.Join(root, "chart", "hikyo", "crds")

	tmp := t.TempDir()
	cmd := exec.Command("go", "tool", "controller-gen",
		"crd",
		"paths=./internal/operator/api/v1alpha1/...",
		"output:crd:dir="+tmp,
	)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("controller-gen failed: %v\n%s", err, out)
	}

	fresh, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("read regenerated dir: %v", err)
	}
	if len(fresh) == 0 {
		t.Fatal("controller-gen produced no CRD files")
	}

	seen := map[string]bool{}
	for _, e := range fresh {
		seen[e.Name()] = true
		want, err := os.ReadFile(filepath.Join(tmp, e.Name()))
		if err != nil {
			t.Fatalf("read regenerated %s: %v", e.Name(), err)
		}
		got, err := os.ReadFile(filepath.Join(committed, e.Name()))
		if err != nil {
			t.Fatalf("committed CRD %s missing or unreadable (run scripts/gen-crds.sh): %v", e.Name(), err)
		}
		if string(got) != string(want) {
			t.Errorf("chart/hikyo/crds/%s is stale; run scripts/gen-crds.sh and commit the result", e.Name())
		}
	}

	// A committed CRD with no regenerated counterpart is also drift (a removed
	// kind whose file lingers).
	committedEntries, err := os.ReadDir(committed)
	if err != nil {
		t.Fatalf("read committed crds dir: %v", err)
	}
	for _, e := range committedEntries {
		if !seen[e.Name()] {
			t.Errorf("chart/hikyo/crds/%s has no generated counterpart; remove it or run scripts/gen-crds.sh", e.Name())
		}
	}
}

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate module root (no go.mod found walking up)")
		}
		dir = parent
	}
}
