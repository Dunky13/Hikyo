// Package boundary enforces the import direction fixed in the
// system-architecture ADR: internal/store is importable only by
// internal/service (and store's own subpackages plus the wiring layer);
// handlers never import store; store never imports upward.
package boundary

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

const module = "github.com/Dunky13/wenv"

// storeImporters is the exact allowlist of packages permitted to import
// internal/store or its subpackages. Additions here are architecture
// decisions, not conveniences.
var storeImporters = map[string]bool{
	module + "/internal/service":         true,
	module + "/internal/app":             true, // construction wiring only
	module + "/internal/store":           true,
	module + "/internal/store/tx":        true,
	module + "/internal/store/migrate":   true,
	module + "/internal/store/sqlitegen": true,
	module + "/internal/store/pggen":     true,
	module + "/internal/conformance":     true, // cross-engine test harness
}

// forbidden direct edges: importer prefix -> banned import prefix.
var forbidden = []struct{ importer, imports, why string }{
	{module + "/internal/server", module + "/internal/store", "handlers cannot reach the datastore directly"},
	{module + "/internal/store", module + "/internal/service", "dependency direction is service→store"},
	{module + "/internal/store", module + "/internal/server", "store never imports the HTTP layer"},
	{module + "/cmd/", module + "/internal/store", "main wires through internal/app, not store"},
	{module + "/internal/config", module + "/internal/", "config is a leaf package"},
}

type pkg struct {
	ImportPath   string
	Imports      []string
	TestImports  []string
	XTestImports []string
}

func loadPackages(t *testing.T) []pkg {
	t.Helper()
	out, err := exec.Command("go", "list", "-json", module+"/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var pkgs []pkg
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p pkg
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decode go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		t.Fatal("go list returned no packages")
	}
	return pkgs
}

// allImports covers production and test imports alike — a test file in
// internal/server reaching into store is the same boundary breach.
func allImports(p pkg) []string {
	out := make([]string, 0, len(p.Imports)+len(p.TestImports)+len(p.XTestImports))
	out = append(out, p.Imports...)
	out = append(out, p.TestImports...)
	out = append(out, p.XTestImports...)
	return out
}

func TestStoreImportAllowlist(t *testing.T) {
	for _, p := range loadPackages(t) {
		for _, imp := range allImports(p) {
			if imp == module+"/internal/store" || strings.HasPrefix(imp, module+"/internal/store/") {
				if !storeImporters[p.ImportPath] {
					t.Errorf("%s imports %s: not on the store-importer allowlist", p.ImportPath, imp)
				}
			}
		}
	}
}

func TestForbiddenEdges(t *testing.T) {
	for _, p := range loadPackages(t) {
		for _, rule := range forbidden {
			if !strings.HasPrefix(p.ImportPath, rule.importer) {
				continue
			}
			for _, imp := range allImports(p) {
				if strings.HasPrefix(imp, rule.imports) {
					t.Errorf("%s imports %s: %s", p.ImportPath, imp, rule.why)
				}
			}
		}
	}
}
