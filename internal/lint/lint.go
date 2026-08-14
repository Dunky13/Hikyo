// Package lint holds the three custom static analyzers the tenant-isolation
// ADR fixes (proof signatures, SQL predicate confinement, proof-forgery
// guard). They run against the real repository from this package's tests, so
// a violation is a build failure in CI. Each is a guardrail with its evasion
// limits stated in the ADR — logic bugs inside the trusted set are review's
// job, not lint's.
//
// The ADR sketches these as go/analysis passes; they are implemented
// directly over go/packages type information instead — same inputs, same
// build-failing effect, less framework. The checks return findings as
// strings so the tests (and the invariant suite) can assert emptiness and
// print every violation at once.
package lint

import (
	"fmt"
	"sync"

	"golang.org/x/tools/go/packages"
)

// Module is the module path the analyzers reason about.
const Module = "github.com/Hikyo-Org/hikyo"

var (
	loadOnce sync.Once
	loaded   []*packages.Package
	loadErr  error
)

// LoadRepo loads every package in the module, with syntax and type
// information, exactly once per test process.
func LoadRepo() ([]*packages.Package, error) {
	loadOnce.Do(func() {
		loaded, loadErr = Load(Module + "/...")
	})
	return loaded, loadErr
}

// Load loads arbitrary patterns (the negative-fixture tests use it on
// testdata packages).
func Load(patterns ...string) ([]*packages.Package, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		// Test packages are in scope: a forged proof in a test outside authz
		// is the same breach as one in production code.
		Tests: true,
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}
	for _, p := range pkgs {
		for _, e := range p.Errors {
			return nil, fmt.Errorf("load %s: %s", p.PkgPath, e)
		}
	}
	return pkgs, nil
}
