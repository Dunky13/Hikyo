package lint

import (
	"fmt"
	"go/types"
	"strings"

	"golang.org/x/tools/go/packages"
)

// driverHandles are the store's raw driver-handle accessors. They exist for
// the transaction package (which must speak to the engine to open a
// transaction) and the test harnesses (fixture seeding, query-count
// instrumentation) — Go has no friend packages, so the accessors are
// exported and this check is what keeps them narrow.
//
// Without it the whole chokepoint is bypassable in one line: any package
// holding a *store.DB could run `pggen.New(db.PG()).GetEnvironment(...)` (or
// raw SQL) with caller-controlled chain values and no proof at all. The
// proof-signature analyzer only sees the repository interfaces and the SQL
// analyzer only sees the query text, so every other guardrail stays green.
var driverHandles = map[string]bool{
	"PG": true, "SQLiteWrite": true, "SQLiteRead": true,
}

// handleUsers is the exact allowlist of packages permitted to touch a raw
// driver handle. Additions are architecture decisions, not conveniences.
var handleUsers = map[string]bool{
	Module + "/internal/store":            true, // defines them
	Module + "/internal/store/tx":         true, // owns the transaction boundary
	Module + "/internal/conformance":      true, // cross-engine fixtures
	Module + "/internal/isolation":        true, // probe fixtures + instrumentation
	Module + "/internal/conformance_test": true,
	Module + "/internal/isolation_test":   true,
}

// generatedPackages are the sqlc outputs. Reaching them directly is the same
// bypass as a raw handle: generated queries take chain parameters as plain
// values, so a caller that can call them can pass any tenant's chain.
var generatedPackages = map[string]bool{
	Module + "/internal/store/sqlitegen": true,
	Module + "/internal/store/pggen":     true,
}

// generatedImporters may import the sqlc outputs.
var generatedImporters = map[string]bool{
	Module + "/internal/store":           true, // the binding layer
	Module + "/internal/store/authn":     true, // the resolution surface
	Module + "/internal/store/sqlitegen": true,
	Module + "/internal/store/pggen":     true,
	Module + "/internal/isolation":       true, // DBTX instrumentation (tests)
	Module + "/internal/boundary":        true, // names them as strings only
}

// CheckDriverHandles enforces both allowlists across the module, test
// packages included — a bypass in a test is still a bypass of the property
// the tests exist to prove.
func CheckDriverHandles(pkgs []*packages.Package) []string {
	var findings []string
	for _, p := range flatten(pkgs) {
		if !strings.HasPrefix(p.PkgPath, Module+"/") && p.PkgPath != Module {
			continue
		}
		base := strings.TrimSuffix(p.PkgPath, ".test")
		if p.TypesInfo == nil {
			continue
		}
		if !handleUsers[base] {
			for ident, obj := range p.TypesInfo.Uses {
				fn, ok := obj.(*types.Func)
				if !ok || !driverHandles[fn.Name()] {
					continue
				}
				if fn.Pkg() == nil || fn.Pkg().Path() != Module+"/internal/store" {
					continue
				}
				sig, ok := fn.Type().(*types.Signature)
				if !ok || sig.Recv() == nil {
					continue
				}
				findings = append(findings, fmt.Sprintf(
					"handles: %s: %s calls store.DB.%s — a raw driver handle bypasses the proof boundary entirely",
					p.Fset.Position(ident.Pos()), base, fn.Name()))
			}
		}
		if generatedImporters[base] {
			continue
		}
		for imp := range p.Imports {
			if generatedPackages[imp] {
				findings = append(findings, fmt.Sprintf(
					"handles: %s imports %s — generated queries take chain parameters as plain values; go through the store's binding layer",
					base, imp))
			}
		}
	}
	return findings
}
