package lint

import (
	"fmt"
	"go/token"
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
	Module + "/internal/store/migrate":    true, // opens its own connection for DDL
	Module + "/internal/store/sqlitegen":  true, // generated: it IS the driver layer
	Module + "/internal/store/pggen":      true, // generated: it IS the driver layer
	Module + "/internal/store_test":       true, // external store harness: runtime durability/state assertions
	Module + "/internal/conformance":      true, // cross-engine fixtures
	Module + "/internal/isolation":        true, // probe fixtures + instrumentation
	Module + "/internal/conformance_test": true,
	Module + "/internal/isolation_test":   true,
}

// driverTypes are the concrete engine handles. Naming one at all — in a
// signature, a field, a local, or a locally-declared interface method — is
// what the accessor check alone cannot see: a package can declare
// `interface{ PG() *pgxpool.Pool }`, accept a *store.DB through it, and call
// PG() on the LOCAL interface, so the selector never resolves to the store's
// method. Requiring that non-allowlisted packages cannot even name these
// types closes that escape and the type-assertion variant with it, because
// both must write the driver type somewhere.
//
// Honest limit, stated: a package inside the allowlist could still hand out
// a wrapper whose methods run queries behind a driver-free interface. That
// is a trusted-set change — the allowlist is the trusted set — and gets
// adversarial review depth, not lint.
// Keyed by the NAMED type, not its pointer spelling: matching "*pkg.Pool"
// as a string misses `*pool` where `type pool = pgxpool.Pool`, and misses a
// value-typed occurrence entirely.
var driverTypes = map[string]bool{
	"github.com/jackc/pgx/v5/pgxpool.Pool": true,
	"github.com/jackc/pgx/v5/pgxpool.Conn": true,
	"github.com/jackc/pgx/v5.Tx":           true,
	"github.com/jackc/pgx/v5.Conn":         true,
	"database/sql.DB":                      true,
	"database/sql.Tx":                      true,
	"database/sql.Conn":                    true,
}

// namedKey is a named type's stable identity, independent of how any use
// site spells it (pointer, alias, generic instantiation).
func namedKey(n *types.Named) string {
	obj := n.Obj()
	if obj == nil || obj.Pkg() == nil {
		return ""
	}
	return obj.Pkg().Path() + "." + obj.Name()
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
	Module + "/internal/store/auditrow":  true, // shared audit Row→params mapping
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
			// Naming a driver type at all: catches the structural-interface
			// and type-assertion escapes, where the accessor call resolves to
			// a locally declared method rather than the store's.
			reported := map[string]bool{}
			report := func(pos token.Pos, named string) {
				if named == "" {
					return
				}
				at := p.Fset.Position(pos)
				key := named + "@" + at.String()
				if reported[key] {
					return
				}
				reported[key] = true
				findings = append(findings, fmt.Sprintf(
					"handles: %s: %s names driver type %s — only the transaction boundary and the harnesses may hold engine handles",
					at, base, named))
			}
			for ident, obj := range p.TypesInfo.Defs {
				if obj == nil || ident == nil {
					continue
				}
				report(ident.Pos(), mentionsDriverType(obj.Type(), map[types.Type]bool{}))
			}
			// Declarations alone miss types that exist only as expressions:
			// an inline type assertion, and a generic instantiation like
			// holder[*pgxpool.Pool] whose declaration carries only the type
			// parameter. Expression types close both.
			for expr, tv := range p.TypesInfo.Types {
				if expr == nil {
					continue
				}
				report(expr.Pos(), mentionsDriverType(tv.Type, map[types.Type]bool{}))
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

// mentionsDriverType reports the first driver type reachable from t —
// through signatures, interface methods, struct fields, and the usual
// composite types — or "" if none is.
func mentionsDriverType(t types.Type, seen map[types.Type]bool) string {
	if t == nil || seen[t] {
		return ""
	}
	seen[t] = true
	// Unwrap aliases: `type pool = pgxpool.Pool` would otherwise make
	// `interface{ PG() *pool }` invisible to both the String() match and the
	// module-scope guard below.
	if u := types.Unalias(t); u != t {
		return mentionsDriverType(u, seen)
	}
	switch u := t.(type) {
	case *types.Named:
		if key := namedKey(u); driverTypes[key] {
			return key
		}
		// Named driver types are matched by String() above. Descend only into
		// interfaces declared in THIS module: that is where a structural
		// escape would have to be written, and it keeps the walk out of the
		// driver libraries' own type graphs, where nearly every interface
		// transitively exposes a *pgx.Conn and would flag every legitimate
		// holder of a generated Queries value.
		obj := u.Obj()
		if obj == nil || obj.Pkg() == nil || !strings.HasPrefix(obj.Pkg().Path(), Module) {
			return ""
		}
		// A generic instantiation carries its arguments here, and nowhere in
		// the generic's own declaration.
		if args := u.TypeArgs(); args != nil {
			for i := range args.Len() {
				if s := mentionsDriverType(args.At(i), seen); s != "" {
					return s
				}
			}
		}
		if iface, ok := u.Underlying().(*types.Interface); ok {
			return mentionsDriverType(iface, seen)
		}
		return ""
	case *types.Pointer:
		return mentionsDriverType(u.Elem(), seen)
	case *types.Slice:
		return mentionsDriverType(u.Elem(), seen)
	case *types.Array:
		return mentionsDriverType(u.Elem(), seen)
	case *types.Map:
		if s := mentionsDriverType(u.Key(), seen); s != "" {
			return s
		}
		return mentionsDriverType(u.Elem(), seen)
	case *types.Chan:
		return mentionsDriverType(u.Elem(), seen)
	case *types.Signature:
		for _, tup := range []*types.Tuple{u.Params(), u.Results()} {
			for i := range tup.Len() {
				if s := mentionsDriverType(tup.At(i).Type(), seen); s != "" {
					return s
				}
			}
		}
		return ""
	case *types.Interface:
		for i := range u.NumMethods() {
			if s := mentionsDriverType(u.Method(i).Type(), seen); s != "" {
				return s
			}
		}
		return ""
	case *types.Struct:
		for i := range u.NumFields() {
			if s := mentionsDriverType(u.Field(i).Type(), seen); s != "" {
				return s
			}
		}
		return ""
	}
	return ""
}
