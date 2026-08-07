package lint

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/packages"
)

// CheckProofForgery is analyzer 3 (tenant-isolation ADR, invariant 9). The
// concrete proof type is unexported, so it cannot be named outside
// internal/authz at all — what remains expressible, and is flagged here:
//
//   - a nil literal in a Proof-typed position (call argument, variable
//     initialisation, assignment, return, struct literal): the only
//     forgeable Proof value. The store boundary already rejects nil at
//     runtime; the guard removes the expression at build time.
//   - reflect or unsafe imported by a package that handles Proof values:
//     conservative by design — the pair is how a forged proof would be
//     assembled, and no package outside authz has business combining them.
//
// The authorization package itself (and its tests) are exempt: boundary
// tests must construct exactly these invalid values.
func CheckProofForgery(pkgs []*packages.Package) []string {
	var findings []string
	for _, p := range flatten(pkgs) {
		if !strings.HasPrefix(p.PkgPath, Module+"/") && p.PkgPath != Module {
			continue
		}
		// The authorization package and its test variants are exempt:
		// boundary tests construct exactly these invalid values on purpose.
		// Exact paths only — a prefix match would silently exempt a
		// neighbouring `internal/authzforge` that reflects on proof values.
		if authzExempt[p.PkgPath] {
			continue
		}
		usesProof := false
		for _, obj := range p.TypesInfo.Uses {
			if isAuthzProof(obj.Type()) {
				usesProof = true
				break
			}
		}
		if usesProof {
			for imp := range p.Imports {
				if imp == "reflect" || imp == "unsafe" {
					findings = append(findings,
						fmt.Sprintf("forgeguard: %s imports %q while handling authz.Proof values", p.PkgPath, imp))
				}
			}
		}
		findings = append(findings, nilProofLiterals(p)...)
	}
	return findings
}

// authzExempt is the exact set of package paths allowed to construct
// non-canonical proof values: the authorization package (in-package tests
// share its path), the test binary go/packages reports beside it, and the
// external-test package path should one ever be added.
var authzExempt = map[string]bool{
	Module + "/internal/authz":      true,
	Module + "/internal/authz.test": true,
	Module + "/internal/authz_test": true,
}

func isAuthzProof(t types.Type) bool {
	n, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := n.Obj()
	return obj.Name() == "Proof" && obj.Pkg() != nil && obj.Pkg().Path() == Module+"/internal/authz"
}

// nilProofLiterals walks the syntax for nil expressions in Proof-typed
// positions. go/types keeps untyped nil untyped, so each syntactic position
// is resolved explicitly: call arguments, variable declarations,
// assignments, returns, and keyed struct literals. Stated limit: a nil
// smuggled through a positional struct literal or an intermediate untyped
// construct escapes this walk — and still dies at the store boundary, which
// is the enforcement; this guard just surfaces it earlier.
func nilProofLiterals(p *packages.Package) []string {
	var findings []string
	flag := func(n ast.Node) {
		pos := p.Fset.Position(n.Pos())
		findings = append(findings,
			fmt.Sprintf("forgeguard: %s: nil in an authz.Proof position — the one forgeable value; get a proof from authorize()", pos))
	}
	isNil := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "nil" && p.TypesInfo.Uses[id] == types.Universe.Lookup("nil")
	}
	for _, file := range p.Syntax {
		// Enclosing-function result types, resolved by narrowest span, so a
		// `return nil` can be matched against the function's Proof results.
		type fnSpan struct {
			pos, end token.Pos
			results  []types.Type
		}
		var fns []fnSpan
		ast.Inspect(file, func(n ast.Node) bool {
			var sig *types.Signature
			switch node := n.(type) {
			case *ast.FuncDecl:
				if obj := p.TypesInfo.Defs[node.Name]; obj != nil {
					sig, _ = obj.Type().(*types.Signature)
				}
			case *ast.FuncLit:
				if tv, ok := p.TypesInfo.Types[node]; ok {
					sig, _ = tv.Type.(*types.Signature)
				}
			default:
				return true
			}
			if sig != nil {
				var results []types.Type
				for i := range sig.Results().Len() {
					results = append(results, sig.Results().At(i).Type())
				}
				fns = append(fns, fnSpan{pos: n.Pos(), end: n.End(), results: results})
			}
			return true
		})
		enclosingResults := func(pos token.Pos) []types.Type {
			var best *fnSpan
			for i := range fns {
				f := &fns[i]
				if f.pos <= pos && pos < f.end && (best == nil || f.pos > best.pos) {
					best = f
				}
			}
			if best == nil {
				return nil
			}
			return best.results
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.ReturnStmt:
				results := enclosingResults(node.Pos())
				for i, e := range node.Results {
					if i < len(results) && isNil(e) && isAuthzProof(results[i]) {
						flag(e)
					}
				}
			case *ast.CallExpr:
				sig, _ := p.TypesInfo.Types[node.Fun].Type.(*types.Signature)
				if sig == nil {
					break
				}
				for i, arg := range node.Args {
					if !isNil(arg) {
						continue
					}
					var pt types.Type
					if sig.Variadic() && i >= sig.Params().Len()-1 {
						continue
					}
					if i < sig.Params().Len() {
						pt = sig.Params().At(i).Type()
					}
					if pt != nil && isAuthzProof(pt) {
						flag(arg)
					}
				}
			case *ast.ValueSpec:
				for _, v := range node.Values {
					if isNil(v) {
						for _, name := range node.Names {
							if obj := p.TypesInfo.Defs[name]; obj != nil && isAuthzProof(obj.Type()) {
								flag(v)
							}
						}
					}
				}
			case *ast.AssignStmt:
				for i, rhs := range node.Rhs {
					if isNil(rhs) && i < len(node.Lhs) {
						if tv, ok := p.TypesInfo.Types[node.Lhs[i]]; ok && isAuthzProof(tv.Type) {
							flag(rhs)
						}
					}
				}
			case *ast.KeyValueExpr:
				if isNil(node.Value) {
					if id, ok := node.Key.(*ast.Ident); ok {
						if obj := p.TypesInfo.Uses[id]; obj != nil && isAuthzProof(obj.Type()) {
							flag(node.Value)
						}
					}
				}
			}
			return true
		})
	}
	return findings
}
