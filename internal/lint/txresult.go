package lint

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/packages"
)

// CheckTransactionResults keeps tx.WriteResult's generic result channel
// detached from transaction-owned authority. Runtime reflection is forbidden
// in packages that handle Proof values, so this repository-wide type walk is
// the fail-closed enforcement point.
func CheckTransactionResults(pkgs []*packages.Package) []string {
	var findings []string
	for _, p := range flatten(pkgs) {
		if p.TypesInfo == nil || (!strings.HasPrefix(p.PkgPath, Module+"/") && p.PkgPath != Module) {
			continue
		}
		for _, file := range p.Syntax {
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || !isWriteResultCall(p, call.Fun) {
					return true
				}
				sig, _ := p.TypesInfo.TypeOf(call.Fun).(*types.Signature)
				if sig == nil || sig.Results().Len() == 0 {
					return true
				}
				resultType := sig.Results().At(0).Type()
				if reason := detachedResultViolation(resultType, make(map[types.Type]bool)); reason != "" {
					findings = append(findings, fmt.Sprintf(
						"txresult: %s: tx.WriteResult result %s is not detached data: %s",
						p.Fset.Position(call.Pos()), types.TypeString(resultType, nil), reason))
				}
				return true
			})
		}
	}
	return findings
}

func isWriteResultCall(p *packages.Package, expr ast.Expr) bool {
	for {
		switch node := expr.(type) {
		case *ast.IndexExpr:
			expr = node.X
			continue
		case *ast.IndexListExpr:
			expr = node.X
			continue
		}
		break
	}
	var obj types.Object
	switch node := expr.(type) {
	case *ast.Ident:
		obj = p.TypesInfo.Uses[node]
	case *ast.SelectorExpr:
		obj = p.TypesInfo.Uses[node.Sel]
	}
	fn, ok := obj.(*types.Func)
	return ok && fn.Name() == "WriteResult" && fn.Pkg() != nil && fn.Pkg().Path() == Module+"/internal/store/tx"
}

func detachedResultViolation(t types.Type, seen map[types.Type]bool) string {
	t = types.Unalias(t)
	if seen[t] {
		return ""
	}
	seen[t] = true
	switch current := t.(type) {
	case *types.Named:
		obj := current.Obj()
		if obj.Pkg() != nil {
			path := obj.Pkg().Path()
			if (path == Module+"/internal/store" && (obj.Name() == "Repos" || obj.Name() == "ReadRepos")) ||
				(path == Module+"/internal/authz" && (obj.Name() == "Proof" || obj.Name() == "TxAuthorizer" || obj.Name() == "TxToken")) {
				return path + "." + obj.Name()
			}
		}
		return detachedResultViolation(current.Underlying(), seen)
	case *types.Pointer:
		return detachedResultViolation(current.Elem(), seen)
	case *types.Array:
		return detachedResultViolation(current.Elem(), seen)
	case *types.Slice:
		return detachedResultViolation(current.Elem(), seen)
	case *types.Map:
		if reason := detachedResultViolation(current.Key(), seen); reason != "" {
			return reason
		}
		return detachedResultViolation(current.Elem(), seen)
	case *types.Struct:
		for i := 0; i < current.NumFields(); i++ {
			if reason := detachedResultViolation(current.Field(i).Type(), seen); reason != "" {
				return reason
			}
		}
	case *types.Interface:
		return "interface values can retain attempt-owned authority"
	case *types.Signature:
		return "function values can capture attempt-owned authority"
	case *types.Chan:
		return "channels can transport attempt-owned authority"
	case *types.TypeParam:
		return "unresolved type parameter"
	case *types.Basic:
		if current.Kind() == types.UnsafePointer {
			return "unsafe.Pointer"
		}
	}
	return ""
}
