package service

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

// TestReauthWindowSeamIsSingleSource pins the A2 invariant structurally: the
// global s.ReauthWindow field is read in exactly ONE place in this package's
// production code — the body of effectiveReauthWindow, the single seam every
// window opener and the disclosure-time slide resolve the effective window
// through. A future caller that computes a window's duration from the global
// directly (the exact class the R2 review flagged twice) reintroduces the
// divergence and fails here, before it can ship. No behavioral test can catch
// this until #55 makes the seam return a per-environment value; this one can.
func TestReauthWindowSeamIsSingleSource(t *testing.T) {
	fset := token.NewFileSet()
	pkg, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var sites []string
	for _, p := range pkg {
		for name, file := range p.Files {
			var enclosing string
			ast.Inspect(file, func(n ast.Node) bool {
				if fn, ok := n.(*ast.FuncDecl); ok {
					enclosing = fn.Name.Name
				}
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "ReauthWindow" {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok || id.Name != "s" {
					return true
				}
				sites = append(sites, enclosing+" ("+name+":"+
					fset.Position(sel.Pos()).String()+")")
				return true
			})
		}
	}
	if len(sites) != 1 || !strings.HasPrefix(sites[0], "effectiveReauthWindow") {
		t.Fatalf("s.ReauthWindow read in %d site(s), want exactly 1 in effectiveReauthWindow: %v", len(sites), sites)
	}
}
