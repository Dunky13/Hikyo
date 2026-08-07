package lint

import (
	"go/ast"
	"strings"
	"testing"
)

// The transport may not name service.LocalPrincipal.
//
// That constructor bypasses session resolution by construction — it is for
// callers already below the network boundary (the isolation harness, and
// local-authority verbs running on the server's own host). A transport that
// could build one could authorize as anybody, and the whole point of handing
// the raw artifact down is that the decision about who is asking happens
// inside the transaction that acts on the answer.
//
// This is the check that keeps the Actor split a rule rather than a habit.
func TestTransportCannotConstructALocalPrincipal(t *testing.T) {
	pkgs, err := LoadRepo()
	if err != nil {
		t.Fatal(err)
	}
	const forbidden = "LocalPrincipal"
	for _, p := range pkgs {
		path := strings.TrimSuffix(p.PkgPath, ".test")
		if path != Module+"/internal/server" {
			continue
		}
		if p.TypesInfo == nil {
			t.Fatalf("no type information for %s", path)
		}
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != forbidden {
					return true
				}
				obj, ok := p.TypesInfo.Uses[sel.Sel]
				if !ok || obj.Pkg() == nil {
					return true
				}
				if obj.Pkg().Path() == Module+"/internal/service" {
					t.Errorf("%s: %s names service.%s — the transport must hand over the raw artifact and let the service resolve it in-transaction",
						p.Fset.Position(sel.Pos()), path, forbidden)
				}
				return true
			})
		}
	}
}
