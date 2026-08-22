package authz

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"
)

// TestStoreOpCatalogueMatchesConstants keeps the constructor's closed runtime
// catalogue total over the exported StoreOp constants. The compiler catches a
// stale catalogue reference after deletion; this test catches a newly declared
// constant that was not added to the catalogue and duplicate constant values
// that would collapse to one map key.
func TestStoreOpCatalogueMatchesConstants(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "registry.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	declared := map[string]bool{}
	catalogued := map[string]bool{}
	for _, declaration := range f.Decls {
		gen, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, rawSpec := range gen.Specs {
			spec, ok := rawSpec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if gen.Tok == token.CONST {
				typeName, ok := spec.Type.(*ast.Ident)
				if !ok || typeName.Name != "StoreOp" {
					continue
				}
				for _, name := range spec.Names {
					if strings.HasPrefix(name.Name, "Store") {
						declared[name.Name] = true
					}
				}
				continue
			}
			if gen.Tok != token.VAR || len(spec.Names) != 1 || spec.Names[0].Name != "storeOpCatalogue" || len(spec.Values) != 1 {
				continue
			}
			literal, ok := spec.Values[0].(*ast.CompositeLit)
			if !ok {
				t.Fatal("storeOpCatalogue is not a composite literal")
			}
			for _, element := range literal.Elts {
				entry, ok := element.(*ast.KeyValueExpr)
				if !ok {
					t.Fatal("storeOpCatalogue contains a non-keyed entry")
				}
				name, ok := entry.Key.(*ast.Ident)
				if !ok {
					t.Fatal("storeOpCatalogue contains a non-identifier key")
				}
				catalogued[name.Name] = true
			}
		}
	}

	missing := difference(declared, catalogued)
	extra := difference(catalogued, declared)
	if len(missing) > 0 || len(extra) > 0 || len(storeOpCatalogue) != len(declared) {
		t.Fatalf("StoreOp catalogue drift: declared=%d runtime=%d missing=%v extra=%v", len(declared), len(storeOpCatalogue), missing, extra)
	}
}

func difference(left, right map[string]bool) []string {
	out := []string{}
	for value := range left {
		if !right[value] {
			out = append(out, value)
		}
	}
	slices.Sort(out)
	return out
}
