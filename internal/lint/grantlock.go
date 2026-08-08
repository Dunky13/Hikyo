package lint

import (
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Grant-lock analyzer (#54 B14). credential-reset's org-bounded test is made
// serializable by locking the target's `principals` row: the reset reads the
// target's grant set under that lock, so a concurrent grant landing must take the
// same lock and therefore serialize behind (or ahead of) the reset. That
// guarantee holds only if EVERY grant writer takes the lock. The general grant
// surface is #55's; this analyzer pins the obligation now so a future grant
// writer cannot forget it — a grant writer that skips the lock is a build
// failure, not a review miss.
//
// The check is structural, like the sole-writer analyzer it is modelled on: any
// function on the resolution surface that names a grant-table-mutating generated
// query must also name the principal-row lock in the same body. It cannot prove
// the lock is taken on the RIGHT principal — that is review's job — but it makes
// "no lock at all" mechanically impossible.

// grantTable is the table whose writers must hold the principal-row lock.
const grantTable = "grants"

// lockName is the lock taken before a grant write: the generated query, or the
// resolver wrapper that calls it (CreateGrant reaches the lock through the
// wrapper, so the name is matched wherever it appears).
const lockName = "LockPrincipalRow"

// GrantWriters returns the mutating generated queries that target the grant
// table, derived from the query files rather than a curated list so a new grant
// writer is covered the moment it is added.
func GrantWriters(repoRoot string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, engine := range []string{"sqlite", "postgres"} {
		queries, err := ParseQueries(filepath.Join(repoRoot, "internal", "store", "queries", engine))
		if err != nil {
			return nil, err
		}
		for _, q := range queries {
			switch q.Cmd {
			case "one", "many", "batchmany", "batchone":
				continue // reads never write a grant row
			}
			table, _, ok := statementTarget(strings.ToUpper(normalizeSpace(q.SQL)))
			if ok && strings.EqualFold(table, grantTable) {
				out[q.Name] = true
			}
		}
	}
	return out, nil
}

// CheckGrantLock enforces the obligation over the resolution surface.
func CheckGrantLock(pkgs []*packages.Package, repoRoot string) []string {
	writers, err := GrantWriters(repoRoot)
	if err != nil {
		return []string{"grantlock: " + err.Error()}
	}
	if len(writers) == 0 {
		return []string{"grantlock: no grant-table writers found — the analyzer would be vacuously green"}
	}
	return CheckGrantLockIn(pkgs, Module+"/internal/store/authn", writers, lockName)
}

// CheckGrantLockIn is CheckGrantLock with the surface and lock named, so the
// negative fixture can prove the check fires on a lockless grant writer.
func CheckGrantLockIn(pkgs []*packages.Package, surface string, writers map[string]bool, lock string) []string {
	var findings []string
	for _, p := range flatten(pkgs) {
		if strings.TrimSuffix(p.PkgPath, ".test") != surface || p.TypesInfo == nil {
			continue
		}
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					return true
				}
				var namesWriter, namesLock bool
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					sel, ok := n.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					// The lock is matched by name whether it is the generated query
					// or the resolver wrapper that calls it.
					if sel.Sel.Name == lock {
						namesLock = true
					}
					obj, ok := p.TypesInfo.Uses[sel.Sel]
					if !ok {
						return true
					}
					f, ok := obj.(*types.Func)
					if !ok || f.Pkg() == nil || !generatedPackages[f.Pkg().Path()] {
						return true
					}
					if writers[f.Name()] {
						namesWriter = true
					}
					return true
				})
				if namesWriter && !namesLock {
					findings = append(findings, fmt.Sprintf(
						"grantlock: %s: %s writes a grant table but does not take the %s principal-row lock — every grant writer must hold it so credential-reset's org-bounded test is serializable (#54 B14)",
						p.Fset.Position(fn.Pos()), fn.Name.Name, lock))
				}
				return true
			})
		}
	}
	return findings
}
