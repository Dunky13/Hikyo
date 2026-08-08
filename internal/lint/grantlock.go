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
// function — in ANY module package, not just the resolution surface — that names
// a grant-table-mutating generated query must also take the principal-row lock in
// the same body, and the lock must type-resolve to the REAL LockPrincipalRow (the
// generated query or the authn resolver wrapper that calls it), not merely any
// selector spelled that way. Residual, stated so it is not mistaken for more:
// the analyzer cannot prove the lock is taken on the RIGHT principal row, nor
// that it precedes the write in execution order within the same transaction —
// that is review's job. Where it cannot be sure it errs toward flagging
// (fail-closed): a grant writer with no resolvable lock at all is a build
// failure, never a silent pass.

// grantTable is the table whose writers must hold the principal-row lock.
const grantTable = "grants"

// lockName is the lock taken before a grant write.
const lockName = "LockPrincipalRow"

// lockDefiners are the packages that define the real principal-row lock: the
// generated query packages and the resolution-surface wrapper that calls them
// (authn.CreateGrant reaches the lock through the wrapper). A selector named
// LockPrincipalRow that type-resolves anywhere else is NOT the lock and does not
// satisfy the obligation.
var lockDefiners = map[string]bool{
	Module + "/internal/store/sqlitegen": true,
	Module + "/internal/store/pggen":     true,
	Module + "/internal/store/authn":     true,
}

// GrantWriters returns the mutating generated queries that target the grant
// table, derived from the query files rather than a curated list so a new grant
// writer is covered the moment it is added. Classification is by SQL verb/target,
// NOT the sqlc command annotation: an `INSERT ... RETURNING` is a `:one` yet
// writes a grant row (the old cmd-based skip classified it as a read and let it
// through). Only a SELECT on the grant table is a read.
func GrantWriters(repoRoot string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, engine := range []string{"sqlite", "postgres"} {
		queries, err := ParseQueries(filepath.Join(repoRoot, "internal", "store", "queries", engine))
		if err != nil {
			return nil, err
		}
		for _, q := range queries {
			table, kind, ok := statementTarget(strings.ToUpper(normalizeSpace(q.SQL)))
			if !ok || !strings.EqualFold(table, grantTable) {
				continue
			}
			switch kind {
			case "INSERT", "UPDATE", "DELETE":
				out[q.Name] = true
			}
		}
	}
	return out, nil
}

// CheckGrantLock enforces the obligation over EVERY module package that can call
// a generated grant-mutation query, not only the resolution surface: a grant
// write is a grant write wherever it is issued from. It scans all loaded
// packages except the generated query packages themselves (whose method bodies
// ARE the queries, not callers of them). testdata fixtures are never loaded by
// the `module/...` pattern, so the negative fixture does not false-positive the
// repo run.
func CheckGrantLock(pkgs []*packages.Package, repoRoot string) []string {
	writers, err := GrantWriters(repoRoot)
	if err != nil {
		return []string{"grantlock: " + err.Error()}
	}
	if len(writers) == 0 {
		return []string{"grantlock: no grant-table writers found — the analyzer would be vacuously green"}
	}
	var findings []string
	for _, p := range flatten(pkgs) {
		path := strings.TrimSuffix(p.PkgPath, ".test")
		if p.TypesInfo == nil || generatedPackages[path] {
			continue
		}
		findings = append(findings, checkGrantLockPkg(p, writers, lockName)...)
	}
	return findings
}

// CheckGrantLockIn is CheckGrantLock scoped to ONE named surface, so the negative
// fixture can prove the check fires on a lockless grant writer and stays silent
// outside the surface it is pointed at.
func CheckGrantLockIn(pkgs []*packages.Package, surface string, writers map[string]bool, lock string) []string {
	var findings []string
	for _, p := range flatten(pkgs) {
		if strings.TrimSuffix(p.PkgPath, ".test") != surface || p.TypesInfo == nil {
			continue
		}
		findings = append(findings, checkGrantLockPkg(p, writers, lock)...)
	}
	return findings
}

// checkGrantLockPkg reports every function in p that names a grant-mutating
// writer but does not take the real principal-row lock in the same body.
func checkGrantLockPkg(p *packages.Package, writers map[string]bool, lock string) []string {
	var findings []string
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
				obj, ok := p.TypesInfo.Uses[sel.Sel]
				if !ok {
					return true
				}
				f, ok := obj.(*types.Func)
				if !ok || f.Pkg() == nil {
					return true
				}
				pkgPath := f.Pkg().Path()
				// The lock counts only when it type-resolves to the REAL
				// LockPrincipalRow — the generated query or the authn wrapper —
				// not merely a selector spelled that way (a struct field or an
				// unrelated method named LockPrincipalRow no longer satisfies it).
				if f.Name() == lock && lockDefiners[pkgPath] {
					namesLock = true
				}
				if generatedPackages[pkgPath] && writers[f.Name()] {
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
	return findings
}
