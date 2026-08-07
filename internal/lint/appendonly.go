package lint

import (
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Analyzer 6 (audit-model ADR CI invariants 3 and 7): append-only audit
// tables, and no session-level durability downgrade.
//
// The application layer holds INSERT and SELECT only on both audit tables.
// The ADR licenses exactly two future deletion queries — the retention-
// pruning job and the org-deletion cascade — each content-pinned like the
// annotated-query allowlist. NEITHER EXISTS YET, so the allowlist ships
// empty and this check is strictly tighter than the ADR until those tickets
// land their pinned entries.

var auditTables = []string{"audit_tenant_events", "audit_instance_events"}

// auditDeletionAllowlist is the content-pinned licensed-deleter set:
// query name → sha256 of its normalized SQL. Empty until the pruning job
// (ops-spec ticket) and the org-deletion cascade land.
var auditDeletionAllowlist = map[string]string{}

// CheckAuditAppendOnly scans every query file on both engines.
func CheckAuditAppendOnly(repoRoot string) []string {
	var findings []string
	for _, engine := range []string{"sqlite", "postgres"} {
		queryDir := filepath.Join(repoRoot, "internal", "store", "queries", engine)
		queries, err := ParseQueries(queryDir)
		if err != nil {
			return append(findings, "appendonly: "+err.Error())
		}
		for _, q := range queries {
			upper := strings.ToUpper(normalizeSpace(q.SQL))
			touchesAudit := false
			for _, tbl := range auditTables {
				if strings.Contains(strings.ToLower(q.SQL), tbl) {
					touchesAudit = true
				}
			}
			if !touchesAudit {
				continue
			}
			if strings.HasPrefix(upper, "INSERT ") || strings.HasPrefix(upper, "SELECT ") {
				continue
			}
			if want, ok := auditDeletionAllowlist[q.Name]; ok && q.Hash() == want {
				continue
			}
			findings = append(findings, fmt.Sprintf(
				"appendonly(%s): %s: statement on an audit table is neither INSERT nor SELECT nor a content-pinned licensed deleter — the trails are append-only at the application layer (audit-model ADR CI invariant 3)",
				engine, q.Name))
		}
	}
	findings = append(findings, checkNoSyncCommitDowngrade(repoRoot)...)
	return findings
}

// syncCommitRe catches any attempt to downgrade commit durability at
// session or transaction level — the audit-model ADR's boot check verifies
// the server setting, and this ban keeps the store from quietly overriding
// it (CI invariant 7).
// The statement form requires the assignment (`= off` / `TO off`), so prose
// merely naming the banned statement — like this comment — does not trip it.
var syncCommitRe = regexp.MustCompile(`(?i)SET\s+(LOCAL\s+)?synchronous_commit\s*(=|TO\s)`)

func checkNoSyncCommitDowngrade(repoRoot string) []string {
	var findings []string
	roots := []string{
		filepath.Join(repoRoot, "internal", "store"),
	}
	for _, root := range roots {
		// Walk and read errors surface as findings: an analyzer that
		// silently skips what it cannot read is fail-open.
		werr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				findings = append(findings, fmt.Sprintf("appendonly: walk %s: %v", path, err))
				return nil
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".sql") {
				return nil
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				findings = append(findings, fmt.Sprintf("appendonly: read %s: %v", path, rerr))
				return nil
			}
			if syncCommitRe.Match(b) {
				findings = append(findings, fmt.Sprintf(
					"appendonly: %s issues SET synchronous_commit — durability is a boot-verified server setting, never a session downgrade (audit-model ADR CI invariant 7)",
					path))
			}
			return nil
		})
		if werr != nil {
			findings = append(findings, fmt.Sprintf("appendonly: walk %s: %v", root, werr))
		}
	}
	return findings
}

// ResolutionSurfaceWriters is the PINNED enumerated write list of the
// authorization resolution surface. It is the review artifact: adding a name
// here is how a new proof-free write path gets noticed, and everything not
// named still fails the build.
//
// The audit-model ADR's amendment part 4 pinned exactly one entry,
// WriteDenial, because a failed authorize() mints no proof and its denial
// event therefore cannot travel the proof-carrying store surface. Human
// authentication (#47) is the same circularity seen from the other side:
// resolving, minting and revoking the artifact that decides WHO a caller is
// cannot run under a proof, because the proof is what that answer produces.
//
// Stated as a deviation rather than smuggled in: the ADR says "exactly one",
// and this is more than one. What is preserved is the property the "exactly
// one" was protecting — every proof-free write is named, in one place, with a
// build failure behind it. See docs/handoff/47-first-slice.md, which routes
// the wording to human disposition.
var ResolutionSurfaceWriters = map[string]bool{
	// Audit (#45, audit-model ADR amendment part 4). writeProofFreeEvent is
	// the shared body WriteDenial and WriteAuthEvent both delegate to, so the
	// two cannot drift; it is the actual call site the analyzer sees.
	"WriteDenial":         true,
	"WriteAuthEvent":      true,
	"writeProofFreeEvent": true,
	// Bootstrap under local host authority (#47) — the closed local-authority
	// exception set's boot/bootstrap member, never reachable over the network.
	"CreatePrincipal":           true,
	"CreateAccount":             true,
	"CreateGrant":               true,
	"CreateCredentialAuthority": true,
	// Credential establishment and the local floor (#47). None of these can
	// hold a proof: the first has no session by design, the rest are the
	// session's own lifecycle.
	"ConsumeCredentialAuthority": true,
	"CreatePasswordCredential":   true,
	"UpdatePasswordCredential":   true,
	"CreateSession":              true,
	"TouchSession":               true,
	"DeleteSession":              true,
	"DeleteSessionsForPrincipal": true,
	"AdvanceGeneration":          true,
}

// CheckDenialWriter enforces the enumerated-writer rule as a build failure,
// not a comment. The import boundary alone cannot see this —
// internal/store/authn already holds the generated query handles, so a
// mutating call inside it would be a proof-free writer that every other guard
// admits. Every call to a generated mutating query from that package must sit
// inside a function named in ResolutionSurfaceWriters.
func CheckDenialWriter(pkgs []*packages.Package) []string {
	return CheckDenialWriterIn(pkgs, Module+"/internal/store/authn", ResolutionSurfaceWriters)
}

// CheckDenialWriterIn is CheckDenialWriter with the surface named, so the
// negative fixture can prove the check actually fires on an unlisted writer
// rather than merely on a package that has none.
func CheckDenialWriterIn(pkgs []*packages.Package, surface string, writers map[string]bool) []string {
	var findings []string
	for _, p := range flatten(pkgs) {
		if strings.TrimSuffix(p.PkgPath, ".test") != surface || p.TypesInfo == nil {
			continue
		}
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok {
					return true
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					obj, ok := p.TypesInfo.Uses[sel.Sel]
					if !ok {
						return true
					}
					f, ok := obj.(*types.Func)
					if !ok || f.Pkg() == nil || !generatedPackages[f.Pkg().Path()] {
						return true
					}
					if !mutatingQuery(f.Name()) || writers[fn.Name.Name] {
						return true
					}
					findings = append(findings, fmt.Sprintf(
						"denialwriter: %s: %s calls the mutating query %s, and %s is not in the pinned enumerated write list — every proof-free writer in the resolution surface must be named there (audit-model ADR amendment part 4, extended by #47)",
						p.Fset.Position(call.Pos()), fn.Name.Name, f.Name(), fn.Name.Name))
					return true
				})
				return false
			})
		}
	}
	return findings
}

// mutatingQuery recognises a generated statement that writes. sqlc names
// queries after their intent, so the prefix set is the whole vocabulary the
// repo uses; a new verb must be added here deliberately.
func mutatingQuery(name string) bool {
	for _, prefix := range []string{"Insert", "Create", "Update", "Delete", "Acquire", "Prune", "Set"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
