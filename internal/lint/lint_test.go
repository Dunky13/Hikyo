package lint

// The three analyzers run here against the real repository — a violation
// anywhere in the module is a build (test) failure, which is what the
// tenant-isolation ADR means by "CI/lint guardrail". The negative-fixture
// tests prove each analyzer actually catches what it claims to catch, so a
// green run is never vacuous.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestProofSignaturesRepo(t *testing.T) {
	pkgs, err := LoadRepo()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range CheckProofSignatures(pkgs, Module+"/internal/store") {
		t.Error(f)
	}
}

func TestProofForgeryRepo(t *testing.T) {
	pkgs, err := LoadRepo()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range CheckProofForgery(pkgs) {
		t.Error(f)
	}
}

func TestSQLPredicatesRepo(t *testing.T) {
	for _, f := range CheckSQLPredicates(repoRoot(t)) {
		t.Error(f)
	}
}

// --- negative fixtures: every analyzer must catch its target violations ---

func TestProofSignaturesCatchesViolations(t *testing.T) {
	pkgs, err := Load("./testdata/badstore")
	if err != nil {
		t.Fatal(err)
	}
	findings := CheckProofSignatures(pkgs, Module+"/internal/lint/testdata/badstore")
	wantSubstrings := []string{
		"Get: second parameter must be authz.Proof",
		"List: tenant-identifier-typed parameter",
		"Search: tenant-identifier-typed parameter",
	}
	assertFindings(t, findings, wantSubstrings)
}

func TestProofForgeryCatchesViolations(t *testing.T) {
	pkgs, err := Load("./testdata/badnil")
	if err != nil {
		t.Fatal(err)
	}
	findings := CheckProofForgery(pkgs)
	wantSubstrings := []string{
		"imports \"reflect\" while handling authz.Proof",
		"nil in an authz.Proof position",
	}
	assertFindings(t, findings, wantSubstrings)
	// All three nil positions (return, var init, call arg) must be caught.
	nilCount := 0
	for _, f := range findings {
		if strings.Contains(f, "nil in an authz.Proof position") {
			nilCount++
		}
	}
	if nilCount < 3 {
		t.Errorf("nil-proof literals caught = %d, want 3 (return, var, call arg):\n%s", nilCount, strings.Join(findings, "\n"))
	}
}

// The forgery guard's exemption must be an exact path match: a neighbouring
// package whose path merely starts with the authorization package's path
// (internal/authzforge) would otherwise be skipped entirely and could
// reflect on live proof values.
func TestForgeryExemptionIsNotPrefixMatched(t *testing.T) {
	neighbours := []string{
		Module + "/internal/authzforge",
		Module + "/internal/authz/forge",
		Module + "/internal/authzutil",
	}
	for _, p := range neighbours {
		if authzExempt[p] {
			t.Errorf("%s is exempt from the forgery guard — exemption must be exact-path", p)
		}
	}
	if !authzExempt[Module+"/internal/authz"] || !authzExempt[Module+"/internal/authz.test"] {
		t.Error("the authorization package and its test binary must stay exempt")
	}
}

func TestSQLPredicateCatchesViolations(t *testing.T) {
	rules := map[string]TableRule{
		"environments": {Class: "environment", Chain: []string{"org_id", "project_id"}},
		"grants":       {Class: "authn"},
	}
	cases := []struct {
		name string
		q    Query
		want string
	}{
		{"missing chain conjunct",
			Query{Name: "Bad1", SQL: "SELECT id FROM environments WHERE id = ?"},
			"missing top-level chain conjunct"},
		{"no where at all",
			Query{Name: "Bad2", SQL: "SELECT id FROM environments"},
			"without a WHERE clause"},
		{"or beside the tenant conjunct",
			Query{Name: "Bad3", SQL: "SELECT id FROM environments WHERE org_id = ? AND project_id = ? OR name = ?"},
			"unprovable shape (OR)"},
		{"union branch",
			Query{Name: "Bad4", SQL: "SELECT id FROM environments WHERE org_id = ? AND project_id = ? UNION SELECT id FROM environments"},
			"unprovable shape"},
		{"cte",
			Query{Name: "Bad5", SQL: "WITH x AS (SELECT id FROM environments) SELECT id FROM x"},
			"unprovable shape"},
		{"join",
			Query{Name: "Bad6", SQL: "SELECT e.id FROM environments e JOIN projects p ON p.id = e.project_id"},
			"unprovable shape"},
		{"set on chain column",
			Query{Name: "Bad7", SQL: "UPDATE environments SET org_id = ? WHERE org_id = ? AND project_id = ? AND id = ?"},
			"immutable column"},
		{"insert omitting chain column",
			Query{Name: "Bad8", SQL: "INSERT INTO environments (id, name) VALUES (?, ?)"},
			"omits chain column"},
		{"unannotated query on authn table",
			Query{Name: "Bad9", SQL: "SELECT capability FROM grants WHERE principal_id = ?"},
			"resolution surface"},
		{"unknown table",
			Query{Name: "Bad10", SQL: "SELECT id FROM widgets WHERE id = ?"},
			"not in the derived scope registry"},
		{"parenthesised predicate",
			Query{Name: "Bad11", SQL: "SELECT id FROM environments WHERE org_id = ? AND project_id = ? AND name IN (?)"},
			"unprovable shape"},
	}
	for _, tc := range cases {
		findings := checkQuery("test", tc.q, rules)
		found := false
		for _, f := range findings {
			if strings.Contains(f, tc.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: findings %v do not contain %q", tc.name, findings, tc.want)
		}
	}
}

// A provable good shape must pass, so the negative cases above are meaningful.
func TestSQLPredicateAcceptsProvableShapes(t *testing.T) {
	rules := map[string]TableRule{
		"environments": {Class: "environment", Chain: []string{"org_id", "project_id"}},
	}
	good := []Query{
		{Name: "Good1", SQL: "SELECT id, name FROM environments WHERE org_id = ? AND project_id = ? AND id = ?"},
		{Name: "Good2", SQL: "UPDATE environments SET note = $1 WHERE org_id = $2 AND project_id = $3 AND id = $4"},
		{Name: "Good3", SQL: "INSERT INTO environments (id, org_id, project_id, name) VALUES (?, ?, ?, ?)"},
	}
	for _, q := range good {
		if findings := checkQuery("test", q, rules); len(findings) != 0 {
			t.Errorf("%s: unexpected findings %v", q.Name, findings)
		}
	}
}

func assertFindings(t *testing.T, findings, wantSubstrings []string) {
	t.Helper()
	for _, want := range wantSubstrings {
		found := false
		for _, f := range findings {
			if strings.Contains(f, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("findings do not contain %q:\n%s", want, strings.Join(findings, "\n"))
		}
	}
}

// The raw driver handles and the generated query packages are the two
// one-line bypasses of the whole proof boundary; both allowlists are
// enforced across the module, tests included.
func TestDriverHandlesRepo(t *testing.T) {
	pkgs, err := LoadRepo()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range CheckDriverHandles(pkgs) {
		t.Error(f)
	}
}

func TestDriverHandlesCatchesViolations(t *testing.T) {
	pkgs, err := Load("./testdata/badhandle")
	if err != nil {
		t.Fatal(err)
	}
	findings := CheckDriverHandles(pkgs)
	assertFindings(t, findings, []string{
		"calls store.DB.PG",
		"calls store.DB.SQLiteWrite",
		"imports " + Module + "/internal/store/pggen",
		// The escapes an accessor-call check alone cannot see: a locally
		// declared structural interface, a type assertion to one, and a
		// handle simply passed in as a parameter.
		"names driver type github.com/jackc/pgx/v5/pgxpool.Pool",
		"names driver type database/sql.DB",
	})
	// The alias and generic-instantiation escapes must be caught at the
	// exact lines where they are written: an alias hides the driver type's
	// spelling, and a generic's declaration carries only its type parameter,
	// so the concrete handle exists solely in the instantiation expression.
	// Lines are located from the fixture source, so it can move freely.
	for marker, what := range map[string]string{
		"type aliasHolder interface": "alias escape",
		"db.(holder[*pgxpool.Pool])": "generic-instantiation escape",
	} {
		line := fixtureLine(t, filepath.Join("testdata", "badhandle", "evasions.go"), marker)
		want := fmt.Sprintf("evasions.go:%d:", line)
		found := false
		for _, f := range findings {
			if strings.Contains(f, want) && strings.Contains(f, "names driver type") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s not caught at %s:\n%s", what, want, strings.Join(findings, "\n"))
		}
	}
}

// fixtureLine finds the 1-indexed line of the first source line containing
// marker, so position assertions survive edits to the fixture above them.
func fixtureLine(t *testing.T, path, marker string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, marker) {
			return i + 1
		}
	}
	t.Fatalf("marker %q not found in %s", marker, path)
	return 0
}

// --- redaction + append-only (audit-model ADR, #45) ---

func TestRedactionSurfacesRepo(t *testing.T) {
	pkgs, err := LoadRepo()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range CheckRedactionSurfaces(pkgs) {
		t.Error(f)
	}
}

func TestSensitiveFormattingRepo(t *testing.T) {
	pkgs, err := LoadRepo()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range CheckSensitiveFormatting(pkgs) {
		t.Error(f)
	}
}

func TestSensitiveFormattingCatchesViolations(t *testing.T) {
	pkgs, err := Load("./testdata/badredact")
	if err != nil {
		t.Fatal(err)
	}
	findings := CheckSensitiveFormatting(pkgs)
	assertFindings(t, findings, []string{
		"passes sensitive type " + Module + "/internal/crypto.Keyring to fmt",
		"passes sensitive type " + Module + "/internal/crypto.ProjectSealer to fmt",
		"passes sensitive type " + Module + "/internal/crypto.Keyring to encoding/json",
		"logs audit content " + Module + "/internal/audit.Event",
		"logs audit content " + Module + "/internal/store.AuditEvent",
	})
	// The erasure evasions must be caught at the lines where they are
	// written, not merely somewhere in the file.
	for marker, what := range map[string]string{
		`any(ev)`:                   "any-conversion erasure",
		`ev.Payload["x"]`:           "payload map-index erasure",
		`fmt.Printf("%v", any(kr))`: "sensitive-type erasure",
	} {
		line := fixtureLine(t, filepath.Join("testdata", "badredact", "badredact.go"), marker)
		want := fmt.Sprintf("badredact.go:%d:", line)
		found := false
		for _, f := range findings {
			if strings.Contains(f, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s not caught at %s:\n%s", what, want, strings.Join(findings, "\n"))
		}
	}
}

func TestAuditAppendOnlyRepo(t *testing.T) {
	for _, f := range CheckAuditAppendOnly(repoRoot(t)) {
		t.Error(f)
	}
}

func TestAuditAppendOnlyCatchesViolations(t *testing.T) {
	// The check parses real query directories; feed it a synthetic tree.
	dir := t.TempDir()
	for _, engine := range []string{"sqlite", "postgres"} {
		qdir := filepath.Join(dir, "internal", "store", "queries", engine)
		if err := os.MkdirAll(qdir, 0o755); err != nil {
			t.Fatal(err)
		}
		bad := "-- name: PruneAudit :exec\nDELETE FROM audit_tenant_events WHERE org_id = ?;\n" +
			"-- name: RewriteAudit :exec\nUPDATE audit_instance_events SET payload = ? WHERE id = ?;\n"
		if err := os.WriteFile(filepath.Join(qdir, "audit.sql"), []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sdir := filepath.Join(dir, "internal", "store")
	if err := os.WriteFile(filepath.Join(sdir, "downgrade.go"), []byte("package store\nconst q = \"SET synchronous_commit = off\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := CheckAuditAppendOnly(dir)
	assertFindings(t, findings, []string{
		"PruneAudit",
		"RewriteAudit",
		"SET synchronous_commit",
	})
}

// The denial writer must be the resolution surface's ONLY write path
// (audit-model ADR amendment part 4) — enforced, not asserted in prose.
func TestDenialWriterIsSoleWriter(t *testing.T) {
	pkgs, err := LoadRepo()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range CheckDenialWriter(pkgs, repoRoot(t)) {
		t.Error(f)
	}
}

func TestGrantLockRepo(t *testing.T) {
	pkgs, err := LoadRepo()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range CheckGrantLock(pkgs, repoRoot(t)) {
		t.Error(f)
	}
}

func TestGrantLockCatchesLocklessWriter(t *testing.T) {
	pkgs, err := Load("./testdata/badgrant")
	if err != nil {
		t.Fatal(err)
	}
	surface := Module + "/internal/lint/testdata/badgrant"
	writers, err := GrantWriters(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if !writers["InsertGrant"] {
		t.Fatal("GrantWriters omits InsertGrant — the analyzer would not enforce the grant surface")
	}
	findings := CheckGrantLockIn(pkgs, surface, writers, lockName)
	assertFindings(t, findings, []string{
		"LocklessWriter writes a grant table but does not take the LockPrincipalRow principal-row lock",
		// The decoy proves the lock match is type-resolved, not name-only: a
		// same-named LockPrincipalRow on an unrelated type does not satisfy it.
		"DecoyLockWriter writes a grant table but does not take the LockPrincipalRow principal-row lock",
	})
	for _, f := range findings {
		if strings.Contains(f, "LockedWriter") || strings.Contains(f, "GrantReadIsFine") {
			t.Errorf("analyzer flagged a locked writer or a read: %s", f)
		}
	}
	// Scoping: the same package is silent when it is not the named surface.
	if f := CheckGrantLockIn(pkgs, Module+"/internal/store/authn", writers, lockName); len(f) != 0 {
		t.Errorf("analyzer fired outside the named surface: %v", f)
	}
}

func TestDenialWriterCatchesSecondWriter(t *testing.T) {
	pkgs, err := Load("./testdata/badauthn")
	if err != nil {
		t.Fatal(err)
	}
	surface := Module + "/internal/lint/testdata/badauthn"
	mutating, mfind, err := MutatingQueries(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(mfind) != 0 {
		t.Errorf("unclassified sqlc commands: %v", mfind)
	}
	findings := CheckDenialWriterIn(pkgs, surface, map[string]bool{"WriteDenial": true}, mutating)
	assertFindings(t, findings, []string{
		"SecondWriter names the mutating query InsertTenantAuditEvent, and SecondWriter is not in the pinned enumerated write list",
		"MethodValueWriter names the mutating query InsertTenantAuditEvent, and MethodValueWriter is not in the pinned enumerated write list",
	})
	for _, f := range findings {
		if strings.Contains(f, "WriteDenial names") || strings.Contains(f, "ReadsAreFine") {
			t.Errorf("analyzer flagged a licensed write or a read: %s", f)
		}
	}
	// Scoping: the same package is silent when it is not the named surface.
	if f := CheckDenialWriterIn(pkgs, Module+"/internal/store/authn", map[string]bool{"WriteDenial": true}, mutating); len(f) != 0 {
		t.Errorf("analyzer fired outside the named surface: %v", f)
	}
	// The classifier is derived from sqlc's command annotation, not from the
	// query's name. These three mutate and none of them starts with a verb a
	// prefix list would have guessed — which is exactly how the previous
	// version let three real writers through.
	for _, name := range []string{"ConsumeCredentialAuthority", "TouchSession", "AdvancePrincipalGeneration", "InsertTenantAuditEvent"} {
		if !mutating[name] {
			t.Errorf("MutatingQueries omits %q — a write the analyzer would not enforce", name)
		}
	}
	for _, name := range []string{"GetPrincipalKind", "ResolveOrgChain", "ListGrantsForPrincipal", "GetSessionByVerifier"} {
		if mutating[name] {
			t.Errorf("MutatingQueries includes %q — a read misclassified as a write", name)
		}
	}
}
