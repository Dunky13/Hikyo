package lint

// The three analyzers run here against the real repository — a violation
// anywhere in the module is a build (test) failure, which is what the
// tenant-isolation ADR means by "CI/lint guardrail". The negative-fixture
// tests prove each analyzer actually catches what it claims to catch, so a
// green run is never vacuous.

import (
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
		"names driver type *github.com/jackc/pgx/v5/pgxpool.Pool",
		"names driver type *database/sql.DB",
	})
}
