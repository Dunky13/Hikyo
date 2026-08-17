package lint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/Hikyo-Org/hikyo/internal/pathutil"
)

// This file is analyzer 2 (tenant-isolation ADR, invariant 8): sqlc queries
// are static SQL, so predicate confinement is checked at build time. The
// analyzer is conservative by design — for every statement touching a
// tenant-owned table it requires the full owning-scope chain predicate as
// top-level conjuncts and REJECTS ANY QUERY SHAPE IT CANNOT PROVE (UNION,
// CTE, OR, JOIN, subqueries, parenthesised predicates), forcing a rewrite
// into a provable shape. The tenant-table registry is derived from the
// scope-class directives in migration metadata, never curated: a table
// without a directive fails the build.
//
// Two annotations exempt a query from the chain-predicate requirement, both
// content-pinned (invariant 13) so drift is a reviewed diff:
//
//	-- hikyo:instance-scoped    cross-tenant by definition (operator surface)
//	-- hikyo:authn-resolution   the authorization package's bootstrap reads
type TableRule struct {
	Class string   // org | project | environment | folder | key | instance | authn | system
	Chain []string // chain columns required as top-level conjuncts ("-" = none)
}

// Query is one parsed sqlc query block.
type Query struct {
	Name       string
	Cmd        string
	Annotation string // hikyo annotation, "" if none
	SQL        string
}

// Hash returns the content pin for annotated queries: sha256 over the
// whitespace-normalized statement.
func (q Query) Hash() string {
	sum := sha256.Sum256([]byte(normalizeSpace(q.SQL)))
	return hex.EncodeToString(sum[:])
}

var (
	directiveRe = regexp.MustCompile(`(?m)^--\s*hikyo:table\s+(\S+)\s+class=(\S+)\s+chain=(\S+)\s*$`)
	// One alternation so create / drop / rename are replayed in source order;
	// three separate scans would lose the ordering the final state depends on.
	tableStatementRe = regexp.MustCompile(`(?im)^\s*(?:` +
		`CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)` +
		`|DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\w+)` +
		`|ALTER\s+TABLE\s+(\w+)\s+RENAME\s+TO\s+(\w+)` +
		`)`)
	nameRe  = regexp.MustCompile(`^--\s*name:\s+(\w+)\s+:(\w+)\s*$`)
	annotRe = regexp.MustCompile(`^--\s*hikyo:(instance-scoped|authn-resolution)\s*$`)
	// A bindable parameter: sqlite positional, postgres positional, or the
	// sqlc named form (the reserved chain_* parameters use it on postgres).
	paramRe = `(\?|\$\d+|SQLCARG_\w+)`
	// sqlcArgRe masks sqlc.arg(name) into a paren-free token so the
	// conservative parenthesis rejection doesn't fire on the named-parameter
	// syntax itself.
	sqlcArgRe = regexp.MustCompile(`(?i)sqlc\.arg\((\w+)\)`)
)

func maskSQLCArgs(s string) string {
	return sqlcArgRe.ReplaceAllString(s, "SQLCARG_$1")
}

// ParseScopeDirectives reads the hikyo:table directives from every migration
// file in dir.
func ParseScopeDirectives(dir string) (map[string]TableRule, error) {
	out := map[string]TableRule{}
	if err := eachSQLFile(dir, func(path, src string) error {
		for _, m := range directiveRe.FindAllStringSubmatch(src, -1) {
			table, class, chain := m[1], m[2], m[3]
			if _, dup := out[table]; dup {
				return fmt.Errorf("%s: duplicate scope directive for table %q", path, table)
			}
			rule := TableRule{Class: class}
			if chain != "-" {
				rule.Chain = strings.Split(chain, ",")
			}
			switch class {
			case "org", "project", "environment", "folder", "key", "instance", "authn", "system":
			default:
				return fmt.Errorf("%s: table %q has unknown scope class %q", path, table, class)
			}
			out[table] = rule
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// CollectTables replays the migration set's table statements in version order
// and returns two sets: the tables that exist at rest (`live`), and every name
// a CREATE ever mentioned (`named`).
//
// They differ because of the sqlite rebuild — create a twin, copy, drop the
// original, rename the twin over it — which is the only way that engine reaches
// a column with no default, since it can neither add a NOT NULL column without
// one nor drop one afterwards (migration 00006 established the shape, 00009
// reuses it). The two sets exist because the two checks that consume them want
// opposite things: "every table is classified" must ask about live tables only,
// or it would demand a directive for a name that is gone by commit; "no
// directive dangles" must ask about every name, or declaring the twin — which
// 00006 does on both engines — would look like a stale entry.
func CollectTables(dir string) (live, named []string, err error) {
	alive := map[string]bool{}
	seen := map[string]bool{}
	if err := eachSQLFile(dir, func(_, src string) error {
		for _, stmt := range tableStatementRe.FindAllStringSubmatch(src, -1) {
			switch {
			case stmt[1] != "": // CREATE TABLE x
				alive[stmt[1]] = true
				seen[stmt[1]] = true
			case stmt[2] != "": // DROP TABLE x
				delete(alive, stmt[2])
			default: // ALTER TABLE x RENAME TO y
				delete(alive, stmt[3])
				alive[stmt[4]] = true
				seen[stmt[4]] = true
			}
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}
	return sortedSet(alive), sortedSet(seen), nil
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ParseQueries reads every sqlc query block in dir, with its hikyo
// annotation if the line directly above the name line carries one.
func ParseQueries(dir string) ([]Query, error) {
	var out []Query
	if err := eachSQLFile(dir, func(path, src string) error {
		lines := strings.Split(src, "\n")
		for i := 0; i < len(lines); i++ {
			m := nameRe.FindStringSubmatch(strings.TrimSpace(lines[i]))
			if m == nil {
				continue
			}
			q := Query{Name: m[1], Cmd: m[2]}
			if i > 0 {
				if a := annotRe.FindStringSubmatch(strings.TrimSpace(lines[i-1])); a != nil {
					q.Annotation = a[1]
				}
			}
			var body []string
			for i++; i < len(lines); i++ {
				line := strings.TrimSpace(lines[i])
				if nameRe.MatchString(line) || annotRe.MatchString(line) {
					i--
					break
				}
				if strings.HasPrefix(line, "--") {
					continue
				}
				if line != "" {
					body = append(body, line)
				}
			}
			q.SQL = strings.TrimSuffix(strings.Join(body, " "), ";")
			out = append(out, q)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// CheckSQLPredicates runs analyzer 2 over both engines' migration and query
// directories under repoRoot, including the cross-engine agreement checks
// (same tables, same directives, same query names on both engines).
func CheckSQLPredicates(repoRoot string) []string {
	var findings []string
	perEngine := map[string][]Query{}
	perEngineRules := map[string]map[string]TableRule{}

	for _, engine := range []string{"sqlite", "postgres"} {
		migDir := filepath.Join(repoRoot, "internal", "store", "migrations", engine)
		queryDir := filepath.Join(repoRoot, "internal", "store", "queries", engine)

		rules, err := ParseScopeDirectives(migDir)
		if err != nil {
			return append(findings, "sqlpredicate: "+err.Error())
		}
		live, named, err := CollectTables(migDir)
		if err != nil {
			return append(findings, "sqlpredicate: "+err.Error())
		}
		for _, t := range live {
			if _, ok := rules[t]; !ok {
				findings = append(findings, fmt.Sprintf("sqlpredicate(%s): table %q has no hikyo:table scope directive — the derived registry must be total", engine, t))
			}
		}
		everNamed := map[string]bool{}
		for _, t := range named {
			everNamed[t] = true
		}
		for t := range rules {
			if !everNamed[t] {
				findings = append(findings, fmt.Sprintf("sqlpredicate(%s): scope directive for %q names no created table", engine, t))
			}
		}

		queries, err := ParseQueries(queryDir)
		if err != nil {
			return append(findings, "sqlpredicate: "+err.Error())
		}
		perEngine[engine] = queries
		perEngineRules[engine] = rules
		for _, q := range queries {
			findings = append(findings, checkQuery(engine, q, rules)...)
		}
	}

	findings = append(findings, crossEngine(perEngine, perEngineRules)...)
	return findings
}

func checkQuery(engine string, q Query, rules map[string]TableRule) []string {
	label := fmt.Sprintf("sqlpredicate(%s): %s", engine, q.Name)
	if q.Annotation != "" {
		// Exempt from predicate requirements; pinned by invariant 13.
		return nil
	}
	sql := maskSQLCArgs(normalizeSpace(q.SQL))
	upper := strings.ToUpper(sql)

	// Conservative rejection: shapes the analyzer cannot prove are refused
	// outright, forcing a provable rewrite.
	for _, banned := range []string{" UNION ", "WITH ", " EXCEPT ", " INTERSECT ", " JOIN ", " OR ", "ON CONFLICT"} {
		if strings.Contains(upper, banned) || strings.HasPrefix(upper, strings.TrimSpace(banned)+" ") {
			return []string{fmt.Sprintf("%s: unprovable shape (%s) — rewrite into a form the analyzer accepts or annotate under review", label, strings.TrimSpace(banned))}
		}
	}
	if strings.Count(upper, "SELECT") > 1 {
		return []string{label + ": nested SELECT is an unprovable shape"}
	}

	table, kind, ok := statementTarget(upper)
	if !ok {
		return []string{label + ": unrecognised statement shape — the analyzer only accepts single-table SELECT/INSERT/UPDATE/DELETE"}
	}
	tableName := strings.ToLower(table)
	rule, known := rules[tableName]
	if !known {
		return []string{fmt.Sprintf("%s: table %q not in the derived scope registry", label, tableName)}
	}

	switch rule.Class {
	case "authn":
		return []string{fmt.Sprintf("%s: table %q is the resolution surface — only hikyo:authn-resolution annotated queries may touch it", label, tableName)}
	case "system":
		return []string{fmt.Sprintf("%s: table %q is system-owned — store queries may not touch it", label, tableName)}
	case "instance":
		// Instance-class tables (principals) hold no tenant chain; the
		// authorization data around them is authn-class. Nothing to require.
		return nil
	}

	// Tenant-owned table: org-class tables are addressed by their own id
	// bound from the proof; deeper classes carry explicit chain columns.
	chainCols := rule.Chain

	switch kind {
	case "INSERT":
		return checkInsert(label, sql, upper, chainCols)
	case "SELECT", "DELETE":
		return checkWhere(label, sql, upper, chainCols)
	case "UPDATE":
		var out []string
		out = append(out, checkWhere(label, sql, upper, chainCols)...)
		out = append(out, checkSet(label, sql, upper, chainCols)...)
		return out
	}
	return []string{label + ": unreachable statement kind"}
}

func statementTarget(upper string) (table, kind string, ok bool) {
	for _, pat := range []struct {
		kind string
		re   *regexp.Regexp
	}{
		{"INSERT", regexp.MustCompile(`^INSERT INTO (\w+)`)},
		{"UPDATE", regexp.MustCompile(`^UPDATE (\w+)`)},
		{"DELETE", regexp.MustCompile(`^DELETE FROM (\w+)`)},
		{"SELECT", regexp.MustCompile(`^SELECT .+ FROM (\w+)(?: WHERE .*| ORDER BY .*)?$`)},
	} {
		if m := pat.re.FindStringSubmatch(upper); m != nil {
			return m[1], pat.kind, true
		}
	}
	return "", "", false
}

// checkWhere demands every chain column as a top-level `col = param`
// conjunct, and refuses parenthesised predicates outright (a paren means a
// shape this analyzer cannot prove).
func checkWhere(label, sql, upper string, chainCols []string) []string {
	idx := strings.Index(upper, " WHERE ")
	if idx < 0 {
		if len(chainCols) == 0 {
			return nil
		}
		return []string{fmt.Sprintf("%s: tenant-owned table queried without a WHERE clause", label)}
	}
	where := sql[idx+len(" WHERE "):]
	// Trailing clauses that are not predicates get cut before the conjunct
	// walk. FOR UPDATE is a row-lock request, ORDER BY a sort; neither narrows
	// which rows the chain conjuncts already confined.
	for _, tail := range []string{" ORDER BY ", " FOR UPDATE"} {
		if end := strings.Index(strings.ToUpper(where), tail); end >= 0 {
			where = where[:end]
		}
	}
	if strings.ContainsAny(where, "()") {
		return []string{label + ": parenthesised predicate is an unprovable shape"}
	}
	conjuncts := andSplitRe.Split(where, -1)
	present := map[string]bool{}
	chain := map[string]bool{}
	for _, col := range chainCols {
		chain[col] = true
	}
	for _, c := range conjuncts {
		c = strings.TrimSpace(c)
		m := conjunctRe.FindStringSubmatch(c)
		if m == nil {
			return []string{fmt.Sprintf("%s: conjunct %q is not a provable `column OP param` shape", label, c)}
		}
		col, op := strings.ToLower(m[1]), m[2]
		// Chain columns require equality — a range predicate on a chain
		// column is not a tenant address. Non-chain columns may carry the
		// comparison operators (cursor and time-range predicates on the
		// audit trails); they only ever narrow within the chain conjunct.
		if chain[col] && op != "=" {
			return []string{fmt.Sprintf("%s: chain column %q used with %q — chain conjuncts must be equality", label, col, op)}
		}
		if op == "=" {
			present[col] = true
		}
	}
	var out []string
	for _, col := range chainCols {
		if !present[col] {
			out = append(out, fmt.Sprintf("%s: missing top-level chain conjunct on %q", label, col))
		}
	}
	return out
}

// checkInsert demands the chain columns in the INSERT column list; the Go
// binding layer (conformance-tested) is what binds them from the proof.
func checkInsert(label, sql, upper string, chainCols []string) []string {
	m := regexp.MustCompile(`^INSERT INTO \w+ \(([^)]+)\)`).FindStringSubmatch(upper)
	if m == nil {
		return []string{label + ": INSERT without an explicit column list is an unprovable shape"}
	}
	cols := map[string]bool{}
	for _, c := range strings.Split(m[1], ",") {
		cols[strings.ToLower(strings.TrimSpace(c))] = true
	}
	var out []string
	for _, col := range chainCols {
		if !cols[col] {
			out = append(out, fmt.Sprintf("%s: INSERT omits chain column %q", label, col))
		}
	}
	return out
}

// checkSet bans SET on chain columns and on the row's own id: chain columns
// are immutable, re-parenting is a new row.
func checkSet(label, sql, upper string, chainCols []string) []string {
	start := strings.Index(upper, " SET ")
	end := strings.Index(upper, " WHERE ")
	if start < 0 || end < 0 || end <= start {
		return []string{label + ": UPDATE without SET/WHERE is an unprovable shape"}
	}
	set := upper[start+len(" SET ") : end]
	immutable := append([]string{"id"}, chainCols...)
	var out []string
	for _, col := range immutable {
		if setColRe(col).MatchString(set) {
			out = append(out, fmt.Sprintf("%s: SET names immutable column %q — chain columns never mutate; re-parenting is a new row", label, col))
		}
	}
	return out
}

func crossEngine(queries map[string][]Query, rules map[string]map[string]TableRule) []string {
	var out []string
	names := map[string]map[string]bool{}
	for engine, qs := range queries {
		names[engine] = map[string]bool{}
		for _, q := range qs {
			names[engine][q.Name] = true
		}
	}
	for name := range names["sqlite"] {
		if !names["postgres"][name] {
			out = append(out, fmt.Sprintf("sqlpredicate: query %q exists on sqlite but not postgres", name))
		}
	}
	for name := range names["postgres"] {
		if !names["sqlite"][name] {
			out = append(out, fmt.Sprintf("sqlpredicate: query %q exists on postgres but not sqlite", name))
		}
	}
	sq, pg := rules["sqlite"], rules["postgres"]
	for t, r := range sq {
		pr, ok := pg[t]
		if !ok || pr.Class != r.Class || strings.Join(pr.Chain, ",") != strings.Join(r.Chain, ",") {
			out = append(out, fmt.Sprintf("sqlpredicate: scope directive for %q differs between engines", t))
		}
	}
	for t := range pg {
		if _, ok := sq[t]; !ok {
			out = append(out, fmt.Sprintf("sqlpredicate: scope directive for %q exists on postgres only", t))
		}
	}
	return out
}

func eachSQLFile(dir string, fn func(path, src string) error) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := pathutil.ReadFileWithin(dir, path)
		if err != nil {
			return err
		}
		if err := fn(path, string(b)); err != nil {
			return err
		}
	}
	return nil
}

var (
	andSplitRe = regexp.MustCompile(`(?i)\s+AND\s+`)
	conjunctRe = regexp.MustCompile(`^(\w+)\s*(=|<=|>=|<|>)\s*` + paramRe + `$`)
	spaceRe    = regexp.MustCompile(`\s+`)

	setColRes  = map[string]*regexp.Regexp{}
	setColResM sync.Mutex
)

// setColRe caches the per-column SET matcher instead of recompiling inside
// the immutable-columns loop.
func setColRe(col string) *regexp.Regexp {
	setColResM.Lock()
	defer setColResM.Unlock()
	re, ok := setColRes[col]
	if !ok {
		re = regexp.MustCompile(`(?i)(^|,)\s*` + regexp.QuoteMeta(col) + `\s*=`)
		setColRes[col] = re
	}
	return re
}

func normalizeSpace(s string) string {
	return strings.TrimSpace(spaceRe.ReplaceAllString(s, " "))
}
