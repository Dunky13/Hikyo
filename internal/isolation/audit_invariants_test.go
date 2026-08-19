package isolation

// The audit-model ADR's CI invariants (#45), joining the tenant-isolation
// suite. Numbering here is the audit-model ADR's own (§ CI invariants); the
// invariant → test map lives in docs/handoff/45-audit-core.md.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/lint"
)

type auditExemptions struct {
	Wire       map[string]string `json:"wire"`
	Operations map[string]string `json:"operations"`
}

func loadAuditExemptions(t *testing.T) auditExemptions {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "audited_exemptions.json"))
	if err != nil {
		t.Fatalf("audited-exemptions fixture: %v", err)
	}
	var out auditExemptions
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("audited-exemptions fixture unreadable: %v", err)
	}
	return out
}

// TestInvariantAuditCompleteness is the audit-model ADR's CI invariant 2, wired
// to the registry that is actually total: every operation and every wire
// entry point maps to event type(s), carries `audited: none` under the
// default-deny permit rule, or sits in the name-pinned exemption fixture
// (a reviewed deviation, one entry per name — a stale entry fails too).
func TestInvariantAuditCompleteness(t *testing.T) {
	ex := loadAuditExemptions(t)

	mappings := facts.AuditMappings()
	for op, m := range mappings {
		_, exempt := ex.Operations[string(op)]
		switch {
		case m.AuditedNone:
			if len(m.Events) > 0 {
				t.Errorf("%s: both audited-none and event types — pick one", op)
			}
			if exempt {
				t.Errorf("%s: audited-none AND exemption-pinned — the fixture must carry only silent operations", op)
			}
			// The default-deny permit rule: tenant class, a non-empty
			// conjunction made only of `read` atoms, mutating nothing. The
			// import presence read has separate project-structure and
			// environment-presence atoms, but remains a pure read.
			if m.Class != authz.ClassTenant {
				t.Errorf("%s: audited-none on a non-tenant operation — refused (default-deny)", op)
			}
			if len(m.Formula) == 0 {
				t.Errorf("%s: audited-none with an empty formula — refused (default-deny)", op)
			}
			for _, atom := range m.Formula {
				if atom.Cap != domain.CapRead {
					t.Errorf("%s: audited-none with formula beyond read-only atoms — refused (default-deny)", op)
				}
			}
			if !m.ReadOnly {
				t.Errorf("%s: audited-none on a mutating operation — refused (default-deny)", op)
			}
		case len(m.Events) > 0:
			if exempt {
				t.Errorf("%s: maps to events but is exemption-pinned — remove the stale fixture entry", op)
			}
		case exempt:
			// Reviewed deviation; nothing further.
		default:
			t.Errorf("%s: unaudited — map it to event types, declare audited-none (if it qualifies), or pin it in the exemption fixture with its reason", op)
		}
	}
	for name := range ex.Operations {
		if _, ok := mappings[authz.Operation(name)]; !ok {
			t.Errorf("exemption fixture names unknown operation %q", name)
		}
	}

	wire := facts.Wire()
	wireEvents := facts.WireEvents()
	for entry, class := range wire {
		if class == authz.ClassStub {
			// Declared not-yet-an-operation: no route, no store, enforced by
			// the totality invariant. Its class change is what obliges audit
			// mapping.
			continue
		}
		_, pinnedExempt := ex.Wire[entry]
		events := wireEvents[entry]
		// A route reaching ONLY audited-none operations is silent by the permit
		// rule; a route reaching any emitting operation is audited. The two are
		// tracked separately because a route can reach both — #50's copy and
		// clone reach the audited-none `value.list` (they read `config`
		// material under it) alongside the operations that emit the copy
		// events — and treating the audited-none leg as an exemption would
		// report an audited route as unaudited.
		silent := true
		for _, op := range facts.WireRoutes()[entry] {
			// A route that reaches a registered operation inherits that
			// operation's audit mapping; declaring it twice is how the two
			// declarations drift apart. A route that dispatches between several
			// operations inherits from every one it can reach.
			m, known := mappings[op]
			if !known {
				t.Errorf("wire entry %s names unregistered operation %q", entry, op)
			}
			events = append(events, m.Events...)
			if !m.AuditedNone {
				silent = false
			}
		}
		switch {
		case len(events) > 0 && pinnedExempt:
			t.Errorf("wire entry %s: emits events AND is exemption-pinned — remove the stale fixture entry", entry)
		case len(events) > 0, pinnedExempt, silent && len(facts.WireRoutes()[entry]) > 0:
			// Audited directly, silent under the permit rule, or a reviewed
			// deviation.
		default:
			t.Errorf("wire entry %s (class %v): unaudited and not exemption-pinned", entry, class)
		}
	}
	for entry := range wireEvents {
		if _, ok := wire[entry]; !ok {
			t.Errorf("wire-event mapping names unknown wire entry %q", entry)
		}
	}
	for name := range ex.Wire {
		if _, ok := wire[name]; !ok {
			t.Errorf("exemption fixture names unknown wire entry %q", name)
		}
	}
}

// TestInvariantAuditRegistryClosure is CI invariant 1's linkage half: every
// event type an operation claims to emit exists in the closed registry.
// (Runtime closure — an unregistered emit failing the operation — is
// audit.Validate, exercised by the write-path tests.)
func TestInvariantAuditRegistryClosure(t *testing.T) {
	for op, m := range facts.AuditMappings() {
		for _, et := range m.Events {
			if _, ok := audit.Spec(et); !ok {
				t.Errorf("%s claims event type %q which is not in the closed registry", op, et)
			}
		}
	}
	// Every registered type is emitted by some operation or is one of the two
	// cross-cutting settlement events: grant denial from authz, or artifact-class
	// refusal from request admission. Neither has one operation row because each
	// can occur across the operation registry. A registered-but-unemittable type
	// is dead catalogue.
	emitted := map[audit.EventType]bool{
		audit.EventGrantDenied:              true,
		audit.EventAuthArtifactClassRefused: true,
	}
	for _, m := range facts.AuditMappings() {
		for _, et := range m.Events {
			emitted[et] = true
		}
	}
	// Wire entries that audit without an operation behind them (the
	// authentication surface) count as emitters too — the point of the
	// invariant is that no registered type is dead catalogue, not that every
	// type has an operation row.
	for entry, events := range facts.WireEvents() {
		for _, et := range events {
			if _, ok := audit.Spec(et); !ok {
				t.Errorf("wire entry %s claims event type %q which is not in the closed registry", entry, et)
			}
			emitted[et] = true
		}
	}
	for site, events := range facts.SystemSiteEvents() {
		for _, et := range events {
			if _, ok := audit.Spec(et); !ok {
				t.Errorf("system site %s claims event type %q which is not in the closed registry", site, et)
			}
			emitted[et] = true
		}
	}
	for _, et := range audit.Types() {
		if !emitted[et] {
			t.Errorf("registered event type %q has no emitting operation", et)
		}
	}
}

// TestInvariantAuditAppendOnly is CI invariant 3 (plus invariant 7's
// SET-ban): INSERT and SELECT only, empty licensed-deleter allowlist until
// pruning and org-deletion land their pinned queries.
func TestInvariantAuditAppendOnly(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range lint.CheckAuditAppendOnly(root) {
		t.Error(f)
	}
}

// TestInvariantAuditRedaction is CI invariant 8: full formatting surface on
// the pinned sensitive types, no formatting/marshaling of them outside
// their owning package, no audit content in ops-log emission.
func TestInvariantAuditRedaction(t *testing.T) {
	pkgs, err := lint.LoadRepo()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range lint.CheckRedactionSurfaces(pkgs) {
		t.Error(f)
	}
	for _, f := range lint.CheckSensitiveFormatting(pkgs) {
		t.Error(f)
	}
}

// TestInvariantAuditFKException is CI invariant 13: audit_tenant_events is
// the SINGLE named tenant-owned table permitted to omit ancestry FKs (an
// audit event must outlive its subject); every other chain-carrying table
// must reference its parents, and the audit tables must reference nothing.
func TestInvariantAuditFKException(t *testing.T) {
	fkExempt := map[string]bool{
		"audit_tenant_events": true, // amendment part 5 — the single named exception
		"orgs":                true, // chain root: its chain IS its own id, no parent exists
	}
	refRe := regexp.MustCompile(`(?i)REFERENCES`)
	for _, engine := range []string{"sqlite", "postgres"} {
		migDir := filepath.Join("..", "store", "migrations", engine)
		rules, err := lint.ParseScopeDirectives(migDir)
		if err != nil {
			t.Fatal(err)
		}
		bodies := tableBodies(t, migDir)
		for table, rule := range rules {
			body, ok := bodies[table]
			if !ok {
				t.Errorf("%s: directive for %q names no created table", engine, table)
				continue
			}
			hasRefs := refRe.MatchString(body)
			switch {
			case table == "audit_tenant_events" || table == "audit_instance_events":
				if hasRefs {
					t.Errorf("%s: %s carries a foreign key — an audit event must outlive its subject; the chain is denormalized immutable ids only", engine, table)
				}
			case len(rule.Chain) > 0 && !fkExempt[table]:
				if !hasRefs {
					t.Errorf("%s: tenant-owned table %s has chain columns but no ancestry FKs — audit_tenant_events is the single named exception (audit-model ADR CI invariant 13)", engine, table)
				}
			}
		}
	}
}

// TestInvariantAuditNoAggregates is CI invariant 5's structural half: no
// counter or mutable-aggregate column exists in the audit schema, pinned by
// asserting the exact envelope column set on both engines (any new column —
// counter or otherwise — is a reviewed diff here).
func TestInvariantAuditNoAggregates(t *testing.T) {
	wantTenant := []string{
		"seq", "id", "type", "schema_version", "occurred_at", "occurred_asserted",
		"recorded_at", "actor_id", "actor_class", "actor_credential_id",
		"authority_id", "scope_class", "org_id", "project_id", "env_id",
		"object_type", "object_id", "outcome", "correlation_id",
		"source_ip", "user_agent", "origin", "payload",
	}
	wantInstance := []string{
		"seq", "id", "type", "schema_version", "occurred_at", "occurred_asserted",
		"recorded_at", "actor_id", "actor_class", "actor_credential_id",
		"authority_id", "object_type", "object_id", "outcome", "correlation_id",
		"source_ip", "user_agent", "origin", "payload",
	}
	sort.Strings(wantTenant)
	sort.Strings(wantInstance)
	for _, engine := range []string{"sqlite", "postgres"} {
		bodies := tableBodies(t, filepath.Join("..", "store", "migrations", engine))
		for table, want := range map[string][]string{
			"audit_tenant_events":   wantTenant,
			"audit_instance_events": wantInstance,
		} {
			got := columnNames(bodies[table])
			sort.Strings(got)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("%s: %s columns drifted from the pinned envelope:\n got %v\nwant %v", engine, table, got, want)
			}
		}
	}
}

// tableBodies returns each CREATE TABLE statement's body text per table.
func tableBodies(t *testing.T, migDir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(migDir)
	if err != nil {
		t.Fatal(err)
	}
	createRe := regexp.MustCompile(`(?is)CREATE TABLE (\w+) \((.*?)\n\);`)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(migDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range createRe.FindAllStringSubmatch(string(b), -1) {
			out[strings.ToLower(m[1])] = m[2]
		}
	}
	return out
}

// columnNames extracts the column identifiers from a CREATE TABLE body,
// skipping table-level constraints.
func columnNames(body string) []string {
	// Strip line comments first: a comma inside prose would otherwise split
	// into a fragment the identifier regex happily reads as a column.
	var stripped []string
	for _, line := range strings.Split(body, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		stripped = append(stripped, line)
	}
	body = strings.Join(stripped, "\n")

	var out []string
	depth := 0
	var lines []string
	current := strings.Builder{}
	for _, r := range body {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				lines = append(lines, current.String())
				current.Reset()
				continue
			}
		}
		current.WriteRune(r)
	}
	lines = append(lines, current.String())
	constraint := regexp.MustCompile(`(?i)^\s*(CHECK|UNIQUE|PRIMARY|FOREIGN|CONSTRAINT)\b`)
	ident := regexp.MustCompile(`^\s*(\w+)`)
	for _, line := range lines {
		if strings.TrimSpace(line) == "" || constraint.MatchString(line) {
			continue
		}
		if m := ident.FindStringSubmatch(line); m != nil {
			out = append(out, strings.ToLower(m[1]))
		}
	}
	return out
}
