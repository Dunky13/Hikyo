package isolation

// The audit-model ADR's end-to-end acceptance criteria (mvp-boundary A4),
// on both engines: denial durability (including under an induced commit
// failure), the export INTENT/OUTCOME pair, and the page-boundary
// revocation stop.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/service"
	"github.com/Dunky13/wenv/internal/store"
)

func queryString(t *testing.T, db *store.DB, q string) string {
	t.Helper()
	var s string
	var err error
	if db.Engine() == store.EnginePostgres {
		err = db.PG().QueryRow(t.Context(), q).Scan(&s)
	} else {
		err = db.SQLiteRead().QueryRowContext(t.Context(), q).Scan(&s)
	}
	if err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return s
}

// hookWriter triggers a side effect on its first write — the mid-export
// revocation lever.
type hookWriter struct {
	buf     bytes.Buffer
	onFirst func()
	fired   bool
}

func (w *hookWriter) Write(p []byte) (int, error) {
	if !w.fired {
		w.fired = true
		if w.onFirst != nil {
			w.onFirst()
		}
	}
	return w.buf.Write(p)
}

// failingWriter fails every write — the sink-disconnect lever.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("sink gone")
}

func runAuditSuite(t *testing.T, db *store.DB) {
	audits := &service.Audits{DB: db, SettleHorizon: service.ZeroSettleHorizon}
	envs := &service.Environments{DB: db}
	projects := &service.Projects{DB: db}
	orgsSvc := &service.Orgs{DB: db}

	countTenant := func(where string) int64 {
		return queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE "+where)
	}
	countInstance := func(where string) int64 {
		return queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE "+where)
	}

	t.Run("denial_resolvable_durable_before_response", func(t *testing.T) {
		before := countTenant("type = 'grant.denied'")
		_, err := envs.Get(tctx(t), bob, domain.Scope{Org: orgA, Project: prjA1, Env: envA1})
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("cross-org probe outcome = %v, want uniform not-found", err)
		}
		// The service call has returned; the denial event must already be
		// durable (flush commits before tx.Read returns), in the TENANT
		// trail with the truthful resolved chain — org A's auditors see
		// org A being probed.
		after := countTenant("type = 'grant.denied' AND org_id = 'org_a' AND actor_id = 'usr_bob' AND actor_class = 'human' AND outcome = 'denied'")
		if after != before+1 {
			t.Fatalf("resolvable denial events for bob in org A: %d, want %d", after, before+1)
		}
		if n := countTenant("type = 'grant.denied' AND actor_id = 'usr_bob' AND payload LIKE '%resolvable%' AND payload LIKE '%environment.read%'"); n == 0 {
			t.Error("denial payload does not carry operation + resolution shape")
		}
		if n := countTenant("payload LIKE '%grants_missing%' OR payload LIKE '%missing_grants%'"); n != 0 {
			t.Error("denial payload enumerates missing grants — authorization oracle")
		}
	})

	t.Run("denial_unresolvable_instance_trail", func(t *testing.T) {
		before := countInstance("type = 'grant.denied'")
		_, err := envs.Get(tctx(t), bob, domain.Scope{Org: "org_zz", Project: "prj_zz", Env: "env_zz"})
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("unresolvable probe outcome = %v, want uniform not-found", err)
		}
		after := countInstance("type = 'grant.denied' AND actor_id = 'usr_bob' AND payload LIKE '%unresolvable%' AND payload LIKE '%org_zz%'")
		if after != before+1 {
			t.Fatalf("unresolvable denial not recorded on the instance trail with caller-asserted claims (%d -> %d)", before, after)
		}
		// No chain is recorded: the addressed identifiers stay claims.
		if n := countTenant("org_id = 'org_zz'"); n != 0 {
			t.Error("unresolvable denial materialized a tenant chain")
		}
	})

	t.Run("instance_denial", func(t *testing.T) {
		_, err := audits.InstanceQuery(tctx(t), nobody, store.AuditFilter{Limit: 10})
		if !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatalf("instance query without audit-read = %v, want unauthorized", err)
		}
		if n := countInstance("type = 'grant.denied' AND actor_id = 'usr_nobody' AND payload LIKE '%audit.instance-query%'"); n != 1 {
			t.Fatalf("instance-operation denial events = %d, want 1", n)
		}
	})

	t.Run("domain_event_committed_in_transaction", func(t *testing.T) {
		proj, err := projects.Create(tctx(t), alice, orgA, "audited-project")
		if err != nil {
			t.Fatal(err)
		}
		if n := countTenant("type = 'settings.project_created' AND org_id = 'org_a' AND actor_id = 'usr_alice' AND object_id = '" + proj.ID + "'"); n != 1 {
			t.Fatalf("project-created events = %d, want 1", n)
		}
	})

	t.Run("query_is_audited_unconditionally", func(t *testing.T) {
		page, err := audits.Query(tctx(t), alice, domain.Scope{Org: orgA}, store.AuditFilter{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			t.Fatal("org A trail is empty — prior subtests wrote events")
		}
		if n := countTenant("type = 'audit.query' AND actor_id = 'usr_alice' AND payload LIKE '%row_count%'"); n != 1 {
			t.Fatalf("audit.query events = %d, want 1 (one per query, normalized filters + row count)", n)
		}
		// The reader capability is its own: org-admin-shaped capabilities do
		// not imply it.
		if _, err := audits.Query(tctx(t), reader, domain.Scope{Org: orgA}, store.AuditFilter{Limit: 10}); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("reader without audit-read = %v, want uniform not-found", err)
		}
	})

	t.Run("instance_query_grant_evaluated", func(t *testing.T) {
		page, err := audits.InstanceQuery(tctx(t), root, store.AuditFilter{Limit: 100})
		if err != nil {
			t.Fatalf("root with instance audit-read: %v", err)
		}
		// Asserting the ROWS, not just the absence of an error: an instance
		// page that silently returns nothing (a mis-bound paging parameter)
		// would otherwise pass every other assertion here.
		if len(page) == 0 {
			t.Fatal("instance trail page is empty — prior subtests wrote instance events")
		}
		if n := countInstance("type = 'audit.query' AND actor_id = 'usr_root'"); n != 1 {
			t.Fatalf("instance audit.query events = %d, want 1", n)
		}
	})

	t.Run("export_intent_outcome_pairing", func(t *testing.T) {
		var buf bytes.Buffer
		if err := audits.Export(tctx(t), alice, domain.Scope{Org: orgA}, store.AuditFilter{}, 2, &buf); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) == 0 {
			t.Fatal("export streamed nothing")
		}
		for _, line := range lines {
			var parsed map[string]any
			if err := json.Unmarshal([]byte(line), &parsed); err != nil {
				t.Fatalf("export line is not JSONL: %v", err)
			}
			if _, ok := parsed["payload"]; !ok {
				t.Fatal("export line lacks the payload")
			}
		}
		startedID := queryString(t, db,
			"SELECT id FROM audit_tenant_events WHERE type = 'audit.export_started' AND outcome = 'intent' ORDER BY seq DESC LIMIT 1")
		completed := countTenant(fmt.Sprintf(
			"type = 'audit.export_completed' AND outcome = 'success' AND correlation_id = '%s' AND payload LIKE '%%\"rows_streamed\":%d%%'",
			startedID, len(lines)))
		if completed != 1 {
			t.Fatalf("completed events correlated to %s with rows_streamed=%d: %d, want 1", startedID, len(lines), completed)
		}
	})

	t.Run("export_sink_disconnect_terminal_outcome", func(t *testing.T) {
		err := audits.Export(tctx(t), alice, domain.Scope{Org: orgA}, store.AuditFilter{}, 2, failingWriter{})
		if err == nil {
			t.Fatal("export into a dead sink succeeded")
		}
		if n := countTenant("type = 'audit.export_completed' AND outcome = 'disconnected'"); n != 1 {
			t.Fatalf("disconnected terminal events = %d, want 1", n)
		}
	})

	t.Run("export_revocation_stops_at_page_boundary", func(t *testing.T) {
		startedBefore := countTenant("type = 'audit.export_started'")
		w := &hookWriter{onFirst: func() {
			// Revoke alice's audit-read after the first committed page has
			// started streaming; the next page's fresh transaction-bound
			// proof must fail.
			execRaw(t, db, "DELETE FROM grants WHERE id = 'g_al_ar'")
		}}
		err := audits.Export(tctx(t), alice, domain.Scope{Org: orgA}, store.AuditFilter{}, 1, w)
		if !errors.Is(err, service.ErrExportUnpaired) {
			t.Fatalf("mid-export revocation outcome = %v, want ErrExportUnpaired", err)
		}
		if w.buf.Len() == 0 {
			t.Fatal("stream stopped before the first page — revocation must stop at the NEXT page boundary")
		}
		if got := int(countTenant("type = 'audit.export_started'")) - int(startedBefore); got != 1 {
			t.Fatalf("started events during revoked export = %d, want 1", got)
		}
		startedID := queryString(t, db,
			"SELECT id FROM audit_tenant_events WHERE type = 'audit.export_started' ORDER BY seq DESC LIMIT 1")
		if n := countTenant("type = 'audit.export_completed' AND correlation_id = '" + startedID + "'"); n != 0 {
			t.Fatal("revoked export has a completed event — the unpaired started record is the visible reconciliation case")
		}
		// The revoked page authorization itself is a recorded denial.
		if n := countTenant("type = 'grant.denied' AND actor_id = 'usr_alice' AND payload LIKE '%audit.export-org%'"); n != 1 {
			t.Fatalf("revocation denial events = %d, want 1", n)
		}
		// Restore the grant for any later subtest.
		execRaw(t, db, "INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_al_ar', 'usr_alice', 'audit-read', 'org_a', NULL, NULL, "+ts+")")
	})

	t.Run("no_token_material_in_trails", func(t *testing.T) {
		// The dump-grep half of CI invariant 4, extended to both audit
		// tables: plant a grammar-valid bearer token in every
		// attacker-influencable field a denial records (user agent, claimed
		// identifiers), then grep the trails — the marker must be there and
		// the token must not.
		token := "ew_1_wl_" + strings.Repeat("Ab3", 15)
		wired := audit.WithContext(tctx(t), audit.Context{
			UserAgent: "probe/1.0 " + token,
			SourceIP:  "203.0.113.7",
			Origin:    audit.OriginAPI,
		})
		if _, err := envs.Get(wired, bob, domain.Scope{Org: orgA, Project: prjA1, Env: envA1}); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("resolvable probe = %v", err)
		}
		if _, err := envs.Get(wired, bob, domain.Scope{Org: domain.OrgID("org_" + token), Project: "prj_x", Env: "env_x"}); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("unresolvable probe = %v", err)
		}
		for _, table := range []string{"audit_tenant_events", "audit_instance_events"} {
			for _, col := range []string{"user_agent", "payload", "source_ip", "object_id", "correlation_id"} {
				if n := queryInt(t, db, "SELECT COUNT(*) FROM "+table+" WHERE "+col+" LIKE '%"+token+"%'"); n != 0 {
					t.Errorf("%s.%s holds raw token material (%d rows)", table, col, n)
				}
			}
			if n := queryInt(t, db, "SELECT COUNT(*) FROM "+table+" WHERE user_agent LIKE '%"+audit.RedactionMarker+"%'"); n == 0 {
				t.Errorf("%s: no redaction marker found — the filter did not run", table)
			}
		}
		if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE payload LIKE '%"+audit.RedactionMarker+"%'"); n == 0 {
			t.Error("claimed identifiers were not token-filtered")
		}
	})

	t.Run("export_ceiling_excludes_unsettled_writes", func(t *testing.T) {
		// With the production horizon, an export must NOT reach events
		// written moments ago: those are exactly the ones whose transaction
		// may still be in flight, and whose seq an earlier page's cursor
		// could otherwise step past (cross-model R3). Same export, ceiling
		// disabled, sees them — so this asserts the ceiling, not an empty
		// trail.
		lagged := &service.Audits{DB: db, SettleHorizon: time.Hour}
		var buf bytes.Buffer
		if err := lagged.Export(tctx(t), alice, domain.Scope{Org: orgA}, store.AuditFilter{}, 10, &buf); err != nil {
			t.Fatal(err)
		}
		if n := strings.TrimSpace(buf.String()); n != "" {
			t.Errorf("export reached events inside the settle horizon:\n%s", n)
		}
		var live bytes.Buffer
		if err := audits.Export(tctx(t), alice, domain.Scope{Org: orgA}, store.AuditFilter{}, 10, &live); err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(live.String()) == "" {
			t.Fatal("ceiling-free export is also empty — the assertion above proves nothing")
		}
		// The started event records the ceiling it actually applied.
		if n := countTenant("type = 'audit.export_started' AND payload LIKE '%filter_to%'"); n == 0 {
			t.Error("export_started does not record the effective ceiling")
		}
	})

	t.Run("every_registered_type_is_actually_emitted", func(t *testing.T) {
		// The registry-closure invariant is static: it proves declarations
		// agree, not that an emitter exists. This runs last over the trails
		// the preceding subtests filled and asserts every registered type
		// really reached a table — an operation that drops its insert while
		// keeping its `events:` declaration fails here.
		if _, err := orgsSvc.List(tctx(t), root); err != nil {
			t.Fatal(err)
		}
		if err := envs.UpdateNote(tctx(t), alice, domain.Scope{Org: orgA, Project: prjA1, Env: envA1}, "noted"); err != nil {
			t.Fatal(err)
		}
		if _, err := envs.Create(tctx(t), alice, domain.Scope{Org: orgA, Project: prjA1}, "audited-env"); err != nil {
			t.Fatal(err)
		}
		if _, err := orgsSvc.Create(tctx(t), root, "audited-org", true, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		for _, typ := range audit.Types() {
			spec, _ := audit.Spec(typ)
			seen := int64(0)
			if spec.Trails[audit.TrailTenant] {
				seen += queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE type = '"+string(typ)+"'")
			}
			if spec.Trails[audit.TrailInstance] {
				seen += queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = '"+string(typ)+"'")
			}
			if seen == 0 {
				t.Errorf("registered event type %s was never emitted — declaration without an emitter", typ)
			}
		}
	})

	t.Run("denial_durability_under_induced_commit_failure", func(t *testing.T) {
		// Break the denial writer's target table, then probe: the response
		// MUST NOT be the uniform denial — a denial answer without its
		// durable record is what fail-closed forbids.
		execRaw(t, db, "ALTER TABLE audit_tenant_events RENAME TO audit_tenant_events_broken")
		defer execRaw(t, db, "ALTER TABLE audit_tenant_events_broken RENAME TO audit_tenant_events")
		_, err := envs.Get(tctx(t), bob, domain.Scope{Org: orgA, Project: prjA1, Env: envA1})
		if err == nil {
			t.Fatal("denied probe answered success under audit-write failure")
		}
		if errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("denied probe answered the uniform denial with no durable record: %v", err)
		}
		if !strings.Contains(err.Error(), "denial audit record not durable") {
			t.Fatalf("induced commit failure surfaced as %v, want the loud refusal", err)
		}
	})
}

func TestAuditCoreSQLite(t *testing.T) {
	runAuditSuite(t, seededDB(t, openSQLite))
}

func TestAuditCorePostgres(t *testing.T) {
	runAuditSuite(t, seededDB(t, openPostgres))
}

// TestPostgresDurabilityBootRefusal is the A4 CI leg the unit test cannot
// reach for real: a database whose synchronous_commit is off must refuse to
// boot. (The fsync leg needs a server restart and is unit-tested through
// the querier seam in internal/store.)
func TestPostgresDurabilityBootRefusal(t *testing.T) {
	dsn := os.Getenv("WENV_TEST_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI run without WENV_TEST_POSTGRES_DSN: the postgres durability leg must not silently skip in CI")
		}
		t.Skip("WENV_TEST_POSTGRES_DSN not set")
	}
	derived := derivedDatabase(t, dsn, "_durability")
	u, err := url.Parse(derived)
	if err != nil {
		t.Fatal(err)
	}
	name := strings.TrimPrefix(u.Path, "/")

	admin, err := store.Open(t.Context(), store.Config{Engine: store.EnginePostgres, DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.PG().Exec(t.Context(), "ALTER DATABASE "+pq(name)+" SET synchronous_commit = off"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.PG().Exec(t.Context(), "ALTER DATABASE "+pq(name)+" RESET synchronous_commit"); err != nil {
			t.Errorf("reset synchronous_commit: %v", err)
		}
	}()

	db, err := store.Open(t.Context(), store.Config{Engine: store.EnginePostgres, DSN: derived})
	if err == nil {
		db.Close()
		t.Fatal("boot accepted a database with synchronous_commit = off")
	}
	if !strings.Contains(err.Error(), "refusing to boot") {
		t.Fatalf("refusal does not name itself: %v", err)
	}
}
