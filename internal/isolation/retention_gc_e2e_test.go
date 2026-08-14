package isolation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

func TestRetentionGCC6SQLite(t *testing.T) {
	runRetentionGCC6(t, seededDB(t, openSQLite))
}

func TestRetentionGCC6Postgres(t *testing.T) {
	runRetentionGCC6(t, seededDB(t, openPostgres))
}

func TestRetentionPinSubsecondBoundarySQLite(t *testing.T) {
	runRetentionPinSubsecondBoundary(t, seededDB(t, openSQLite))
}

func TestRetentionPinSubsecondBoundaryPostgres(t *testing.T) {
	runRetentionPinSubsecondBoundary(t, seededDB(t, openPostgres))
}

func TestRetentionFailedSweepAuditSQLite(t *testing.T) {
	runRetentionFailedSweepAudit(t, seededDB(t, openSQLite))
}

func TestRetentionFailedSweepAuditPostgres(t *testing.T) {
	runRetentionFailedSweepAudit(t, seededDB(t, openPostgres))
}

func runRetentionFailedSweepAudit(t *testing.T, db *store.DB) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	retention := &service.Retention{DB: db, Now: func() time.Time {
		return time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	}}
	if _, err := retention.Sweep(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled sweep error = %v", err)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_instance_events
        WHERE type = 'retention.prune_run' AND outcome = 'failure'
          AND actor_class = 'system' AND payload LIKE '%"error_class":"canceled"%'`); n != 1 {
		t.Fatalf("failed prune-run audit events = %d, want 1", n)
	}
}

func runRetentionPinSubsecondBoundary(t *testing.T, db *store.DB) {
	t.Helper()
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	retention := &service.Retention{DB: db, Now: func() time.Time { return now }}
	policy := service.RetentionPolicy{MaxAge: time.Hour, LastRevisions: 1}
	if _, err := retention.SetProject(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeProject(orgA, prjA1), &policy); err != nil {
		t.Fatalf("set project retention: %v", err)
	}

	execRaw(t, db, `INSERT INTO environments
        (id, org_id, project_id, name, note, created_at, display_order)
        VALUES ('env_pin_boundary', 'org_a', 'prj_a1', 'pin-boundary', '', `+ts+`, 11)`)
	for revision, published := range map[int]string{
		1: "2026-08-01T00:00:00.000000Z",
		2: "2026-08-15T11:30:00.000000Z",
	} {
		snapshotID := fmt.Sprintf("snp_pin_boundary_%d", revision)
		execRaw(t, db, fmt.Sprintf(`INSERT INTO snapshots
            (id, org_id, project_id, environment_id, revision, schema_revision, published_by, published_at)
            VALUES ('%s', 'org_a', 'prj_a1', 'env_pin_boundary', %d, 1, 'usr_orgadmin', '%s')`,
			snapshotID, revision, published))
		execRaw(t, db, fmt.Sprintf(`INSERT INTO snapshot_entries
            (id, org_id, project_id, environment_id, snapshot_id, key_id, key_name, classification, ciphertext, value_entry_id)
            VALUES ('sen_pin_boundary_%d', 'org_a', 'prj_a1', 'env_pin_boundary', '%s', 'key_a1', 'GC_VALUE', 'config', 'payload-%d', 'val_pin_%d')`,
			revision, snapshotID, revision, revision))
	}
	execRaw(t, db, `INSERT INTO revision_pins
        (id, org_id, project_id, environment_id, workload_principal_id,
         snapshot_id, revision, authority_principal_id, expires_at, created_at,
         authorized_at, history_authorized, schema_override)
        VALUES ('pin_boundary', 'org_a', 'prj_a1', 'env_pin_boundary', 'mch_workload',
                'snp_pin_boundary_1', 1, 'usr_orgadmin', '2026-08-15T12:00:00.5Z',
                '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z', TRUE, FALSE)`)

	err := tx.Write(t.Context(), db, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		proof, err := authz.SystemAuthority(authz.SiteScheduler, az.Token())
		if err != nil {
			return err
		}
		eligible, err := repos.Retention().Eligible(ctx, proof, now, service.RetentionBatchSize)
		if err != nil {
			return err
		}
		for _, row := range eligible {
			if row.ID == "snp_pin_boundary_1" {
				t.Fatalf("future sub-second pin was treated as expired during eligibility")
			}
		}
		marked, err := repos.Retention().MarkCollected(ctx, proof, "snp_pin_boundary_1", "test-policy", now)
		if err != nil {
			return err
		}
		if marked {
			t.Fatalf("future sub-second pin was treated as expired during mark-time re-check")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("sub-second pin boundary: %v", err)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM snapshots WHERE id = 'snp_pin_boundary_1' AND payload_present = TRUE"); n != 1 {
		t.Fatal("future-pinned snapshot payload was collected")
	}
}

func runRetentionGCC6(t *testing.T, db *store.DB) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	retention := &service.Retention{DB: db, Now: func() time.Time { return now }}
	actor := service.LocalPrincipal(orgAdmin)

	orgPolicy := service.RetentionPolicy{MaxAge: 30 * 24 * time.Hour, LastRevisions: 3}
	if _, err := retention.SetOrg(t.Context(), actor, orgA, orgPolicy); err != nil {
		t.Fatalf("set org retention: %v", err)
	}
	projectPolicy := service.RetentionPolicy{MaxAge: 20 * 24 * time.Hour, LastRevisions: 2}
	const collectedPolicy = "keep-if-either(max_age=480h0m0s,last_revisions=2)"
	if _, err := retention.SetProject(t.Context(), actor, scopeProject(orgA, prjA1), &projectPolicy); err != nil {
		t.Fatalf("set project retention: %v", err)
	}
	_, err := retention.SetOrg(t.Context(), actor, orgA, service.RetentionPolicy{
		MaxAge: 10 * 24 * time.Hour, LastRevisions: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "org retention cap") || !strings.Contains(err.Error(), "prj_a1") {
		t.Fatalf("tighten below project override error = %v, want named org-cap refusal", err)
	}

	seedRetentionCorpus(t, db)
	if _, err := probeKeyring(t, db).ForProject(t.Context(), string(orgA), string(prjA1)); err != nil {
		t.Fatalf("seed GC project key: %v", err)
	}
	finishedAt := now.Add(5*time.Minute + 987*time.Nanosecond)
	clockReads := 0
	retention.Now = func() time.Time {
		clockReads++
		if clockReads >= 3 {
			return finishedAt
		}
		return now
	}
	collected, err := retention.Sweep(t.Context())
	if err != nil {
		t.Fatalf("retention sweep: %v", err)
	}
	if collected != 3 {
		t.Fatalf("collected snapshots = %d, want 3; markers=%s", collected,
			queryStrings(t, db, "SELECT environment_id || ':' || revision FROM snapshots WHERE collected_at IS NOT NULL ORDER BY environment_id, revision"))
	}

	for _, pair := range []string{"env_gc:1", "env_gc:3", "env_gc_inherited:1"} {
		env, rev, _ := strings.Cut(pair, ":")
		if n := queryInt(t, db, fmt.Sprintf(
			"SELECT COUNT(*) FROM snapshot_entries WHERE environment_id = '%s' AND snapshot_id = (SELECT id FROM snapshots WHERE environment_id = '%s' AND revision = %s)", env, env, rev)); n != 0 {
			t.Errorf("collected %s still has %d value-bearing rows", pair, n)
		}
		if n := queryInt(t, db, fmt.Sprintf(
			"SELECT COUNT(*) FROM snapshots WHERE environment_id = '%s' AND revision = %s AND payload_present = FALSE AND collected_at IS NOT NULL AND collected_policy <> ''", env, rev)); n != 1 {
			t.Errorf("collected %s has no durable presence bit, marker, and policy", pair)
		}
	}

	for _, pair := range []string{
		"env_gc:2",           // live pin
		"env_gc:4",           // within age window
		"env_gc:5",           // within project last-N
		"env_gc:6",           // current
		"env_gc_inherited:2", // within org last-N
		"env_gc_inherited:3", // within age window
		"env_gc_inherited:4", // current
	} {
		env, rev, _ := strings.Cut(pair, ":")
		if n := queryInt(t, db, fmt.Sprintf(
			"SELECT COUNT(*) FROM snapshot_entries WHERE environment_id = '%s' AND snapshot_id = (SELECT id FROM snapshots WHERE environment_id = '%s' AND revision = %s)", env, env, rev)); n != 1 {
			t.Errorf("retained %s has %d payload rows, want 1", pair, n)
		}
	}

	if n := queryInt(t, db, "SELECT COUNT(*) FROM snapshots WHERE environment_id IN ('env_gc', 'env_gc_inherited')"); n != 10 {
		t.Errorf("lineage snapshot rows = %d, want all 10", n)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM revision_key_changes WHERE environment_id IN ('env_gc', 'env_gc_inherited')"); n != 10 {
		t.Errorf("lineage key-change rows = %d, want all 10", n)
	}

	revisions := &service.Revisions{DB: db, Keyring: probeKeyring(t, db)}
	_, err = revisions.Show(t.Context(), actor, scopeEnv(orgA, prjA1, domain.EnvID("env_gc")), 1)
	var refusal *domain.CollectedRevisionError
	if !errors.As(err, &refusal) {
		t.Fatalf("collected fetch error = %v, want CollectedRevisionError", err)
	}
	if refusal.Revision != 1 || refusal.Policy != collectedPolicy {
		t.Fatalf("collected refusal = %+v, want revision 1 and collecting project policy", refusal)
	}
	pins := &service.Pins{DB: db, Keyring: probeKeyring(t, db), Now: func() time.Time { return now }}
	_, err = pins.Set(t.Context(), actor, scopeEnv(orgA, prjA1, domain.EnvID("env_gc")), service.SetPinRequest{
		WorkloadPrincipalID: mchWork,
		Revision:            1,
	})
	refusal = nil
	if !errors.As(err, &refusal) {
		t.Fatalf("pin collected revision error = %v, want CollectedRevisionError", err)
	}
	if refusal.Revision != 1 || refusal.Policy != collectedPolicy {
		t.Fatalf("pin collected refusal = %+v, want revision 1 and collecting project policy", refusal)
	}

	for _, eventType := range []string{"settings.org_retention_changed", "settings.project_retention_changed"} {
		if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE type = '"+eventType+"'"); n != 1 {
			t.Errorf("audit events %s = %d, want 1", eventType, n)
		}
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events
        WHERE type = 'retention.payload_gc' AND outcome = 'success'
          AND actor_class = 'system' AND scope_class = 'env'
          AND org_id = 'org_a' AND project_id IS NOT NULL AND env_id IS NOT NULL
          AND payload LIKE '%"snapshot_id"%' AND payload LIKE '%"collected_at"%'
          AND payload LIKE '%"policy"%'`); n != 3 {
		t.Errorf("payload-GC audit events = %d, want one scoped event per collected snapshot", n)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_instance_events
        WHERE type = 'retention.prune_run' AND outcome = 'success'
          AND actor_class = 'system' AND payload LIKE '%"candidates":3%'
          AND payload LIKE '%"revision_payloads":3%'`); n != 1 {
		t.Errorf("successful prune-run audit events = %d, want 1 with candidates and category count", n)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM retention_runtime WHERE id = 1 AND last_prune_success IS NOT NULL"); n != 1 {
		t.Error("last_prune_success was not persisted")
	}
	lastSuccess, recorded, err := retention.LastPruneSuccess(t.Context())
	if err != nil {
		t.Fatalf("read last_prune_success: %v", err)
	}
	wantFinishedAt := store.CanonTime(finishedAt)
	if !recorded || !lastSuccess.Equal(wantFinishedAt) {
		t.Errorf("last_prune_success = %s, recorded=%t, want canonical completion %s", lastSuccess, recorded, wantFinishedAt)
	}
}

func seedRetentionCorpus(t *testing.T, db *store.DB) {
	execRaw(t, db, `INSERT INTO environments
        (id, org_id, project_id, name, note, created_at, display_order)
        VALUES ('env_gc', 'org_a', 'prj_a1', 'gc-project', '', `+ts+`, 10)`)
	execRaw(t, db, `INSERT INTO environments
        (id, org_id, project_id, name, note, created_at, display_order)
        VALUES ('env_gc_inherited', 'org_a', 'prj_a2', 'gc-inherited', '', `+ts+`, 10)`)
	execRaw(t, db, `INSERT INTO service_accounts
        (id, principal_id, org_id, project_id, name, kind, created_at, created_by)
        VALUES ('svc_gc_workload', 'mch_workload', 'org_a', 'prj_a1', 'gc-workload', 'workload', `+ts+`, 'usr_orgadmin')`)
	execRaw(t, db, `INSERT INTO grants
        (id, principal_id, capability, org_id, project_id, env_id, created_at)
        VALUES ('g_gc_pin', 'usr_orgadmin', 'pin', 'org_a', 'prj_a1', 'env_gc', `+ts+`)`)
	execRaw(t, db, `INSERT INTO grants
        (id, principal_id, capability, org_id, project_id, env_id, created_at)
        VALUES ('g_gc_publish', 'usr_orgadmin', 'publish', 'org_a', 'prj_a1', 'env_gc', `+ts+`)`)
	seedOrigins(t, db)

	type corpus struct {
		env       string
		project   string
		key       string
		revisions []struct {
			revision int
			at       string
		}
	}
	sets := []corpus{
		{env: "env_gc", project: "prj_a1", key: "key_a1", revisions: []struct {
			revision int
			at       string
		}{{1, "2026-06-01T00:00:00.000000Z"}, {2, "2026-06-02T00:00:00.000000Z"}, {3, "2026-06-03T00:00:00.000000Z"}, {4, "2026-08-10T00:00:00.000000Z"}, {5, "2026-06-05T00:00:00.000000Z"}, {6, "2026-06-06T00:00:00.000000Z"}}},
		{env: "env_gc_inherited", project: "prj_a2", key: "key_a2", revisions: []struct {
			revision int
			at       string
		}{{1, "2026-06-01T00:00:00.000000Z"}, {2, "2026-06-02T00:00:00.000000Z"}, {3, "2026-08-10T00:00:00.000000Z"}, {4, "2026-06-04T00:00:00.000000Z"}}},
	}
	for _, set := range sets {
		for _, rev := range set.revisions {
			snapshotID := fmt.Sprintf("snp_%s_%d", set.env, rev.revision)
			execRaw(t, db, fmt.Sprintf(`INSERT INTO snapshots
                (id, org_id, project_id, environment_id, revision, schema_revision, published_by, published_at)
                VALUES ('%s', 'org_a', '%s', '%s', %d, 1, 'usr_orgadmin', '%s')`,
				snapshotID, set.project, set.env, rev.revision, rev.at))
			execRaw(t, db, fmt.Sprintf(`INSERT INTO snapshot_entries
                (id, org_id, project_id, environment_id, snapshot_id, key_id, key_name, classification, ciphertext, value_entry_id)
                VALUES ('sen_%s_%d', 'org_a', '%s', '%s', '%s', '%s', 'GC_VALUE', 'config', 'payload-%d', 'val_%d')`,
				set.env, rev.revision, set.project, set.env, snapshotID, set.key, rev.revision, rev.revision))
			execRaw(t, db, fmt.Sprintf(`INSERT INTO revision_key_changes
                (org_id, project_id, environment_id, revision, key_id, key_name, change)
                VALUES ('org_a', '%s', '%s', %d, '%s', 'GC_VALUE', 'edited')`,
				set.project, set.env, rev.revision, set.key))
		}
	}
	execRaw(t, db, `INSERT INTO revision_pins
        (id, org_id, project_id, environment_id, workload_principal_id,
         snapshot_id, revision, authority_principal_id, expires_at, created_at,
         authorized_at, history_authorized, schema_override)
        VALUES ('pin_gc_2', 'org_a', 'prj_a1', 'env_gc', 'mch_workload',
                'snp_env_gc_2', 2, 'usr_orgadmin', '2026-09-01T00:00:00.000000Z',
                '2026-08-01T00:00:00.000000Z', '2026-08-01T00:00:00.000000Z', TRUE, FALSE)`)
}
