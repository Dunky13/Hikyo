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

func TestPinReleaseRetentionConsequenceSQLite(t *testing.T) {
	runPinReleaseRetentionConsequence(t, seededDB(t, openSQLite))
}

func TestPinReleaseRetentionConsequencePostgres(t *testing.T) {
	runPinReleaseRetentionConsequence(t, seededDB(t, openPostgres))
}

func TestPinReleaseConcurrentGCPostgres(t *testing.T) {
	runPinReleaseConcurrentGC(t, seededDB(t, openPostgres))
}

func TestPinReleaseConcurrentGCSQLite(t *testing.T) {
	runPinReleaseConcurrentGC(t, seededDB(t, openSQLite))
}

func TestRetentionFailedSweepAuditSQLite(t *testing.T) {
	runRetentionFailedSweepAudit(t, seededDB(t, openSQLite))
}

func TestRetentionFailedSweepAuditPostgres(t *testing.T) {
	runRetentionFailedSweepAudit(t, seededDB(t, openPostgres))
}

func TestRetentionFailedSweepCountsObservedCandidatesSQLite(t *testing.T) {
	runRetentionFailedSweepCountsObservedCandidates(t, seededDB(t, openSQLite))
}

func TestRetentionFailedSweepCountsObservedCandidatesPostgres(t *testing.T) {
	runRetentionFailedSweepCountsObservedCandidates(t, seededDB(t, openPostgres))
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

func runRetentionFailedSweepCountsObservedCandidates(t *testing.T, db *store.DB) {
	t.Helper()
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	retention := &service.Retention{DB: db, Now: func() time.Time { return now }}
	if _, err := retention.SetProject(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeProject(orgA, prjA1), &service.RetentionPolicy{MaxAge: 20 * 24 * time.Hour, LastRevisions: 2}); err != nil {
		t.Fatalf("set project retention: %v", err)
	}
	seedRetentionCorpus(t, db)

	// Eligible reads only snapshot lineage. Removing the payload table makes the
	// chunk fail after it has observed both eligible candidates but before commit.
	execRaw(t, db, "DROP TABLE snapshot_entries")
	if _, err := retention.Sweep(t.Context()); err == nil {
		t.Fatal("sweep succeeded after payload table removal")
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_instance_events
        WHERE type = 'retention.prune_run' AND outcome = 'failure'
          AND payload LIKE '%"candidates":2%'`); n != 1 {
		payloads := queryStrings(t, db, `SELECT payload FROM audit_instance_events
            WHERE type = 'retention.prune_run' AND outcome = 'failure'`)
		t.Fatalf("failed prune-run events with two observed candidates = %d, want 1; payloads=%s", n, payloads)
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

func runPinReleaseRetentionConsequence(t *testing.T, db *store.DB) {
	t.Helper()
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	retention := &service.Retention{DB: db, Now: func() time.Time { return now }}
	policy := service.RetentionPolicy{MaxAge: 20 * 24 * time.Hour, LastRevisions: 2}
	if _, err := retention.SetProject(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeProject(orgA, prjA1), &policy); err != nil {
		t.Fatalf("set project retention: %v", err)
	}
	seedRetentionCorpus(t, db)

	pins := &service.Pins{DB: db, Now: func() time.Time { return now }}
	preview, err := pins.List(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeEnv(orgA, prjA1, domain.EnvID("env_gc")))
	if err != nil || len(preview) != 1 || preview[0].ReleaseRetentionConsequence != service.RetentionCollectionEligible {
		t.Fatalf("sole-keeper release preview = %+v, %v; want collection_eligible", preview, err)
	}
	result, err := pins.Release(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeEnv(orgA, prjA1, domain.EnvID("env_gc")), mchWork)
	if err != nil {
		t.Fatalf("release old sole pin: %v", err)
	}
	if result.RetentionConsequence != service.RetentionCollectionEligible {
		t.Fatalf("release consequence = %q, want %q", result.RetentionConsequence, service.RetentionCollectionEligible)
	}

	collected, err := retention.Sweep(t.Context())
	if err != nil {
		t.Fatalf("immediate retention sweep: %v", err)
	}
	if collected == 0 || queryInt(t, db,
		"SELECT COUNT(*) FROM snapshots WHERE id = 'snp_env_gc_2' AND payload_present = FALSE") != 1 {
		t.Fatalf("release result was not transaction-time truth before immediate GC: collected=%d", collected)
	}

	boundaryPolicy := service.RetentionPolicy{MaxAge: time.Hour, LastRevisions: 1}
	if _, err := retention.SetProject(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeProject(orgA, prjA1), &boundaryPolicy); err != nil {
		t.Fatalf("set boundary retention: %v", err)
	}
	execRaw(t, db, `INSERT INTO principals (id, kind, class, created_at)
        VALUES ('mch_release_keeper', 'machine', 'workload', `+ts+`)`)
	execRaw(t, db, `INSERT INTO service_accounts
        (id, principal_id, org_id, project_id, name, kind, created_at, created_by)
        VALUES ('svc_release_keeper', 'mch_release_keeper', 'org_a', 'prj_a1',
                'release-keeper', 'workload', `+ts+`, 'usr_orgadmin')`)

	seedPinReleaseFixture(t, db, "env_release_boundary", now.Add(-time.Hour), false)
	boundary, err := pins.Release(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeEnv(orgA, prjA1, domain.EnvID("env_release_boundary")), mchWork)
	if err != nil || boundary.RetentionConsequence != service.RetentionRetained {
		t.Fatalf("exact age boundary release = %+v, %v; want retained (pins=%d snapshots=%d)", boundary, err,
			queryInt(t, db, "SELECT COUNT(*) FROM revision_pins WHERE environment_id = 'env_release_boundary'"),
			queryInt(t, db, "SELECT COUNT(*) FROM snapshots WHERE environment_id = 'env_release_boundary'"))
	}
	if _, err := retention.Sweep(t.Context()); err != nil {
		t.Fatalf("sweep at exact age boundary: %v", err)
	}
	if queryInt(t, db, "SELECT COUNT(*) FROM snapshots WHERE id = 'snp_env_release_boundary_1' AND payload_present = TRUE") != 1 {
		t.Fatal("exact age boundary disagreed with GC predicate")
	}

	for _, boundary := range []struct {
		name      string
		published time.Time
		want      service.RetentionConsequence
		present   int64
	}{
		{name: "just_inside_age", published: now.Add(-time.Hour + time.Second), want: service.RetentionRetained, present: 1},
		{name: "just_outside_age", published: now.Add(-time.Hour - time.Second), want: service.RetentionCollectionEligible, present: 0},
	} {
		envID := "env_release_" + boundary.name
		seedPinReleaseFixture(t, db, envID, boundary.published, false)
		got, err := pins.Release(t.Context(), service.LocalPrincipal(orgAdmin),
			scopeEnv(orgA, prjA1, domain.EnvID(envID)), mchWork)
		if err != nil || got.RetentionConsequence != boundary.want {
			t.Fatalf("%s release = %+v, %v; want %q", boundary.name, got, err, boundary.want)
		}
		if _, err := retention.Sweep(t.Context()); err != nil {
			t.Fatalf("%s equivalence sweep: %v", boundary.name, err)
		}
		if present := queryInt(t, db, fmt.Sprintf(
			"SELECT COUNT(*) FROM snapshots WHERE id = 'snp_%s_1' AND payload_present = TRUE", envID)); present != boundary.present {
			t.Fatalf("%s consequence disagreed with GC: payload-present rows = %d, want %d", boundary.name, present, boundary.present)
		}
	}

	countBoundaryPolicy := service.RetentionPolicy{MaxAge: time.Hour, LastRevisions: 2}
	if _, err := retention.SetProject(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeProject(orgA, prjA1), &countBoundaryPolicy); err != nil {
		t.Fatalf("set revision-count boundary retention: %v", err)
	}
	seedPinReleaseFixture(t, db, "env_release_count_boundary", now.Add(-2*time.Hour), false)
	countBoundary, err := pins.Release(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeEnv(orgA, prjA1, domain.EnvID("env_release_count_boundary")), mchWork)
	if err != nil || countBoundary.RetentionConsequence != service.RetentionRetained {
		t.Fatalf("revision-count cutoff release = %+v, %v; want retained", countBoundary, err)
	}
	if _, err := retention.Sweep(t.Context()); err != nil {
		t.Fatalf("revision-count equivalence sweep: %v", err)
	}
	if queryInt(t, db, "SELECT COUNT(*) FROM snapshots WHERE id = 'snp_env_release_count_boundary_1' AND payload_present = TRUE") != 1 {
		t.Fatal("revision-count cutoff consequence disagreed with GC")
	}
	if _, err := retention.SetProject(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeProject(orgA, prjA1), &boundaryPolicy); err != nil {
		t.Fatalf("restore boundary retention: %v", err)
	}

	seedPinReleaseFixture(t, db, "env_release_decision_clock", now.Add(-time.Hour), false)
	clockReads := 0
	decisionClockPins := &service.Pins{DB: db, Now: func() time.Time {
		clockReads++
		if clockReads == 1 {
			return now.Add(-time.Second)
		}
		return now.Add(time.Second)
	}}
	decisionClock, err := decisionClockPins.Release(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeEnv(orgA, prjA1, domain.EnvID("env_release_decision_clock")), mchWork)
	if err != nil || decisionClock.RetentionConsequence != service.RetentionCollectionEligible {
		t.Fatalf("post-lock decision clock release = %+v, %v; want collection_eligible", decisionClock, err)
	}

	seedPinReleaseFixture(t, db, "env_release_collected", now.Add(-2*time.Hour), false)
	execRaw(t, db, "UPDATE revision_pins SET expires_at = '2026-08-15T12:00:00Z' WHERE id = 'pin_env_release_collected_primary'")
	if _, err := retention.Sweep(t.Context()); err != nil {
		t.Fatalf("GC-before-release sweep: %v", err)
	}
	alreadyCollected, err := pins.Release(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeEnv(orgA, prjA1, domain.EnvID("env_release_collected")), mchWork)
	if err != nil || alreadyCollected.RetentionConsequence != service.RetentionAlreadyCollected {
		t.Fatalf("GC-before-release result = %+v, %v; want already_collected", alreadyCollected, err)
	}

	seedPinReleaseFixture(t, db, "env_release_other_pin", now.Add(-2*time.Hour), true)
	otherPinPreview, err := pins.List(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeEnv(orgA, prjA1, domain.EnvID("env_release_other_pin")))
	if err != nil || len(otherPinPreview) != 2 {
		t.Fatalf("other-pin release previews = %+v, %v", otherPinPreview, err)
	}
	for _, pin := range otherPinPreview {
		if pin.ReleaseRetentionConsequence != service.RetentionRetained {
			t.Fatalf("other-pin release preview for %s = %q, want retained", pin.ID, pin.ReleaseRetentionConsequence)
		}
	}
	otherPin, err := pins.Release(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeEnv(orgA, prjA1, domain.EnvID("env_release_other_pin")), mchWork)
	if err != nil || otherPin.RetentionConsequence != service.RetentionRetained {
		t.Fatalf("release with another live pin = %+v, %v; want retained", otherPin, err)
	}
	if _, err := retention.Sweep(t.Context()); err != nil {
		t.Fatalf("other-pin equivalence sweep: %v", err)
	}
	if queryInt(t, db, "SELECT COUNT(*) FROM snapshots WHERE id = 'snp_env_release_other_pin_1' AND payload_present = TRUE") != 1 {
		t.Fatal("other-live-pin consequence disagreed with GC")
	}

	seedPinReleaseFixture(t, db, "env_release_pin_expiry", now.Add(-2*time.Hour), true)
	execRaw(t, db, "UPDATE revision_pins SET expires_at = '2026-08-15T12:00:00Z' WHERE id = 'pin_env_release_pin_expiry_keeper'")
	exactExpiry, err := pins.Release(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeEnv(orgA, prjA1, domain.EnvID("env_release_pin_expiry")), mchWork)
	if err != nil || exactExpiry.RetentionConsequence != service.RetentionCollectionEligible {
		t.Fatalf("exact pin-expiry cutoff release = %+v, %v; want collection_eligible", exactExpiry, err)
	}

	widePolicy := service.RetentionPolicy{MaxAge: 90 * 24 * time.Hour, LastRevisions: 1}
	if _, err := retention.SetProject(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeProject(orgA, prjA1), &widePolicy); err != nil {
		t.Fatalf("set pre-change retention: %v", err)
	}
	seedPinReleaseFixture(t, db, "env_release_policy_change", now.Add(-2*time.Hour), false)
	if _, err := retention.SetProject(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeProject(orgA, prjA1), &boundaryPolicy); err != nil {
		t.Fatalf("tighten retention before release: %v", err)
	}
	afterPolicyChange, err := pins.Release(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeEnv(orgA, prjA1, domain.EnvID("env_release_policy_change")), mchWork)
	if err != nil || afterPolicyChange.RetentionConsequence != service.RetentionCollectionEligible {
		t.Fatalf("post-policy-change release = %+v, %v; want collection_eligible", afterPolicyChange, err)
	}
	if _, err := retention.Sweep(t.Context()); err != nil {
		t.Fatalf("policy-change equivalence sweep: %v", err)
	}
	if queryInt(t, db, "SELECT COUNT(*) FROM snapshots WHERE id = 'snp_env_release_policy_change_1' AND payload_present = FALSE") != 1 {
		t.Fatal("policy-change consequence disagreed with GC")
	}
}

// runPinReleaseConcurrentGC forces the GC-first lock order on both engines.
// SQLite serializes writers at transaction start; Postgres holds the snapshot
// row update lock. In either case release waits, then observes already_collected
// after GC commits instead of reporting stale collection_eligible truth.
type pinReleaseRaceResult struct {
	result service.ReleasePinResult
	err    error
}

func runPinReleaseConcurrentGC(t *testing.T, db *store.DB) {
	t.Helper()
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	retention := &service.Retention{DB: db, Now: func() time.Time { return now }}
	policy := service.RetentionPolicy{MaxAge: time.Hour, LastRevisions: 1}
	if _, err := retention.SetProject(t.Context(), service.LocalPrincipal(orgAdmin),
		scopeProject(orgA, prjA1), &policy); err != nil {
		t.Fatalf("set concurrent retention: %v", err)
	}
	seedPinReleaseFixture(t, db, "env_release_gc_race", now.Add(-2*time.Hour), false)
	execRaw(t, db, "UPDATE revision_pins SET expires_at = '2026-08-15T12:00:00Z' WHERE id = 'pin_env_release_gc_race_primary'")

	marked := make(chan struct{})
	allowGCCommit := make(chan struct{})
	retention.AfterMarkCollected = func(ctx context.Context, snapshotID string) error {
		if snapshotID != "snp_env_release_gc_race_1" {
			return nil
		}
		close(marked)
		select {
		case <-allowGCCommit:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	gcDone := make(chan error, 1)
	go func() {
		_, err := retention.Sweep(t.Context())
		gcDone <- err
	}()
	<-marked

	releaseDone := make(chan pinReleaseRaceResult, 1)
	sqliteWaits := int64(0)
	if db.Engine() == store.EngineSQLite {
		sqliteWaits = db.SQLiteWrite().Stats().WaitCount
	}
	go func() {
		pins := &service.Pins{DB: db, Now: func() time.Time { return now }}
		result, err := pins.Release(t.Context(), service.LocalPrincipal(orgAdmin),
			scopeEnv(orgA, prjA1, domain.EnvID("env_release_gc_race")), mchWork)
		releaseDone <- pinReleaseRaceResult{result: result, err: err}
	}()
	waitForPinReleaseContention(t, db, sqliteWaits, releaseDone)
	close(allowGCCommit)
	if err := <-gcDone; err != nil {
		t.Fatalf("concurrent GC: %v", err)
	}
	released := <-releaseDone
	if released.err != nil || released.result.RetentionConsequence != service.RetentionAlreadyCollected {
		t.Fatalf("GC-first concurrent release = %+v, %v; want already_collected", released.result, released.err)
	}
}

func waitForPinReleaseContention(t *testing.T, db *store.DB, sqliteWaits int64,
	releaseDone <-chan pinReleaseRaceResult) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case released := <-releaseDone:
			t.Fatalf("release finished before contending with GC = %+v, %v", released.result, released.err)
		default:
		}
		switch db.Engine() {
		case store.EngineSQLite:
			if db.SQLiteWrite().Stats().WaitCount > sqliteWaits {
				return
			}
		case store.EnginePostgres:
			var waiting int
			if err := db.PG().QueryRow(t.Context(), `SELECT COUNT(*) FROM pg_stat_activity
                    WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting); err != nil {
				t.Fatalf("observe release lock contention: %v", err)
			}
			if waiting > 0 {
				return
			}
		default:
			t.Fatalf("unknown engine %q", db.Engine())
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("release never visibly contended with the in-flight GC transaction")
}

func seedPinReleaseFixture(t *testing.T, db *store.DB, envID string, publishedAt time.Time, otherLivePin bool) {
	t.Helper()
	execRaw(t, db, fmt.Sprintf(`INSERT INTO environments
        (id, org_id, project_id, name, note, created_at, display_order)
        VALUES ('%s', 'org_a', 'prj_a1', '%s', '', %s, 20)`, envID, envID, ts))
	execRaw(t, db, fmt.Sprintf(`INSERT INTO grants
        (id, principal_id, capability, org_id, project_id, env_id, created_at)
        VALUES ('grt_%s_pin', 'usr_orgadmin', 'pin', 'org_a', 'prj_a1', '%s', %s)`, envID, envID, ts))
	for revision, at := range []time.Time{publishedAt, publishedAt.Add(time.Minute)} {
		revision++
		snapshotID := fmt.Sprintf("snp_%s_%d", envID, revision)
		execRaw(t, db, fmt.Sprintf(`INSERT INTO snapshots
            (id, org_id, project_id, environment_id, revision, schema_revision, published_by, published_at)
            VALUES ('%s', 'org_a', 'prj_a1', '%s', %d, 1, 'usr_orgadmin', '%s')`,
			snapshotID, envID, revision, store.CanonTime(at).Format(time.RFC3339Nano)))
	}
	execRaw(t, db, fmt.Sprintf(`INSERT INTO revision_pins
        (id, org_id, project_id, environment_id, workload_principal_id,
         snapshot_id, revision, authority_principal_id, expires_at, created_at,
         authorized_at, history_authorized, schema_override)
        VALUES ('pin_%s_primary', 'org_a', 'prj_a1', '%s', 'mch_workload',
                'snp_%s_1', 1, 'usr_orgadmin', '2026-08-16T12:00:00Z',
                '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z', TRUE, FALSE)`, envID, envID, envID))
	if otherLivePin {
		execRaw(t, db, fmt.Sprintf(`INSERT INTO revision_pins
            (id, org_id, project_id, environment_id, workload_principal_id,
             snapshot_id, revision, authority_principal_id, expires_at, created_at,
             authorized_at, history_authorized, schema_override)
            VALUES ('pin_%s_keeper', 'org_a', 'prj_a1', '%s', 'mch_release_keeper',
                    'snp_%s_1', 1, 'usr_orgadmin', '2026-08-16T12:00:00Z',
                    '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z', TRUE, FALSE)`, envID, envID, envID))
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
	// The collection bit is LINEAGE, so it has to survive on the read that
	// still works. `Show` refuses a collected revision outright, which is why
	// the history drawer (#59) can only gate its diff/restore/pin actions if
	// `listRevisions` carries the bit and the stamped policy through.
	history, err := revisions.History(t.Context(), actor, scopeEnv(orgA, prjA1, domain.EnvID("env_gc")))
	if err != nil {
		t.Fatalf("history after collection: %v", err)
	}
	if len(history) != 6 {
		t.Fatalf("history entries = %d, want 6 (lineage outlives its payload)", len(history))
	}
	for _, entry := range history {
		wantPresent := entry.Revision != 1 && entry.Revision != 3
		if entry.PayloadPresent != wantPresent {
			t.Errorf("r%d payload_present = %v, want %v", entry.Revision, entry.PayloadPresent, wantPresent)
		}
		wantPolicy := ""
		if !wantPresent {
			wantPolicy = collectedPolicy
		}
		if entry.CollectedPolicy != wantPolicy {
			t.Errorf("r%d collected_policy = %q, want %q", entry.Revision, entry.CollectedPolicy, wantPolicy)
		}
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
