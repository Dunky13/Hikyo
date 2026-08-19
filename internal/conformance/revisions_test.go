package conformance

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// Revisions, drafts and publishing (#51) — the cross-engine acceptance corpus
// for mvp-boundary C4 and C2's publish clause.
//
// Every scenario runs through the service layer against a real datastore and a
// real keyring on BOTH engines, which is what the [E2E] class requires: no
// mocked server components, and the change token is keyed, so there is nothing
// to fake about it either.
//
//	C4  Revisions & publishing — "[E2E] concurrent publish serialization;
//	    selective publish with group closure; `rotate-token-key` changes the
//	    token without touching content, revision numbers, or pinned input
//	    revisions"                        (revision-model.md)
//	C2  Flat value model (publish clause) — "a value publish recomputes matrix
//	    signals for exactly the touched environments, a semantic schema publish
//	    for every environment; ... a `required_in` key left `absent` vetoes
//	    publish naming key and environment"          (flat-model.md)

func init() {
	corpus = append(corpus,
		scenario{"publish_is_serialized_per_project", scenarioPublishSerialization},
		scenario{"selective_publish_closes_over_key_groups", scenarioSelectivePublish},
		scenario{"rotate_token_key_moves_only_the_token", scenarioRotateTokenKey},
		scenario{"publish_recomputes_signals_for_touched_environments", scenarioPublishSignals},
		scenario{"pending_draft_preview_is_owner_filtered_and_classification_safe", scenarioPendingDraftPreview},
		scenario{"required_in_absent_vetoes_publish", scenarioRequiredInVeto},
		scenario{"revision_ciphertext_is_owner_bound", scenarioRevisionCiphertextBinding},
		scenario{"advisory_projects_authorization_per_event", scenarioAdvisoryAuthorization},
		scenario{"historical_export_takes_reveal_history_not_reveal", scenarioHistoricalExportFormula},
		scenario{"restore_of_superseded_secret_takes_reveal_history", scenarioRestoreSupersededSecret},
		scenario{"restore_gate_uses_written_time_classification", scenarioRestoreWrittenTimeClassification},
		scenario{"restore_secret_formulas_are_side_specific", scenarioRestoreSideSpecificSecretFormula},
		scenario{"secret_classification_survives_payload_collection", scenarioSecretClassificationSurvivesCollection},
		scenario{"per_key_restore_refuses_reused_key_identity", scenarioRestoreReusedKeyIdentity},
		scenario{"schema_failing_restore_blocks_loud", scenarioSchemaFailingRestore},
		scenario{"adapter_crash_reservation_release_is_generation_fenced", scenarioAdapterCrashReservationRelease},
		scenario{"publish_enqueues_adapter_sync_with_recorded_authority", scenarioPublishEnqueuesAdapterSync},
		scenario{"pin_lifecycle_quota_and_expiry_refusals_by_name", scenarioPinLifecycle},
		scenario{"delivery_retry_clears_rolled_back_pin_metadata", scenarioDeliveryRetryClearsPinMetadata},
	)
}

func scenarioAdapterCrashReservationRelease(t *testing.T, db *store.DB) {
	who, scope, _, envs, _ := valueFixture(t, db, "adapterreserve")
	env := mustEnv(t, envs, service.LocalPrincipal(who), scope, "prod")
	seed(t, db, []string{
		fmt.Sprintf(`INSERT INTO adapters (id,org_id,project_id,provider,origin,authority_principal_id,state,created_at) VALUES ('adp_reservation_release','%s','%s','forgejo','https://git.example/adapterreserve','%s','active','2026-08-17T00:00:00Z')`, scope.Org, scope.Project, who),
		fmt.Sprintf(`INSERT INTO adapter_targets (id,org_id,project_id,environment_id,adapter_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,generation,state,sync_status,active_job_id,created_at) VALUES ('tgt_reservation_release','%s','%s','%s','adp_reservation_release','repository','acme','app',4201,'',1,'active','converging','job_reservation_old','2026-08-17T00:00:00Z')`, scope.Org, scope.Project, env.Env),
		fmt.Sprintf(`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,lease_owner,lease_expires_at,created_at) VALUES ('job_reservation_old','%s','%s','%s','tgt_reservation_release','converge','%s',1,'tgt_reservation_release',1,'2026-08-17T00:00:00Z','running','worker_old','2099-08-17T00:00:00Z','2026-08-17T00:00:00Z')`, scope.Org, scope.Project, env.Env, who),
	})
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	oldJob := adapter.Job{ID: "job_reservation_old", OrgID: string(scope.Org), ProjectID: string(scope.Project), EnvironmentID: string(env.Env), TargetID: "tgt_reservation_release", Kind: adapter.Converge, AuthorityPrincipal: string(who), Generation: 1, LeaseOwner: "worker_old"}
	effect := adapter.Effect{Surface: adapter.Secret, EffectiveName: "STALE", Disposition: adapter.Create}
	oldJournal := runtime.Journal(oldJob)
	if state, err := oldJournal.Reserve(t.Context(), effect); err != nil || state != adapter.Reserved {
		t.Fatalf("Reserve() = %q, %v", state, err)
	}
	newJob, err := runtime.Enqueue(t.Context(), adapter.Job{OrgID: string(scope.Org), ProjectID: string(scope.Project), EnvironmentID: string(env.Env), TargetID: oldJob.TargetID, Kind: adapter.Converge, AuthorityPrincipal: string(who)}, time.Date(2026, 8, 17, 0, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := oldJournal.ReleaseReservation(t.Context(), effect); !errors.Is(err, adapter.ErrSuperseded) {
		t.Fatalf("old generation release = %v, want superseded", err)
	}
	newJob.LeaseOwner = "worker_new"
	if db.Engine() == store.EnginePostgres {
		if _, err := db.PG().Exec(t.Context(), `UPDATE adapter_outbox SET state='running',lease_owner=$1,lease_expires_at='2099-08-17T00:00:00Z' WHERE id=$2`, newJob.LeaseOwner, newJob.ID); err != nil {
			t.Fatal(err)
		}
	} else if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_outbox SET state='running',lease_owner=?,lease_expires_at='2099-08-17T00:00:00Z' WHERE id=?`, newJob.LeaseOwner, newJob.ID); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Journal(newJob).ReleaseReservation(t.Context(), adapter.Effect{Surface: adapter.Secret, EffectiveName: "STALE", Disposition: adapter.Delete}); err != nil {
		t.Fatal(err)
	}
	var ledger, conflicts, effects int
	if db.Engine() == store.EnginePostgres {
		if err := db.PG().QueryRow(t.Context(), `SELECT COUNT(*) FROM adapter_ledger WHERE target_id=$1`, oldJob.TargetID).Scan(&ledger); err != nil {
			t.Fatal(err)
		}
		if err := db.PG().QueryRow(t.Context(), `SELECT COUNT(*) FROM adapter_conflicts WHERE target_id=$1`, oldJob.TargetID).Scan(&conflicts); err != nil {
			t.Fatal(err)
		}
		if err := db.PG().QueryRow(t.Context(), `SELECT COUNT(*) FROM adapter_effects WHERE target_id=$1`, oldJob.TargetID).Scan(&effects); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_ledger WHERE target_id=?`, oldJob.TargetID).Scan(&ledger); err != nil {
			t.Fatal(err)
		}
		if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_conflicts WHERE target_id=?`, oldJob.TargetID).Scan(&conflicts); err != nil {
			t.Fatal(err)
		}
		if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_effects WHERE target_id=?`, oldJob.TargetID).Scan(&effects); err != nil {
			t.Fatal(err)
		}
	}
	if ledger != 0 || conflicts != 0 || effects != 0 {
		t.Fatalf("ledger=%d conflicts=%d effects=%d, want local reservation release only", ledger, conflicts, effects)
	}
}

func scenarioPublishEnqueuesAdapterSync(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "adapterpublish")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	prod := mustEnv(t, envs, actor, scope, "prod")
	key := mustKey(t, keys, actor, scope, "SYNCED", string(schema.Config), schema.DefaultPresenceRules())
	seed(t, db, []string{
		fmt.Sprintf(`INSERT INTO adapters (id,org_id,project_id,provider,origin,authority_principal_id,state,created_at) VALUES ('adp_publish_hook','%s','%s','forgejo','https://git.example/adapterpublish','%s','active','2026-08-17T00:00:00Z')`, scope.Org, scope.Project, who),
		fmt.Sprintf(`INSERT INTO adapter_targets (id,org_id,project_id,environment_id,adapter_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,generation,state,sync_status,created_at) VALUES ('tgt_publish_dev','%s','%s','%s','adp_publish_hook','repository','acme','dev',4101,'DEV_',1,'active','never','2026-08-17T00:00:00Z')`, scope.Org, scope.Project, dev.Env),
		fmt.Sprintf(`INSERT INTO adapter_targets (id,org_id,project_id,environment_id,adapter_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,generation,state,sync_status,created_at) VALUES ('tgt_publish_prod','%s','%s','%s','adp_publish_hook','repository','acme','prod',4102,'PROD_',1,'active','never','2026-08-17T00:00:00Z')`, scope.Org, scope.Project, prod.Env),
	})

	staged, err := values.Set(t.Context(), actor, dev, "SYNCED", "one")
	if err != nil {
		t.Fatal(err)
	}
	canonicalNow := time.Date(2026, 8, 17, 12, 34, 56, 0, time.UTC)
	revisions := &service.Revisions{DB: db, Keyring: sharedKeyring(t, db), Now: func() time.Time { return canonicalNow }}
	if _, err := revisions.Publish(t.Context(), actor, dev, []string{staged.VersionID}); err != nil {
		t.Fatal(err)
	}
	assertAdapterPublishState(t, db, "tgt_publish_dev", 2, 1, string(who), canonicalNow)
	assertAdapterPublishState(t, db, "tgt_publish_prod", 1, 0, string(who), time.Time{})

	if _, err := keys.Rename(t.Context(), actor, scope, key.ID, "SYNCED_RENAMED"); err != nil {
		t.Fatal(err)
	}
	assertAdapterPublishState(t, db, "tgt_publish_dev", 3, 2, string(who), time.Time{})
	assertAdapterPublishState(t, db, "tgt_publish_prod", 2, 1, string(who), time.Time{})
}

func assertAdapterPublishState(t *testing.T, db *store.DB, targetID string, wantGeneration int64, wantAudits int, wantAuthority string, wantCreatedAt time.Time) {
	t.Helper()
	var generation int64
	var jobCount, auditCount int
	var authority string
	var created any
	if db.Engine() == store.EnginePostgres {
		if err := db.PG().QueryRow(t.Context(), `SELECT generation FROM adapter_targets WHERE id=$1`, targetID).Scan(&generation); err != nil {
			t.Fatal(err)
		}
		if err := db.PG().QueryRow(t.Context(), `SELECT COUNT(*),COALESCE(MAX(authority_principal_id),''),MAX(created_at) FROM adapter_outbox WHERE target_id=$1`, targetID).Scan(&jobCount, &authority, &created); err != nil {
			t.Fatal(err)
		}
		if err := db.PG().QueryRow(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.sync_requested' AND object_id=$1 AND authority_id=$2 AND (payload::jsonb)->>'trigger'='on-publish'`, targetID, wantAuthority).Scan(&auditCount); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT generation FROM adapter_targets WHERE id=?`, targetID).Scan(&generation); err != nil {
			t.Fatal(err)
		}
		if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*),COALESCE(MAX(authority_principal_id),''),MAX(created_at) FROM adapter_outbox WHERE target_id=?`, targetID).Scan(&jobCount, &authority, &created); err != nil {
			t.Fatal(err)
		}
		if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.sync_requested' AND object_id=? AND authority_id=? AND json_extract(payload,'$.trigger')='on-publish'`, targetID, wantAuthority).Scan(&auditCount); err != nil {
			t.Fatal(err)
		}
	}
	if generation != wantGeneration || jobCount != wantAudits || auditCount != wantAudits || (wantAudits > 0 && authority != wantAuthority) {
		t.Fatalf("target %s: generation=%d jobs=%d audits=%d authority=%q", targetID, generation, jobCount, auditCount, authority)
	}
	if wantCreatedAt.IsZero() || wantAudits == 0 {
		return
	}
	var got time.Time
	switch value := created.(type) {
	case time.Time:
		got = value.UTC()
	case string:
		got, _ = time.Parse(time.RFC3339Nano, value)
	case []byte:
		got, _ = time.Parse(time.RFC3339Nano, string(value))
	}
	if !got.Equal(wantCreatedAt) {
		t.Fatalf("target %s created_at=%T(%v) parsed=%v, want transaction clock %v", targetID, created, created, got, wantCreatedAt)
	}
}

func scenarioPendingDraftPreview(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "pendingpreview")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	configSetKey := mustKey(t, keys, actor, scope, "CONFIG_SET", string(schema.Config), schema.DefaultPresenceRules())
	mustKey(t, keys, actor, scope, "SECRET_SET", string(schema.Secret), schema.DefaultPresenceRules())
	mustKey(t, keys, actor, scope, "CONFIG_CLEAR", string(schema.Config), schema.DefaultPresenceRules())
	mustKey(t, keys, actor, scope, "OTHER_CONFIG", string(schema.Config), schema.DefaultPresenceRules())
	restoredKey := mustKey(t, keys, actor, scope, "RESTORED_SECRET", string(schema.Secret), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "CONFIG_CLEAR", "published")
	publishValue(t, db, values, actor, dev, "RESTORED_SECRET", "historical secret")
	historicalSecretRevision := latestRevisionOf(t, db, string(dev.Env))
	grantOrg(t, db, who, scope.Org, "pendingpreviewhistory", "reveal-history")
	if _, err := keys.Reclassify(t.Context(), actor, scope, restoredKey.ID, string(schema.Config)); err != nil {
		t.Fatal(err)
	}
	publishValue(t, db, values, actor, dev, "RESTORED_SECRET", "current config")
	restored, err := revisionSvc(t, db).Restore(t.Context(), actor, dev, historicalSecretRevision, "RESTORED_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Changes) != 1 {
		t.Fatalf("historical secret restore staged %d changes, want 1: %+v", len(restored.Changes), restored)
	}

	config, err := values.Set(t.Context(), actor, dev, "CONFIG_SET", "draft config")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := values.Set(t.Context(), actor, dev, "SECRET_SET", "draft secret")
	if err != nil {
		t.Fatal(err)
	}
	cleared, err := values.Unset(t.Context(), actor, dev, "CONFIG_CLEAR")
	if err != nil {
		t.Fatal(err)
	}
	other := newPrincipal(t, db, "usr_pending_preview_other_"+string(scope.Project), []grantSpec{
		{capability: "read", scope: scope}, {capability: "edit", scope: scope},
	})
	if _, err := values.Set(t.Context(), service.LocalPrincipal(other), dev, "OTHER_CONFIG", "not yours"); err != nil {
		t.Fatal(err)
	}

	drafts, err := revisionSvc(t, db).PendingDrafts(t.Context(), actor, dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(drafts) != 4 {
		t.Fatalf("pending draft count = %d, want 4 caller-owned drafts: %+v", len(drafts), drafts)
	}
	byID := make(map[string]service.PendingDraft, len(drafts))
	for _, draft := range drafts {
		byID[draft.VersionID] = draft
		if draft.Name == "OTHER_CONFIG" {
			t.Fatalf("another principal's draft appeared in preview: %+v", draft)
		}
	}
	if got := byID[config.VersionID]; got.Name != "CONFIG_SET" || got.Classification != string(schema.Config) ||
		got.Operation != string(store.PendingSet) || !got.Revealed || got.Value != "draft config" {
		t.Fatalf("config draft = %+v, want revealed plaintext", got)
	}
	if got := byID[secret.VersionID]; got.Name != "SECRET_SET" || got.Classification != string(schema.Secret) ||
		got.Operation != string(store.PendingSet) || got.Revealed || got.Value != "" {
		t.Fatalf("secret draft = %+v, want masked without material", got)
	}
	if got := byID[cleared.VersionID]; got.Name != "CONFIG_CLEAR" || got.Operation != string(store.PendingUnset) ||
		got.Revealed || got.Value != "" {
		t.Fatalf("unset draft = %+v, want no material", got)
	}
	if got := byID[restored.Changes[0].VersionID]; got.Name != "RESTORED_SECRET" ||
		got.Classification != string(schema.Config) || got.Operation != string(store.PendingSet) || got.Revealed || got.Value != "" {
		t.Fatalf("secret-origin config draft = %+v, want hidden material", got)
	}

	// The gate reads the key's CURRENT classification, not the one at staging
	// time: a config draft staged before a config->secret reclassification is
	// secret material from the moment the key is, and the preview must stop
	// showing it without anybody re-staging.
	if _, err := keys.Reclassify(t.Context(), actor, scope, configSetKey.ID, string(schema.Secret)); err != nil {
		t.Fatal(err)
	}
	drafts, err = revisionSvc(t, db).PendingDrafts(t.Context(), actor, dev)
	if err != nil {
		t.Fatal(err)
	}
	reclassified := false
	for _, draft := range drafts {
		if draft.VersionID != config.VersionID {
			continue
		}
		reclassified = true
		if draft.Classification != string(schema.Secret) || draft.Revealed || draft.Value != "" {
			t.Fatalf("config draft after config->secret reclassification = %+v, want hidden material", draft)
		}
	}
	if !reclassified {
		t.Fatalf("config draft %s vanished after reclassification: %+v", config.VersionID, drafts)
	}

	noRead := newPrincipal(t, db, "usr_pending_preview_no_read_"+string(scope.Project), nil)
	if _, err := revisionSvc(t, db).PendingDrafts(t.Context(), service.LocalPrincipal(noRead), dev); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("pending drafts without read = %v, want uniform not found", err)
	}
}

func scenarioRestoreSideSpecificSecretFormula(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "restoresides")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")

	historicalSecret := mustKey(t, keys, actor, scope, "HISTORICAL_SECRET", string(schema.Secret), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "HISTORICAL_SECRET", "secret-before")
	historicalSecretRevision := latestRevisionOf(t, db, string(dev.Env))
	if _, err := keys.Reclassify(t.Context(), actor, scope, historicalSecret.ID, string(schema.Config)); err != nil {
		t.Fatal(err)
	}
	publishValue(t, db, values, actor, dev, "HISTORICAL_SECRET", "config-now")
	historian := newPrincipal(t, db, "usr_restore_history_only_"+string(scope.Project), []grantSpec{
		{capability: "read", scope: scope}, {capability: "edit", scope: scope},
		{capability: "publish", scope: scope}, {capability: "reveal-history", scope: scope},
	})
	before := auditEventCount(t, db, string(dev.Env), "disclosure.value_revealed")
	if _, err := revisionSvc(t, db).Restore(t.Context(), service.LocalPrincipal(historian), dev, historicalSecretRevision, "HISTORICAL_SECRET"); err != nil {
		t.Fatalf("historical-secret/current-config restore with history reveal only: %v", err)
	}
	if got := auditEventCount(t, db, string(dev.Env), "disclosure.value_revealed") - before; got != 1 {
		t.Fatalf("historical-only restore disclosure events = %d, want 1", got)
	}

	historicalConfig := mustKey(t, keys, actor, scope, "CURRENT_SECRET", string(schema.Config), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "CURRENT_SECRET", "config-before")
	historicalConfigRevision := latestRevisionOf(t, db, string(dev.Env))
	unpublishValue(t, db, values, actor, dev, "CURRENT_SECRET")
	if _, err := keys.Reclassify(t.Context(), actor, scope, historicalConfig.ID, string(schema.Secret)); err != nil {
		t.Fatal(err)
	}
	publishValue(t, db, values, actor, dev, "CURRENT_SECRET", "secret-now")
	revealer := newPrincipal(t, db, "usr_restore_current_only_"+string(scope.Project), []grantSpec{
		{capability: "read", scope: scope}, {capability: "edit", scope: scope},
		{capability: "publish", scope: scope}, {capability: "reveal", scope: scope},
	})
	before = auditEventCount(t, db, string(dev.Env), "disclosure.value_revealed")
	if _, err := revisionSvc(t, db).Restore(t.Context(), service.LocalPrincipal(revealer), dev, historicalConfigRevision, "CURRENT_SECRET"); err != nil {
		t.Fatalf("historical-config/current-secret restore with current reveal only: %v", err)
	}
	if got := auditEventCount(t, db, string(dev.Env), "disclosure.value_revealed") - before; got != 1 {
		t.Fatalf("current-only restore disclosure events = %d, want 1", got)
	}

	mustKey(t, keys, actor, scope, "CLEAR_SECRET", string(schema.Secret), schema.DefaultPresenceRules())
	clearTarget := latestRevisionOf(t, db, string(dev.Env))
	publishValue(t, db, values, actor, dev, "CLEAR_SECRET", "current-secret")
	clearer := newPrincipal(t, db, "usr_restore_secret_clear_"+string(scope.Project), []grantSpec{
		{capability: "read", scope: scope}, {capability: "edit", scope: scope}, {capability: "publish", scope: scope},
	})
	cleared, err := revisionSvc(t, db).Restore(t.Context(), service.LocalPrincipal(clearer), dev, clearTarget, "CLEAR_SECRET")
	if err != nil || len(cleared.Changes) != 1 || cleared.Changes[0].Operation != string(store.PendingUnset) {
		t.Fatalf("restore-to-absent current secret without reveal = %+v, %v; want one clear", cleared, err)
	}
}

func scenarioSecretClassificationSurvivesCollection(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "restorecollectedclass")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	key := mustKey(t, keys, actor, scope, "STICKY_SECRET", string(schema.Secret), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "STICKY_SECRET", "same-occurrence")
	if _, err := keys.Reclassify(t.Context(), actor, scope, key.ID, string(schema.Config)); err != nil {
		t.Fatal(err)
	}
	target := latestRevisionOf(t, db, string(dev.Env))
	publishValue(t, db, values, actor, dev, "STICKY_SECRET", "new-config-occurrence")
	seed(t, db, []string{
		fmt.Sprintf("UPDATE snapshots SET payload_present = FALSE, collected_at = '2026-08-15T12:00:00.000000Z', collected_policy = 'classification-retention-test' WHERE id IN (SELECT snapshot_id FROM snapshot_entries WHERE environment_id = '%s' AND classification = 'secret')", dev.Env),
		fmt.Sprintf("DELETE FROM snapshot_entries WHERE environment_id = '%s' AND classification = 'secret'", dev.Env),
	})
	restorer := newPrincipal(t, db, "usr_restore_collected_class_"+string(scope.Project), []grantSpec{
		{capability: "read", scope: scope}, {capability: "edit", scope: scope}, {capability: "publish", scope: scope},
	})
	revisions := revisionSvc(t, db)
	if _, err := revisions.Restore(t.Context(), service.LocalPrincipal(restorer), dev, target, "STICKY_SECRET"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("restore after secret classification payload collection = %v, want history refusal", err)
	}
	grantOrg(t, db, restorer, scope.Org, "restorecollectedclass_history", "reveal-history")
	restored, err := revisions.Restore(t.Context(), service.LocalPrincipal(restorer), dev, target, "STICKY_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Preview.Environments) != 1 || len(restored.Preview.Environments[0].Changes) != 1 ||
		restored.Preview.Environments[0].Changes[0].Classification != string(schema.Secret) ||
		restored.Preview.Environments[0].Changes[0].Before != nil || restored.Preview.Environments[0].Changes[0].After != nil {
		t.Fatalf("collected sticky-secret preview disclosed or downgraded material: %+v", restored.Preview)
	}
	published, err := revisions.PublishPlanned(t.Context(), service.LocalPrincipal(restorer), dev, service.PublishRequest{
		VersionIDs: []string{restored.Changes[0].VersionID}, PreviewToken: restored.Preview.Token,
	})
	if err != nil || len(published.Environments) != 1 {
		t.Fatalf("publish restored sticky-secret material = %+v, %v", published, err)
	}
	restoredRevision := published.Environments[0].Revision
	publishValue(t, db, values, actor, dev, "STICKY_SECRET", "ordinary-config-after-restore")
	withoutHistory := newPrincipal(t, db, "usr_restore_propagated_class_"+string(scope.Project), []grantSpec{
		{capability: "read", scope: scope}, {capability: "edit", scope: scope}, {capability: "publish", scope: scope},
	})
	if _, err := revisions.Restore(t.Context(), service.LocalPrincipal(withoutHistory), dev, restoredRevision, "STICKY_SECRET"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("republished historical-secret material lost sticky classification: %v", err)
	}
}

type deliveryRetryResetProbe struct {
	t        *testing.T
	attempts int
}

func (p *deliveryRetryResetProbe) AfterAttemptReset(out *service.FetchResult) error {
	p.t.Helper()
	p.attempts++
	if p.attempts == 1 {
		out.PinnedRevision = 41
		out.PinExpired = true
		out.ChangeToken = "rolled-back"
		return store.ErrRetrySerialization
	}
	if out.PinnedRevision != 0 || out.PinExpired || out.ChangeToken != "" {
		p.t.Fatalf("retry retained rolled-back pin state: %+v", out)
	}
	return nil
}

func scenarioDeliveryRetryClearsPinMetadata(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "deliveryretry")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	mustKey(t, keys, actor, scope, "VERSION", string(schema.Config), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "VERSION", "one")
	probe := &deliveryRetryResetProbe{t: t}
	delivery := &service.Delivery{DB: db, Keyring: sharedKeyring(t, db), FetchProbe: probe}
	result, err := delivery.FetchAs(t.Context(), actor, dev, "")
	if err != nil {
		t.Fatal(err)
	}
	if probe.attempts != 2 {
		t.Fatalf("delivery attempts = %d, want one retry", probe.attempts)
	}
	if result.PinnedRevision != 0 || result.PinExpired {
		t.Fatalf("unpinned successful retry retained rolled-back metadata: %+v", result)
	}
}

func scenarioSchemaFailingRestore(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "restoreschema")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	key := mustKey(t, keys, actor, scope, "WORKERS", string(schema.Config), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "WORKERS", "not-an-integer")
	target := latestRevisionOf(t, db, string(dev.Env))
	publishValue(t, db, values, actor, dev, "WORKERS", "12")
	grantOrg(t, db, who, scope.Org, "restoreschema", "pin", "reveal-history")
	pins := &service.Pins{DB: db, Keyring: sharedKeyring(t, db)}
	driftWorkload := seedWorkload(t, db, scope, who, "schema_drift")
	driftRequest := service.SetPinRequest{WorkloadPrincipalID: driftWorkload, Revision: target}
	createdBeforeDrift, err := pins.Set(t.Context(), actor, dev, driftRequest)
	if err != nil || createdBeforeDrift.Pin.SchemaOverride {
		t.Fatalf("pre-drift pin = %+v, %v; want valid without override", createdBeforeDrift, err)
	}
	if _, err := keys.UpdateDeclaration(t.Context(), actor, scope, key.ID, service.KeyDeclarationUpdate{
		Declaration: decl(schema.Rule{Type: schema.TypeInteger}),
		Presence:    schema.DefaultPresenceRules(),
	}); err != nil {
		t.Fatal(err)
	}
	restored, err := revisionSvc(t, db).Restore(t.Context(), actor, dev, target, "WORKERS")
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Changes) != 1 {
		t.Fatalf("restore changes = %+v, want one staged value", restored.Changes)
	}
	_, err = revisionSvc(t, db).PublishPlanned(t.Context(), actor, dev, service.PublishRequest{
		VersionIDs: []string{restored.Changes[0].VersionID}, PreviewToken: restored.Preview.Token,
	})
	if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "WORKERS") {
		t.Fatalf("schema-failing restore publish = %v, want loud refusal naming WORKERS", err)
	}
	drifted, err := pins.Set(t.Context(), actor, dev, driftRequest)
	if err != nil || drifted.Action != service.PinRenewed || !drifted.Pin.SchemaOverride {
		t.Fatalf("schema-drift renewal = %+v, %v; want grandfathered drift surfaced", drifted, err)
	}
	workload := seedWorkload(t, db, scope, who, "schema_override")
	request := service.SetPinRequest{WorkloadPrincipalID: workload, Revision: target}
	if _, err := pins.Set(t.Context(), actor, dev, request); !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "WORKERS") {
		t.Fatalf("schema-invalid pin = %v, want refusal naming WORKERS", err)
	}
	request.OverrideSchema = true
	created, err := pins.Set(t.Context(), actor, dev, request)
	if err != nil {
		t.Fatalf("explicit schema override was refused: %v", err)
	}
	request.OverrideSchema = false
	renewed, err := pins.Set(t.Context(), actor, dev, request)
	if err != nil || renewed.Action != service.PinRenewed || !renewed.Pin.SchemaOverride || renewed.Pin.ID != created.Pin.ID {
		t.Fatalf("grandfathered schema-invalid pin renewal = %+v, %v", renewed, err)
	}

	secretKey := mustKey(t, keys, actor, scope, "PIN_SECRET", string(schema.Secret), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "PIN_SECRET", "short")
	secretRevision := latestRevisionOf(t, db, string(dev.Env))
	publishValue(t, db, values, actor, dev, "PIN_SECRET", "long-enough-value")
	minLength := 10
	if _, err := keys.UpdateDeclaration(t.Context(), actor, scope, secretKey.ID, service.KeyDeclarationUpdate{
		Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString, MinLength: &minLength}},
		Presence:    schema.DefaultPresenceRules(),
	}); err != nil {
		t.Fatal(err)
	}
	disclosuresBeforeRefusal := auditEventCount(t, db, string(dev.Env), "disclosure.value_revealed")
	secretWorkload := seedWorkload(t, db, scope, who, "schema_secret_refusal")
	if _, err := pins.Set(t.Context(), actor, dev, service.SetPinRequest{
		WorkloadPrincipalID: secretWorkload, Revision: secretRevision,
	}); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("schema-invalid historical-secret pin = %v, want invalid refusal", err)
	}
	if got := auditEventCount(t, db, string(dev.Env), "disclosure.value_revealed"); got != disclosuresBeforeRefusal+1 {
		t.Fatalf("schema-invalid historical-secret pin wrote %d new disclosure events, want one", got-disclosuresBeforeRefusal)
	}
}

func scenarioPinLifecycle(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "pinlifecycle")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	mustKey(t, keys, actor, scope, "VERSION", string(schema.Secret), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "VERSION", "one")
	oldRevision := latestRevisionOf(t, db, string(dev.Env))
	publishValue(t, db, values, actor, dev, "VERSION", "two")
	latestRevision := latestRevisionOf(t, db, string(dev.Env))
	grantOrg(t, db, who, scope.Org, "pinlifecycle", "pin")

	workload := seedWorkload(t, db, scope, who, "pin_primary")
	clock := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	pins := &service.Pins{DB: db, Keyring: sharedKeyring(t, db), Now: func() time.Time { return clock }}
	if _, err := pins.Set(t.Context(), actor, dev, service.SetPinRequest{
		WorkloadPrincipalID: workload, Revision: latestRevision,
		ExpiresAt: clock.Add(service.MaxPinLifetime + time.Hour),
	}); !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "365") {
		t.Fatalf("expiry refusal = %v, want named 365-day maximum", err)
	}
	created, err := pins.Set(t.Context(), actor, dev, service.SetPinRequest{
		WorkloadPrincipalID: workload, Revision: latestRevision, OverrideSchema: true,
	})
	if err != nil || created.Action != service.PinCreated || created.Pin.HistoryAuthorized || created.Pin.SchemaOverride {
		t.Fatalf("pin create = %+v, %v", created, err)
	}
	listed, err := pins.List(t.Context(), actor, dev)
	if err != nil || len(listed) != 1 || listed[0].SchemaOverride {
		t.Fatalf("valid pin with unused schema override listed as %+v, %v; want override false", listed, err)
	}
	publishValue(t, db, values, actor, dev, "VERSION", "three")
	deliverySvc := &service.Delivery{DB: db, Keyring: sharedKeyring(t, db), Now: func() time.Time { return clock }}
	if _, err := deliverySvc.FetchAs(t.Context(), service.LocalPrincipal(workload), dev, ""); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("pin that became historical without reveal-history = %v, want refusal", err)
	}
	grantOrg(t, db, who, scope.Org, "pinlifecycle_history", "reveal-history")
	disclosuresBeforeRenewal := auditEventCount(t, db, string(dev.Env), "disclosure.value_revealed")
	fetched, err := deliverySvc.FetchAs(t.Context(), service.LocalPrincipal(workload), dev, "")
	if err != nil || fetched.PinnedRevision != latestRevision {
		t.Fatalf("current-at-creation pin after later publish = %+v, %v", fetched, err)
	}
	renewed, err := pins.Set(t.Context(), actor, dev, service.SetPinRequest{
		WorkloadPrincipalID: workload, Revision: latestRevision,
		ExpiresAt: clock.Add(200 * 24 * time.Hour),
	})
	if err != nil || renewed.Action != service.PinRenewed || renewed.Pin.ID != created.Pin.ID {
		t.Fatalf("pin renewal = %+v, %v", renewed, err)
	}
	if !renewed.Pin.HistoryAuthorized || auditEventCount(t, db, string(dev.Env), "disclosure.value_revealed") != disclosuresBeforeRenewal+1 {
		t.Fatalf("historical renewal = %+v; want history gate and one disclosure event", renewed)
	}
	reassigned, err := pins.Set(t.Context(), actor, dev, service.SetPinRequest{
		WorkloadPrincipalID: workload, Revision: oldRevision,
		ExpiresAt: clock.Add(time.Hour),
	})
	if err != nil || reassigned.Action != service.PinReassigned || !reassigned.Pin.HistoryAuthorized {
		t.Fatalf("pin reassignment = %+v, %v", reassigned, err)
	}
	listed, err = pins.List(t.Context(), actor, dev)
	if err != nil || len(listed) != 1 || listed[0].Revision != oldRevision {
		t.Fatalf("pin list = %+v, %v", listed, err)
	}
	deliverySvc.Now = func() time.Time { return clock.Add(2 * time.Hour) }
	fetched, err = deliverySvc.FetchAs(t.Context(), service.LocalPrincipal(workload), dev, "")
	if err != nil || fetched.PinnedRevision != oldRevision || !fetched.PinExpired {
		t.Fatalf("pinned delivery = %+v, %v", fetched, err)
	}
	seed(t, db, []string{`DELETE FROM grants WHERE id = 'grt_pinlifecycle_pin_0'`})
	denialsBeforeFetch := auditEventCount(t, db, string(dev.Env), "grant.denied")
	attributedBeforeFetch := attributedDenialCount(t, db, string(dev.Env), string(workload), string(who))
	if _, err := deliverySvc.FetchAs(t.Context(), service.LocalPrincipal(workload), dev, ""); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("pinned delivery after authority grant removal = %v, want loud refusal", err)
	}
	if got := auditEventCount(t, db, string(dev.Env), "grant.denied"); got != denialsBeforeFetch+1 {
		t.Fatalf("pinned delivery authority refusal wrote %d denial events, want one", got-denialsBeforeFetch)
	}
	if got := attributedDenialCount(t, db, string(dev.Env), string(workload), string(who)); got != attributedBeforeFetch+1 {
		t.Fatalf("recorded-authority denial attribution count advanced by %d, want 1", got-attributedBeforeFetch)
	}
	grantOrg(t, db, who, scope.Org, "pinlifecycle_regrant", "pin")
	const collectedPolicy = "keep-if-either(max_age=720h0m0s,last_revisions=2)"
	seed(t, db, []string{fmt.Sprintf(
		"UPDATE snapshots SET payload_present = FALSE, collected_at = '2026-08-15T12:00:00.000000Z', collected_policy = '%s' WHERE environment_id = '%s' AND revision = %d",
		collectedPolicy, dev.Env, oldRevision)})
	_, err = deliverySvc.FetchAs(t.Context(), service.LocalPrincipal(workload), dev, "")
	var collected *domain.CollectedRevisionError
	if !errors.As(err, &collected) || !errors.Is(err, domain.ErrConflict) ||
		collected.Revision != oldRevision || collected.Policy != collectedPolicy {
		t.Fatalf("collected pinned payload = %v (%+v), want conflict naming revision %d and policy %q", err, collected, oldRevision, collectedPolicy)
	}
	_, err = revisionSvc(t, db).Restore(t.Context(), actor, dev, oldRevision, "")
	collected = nil
	if !errors.As(err, &collected) || !errors.Is(err, domain.ErrConflict) ||
		collected.Revision != oldRevision || collected.Policy != collectedPolicy {
		t.Fatalf("collected restore payload = %v (%+v), want conflict naming revision %d and policy %q", err, collected, oldRevision, collectedPolicy)
	}
	seed(t, db, []string{fmt.Sprintf(
		"UPDATE snapshots SET payload_present = TRUE, collected_at = NULL, collected_policy = '' WHERE environment_id = '%s' AND revision = %d",
		dev.Env, oldRevision)})
	if err := pins.Release(t.Context(), actor, dev, workload); err != nil {
		t.Fatal(err)
	}
	if listed, err := pins.List(t.Context(), actor, dev); err != nil || len(listed) != 0 {
		t.Fatalf("pin release left %+v, %v", listed, err)
	}

	for i := 0; i < service.PinQuotaPerProject; i++ {
		principal := seedWorkload(t, db, scope, who, fmt.Sprintf("pin_quota_%03d", i))
		if _, err := pins.Set(t.Context(), actor, dev, service.SetPinRequest{
			WorkloadPrincipalID: principal, Revision: latestRevision,
		}); err != nil {
			t.Fatalf("quota seed pin %d: %v", i, err)
		}
	}
	over := seedWorkload(t, db, scope, who, "pin_quota_over")
	if _, err := pins.Set(t.Context(), actor, dev, service.SetPinRequest{
		WorkloadPrincipalID: over, Revision: latestRevision,
	}); !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "quota 100") {
		t.Fatalf("quota refusal = %v, want named quota 100", err)
	}
}

func attributedDenialCount(t *testing.T, db *store.DB, envID, actorID, authorityID string) int64 {
	t.Helper()
	q := `SELECT COUNT(*) FROM audit_tenant_events
		WHERE type = $1 AND env_id = $2 AND actor_id = $3 AND authority_id = $4`
	var out int64
	var err error
	if db.Engine() == store.EnginePostgres {
		err = db.PG().QueryRow(t.Context(), q, "grant.denied", envID, actorID, authorityID).Scan(&out)
	} else {
		err = db.SQLiteRead().QueryRowContext(t.Context(),
			strings.NewReplacer("$1", "?", "$2", "?", "$3", "?", "$4", "?").Replace(q),
			"grant.denied", envID, actorID, authorityID).Scan(&out)
	}
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func seedWorkload(t *testing.T, db *store.DB, scope domain.Scope, creator domain.PrincipalID, label string) domain.PrincipalID {
	t.Helper()
	principal := domain.PrincipalID("wld_" + label + "_" + string(scope.Project))
	seed(t, db, []string{
		fmt.Sprintf(`INSERT INTO principals (id, kind, created_at) VALUES ('%s', 'machine', '2026-01-01T00:00:00Z')`, principal),
		fmt.Sprintf(`INSERT INTO service_accounts (id, principal_id, org_id, project_id, name, kind, created_at, created_by)
			VALUES ('sa_%s_%s', '%s', '%s', '%s', '%s', 'workload', '2026-01-01T00:00:00.000000Z', '%s')`,
			label, scope.Project, principal, scope.Org, scope.Project, label, creator),
		fmt.Sprintf(`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
			VALUES ('grt_%s_read', '%s', 'read', '%s', NULL, NULL, '2026-01-01T00:00:00Z')`,
			label, principal, scope.Org),
	})
	return principal
}

func scenarioRestoreSupersededSecret(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "restorehistory")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	mustKey(t, keys, actor, scope, "API_TOKEN", string(schema.Secret), schema.DefaultPresenceRules())
	mustKey(t, keys, actor, scope, "CURRENT_ONLY", string(schema.Config), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "API_TOKEN", "old-token")
	target := latestRevisionOf(t, db, string(dev.Env))
	publishValue(t, db, values, actor, dev, "API_TOKEN", "new-token")
	publishValue(t, db, values, actor, dev, "CURRENT_ONLY", "clear-me")

	revisions := revisionSvc(t, db)
	if _, err := revisions.Restore(t.Context(), actor, dev, target, ""); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("restore without reveal-history = %v, want uniform refusal", err)
	}
	grantOrg(t, db, who, scope.Org, "restorehistory", "reveal-history")
	restored, err := revisions.Restore(t.Context(), actor, dev, target, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Changes) != 2 {
		t.Fatalf("restore staged %d changes, want old secret set plus current-only clear: %+v", len(restored.Changes), restored)
	}
	if restored.Preview.Token == "" || len(restored.Preview.Environments) != 1 || len(restored.Preview.Environments[0].Changes) != 2 {
		t.Fatalf("restore impact preview = %+v, want token plus both changes", restored.Preview)
	}
	for _, change := range restored.Preview.Environments[0].Changes {
		if change.Name == "API_TOKEN" && (change.Before != nil || change.After != nil || change.Classification != string(schema.Secret)) {
			t.Fatalf("secret restore preview disclosed plaintext or lost sticky classification: %+v", change)
		}
	}
	if got := auditEventCount(t, db, string(dev.Env), "disclosure.value_revealed"); got != 2 {
		t.Fatalf("restore wrote %d disclosure events, want one for each historical and current secret read", got)
	}
	versions := make([]string, 0, len(restored.Changes))
	for _, change := range restored.Changes {
		versions = append(versions, change.VersionID)
	}
	if _, err := revisions.Publish(t.Context(), actor, dev, versions); !errors.Is(err, service.ErrStalePreview) {
		t.Fatalf("restore publish without preview = %v, want ErrStalePreview", err)
	}
	seed(t, db, []string{fmt.Sprintf("UPDATE environments SET protected = TRUE WHERE id = '%s'", dev.Env)})
	if _, err := revisions.PublishPlanned(t.Context(), actor, dev, service.PublishRequest{
		VersionIDs: versions, PreviewToken: restored.Preview.Token,
	}); !errors.Is(err, service.ErrStalePreview) {
		t.Fatalf("restore preview after protected-set growth = %v, want stale preview", err)
	}
	refreshed, err := revisions.Restore(t.Context(), actor, dev, target, "")
	if err != nil {
		t.Fatal(err)
	}
	versions = versions[:0]
	for _, change := range refreshed.Changes {
		versions = append(versions, change.VersionID)
	}
	if len(refreshed.Preview.Environments) != 1 || !refreshed.Preview.Environments[0].Protected {
		t.Fatalf("refreshed preview did not surface protected state: %+v", refreshed.Preview)
	}
	if _, err := revisions.PublishPlanned(t.Context(), actor, dev, service.PublishRequest{
		VersionIDs: versions, PreviewToken: refreshed.Preview.Token,
	}); !errors.Is(err, service.ErrProtectedDestination) {
		t.Fatalf("protected restore publish without named confirmation = %v, want protected refusal", err)
	}
	if _, err := revisions.PublishPlanned(t.Context(), actor, dev, service.PublishRequest{
		VersionIDs: versions, PreviewToken: refreshed.Preview.Token,
		ConfirmedProtectedEnvironments: []string{string(dev.Env)},
	}); err != nil {
		t.Fatal(err)
	}
	got, _, err := revisions.Export(t.Context(), actor, dev, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "API_TOKEN" || got[0].Value != "old-token" {
		t.Fatalf("restored snapshot = %+v, want only API_TOKEN=old-token", got)
	}
	if second, err := revisions.Restore(t.Context(), actor, dev, target, "API_TOKEN"); err != nil {
		t.Fatal(err)
	} else if len(second.Changes) != 0 {
		t.Fatalf("matching per-key restore churned: %+v", second)
	}
}

func scenarioRestoreReusedKeyIdentity(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "restoreidentity")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	old := mustKey(t, keys, actor, scope, "REUSED", string(schema.Config), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "REUSED", "old")
	target := latestRevisionOf(t, db, string(dev.Env))
	unpublishValue(t, db, values, actor, dev, "REUSED")
	if err := keys.Delete(t.Context(), actor, scope, old.ID); err != nil {
		t.Fatal(err)
	}
	newKey := mustKey(t, keys, actor, scope, "REUSED", string(schema.Config), schema.DefaultPresenceRules())
	if newKey.ID == old.ID {
		t.Fatal("recreated key reused identity")
	}
	publishValue(t, db, values, actor, dev, "REUSED", "replacement")
	if _, err := revisionSvc(t, db).Restore(t.Context(), actor, dev, target, "REUSED"); !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "different identity") {
		t.Fatalf("per-key restore across name reuse = %v, want loud identity refusal", err)
	}
}

func scenarioRestoreWrittenTimeClassification(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "restorewrittenclass")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	key := mustKey(t, keys, actor, scope, "PAYMENT_PIN", string(schema.Secret), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "PAYMENT_PIN", "old-pin")
	target := latestRevisionOf(t, db, string(dev.Env))
	publishValue(t, db, values, actor, dev, "PAYMENT_PIN", "new-pin")
	if _, err := keys.Reclassify(t.Context(), actor, scope, key.ID, string(schema.Config)); err != nil {
		t.Fatal(err)
	}

	restorer := newPrincipal(t, db, "usr_restore_written_class_"+string(scope.Project), []grantSpec{
		{capability: "read", scope: scope},
		{capability: "edit", scope: scope},
		{capability: "publish", scope: scope},
	})
	restoreActor := service.LocalPrincipal(restorer)
	revisions := revisionSvc(t, db)
	if _, err := revisions.Restore(t.Context(), restoreActor, dev, target, "PAYMENT_PIN"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("restore of written-time secret without reveal-history = %v, want uniform refusal", err)
	}
	grantOrg(t, db, restorer, scope.Org, "restorewrittenclass", "reveal-history")
	if _, err := revisions.Restore(t.Context(), restoreActor, dev, target, "PAYMENT_PIN"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("restore comparing a current secret without reveal = %v, want uniform refusal", err)
	}
	grantOrg(t, db, restorer, scope.Org, "restorewrittenclass_current", "reveal")
	restored, err := revisions.Restore(t.Context(), restoreActor, dev, target, "PAYMENT_PIN")
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Changes) != 1 {
		t.Fatalf("restore changes = %+v, want one historical secret value", restored.Changes)
	}
	if _, err := revisions.PublishPlanned(t.Context(), restoreActor, dev, service.PublishRequest{
		VersionIDs: []string{restored.Changes[0].VersionID}, PreviewToken: restored.Preview.Token,
	}); err != nil {
		t.Fatal(err)
	}
}

// scenarioHistoricalExportFormula pins the export half of the revision-model ADR's
// disclosure formula, stated separately because the capabilities imply nothing
// about each other: CURRENT material is `read AND reveal`; HISTORICAL material
// — any revision that is not the latest — is `read AND reveal-history`. The
// permission-model ADR makes the two independently strippable grants, so an export
// must demand exactly the one that governs the material it serves: a
// historian without current `reveal` exports old revisions and nothing else,
// and a revealer without `reveal-history` exports the present and nothing
// else.
func scenarioHistoricalExportFormula(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "exporthist")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	mustKey(t, keys, actor, scope, "API_TOKEN", string(schema.Secret), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "API_TOKEN", "tok-rev-1")
	historicalRevision := latestRevisionOf(t, db, string(dev.Env))
	publishValue(t, db, values, actor, dev, "API_TOKEN", "tok-rev-2")

	revisions := revisionSvc(t, db)
	envScope := domain.Scope{Org: scope.Org}

	// The historian: `read` and `reveal-history`, NO current `reveal`.
	historian := service.LocalPrincipal(newPrincipal(t, db,
		"usr_export_historian_"+string(scope.Project), []grantSpec{
			{"read", envScope}, {"reveal-history", envScope},
		}))
	exported, served, err := revisions.Export(t.Context(), historian, dev, historicalRevision, true)
	if err != nil {
		t.Fatalf("read+reveal-history could not export a historical revision: %v", err)
	}
	if served != historicalRevision {
		t.Fatalf("served revision %d, want the historical %d", served, historicalRevision)
	}
	if len(exported) != 1 || exported[0].Value != "tok-rev-1" || !exported[0].Revealed {
		t.Fatalf("historical export under reveal-history = %+v, want tok-rev-1 revealed", exported)
	}
	// The same historian must NOT reveal the present: latest rides `reveal`.
	if _, _, err := revisions.Export(t.Context(), historian, dev, 0, true); err == nil {
		t.Fatal("reveal-history alone exported CURRENT material — the current half of the formula was not evaluated")
	}

	// The revealer: `read` and `reveal`, NO `reveal-history`.
	revealer := service.LocalPrincipal(newPrincipal(t, db,
		"usr_export_revealer_"+string(scope.Project), []grantSpec{
			{"read", envScope}, {"reveal", envScope},
		}))
	if _, _, err := revisions.Export(t.Context(), revealer, dev, historicalRevision, true); err == nil {
		t.Fatal("reveal alone exported HISTORICAL material — the historical half of the formula was not evaluated")
	}
	exported, served, err = revisions.Export(t.Context(), revealer, dev, 0, true)
	if err != nil {
		t.Fatalf("read+reveal could not export current material: %v", err)
	}
	if served != historicalRevision+1 || len(exported) != 1 || exported[0].Value != "tok-rev-2" {
		t.Fatalf("current export = rev %d %+v, want rev %d tok-rev-2", served, exported, historicalRevision+1)
	}
}

// scenarioPublishSerialization is C4's first clause.
//
// TWO PUBLISHES COMPUTED FROM THE SAME BASELINE both commit, and the second one
// must not silently revert the first. That is the failure the revision-model ADR
// names in full: "X publishing A=2 and Y publishing B=2 ... the later
// latest-pointer advance silently reverts the other's key, because per-entry
// freshness checks each pass and unique revision numbers alone do not linearize
// the outcome."
//
// The assertion is therefore about the OUTCOME, not about timing: after both
// publishes, BOTH keys deliver their new values, the revision numbers are
// distinct and consecutive, and the lineage records each change exactly once.
// A test that only asserted "no error" would pass against the broken
// implementation the ADR describes.
func scenarioPublishSerialization(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "publishserial")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	mustKey(t, keys, actor, scope, "ALPHA", string(schema.Config), schema.DefaultPresenceRules())
	mustKey(t, keys, actor, scope, "BETA", string(schema.Config), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "ALPHA", "a1")
	publishValue(t, db, values, actor, dev, "BETA", "b1")

	baseline := latestRevisionOf(t, db, string(dev.Env))

	// Both drafts are staged against the SAME baseline before either publishes.
	// That is the precondition the ADR describes; staging them in sequence with
	// a publish in between would test nothing.
	alpha, err := values.Set(t.Context(), actor, dev, "ALPHA", "a2")
	if err != nil {
		t.Fatal(err)
	}
	beta, err := values.Set(t.Context(), actor, dev, "BETA", "b2")
	if err != nil {
		t.Fatal(err)
	}
	if alpha.StagedFromRevision != baseline || beta.StagedFromRevision != baseline {
		t.Fatalf("drafts were not staged from one baseline: %d, %d, want %d",
			alpha.StagedFromRevision, beta.StagedFromRevision, baseline)
	}

	revisions := revisionSvc(t, db)
	var wg sync.WaitGroup
	results := make([]error, 2)
	versionIDs := []string{alpha.VersionID, beta.VersionID}
	start := func(i int) {
		versionID := versionIDs[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = revisions.Publish(t.Context(), actor, dev, []string{versionID})
		}()
	}
	if db.Engine() == store.EnginePostgres {
		probe := newPublishOverlapProbe(alpha.VersionID, beta.VersionID)
		revisions.PublishProbe = probe
		start(0)
		<-probe.firstBaseline
		start(1)
		<-probe.secondBeforeLock
		select {
		case <-probe.secondBaseline:
			close(probe.release)
			wg.Wait()
			t.Fatal("second publish read the baseline while the first transaction was paused: project lock did not serialize them")
		case <-time.After(500 * time.Millisecond):
			close(probe.release)
		}
	} else {
		start(0)
		start(1)
	}
	wg.Wait()
	for i, err := range results {
		if err != nil {
			t.Fatalf("concurrent publish %d failed: %v", i, err)
		}
	}

	// NEITHER KEY WAS REVERTED. This is the whole criterion: the second
	// materialization computed its snapshot from the state the first committed,
	// not from the baseline they both started at.
	for key, want := range map[string]string{"ALPHA": "a2", "BETA": "b2"} {
		cell, err := values.Get(t.Context(), actor, dev, key, false)
		if err != nil {
			t.Fatal(err)
		}
		if !cell.Set || cell.Value != want {
			t.Fatalf("%s = %+v after two concurrent publishes, want %q — the later publish reverted the earlier one",
				key, cell, want)
		}
	}
	// Two distinct, consecutive revisions: the allocation is serialized, so
	// nothing collided and nothing was skipped.
	if got := latestRevisionOf(t, db, string(dev.Env)); got != baseline+2 {
		t.Fatalf("revision after two publishes = %d, want %d", got, baseline+2)
	}
	// …and the delivered snapshot at that revision carries both new values, so
	// the latest pointer and the payload agree.
	exported, servedRevision, err := revisions.Export(t.Context(), actor, dev, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if servedRevision != baseline+2 {
		t.Fatalf("export served revision %d, want the latest %d", servedRevision, baseline+2)
	}
	delivered := map[string]string{}
	for _, value := range exported {
		delivered[value.Name] = value.Value
	}
	if delivered["ALPHA"] != "a2" || delivered["BETA"] != "b2" {
		t.Fatalf("the latest snapshot does not carry both publishes: %+v", delivered)
	}
}

// scenarioSelectivePublish is C4's second clause: selective publish with
// key-group closure.
//
// Three properties, each asserted separately because each fails on its own:
//
//  1. SELECTION ISOLATION — a publish carries the named versions and nothing
//     else. The publisher's own unselected draft stays pending and its cell
//     keeps delivering the published value.
//  2. CLOSURE — selecting a draft to any group member pulls the publisher's
//     drafts to the OTHER members of that group, in the same environment, into
//     the same publish. The rotated password and the matching user commit
//     together or not at all.
//  3. THE CROSS-USER REFUSAL — a group member whose pending change is owned by
//     ANOTHER principal aborts the publish, loud, naming the group and the key.
//     Never silently split, never a hand-off.
func scenarioSelectivePublish(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "selective")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	groups := &service.KeyGroups{DB: db, Keyring: sharedKeyring(t, db)}
	group, err := groups.Create(t.Context(), actor, scope, "database")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"DB_USER", "DB_PASSWORD"} {
		key := mustKey(t, keys, actor, scope, name, string(schema.Config), schema.DefaultPresenceRules())
		if _, err := keys.SetGroup(t.Context(), actor, scope, key.ID, group.ID); err != nil {
			t.Fatal(err)
		}
	}
	mustKey(t, keys, actor, scope, "UNRELATED", string(schema.Config), schema.DefaultPresenceRules())
	// The two group members land in ONE publish. They must: all-or-none resolved
	// presence means an environment where one member is `set` and the other
	// `absent` is invalid, so a group cannot be populated one publish at a time.
	// That is the state half of the coupling, and it is already load-bearing
	// before the closure assertions below get to the timing half.
	seedUser, err := values.Set(t.Context(), actor, dev, "DB_USER", "app")
	if err != nil {
		t.Fatal(err)
	}
	seedPassword, err := values.Set(t.Context(), actor, dev, "DB_PASSWORD", "pw1")
	if err != nil {
		t.Fatal(err)
	}
	publishVersions(t, db, actor, dev, seedUser.VersionID, seedPassword.VersionID)
	publishValue(t, db, values, actor, dev, "UNRELATED", "keep")

	// Three drafts; the publish names ONE of them.
	user, err := values.Set(t.Context(), actor, dev, "DB_USER", "app2")
	if err != nil {
		t.Fatal(err)
	}
	password, err := values.Set(t.Context(), actor, dev, "DB_PASSWORD", "pw2")
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := values.Set(t.Context(), actor, dev, "UNRELATED", "changed")
	if err != nil {
		t.Fatal(err)
	}

	result := publishVersions(t, db, actor, dev, password.VersionID)

	// CLOSURE: the user's draft rode along, and the result says so — the caller
	// can tell what it asked for from what the coupling required.
	if len(result.Published) != 2 {
		t.Fatalf("publishing one group member committed %d versions, want 2 (closure): %+v", len(result.Published), result)
	}
	if len(result.ClosedIn) != 1 || result.ClosedIn[0] != user.VersionID {
		t.Fatalf("closure did not report pulling the sibling in: %+v", result.ClosedIn)
	}
	for name, want := range map[string]string{"DB_USER": "app2", "DB_PASSWORD": "pw2"} {
		cell, err := values.Get(t.Context(), actor, dev, name, false)
		if err != nil {
			t.Fatal(err)
		}
		if cell.Value != want {
			t.Fatalf("%s = %q after the closed publish, want %q — the group split", name, cell.Value, want)
		}
	}
	// SELECTION ISOLATION: the unrelated draft is untouched and still pending,
	// and its cell still delivers what it delivered before.
	if cell, err := values.Get(t.Context(), actor, dev, "UNRELATED", false); err != nil || cell.Value != "keep" {
		t.Fatalf("an unselected draft leaked into the publish: %+v, %v", cell, err)
	}
	signals, err := revisionSvc(t, db).Signals(t.Context(), actor, dev)
	if err != nil {
		t.Fatal(err)
	}
	if id := pendingVersionFor(signals, "UNRELATED"); id != unrelated.VersionID {
		t.Fatalf("the unselected draft is no longer pending: %q, want %q", id, unrelated.VersionID)
	}
	if id := pendingVersionFor(signals, "DB_USER"); id != "" {
		t.Fatalf("a published draft is still pending: %q", id)
	}

	// THE CROSS-USER REFUSAL. A second principal stages a change to the other
	// group member; the first principal's publish is refused by name rather
	// than splitting the group or reaching into somebody else's working state.
	other := newPrincipal(t, db, "usr_selective_other_"+string(scope.Project), []grantSpec{
		{"read", domain.Scope{Org: scope.Org}},
		{"edit", domain.Scope{Org: scope.Org}},
		{"publish", domain.Scope{Org: scope.Org}},
	})
	if _, err := values.Set(t.Context(), service.LocalPrincipal(other), dev, "DB_USER", "theirs"); err != nil {
		t.Fatal(err)
	}
	mine, err := values.Set(t.Context(), actor, dev, "DB_PASSWORD", "pw3")
	if err != nil {
		t.Fatal(err)
	}
	_, err = revisionSvc(t, db).Publish(t.Context(), actor, dev, []string{mine.VersionID})
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("a group member held by another principal did not refuse the publish: %v", err)
	}
	if !strings.Contains(err.Error(), group.ID) || !strings.Contains(err.Error(), "DB_USER") {
		t.Fatalf("the refusal names neither the group nor the member: %v", err)
	}
	// It is a REFUSAL, not a split: nothing moved.
	if cell, err := values.Get(t.Context(), actor, dev, "DB_PASSWORD", false); err != nil || cell.Value != "pw2" {
		t.Fatalf("a refused publish committed anyway: %+v, %v", cell, err)
	}

	// SAME-CELL collision: remove the sibling marker used above, then let the
	// other principal stage the exact grouped cell Alice selected. Closure must
	// inspect the selected member too; skipping it is a cross-owner bypass.
	deletePendingCell(t, db, string(dev.Env), keyIDByName(t, keys, actor, scope, "DB_USER"), string(other))
	if _, err := values.Set(t.Context(), service.LocalPrincipal(other), dev, "DB_PASSWORD", "theirs-too"); err != nil {
		t.Fatal(err)
	}
	_, err = revisionSvc(t, db).Publish(t.Context(), actor, dev, []string{mine.VersionID})
	if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "DB_PASSWORD") {
		t.Fatalf("another owner on the selected grouped cell did not refuse by name: %v", err)
	}
}

type publishOverlapProbe struct {
	first, second    string
	firstBaseline    chan struct{}
	secondBeforeLock chan struct{}
	secondBaseline   chan struct{}
	release          chan struct{}
	firstOnce        sync.Once
	beforeOnce       sync.Once
	secondOnce       sync.Once
}

func newPublishOverlapProbe(first, second string) *publishOverlapProbe {
	return &publishOverlapProbe{
		first: first, second: second,
		firstBaseline: make(chan struct{}), secondBeforeLock: make(chan struct{}),
		secondBaseline: make(chan struct{}), release: make(chan struct{}),
	}
}

func (p *publishOverlapProbe) BeforeProjectLock(ids []string) {
	if len(ids) == 1 && ids[0] == p.second {
		p.beforeOnce.Do(func() { close(p.secondBeforeLock) })
	}
}

func (p *publishOverlapProbe) AfterBaselineRead(ids []string) {
	if len(ids) != 1 {
		return
	}
	switch ids[0] {
	case p.first:
		p.firstOnce.Do(func() { close(p.firstBaseline) })
		<-p.release
	case p.second:
		p.secondOnce.Do(func() { close(p.secondBaseline) })
		<-p.release
	}
}

func deletePendingCell(t *testing.T, db *store.DB, envID, keyID, ownerID string) {
	t.Helper()
	query := `DELETE FROM pending_changes WHERE environment_id = $1 AND owner_id = $2 AND key_id = $3`
	execConformance(t, db, query, envID, ownerID, keyID)
}

func scenarioRevisionCiphertextBinding(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "revisionaad")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	prod := mustEnv(t, envs, actor, scope, "prod")
	mustKey(t, keys, actor, scope, "SOURCE", string(schema.Config), schema.DefaultPresenceRules())
	mustKey(t, keys, actor, scope, "TARGET", string(schema.Config), schema.DefaultPresenceRules())

	draft, err := values.Set(t.Context(), actor, dev, "SOURCE", "draft-material")
	if err != nil {
		t.Fatal(err)
	}
	execConformance(t, db, `UPDATE pending_changes SET environment_id = $1,
		key_id = (SELECT id FROM keys WHERE name = $2) WHERE id = $3`,
		string(prod.Env), "TARGET", draft.VersionID)
	_, err = revisionSvc(t, db).Publish(t.Context(), actor, prod, []string{draft.VersionID})
	if !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("relocated pending ciphertext opened under changed environment/key metadata: %v", err)
	}

	publishValue(t, db, values, actor, dev, "SOURCE", "snapshot-material")
	execConformance(t, db, `UPDATE snapshot_entries SET environment_id = $1,
		snapshot_id = (SELECT id FROM snapshots WHERE environment_id = $1 ORDER BY revision DESC LIMIT 1)
		WHERE id = (SELECT se.id FROM snapshot_entries se JOIN snapshots s ON s.id = se.snapshot_id
			WHERE se.environment_id = $2 AND se.key_name = $3 ORDER BY s.revision DESC LIMIT 1)`,
		string(prod.Env), string(dev.Env), "SOURCE")
	if _, _, err := revisionSvc(t, db).Export(t.Context(), actor, prod, 0, false); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("relocated snapshot ciphertext opened under changed environment/snapshot metadata: %v", err)
	}
}

func scenarioAdvisoryAuthorization(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "advisoryauthz")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	prod := mustEnv(t, envs, actor, scope, "prod")
	mustKey(t, keys, actor, scope, "NOTICE", string(schema.Config), schema.DefaultPresenceRules())

	advisory := service.NewAdvisory()
	values.Advisory = advisory
	revisions := &service.Revisions{DB: db, Keyring: sharedKeyring(t, db), Advisory: advisory}
	reader := newPrincipal(t, db, "usr_advisory_reader_"+string(scope.Project), []grantSpec{
		{"read", domain.Scope{Org: scope.Org, Project: scope.Project}},
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	events, err := revisions.Watch(ctx, service.LocalPrincipal(reader), scope)
	if err != nil {
		t.Fatal(err)
	}
	// Scope the live grant down AFTER connect. Per-event authorization must see
	// current state: prod references disappear; dev references still arrive.
	execConformance(t, db, `DELETE FROM grants WHERE principal_id = $1`, string(reader))
	execConformance(t, db, `INSERT INTO grants
		(id, principal_id, capability, org_id, project_id, env_id, created_at)
		VALUES ($1, $2, 'read', $3, $4, $5, '2026-01-01T00:00:00Z')`,
		"grt_advisory_scoped_"+string(scope.Project), string(reader), string(scope.Org), string(scope.Project), string(dev.Env))

	prodDraft, err := values.Set(t.Context(), actor, prod, "NOTICE", "hidden")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revisions.Publish(t.Context(), actor, prod, []string{prodDraft.VersionID}); err != nil {
		t.Fatal(err)
	}
	devDraft, err := values.Set(t.Context(), actor, dev, "NOTICE", "visible")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revisions.Publish(t.Context(), actor, dev, []string{devDraft.VersionID}); err != nil {
		t.Fatal(err)
	}

	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				t.Fatal("advisory stream closed before authorized event arrived")
			}
			if ev.EnvironmentID == string(prod.Env) {
				t.Fatalf("subscriber without prod read received prod event: %+v", ev)
			}
			if ev.EnvironmentID == string(dev.Env) && ev.Type == service.AdvisoryPublished {
				return
			}
		case <-deadline.C:
			t.Fatal("authorized dev advisory did not arrive")
		}
	}
}

func execConformance(t *testing.T, db *store.DB, query string, args ...any) {
	t.Helper()
	var err error
	if db.Engine() == store.EnginePostgres {
		_, err = db.PG().Exec(t.Context(), query, args...)
	} else {
		var sqliteQuery strings.Builder
		sqliteArgs := make([]any, 0, len(args))
		for i := 0; i < len(query); {
			if query[i] != '$' {
				sqliteQuery.WriteByte(query[i])
				i++
				continue
			}
			j := i + 1
			for j < len(query) && query[j] >= '0' && query[j] <= '9' {
				j++
			}
			position, convErr := strconv.Atoi(query[i+1 : j])
			if convErr != nil || position < 1 || position > len(args) {
				t.Fatalf("invalid SQL placeholder near %q", query[i:])
			}
			sqliteQuery.WriteByte('?')
			sqliteArgs = append(sqliteArgs, args[position-1])
			i = j
		}
		_, err = db.SQLiteWrite().ExecContext(t.Context(), sqliteQuery.String(), sqliteArgs...)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// scenarioRotateTokenKey is C4's third clause, and the encryption-model ADR's CI
// invariant 15: `rotate-token-key` changes the token WITHOUT touching content,
// revision numbers, or pinned input revisions.
//
// The four negatives are what make it a real assertion. A rotation that
// re-materialized every snapshot would also "change the token" — and would
// break every pin, every history reference and every stored verdict. So the
// test pins all four facts before rotating and requires them byte-identical
// after.
func scenarioRotateTokenKey(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "tokenrotate")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	mustKey(t, keys, actor, scope, "ROTATE_ME", string(schema.Config), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "ROTATE_ME", "content")

	revisions := revisionSvc(t, db)
	before, err := revisions.Show(t.Context(), actor, dev, 0)
	if err != nil {
		t.Fatal(err)
	}
	pinnedEntriesBefore := pinnedValueEntries(t, db, string(dev.Env), before.Revision)
	if len(pinnedEntriesBefore) == 0 {
		t.Fatal("fixture broken: the snapshot pinned no value entries")
	}

	// The operator capability is `rotate-dek`: the permission-model ADR's capability
	// set is closed and names four rotation atoms for five rotation verbs, and
	// the root token key is a tier-3 key alongside the DEKs.
	operator := newPrincipal(t, db, "usr_rotate_"+string(scope.Project), []grantSpec{
		{"rotate-dek", domain.Scope{}},
	})
	rotation, err := revisions.RotateTokenKey(t.Context(), service.LocalPrincipal(operator))
	if err != nil {
		t.Fatal(err)
	}
	if rotation.Version < 2 {
		t.Fatalf("rotation reported version %d, want a successor to the boot key", rotation.Version)
	}

	after, err := revisions.Show(t.Context(), actor, dev, 0)
	if err != nil {
		t.Fatal(err)
	}
	// 1. THE TOKEN MOVED.
	if after.ChangeToken == before.ChangeToken {
		t.Fatal("rotate-token-key left the change token unchanged")
	}
	// …and still carries the SCHEME version prefix, which is the public machine
	// contract. The KEY version is deliberately not in it: a consumer able to
	// tell key versions apart could tell a rotation from a content change.
	if !strings.HasPrefix(after.ChangeToken, "v1:") {
		t.Fatalf("rotated token lost its scheme prefix: %q", after.ChangeToken)
	}
	// 2. THE REVISION NUMBER DID NOT MOVE.
	if after.Revision != before.Revision {
		t.Fatalf("rotate-token-key moved the revision %d -> %d", before.Revision, after.Revision)
	}
	// 3. THE PINNED INPUT REVISIONS DID NOT MOVE — neither the schema revision
	//    on the snapshot nor the per-entry value-entry ids it pinned.
	if after.SchemaRevision != before.SchemaRevision {
		t.Fatalf("rotate-token-key moved the pinned schema revision %d -> %d",
			before.SchemaRevision, after.SchemaRevision)
	}
	pinnedEntriesAfter := pinnedValueEntries(t, db, string(dev.Env), after.Revision)
	if len(pinnedEntriesAfter) != len(pinnedEntriesBefore) {
		t.Fatalf("rotate-token-key changed the pinned entry set: %v -> %v", pinnedEntriesBefore, pinnedEntriesAfter)
	}
	for i := range pinnedEntriesBefore {
		if pinnedEntriesBefore[i] != pinnedEntriesAfter[i] {
			t.Fatalf("rotate-token-key moved a pinned value-entry revision: %q -> %q",
				pinnedEntriesBefore[i], pinnedEntriesAfter[i])
		}
	}
	// 4. THE CONTENT DID NOT MOVE.
	cell, err := values.Get(t.Context(), actor, dev, "ROTATE_ME", false)
	if err != nil {
		t.Fatal(err)
	}
	if !cell.Set || cell.Value != "content" {
		t.Fatalf("rotate-token-key disturbed the delivered content: %+v", cell)
	}
	// The new token is STABLE: a second read derives the same value, so the
	// rotation is a swap rather than a source of churn.
	again, err := revisions.Show(t.Context(), actor, dev, 0)
	if err != nil {
		t.Fatal(err)
	}
	if again.ChangeToken != after.ChangeToken {
		t.Fatalf("the token is not stable after rotation: %q then %q", after.ChangeToken, again.ChangeToken)
	}

	// CONCURRENT ROTATIONS AGREE WITH THE DATASTORE. Two rotations race; the
	// store's retire is a compare-and-swap on the predecessor version and the
	// in-memory adopt is version-monotonic, so whatever interleaving happens,
	// each attempt either succeeds or refuses with a CONFLICT (never a server
	// fault), and the token the process derives afterwards is the token a
	// restart would derive -- i.e. the live handle matches the committed key.
	rotator := service.LocalPrincipal(operator)
	var wg sync.WaitGroup
	raceErrs := make([]error, 2)
	for i := range raceErrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, raceErrs[i] = revisions.RotateTokenKey(t.Context(), rotator)
		}()
	}
	wg.Wait()
	succeeded := 0
	for i, raceErr := range raceErrs {
		switch {
		case raceErr == nil:
			succeeded++
		case errors.Is(raceErr, domain.ErrConflict):
			// The loser of the compare-and-swap, refusing loudly.
		default:
			t.Fatalf("concurrent rotation %d failed with a non-conflict error: %v", i, raceErr)
		}
	}
	if succeeded == 0 {
		t.Fatal("both concurrent rotations refused: the compare-and-swap has no winner")
	}
	// The derived token is stable across reads AND consistent with the
	// committed key: deriving twice through the live handle must agree, and a
	// mismatch between memory and datastore would surface here as churn.
	first, err := revisions.Show(t.Context(), actor, dev, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := revisions.Show(t.Context(), actor, dev, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.ChangeToken != second.ChangeToken {
		t.Fatalf("token unstable after concurrent rotations: %q then %q", first.ChangeToken, second.ChangeToken)
	}
	if first.ChangeToken == after.ChangeToken {
		t.Fatal("a successful concurrent rotation left the token unchanged")
	}
}

// scenarioPublishSignals is C2's publish clause, first half: "a value publish
// recomputes matrix signals for exactly the touched environments, a semantic
// schema publish for every environment".
//
// EXACTLY is the word under test. A value publish into `dev` must leave
// `prod`'s revision and `prod`'s changed-key signal alone; a semantic schema
// change must move BOTH.
func scenarioPublishSignals(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "signals")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	prod := mustEnv(t, envs, actor, scope, "prod")
	key := mustKey(t, keys, actor, scope, "SIGNAL", string(schema.Config), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "SIGNAL", "dev-1")
	publishValue(t, db, values, actor, prod, "SIGNAL", "prod-1")

	revisions := revisionSvc(t, db)
	devBefore := latestRevisionOf(t, db, string(dev.Env))
	prodBefore := latestRevisionOf(t, db, string(prod.Env))
	prodSignalsBefore, err := revisions.Signals(t.Context(), actor, prod)
	if err != nil {
		t.Fatal(err)
	}
	prodChangedBefore := changedIn(prodSignalsBefore, "SIGNAL")

	// A VALUE PUBLISH touches exactly one environment.
	publishValue(t, db, values, actor, dev, "SIGNAL", "dev-2")

	if got := latestRevisionOf(t, db, string(dev.Env)); got != devBefore+1 {
		t.Fatalf("the touched environment advanced %d -> %d, want one revision", devBefore, got)
	}
	if got := latestRevisionOf(t, db, string(prod.Env)); got != prodBefore {
		t.Fatalf("an UNTOUCHED environment advanced %d -> %d: a value publish must not fan out",
			prodBefore, got)
	}
	devSignals, err := revisions.Signals(t.Context(), actor, dev)
	if err != nil {
		t.Fatal(err)
	}
	if changedIn(devSignals, "SIGNAL") != devBefore+1 {
		t.Fatalf("the touched cell carries no `recently changed` signal at the new revision: %+v", devSignals)
	}
	prodSignals, err := revisions.Signals(t.Context(), actor, prod)
	if err != nil {
		t.Fatal(err)
	}
	// prod's signal is UNCHANGED — still pointing at prod's own last revision,
	// not recomputed against dev's. "Recomputes for exactly the touched
	// environments" is a statement about which signals move, so the assertion
	// compares before and after rather than expecting an untouched environment
	// to carry no signal at all: prod legitimately changed in prod's own
	// revision, and that fact must survive dev publishing.
	if got := changedIn(prodSignals, "SIGNAL"); got != prodChangedBefore {
		t.Fatalf("an untouched environment's signal moved %d -> %d when another environment published",
			prodChangedBefore, got)
	}

	// A SEMANTIC SCHEMA PUBLISH does not narrow: every environment in the
	// project materializes a new snapshot at the new schema revision, even
	// where no value and no verdict changes, because its PINNED SCHEMA REVISION
	// changed and that is a pinned input.
	devBefore = latestRevisionOf(t, db, string(dev.Env))
	prodBefore = latestRevisionOf(t, db, string(prod.Env))
	if _, err := keys.Rename(t.Context(), actor, scope, key.ID, "SIGNAL_RENAMED"); err != nil {
		t.Fatal(err)
	}
	if got := latestRevisionOf(t, db, string(dev.Env)); got != devBefore+1 {
		t.Fatalf("a semantic schema publish missed dev: %d -> %d", devBefore, got)
	}
	if got := latestRevisionOf(t, db, string(prod.Env)); got != prodBefore+1 {
		t.Fatalf("a semantic schema publish did not fan out to prod: %d -> %d", prodBefore, got)
	}
	// The rename moved the delivered key set, so BOTH environments record it in
	// lineage — the fan-out materialized real snapshots, not empty ones.
	for _, env := range []domain.Scope{dev, prod} {
		detail, err := revisions.Show(t.Context(), actor, env, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(detail.Keys) != 1 || detail.Keys[0].Name != "SIGNAL_RENAMED" {
			t.Fatalf("%s's new snapshot does not carry the renamed key: %+v", env.Env, detail.Keys)
		}
	}
}

// scenarioRequiredInVeto is C2's publish clause, second half, verbatim: "a
// `required_in` key left `absent` vetoes publish naming key and environment".
//
// It also pins the half that makes the veto legitimate: SAVING IS FREE. The
// draft that would strand the key stages without complaint — a draft is the
// user's scratchpad, and blocking the save pushes work in progress into
// external notepads, which for secrets is exactly where it must not go.
func scenarioRequiredInVeto(t *testing.T, db *store.DB) {
	who, scope, values, envs, keys := valueFixture(t, db, "requiredveto")
	actor := service.LocalPrincipal(who)
	dev := mustEnv(t, envs, actor, scope, "dev")
	key := mustKey(t, keys, actor, scope, "MUST_EXIST", string(schema.Config), schema.DefaultPresenceRules())
	publishValue(t, db, values, actor, dev, "MUST_EXIST", "present")
	if _, err := keys.UpdateDeclaration(t.Context(), actor, scope, key.ID, service.KeyDeclarationUpdate{
		Declaration: decl(schema.Rule{Type: schema.TypeString}),
		Presence: schema.PresenceRules{
			Required:  schema.Presence{Mode: schema.PresenceExplicit, Environments: []string{string(dev.Env)}},
			Forbidden: schema.Presence{Mode: schema.PresenceNone},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// SAVING IS FREE: the clear stages, and the environment keeps delivering.
	staged, err := values.Unset(t.Context(), actor, dev, "MUST_EXIST")
	if err != nil {
		t.Fatalf("staging a clear of a required key was refused; saving is free: %v", err)
	}
	if cell, err := values.Get(t.Context(), actor, dev, "MUST_EXIST", false); err != nil || !cell.Set {
		t.Fatalf("a staged clear stopped delivery before publish: %+v, %v", cell, err)
	}

	// PUBLISH IS THE AUTHORITY, and the veto names both.
	revisionBefore := latestRevisionOf(t, db, string(dev.Env))
	_, err = revisionSvc(t, db).Publish(t.Context(), actor, dev, []string{staged.VersionID})
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("publishing a clear of a `required_in` key was accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "MUST_EXIST") {
		t.Fatalf("the veto does not name the key: %v", err)
	}
	if !strings.Contains(err.Error(), string(dev.Env)) {
		t.Fatalf("the veto does not name the environment: %v", err)
	}
	// The refusal carries both to the wire as a caller-safe detail. Key names
	// are schema and environment ids are the caller's own request, so naming
	// them discloses nothing.
	var sd interface{ SafeDetail() string }
	if !errors.As(err, &sd) || !strings.Contains(sd.SafeDetail(), "MUST_EXIST") {
		t.Fatalf("the veto does not expose the key as a safe detail: %v", err)
	}
	// A REAL veto: nothing was published, and the draft is still pending, so
	// the operator can fix it rather than restage from scratch.
	if got := latestRevisionOf(t, db, string(dev.Env)); got != revisionBefore {
		t.Fatalf("a vetoed publish still advanced the revision %d -> %d", revisionBefore, got)
	}
	if cell, err := values.Get(t.Context(), actor, dev, "MUST_EXIST", false); err != nil || cell.Value != "present" {
		t.Fatalf("a vetoed publish disturbed the delivered value: %+v, %v", cell, err)
	}
	signals, err := revisionSvc(t, db).Signals(t.Context(), actor, dev)
	if err != nil {
		t.Fatal(err)
	}
	if pendingVersionFor(signals, "MUST_EXIST") != staged.VersionID {
		t.Fatalf("a vetoed publish discarded the draft: %+v", signals)
	}
}

// latestRevisionOf reads one environment's newest published revision straight
// from the datastore. The assertions above are about what the pipeline
// RECORDED, so reading it back through the pipeline's own API would only prove
// the API agrees with itself.
func latestRevisionOf(t *testing.T, db *store.DB, envID string) int64 {
	t.Helper()
	q := `SELECT COALESCE(MAX(revision), 0) FROM snapshots WHERE environment_id = $1`
	var out int64
	var err error
	if db.Engine() == store.EnginePostgres {
		err = db.PG().QueryRow(t.Context(), q, envID).Scan(&out)
	} else {
		err = db.SQLiteRead().QueryRowContext(t.Context(),
			strings.NewReplacer("$1", "?").Replace(q), envID).Scan(&out)
	}
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// pinnedValueEntries reads the value-entry revisions one snapshot pinned,
// ordered by key. This is the "pinned input revisions" half of C4's
// rotate-token-key criterion, and it is read from the rows rather than from a
// service so a rotation that quietly re-materialized could not hide behind an
// API that recomputes.
func pinnedValueEntries(t *testing.T, db *store.DB, envID string, revision int64) []string {
	t.Helper()
	query := `SELECT value_entry_id FROM snapshot_entries
	          WHERE environment_id = $1 AND snapshot_id = (
	              SELECT id FROM snapshots WHERE environment_id = $1 AND revision = $2)
	          ORDER BY key_name`
	var out []string
	if db.Engine() == store.EnginePostgres {
		rows, err := db.PG().Query(t.Context(), query, envID, revision)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out = append(out, id)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	// sqlite has no repeated positional parameters, so the environment is bound
	// twice rather than rewritten into a join the predicate analyzer would
	// reject in production SQL.
	rows, err := db.SQLiteRead().QueryContext(t.Context(),
		strings.NewReplacer("$1", "?", "$2", "?").Replace(
			`SELECT value_entry_id FROM snapshot_entries
			 WHERE environment_id = $1 AND snapshot_id = (
			     SELECT id FROM snapshots WHERE environment_id = $1 AND revision = $2)
			 ORDER BY key_name`), envID, envID, revision)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func pendingVersionFor(signals service.EnvironmentSignals, name string) string {
	for _, cell := range signals.Cells {
		if cell.Name == name {
			return cell.PendingVersionID
		}
	}
	return ""
}

func changedIn(signals service.EnvironmentSignals, name string) int64 {
	for _, cell := range signals.Cells {
		if cell.Name == name {
			return cell.ChangedInRevision
		}
	}
	return 0
}
