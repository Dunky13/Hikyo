package store_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/migrate"
	storetx "github.com/Hikyo-Org/hikyo/internal/store/tx"
)

func adapterRuntimeDB(t *testing.T) *store.DB {
	t.Helper()
	cfg := store.Config{Engine: store.EngineSQLite, Path: filepath.Join(t.TempDir(), "adapter-runtime.db")}
	if err := migrate.Run(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	statements := []string{
		`INSERT INTO orgs (id,name,active,metadata,created_at) VALUES ('org_adapter','Adapter',1,'{}','2026-08-17T00:00:00Z')`,
		`INSERT INTO projects (id,org_id,name,created_at) VALUES ('prj_adapter','org_adapter','Adapter','2026-08-17T00:00:00Z')`,
		`INSERT INTO environments (id,org_id,project_id,name,note,created_at,display_order) VALUES ('env_adapter','org_adapter','prj_adapter','prod','','2026-08-17T00:00:00Z',0)`,
		`INSERT INTO principals (id,kind,created_at) VALUES ('usr_adapter','human','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapters (id,org_id,project_id,provider,origin,authority_principal_id,state,created_at) VALUES ('adp_1','org_adapter','prj_adapter','forgejo','https://git.example','usr_adapter','active','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_targets (id,org_id,project_id,environment_id,adapter_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,generation,state,sync_status,active_job_id,created_at) VALUES ('tgt_1','org_adapter','prj_adapter','env_adapter','adp_1','repository','acme','app',42,'',1,'active','converging','job_1','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,authority_principal_id,generation,dedup_key,next_attempt_at,state,created_at) VALUES ('job_1','org_adapter','prj_adapter','env_adapter','tgt_1','converge','usr_adapter',1,'tgt_1','2026-08-17T00:00:00Z','queued','2026-08-17T00:00:00Z')`,
	}
	for _, statement := range statements {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestAdapterJournalCommitsIntentOutcomeAndLedgerAtomically(t *testing.T) {
	db := adapterRuntimeDB(t)
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	now := time.Now().UTC()
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_1", now, now.Add(adapter.LeaseTime))
	if err != nil || !ok {
		t.Fatalf("ClaimDue() = %+v, %v, %v", job, ok, err)
	}
	effect := adapter.Effect{Surface: adapter.Secret, EffectiveName: "TOKEN", Disposition: adapter.Create, KeyID: "key_1"}
	journal := runtime.Journal(job)
	if err := journal.Gate(t.Context(), effect); err != nil {
		t.Fatal(err)
	}
	state, err := journal.Reserve(t.Context(), effect)
	if err != nil || state != adapter.Reserved {
		t.Fatalf("Reserve() = %q, %v", state, err)
	}
	if err := journal.Prepare(t.Context(), effect, state); err != nil {
		t.Fatal(err)
	}
	if err := journal.Finish(t.Context(), effect, adapter.Completion{Outcome: "success", State: adapter.Owned}); err != nil {
		t.Fatal(err)
	}
	var ledgerState, effectOutcome string
	var intents, outcomes, delivered int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_ledger WHERE target_id='tgt_1' AND surface='secret' AND normalized_name='TOKEN'`).Scan(&ledgerState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT outcome FROM adapter_effects WHERE job_id='job_1'`).Scan(&effectOutcome); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE correlation_id='job_1' AND type='adapter.push_intent'`).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE correlation_id='job_1' AND type='adapter.push_outcome'`).Scan(&outcomes); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE correlation_id='job_1' AND type='adapter.key_delivered' AND json_extract(payload,'$.key_id')='key_1'`).Scan(&delivered); err != nil {
		t.Fatal(err)
	}
	if ledgerState != "owned" || effectOutcome != "success" || intents != 1 || outcomes != 1 || delivered != 1 {
		t.Fatalf("ledger=%q effect=%q intents=%d outcomes=%d delivered=%d", ledgerState, effectOutcome, intents, outcomes, delivered)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := runtime.Enqueue(ctx, adapter.Job{OrgID: job.OrgID, ProjectID: job.ProjectID, EnvironmentID: job.EnvironmentID, TargetID: job.TargetID, Kind: adapter.Converge, AuthorityPrincipal: job.AuthorityPrincipal}, now); err != nil {
		t.Fatalf("Finish did not release provider fence: %v", err)
	}
}

func TestAdapterJournalPUTNotFoundEndsEffectBeforeFreshCreateRetry(t *testing.T) {
	db := adapterRuntimeDB(t)
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_variable','org_adapter','prj_adapter','env_adapter','tgt_1','https://git.example',42,'variable','LOG_LEVEL','LOG_LEVEL','owned','2026-08-17T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	now := time.Now().UTC()
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_1", now, now.Add(adapter.LeaseTime))
	if err != nil || !ok {
		t.Fatalf("ClaimDue(first) = %+v, %v, %v", job, ok, err)
	}
	update := adapter.Effect{Surface: adapter.Variable, EffectiveName: "LOG_LEVEL", Disposition: adapter.Update, KeyID: "key_1"}
	first := runtime.Journal(job)
	if err := first.Prepare(t.Context(), update, adapter.Owned); err != nil {
		t.Fatal(err)
	}
	if err := first.Finish(t.Context(), update, adapter.Completion{Outcome: "failure", State: ""}); err != nil {
		t.Fatal(err)
	}
	var ledgerRows, firstEffects int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_ledger WHERE target_id='tgt_1' AND surface='variable' AND normalized_name='LOG_LEVEL'`).Scan(&ledgerRows); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_effects WHERE job_id='job_1' AND surface='variable' AND effective_name='LOG_LEVEL' AND disposition='update' AND outcome='failure'`).Scan(&firstEffects); err != nil {
		t.Fatal(err)
	}
	if ledgerRows != 0 || firstEffects != 1 {
		t.Fatalf("after PUT 404 ledger=%d terminal update effects=%d", ledgerRows, firstEffects)
	}

	due := now.Add(time.Second)
	if err := runtime.Retry(t.Context(), job, due, []adapter.Change{{Surface: adapter.Variable, EffectiveName: "LOG_LEVEL", Disposition: adapter.Update}}, errors.New("provider returned 404")); err != nil {
		t.Fatal(err)
	}
	retryJob, ok, err := runtime.ClaimDue(t.Context(), "worker_2", due.Add(time.Second), due.Add(time.Second).Add(adapter.LeaseTime))
	if err != nil || !ok {
		t.Fatalf("ClaimDue(retry) = %+v, %v, %v", retryJob, ok, err)
	}
	create := adapter.Effect{Surface: adapter.Variable, EffectiveName: "LOG_LEVEL", Disposition: adapter.Create, KeyID: "key_1"}
	second := runtime.Journal(retryJob)
	state, err := second.Reserve(t.Context(), create)
	if err != nil || state != adapter.Reserved {
		t.Fatalf("Reserve(retry) = %q, %v", state, err)
	}
	if err := second.Prepare(t.Context(), create, state); err != nil {
		t.Fatal(err)
	}
	if err := second.Finish(t.Context(), create, adapter.Completion{Outcome: "success", State: adapter.Owned}); err != nil {
		t.Fatal(err)
	}
	var effects, intents, outcomes int
	var ledgerState string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_effects WHERE job_id='job_1' AND surface='variable' AND effective_name='LOG_LEVEL'`).Scan(&effects); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE correlation_id='job_1' AND type='adapter.push_intent' AND json_extract(payload,'$.effective_name')='LOG_LEVEL'`).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE correlation_id='job_1' AND type='adapter.push_outcome' AND json_extract(payload,'$.effective_name')='LOG_LEVEL'`).Scan(&outcomes); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_ledger WHERE target_id='tgt_1' AND surface='variable' AND normalized_name='LOG_LEVEL'`).Scan(&ledgerState); err != nil {
		t.Fatal(err)
	}
	if effects != 2 || intents != 2 || outcomes != 2 || ledgerState != "owned" {
		t.Fatalf("effects=%d intents=%d outcomes=%d ledger=%q", effects, intents, outcomes, ledgerState)
	}
}

func TestAdapterJournalFinishesUnsentIntentBeforeAuthorityAbort(t *testing.T) {
	db := adapterRuntimeDB(t)
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return adapter.ErrUnauthorized })
	now := time.Now().UTC()
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_1", now, now.Add(adapter.LeaseTime))
	if err != nil || !ok {
		t.Fatalf("ClaimDue() = %+v, %v, %v", job, ok, err)
	}
	effect := adapter.Effect{Surface: adapter.Variable, EffectiveName: "MODE", Disposition: adapter.Create}
	journal := runtime.Journal(job)
	state, err := journal.Reserve(t.Context(), effect)
	if err != nil || state != adapter.Reserved {
		t.Fatalf("Reserve() = %q, %v", state, err)
	}
	if err := journal.Prepare(t.Context(), effect, state); err != nil {
		t.Fatal(err)
	}
	if err := journal.Gate(t.Context(), effect); !errors.Is(err, adapter.ErrUnauthorized) {
		t.Fatalf("post-Prepare Gate() = %v", err)
	}
	if err := journal.Finish(t.Context(), effect, adapter.Completion{Outcome: "failure", State: state}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Fail(t.Context(), job, now.Add(time.Second), adapter.ErrUnauthorized); err != nil {
		t.Fatal(err)
	}
	var ledgerState, outcome string
	var fenceRows, aborts int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_ledger WHERE target_id='tgt_1' AND surface='variable' AND normalized_name='MODE'`).Scan(&ledgerState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT outcome FROM adapter_effects WHERE job_id='job_1' AND surface='variable' AND effective_name='MODE'`).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_targets WHERE id='tgt_1' AND provider_lease_job_id IS NOT NULL`).Scan(&fenceRows); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE correlation_id='job_1' AND type='adapter.abort' AND outcome='failure' AND json_extract(payload,'$.cause')='authority'`).Scan(&aborts); err != nil {
		t.Fatal(err)
	}
	if ledgerState != "reserved" || outcome != "failure" || fenceRows != 0 || aborts != 1 {
		t.Fatalf("ledger=%q outcome=%q fences=%d aborts=%d", ledgerState, outcome, fenceRows, aborts)
	}
}

func TestAdapterJournalFinishesUnsentIntentBeforeGenerationAbort(t *testing.T) {
	db := adapterRuntimeDB(t)
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	now := time.Now().UTC()
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_1", now, now.Add(adapter.LeaseTime))
	if err != nil || !ok {
		t.Fatalf("ClaimDue() = %+v, %v, %v", job, ok, err)
	}
	effect := adapter.Effect{Surface: adapter.Variable, EffectiveName: "MODE", Disposition: adapter.Create}
	journal := runtime.Journal(job)
	state, err := journal.Reserve(t.Context(), effect)
	if err != nil || state != adapter.Reserved {
		t.Fatalf("Reserve() = %q, %v", state, err)
	}
	if err := journal.Prepare(t.Context(), effect, state); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_targets SET generation=2 WHERE id='tgt_1'`); err != nil {
		t.Fatal(err)
	}
	if err := journal.Gate(t.Context(), effect); !errors.Is(err, adapter.ErrSuperseded) {
		t.Fatalf("post-Prepare Gate() = %v", err)
	}
	if err := journal.Finish(t.Context(), effect, adapter.Completion{Outcome: "failure", State: state}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Fail(t.Context(), job, now.Add(time.Second), adapter.ErrSuperseded); err != nil {
		t.Fatal(err)
	}
	var fenceRows, aborts int
	var outcome string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT outcome FROM adapter_effects WHERE job_id='job_1' AND surface='variable' AND effective_name='MODE'`).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_targets WHERE id='tgt_1' AND provider_lease_job_id IS NOT NULL`).Scan(&fenceRows); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE correlation_id='job_1' AND type='adapter.abort' AND outcome='failure' AND json_extract(payload,'$.cause')='generation'`).Scan(&aborts); err != nil {
		t.Fatal(err)
	}
	if outcome != "failure" || fenceRows != 0 || aborts != 1 {
		t.Fatalf("outcome=%q fences=%d aborts=%d", outcome, fenceRows, aborts)
	}
}

func TestPublishedGenerationSupersedesWithoutStealingLiveProviderFence(t *testing.T) {
	db := adapterRuntimeDB(t)
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_publish_adapter','usr_adapter','publish','org_adapter','prj_adapter','env_adapter','2026-08-17T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	now := time.Now().UTC()
	oldJob, ok, err := runtime.ClaimDue(t.Context(), "worker_old", now, now.Add(adapter.LeaseTime))
	if err != nil || !ok {
		t.Fatalf("ClaimDue(old) = %+v, %v, %v", oldJob, ok, err)
	}
	effect := adapter.Effect{Surface: adapter.Secret, EffectiveName: "TOKEN", Disposition: adapter.Create}
	journal := runtime.Journal(oldJob)
	state, err := journal.Reserve(t.Context(), effect)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Prepare(t.Context(), effect, state); err != nil {
		t.Fatal(err)
	}

	var enqueued []store.AdapterEnqueueResult
	err = storetx.Write(t.Context(), db, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		proof, err := az.Authorize(ctx, authz.Identity{Principal: "usr_adapter"}, authz.OpValuePublish,
			domain.Scope{Org: "org_adapter", Project: "prj_adapter", Env: "env_adapter"})
		if err != nil {
			return err
		}
		enqueued, err = repos.Adapters().EnqueuePublished(ctx, proof, now.Add(time.Second))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(enqueued) != 1 || enqueued[0].Generation != 2 || enqueued[0].AuthorityPrincipalID != "usr_adapter" {
		t.Fatalf("EnqueuePublished() = %+v", enqueued)
	}
	var oldState, leaseJob, leaseEffect string
	var generation int64
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT generation,provider_lease_job_id,provider_lease_effect_id FROM adapter_targets WHERE id='tgt_1'`).Scan(&generation, &leaseJob, &leaseEffect); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_outbox WHERE id='job_1'`).Scan(&oldState); err != nil {
		t.Fatal(err)
	}
	if generation != 2 || leaseJob != oldJob.ID || leaseEffect == "" || oldState != "superseded" {
		t.Fatalf("publish stole live fence: generation=%d lease=%q/%q old=%q", generation, leaseJob, leaseEffect, oldState)
	}

	if err := journal.Finish(t.Context(), effect, adapter.Completion{Outcome: "success", State: adapter.Owned}); err != nil {
		t.Fatalf("old in-flight effect could not finish after publish generation bump: %v", err)
	}
	if err := journal.Gate(t.Context(), adapter.Effect{}); !errors.Is(err, adapter.ErrSuperseded) {
		t.Fatalf("old job Gate() = %v, want superseded", err)
	}
	var released any
	var ledgerState, outcome string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT provider_lease_job_id FROM adapter_targets WHERE id='tgt_1'`).Scan(&released); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_ledger WHERE target_id='tgt_1' AND normalized_name='TOKEN'`).Scan(&ledgerState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT outcome FROM adapter_effects WHERE job_id='job_1'`).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	if released != nil || ledgerState != "owned" || outcome != "success" {
		t.Fatalf("terminal state after generation bump: lease=%v ledger=%q outcome=%q", released, ledgerState, outcome)
	}
	newJob, ok, err := runtime.ClaimDue(t.Context(), "worker_new", now.Add(2*time.Second), now.Add(adapter.LeaseTime))
	if err != nil || !ok || newJob.ID != enqueued[0].JobID {
		t.Fatalf("ClaimDue(new) = %+v, %v, %v", newJob, ok, err)
	}
	if err := runtime.Journal(newJob).Gate(t.Context(), adapter.Effect{}); err != nil {
		t.Fatalf("new job did not run after old fence released: %v", err)
	}
}

func TestCrashReservationReleaseIsGenerationFencedAndLeavesNoConflict(t *testing.T) {
	for _, kind := range []adapter.JobKind{adapter.Converge, adapter.Scrub} {
		t.Run(string(kind), func(t *testing.T) {
			db := adapterRuntimeDB(t)
			runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
			now := time.Now().UTC()
			oldJob, ok, err := runtime.ClaimDue(t.Context(), "worker_old", now, now.Add(adapter.LeaseTime))
			if err != nil || !ok {
				t.Fatalf("ClaimDue(old) = %+v, %v, %v", oldJob, ok, err)
			}
			effect := adapter.Effect{Surface: adapter.Secret, EffectiveName: "STALE", Disposition: adapter.Create}
			oldJournal := runtime.Journal(oldJob)
			if state, err := oldJournal.Reserve(t.Context(), effect); err != nil || state != adapter.Reserved {
				t.Fatalf("Reserve() = %q, %v", state, err)
			}

			// The same effective name on another destination proves the release is
			// scoped through the complete target and tenant chain.
			for _, statement := range []string{
				`INSERT INTO adapter_targets (id,org_id,project_id,environment_id,adapter_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,generation,state,sync_status,created_at) VALUES ('tgt_other','org_adapter','prj_adapter','env_adapter','adp_1','repository','acme','other',43,'',1,'active','converging','2026-08-17T00:00:00Z')`,
				`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_other','org_adapter','prj_adapter','env_adapter','tgt_other','https://git.example',43,'secret','STALE','STALE','reserved','2026-08-17T00:00:00Z')`,
			} {
				if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
					t.Fatal(err)
				}
			}

			newGoal, err := runtime.Enqueue(t.Context(), adapter.Job{
				OrgID: oldJob.OrgID, ProjectID: oldJob.ProjectID, EnvironmentID: oldJob.EnvironmentID,
				TargetID: oldJob.TargetID, Kind: kind, AuthorityPrincipal: oldJob.AuthorityPrincipal,
			}, now.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if err := oldJournal.ReleaseReservation(t.Context(), effect); !errors.Is(err, adapter.ErrSuperseded) {
				t.Fatalf("old generation ReleaseReservation() = %v, want superseded", err)
			}
			newJob, ok, err := runtime.ClaimDue(t.Context(), "worker_new", now.Add(2*time.Second), now.Add(2*time.Second).Add(adapter.LeaseTime))
			if err != nil || !ok || newJob.ID != newGoal.ID {
				t.Fatalf("ClaimDue(new) = %+v, %v, %v; goal=%+v", newJob, ok, err, newGoal)
			}
			newJournal := runtime.Journal(newJob)
			if err := newJournal.ReleaseReservation(t.Context(), adapter.Effect{Surface: adapter.Secret, EffectiveName: "STALE", Disposition: adapter.Delete}); err != nil {
				t.Fatal(err)
			}
			if err := runtime.Succeed(t.Context(), newJob, 0, now.Add(3*time.Second)); err != nil {
				t.Fatalf("Succeed(%s) = %v", kind, err)
			}

			var staleHere, staleOther, conflicts, effects int
			var jobState, targetStatus string
			queries := []struct {
				query string
				out   *int
			}{
				{`SELECT COUNT(*) FROM adapter_ledger WHERE target_id='tgt_1' AND normalized_name='STALE'`, &staleHere},
				{`SELECT COUNT(*) FROM adapter_ledger WHERE target_id='tgt_other' AND normalized_name='STALE' AND state='reserved'`, &staleOther},
				{`SELECT COUNT(*) FROM adapter_conflicts WHERE target_id='tgt_1'`, &conflicts},
				{`SELECT COUNT(*) FROM adapter_effects WHERE target_id='tgt_1'`, &effects},
			}
			for _, query := range queries {
				if err := db.SQLiteRead().QueryRowContext(t.Context(), query.query).Scan(query.out); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_outbox WHERE id=?`, newJob.ID).Scan(&jobState); err != nil {
				t.Fatal(err)
			}
			if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT sync_status FROM adapter_targets WHERE id='tgt_1'`).Scan(&targetStatus); err != nil {
				t.Fatal(err)
			}
			if staleHere != 0 || staleOther != 1 || conflicts != 0 || effects != 0 || jobState != "succeeded" || targetStatus != "converged" {
				t.Fatalf("stale=%d other=%d conflicts=%d effects=%d job=%q target=%q", staleHere, staleOther, conflicts, effects, jobState, targetStatus)
			}
		})
	}
}

func TestReservationReleaseCannotDropOwnedOrDispatchedCustody(t *testing.T) {
	db := adapterRuntimeDB(t)
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	now := time.Now().UTC()
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_1", now, now.Add(adapter.LeaseTime))
	if err != nil || !ok {
		t.Fatalf("ClaimDue() = %+v, %v, %v", job, ok, err)
	}
	journal := runtime.Journal(job)
	for _, row := range []struct {
		name  string
		state adapter.LedgerState
	}{{"OWNED", adapter.Owned}, {"DISPATCHED", adapter.Dispatched}} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, "led_"+strings.ToLower(row.name), job.OrgID, job.ProjectID, job.EnvironmentID, job.TargetID, "https://git.example", 42, "secret", row.name, row.name, string(row.state), "2026-08-17T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
		if err := journal.ReleaseReservation(t.Context(), adapter.Effect{Surface: adapter.Secret, EffectiveName: row.name, Disposition: adapter.Delete}); !errors.Is(err, adapter.ErrSuperseded) {
			t.Fatalf("ReleaseReservation(%s) = %v, want exact-state refusal", row.state, err)
		}
	}
	var retained, conflicts int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_ledger WHERE target_id='tgt_1' AND normalized_name IN ('OWNED','DISPATCHED')`).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_conflicts WHERE target_id='tgt_1'`).Scan(&conflicts); err != nil {
		t.Fatal(err)
	}
	if retained != 2 || conflicts != 0 {
		t.Fatalf("retained=%d conflicts=%d", retained, conflicts)
	}
}

func TestAdapterFinishPreservesConcurrentReleasedCustody(t *testing.T) {
	db := adapterRuntimeDB(t)
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	now := time.Now().UTC()
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_1", now, now.Add(adapter.LeaseTime))
	if err != nil || !ok {
		t.Fatalf("ClaimDue() = %+v, %v, %v", job, ok, err)
	}
	effect := adapter.Effect{Surface: adapter.Secret, EffectiveName: "TOKEN", Disposition: adapter.Create}
	journal := runtime.Journal(job)
	state, err := journal.Reserve(t.Context(), effect)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Prepare(t.Context(), effect, state); err != nil {
		t.Fatal(err)
	}
	// This models a teardown release winning after the request crossed the
	// provider boundary. Finish must retain the custody decision while still
	// recording the provider outcome and releasing only its exact fence.
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_targets SET generation=2 WHERE id='tgt_1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_ledger SET state='released' WHERE target_id='tgt_1' AND normalized_name='TOKEN'`); err != nil {
		t.Fatal(err)
	}
	if err := journal.Finish(t.Context(), effect, adapter.Completion{Outcome: "success", State: adapter.Owned}); err != nil {
		t.Fatal(err)
	}
	var ledgerState, outcome string
	var lease any
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_ledger WHERE target_id='tgt_1' AND normalized_name='TOKEN'`).Scan(&ledgerState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT outcome FROM adapter_effects WHERE job_id='job_1'`).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT provider_lease_job_id FROM adapter_targets WHERE id='tgt_1'`).Scan(&lease); err != nil {
		t.Fatal(err)
	}
	if ledgerState != "released" || outcome != "success" || lease != nil {
		t.Fatalf("released race = ledger %q outcome %q lease %v", ledgerState, outcome, lease)
	}
}

func TestAdapterReserveRebindsReleasedHistoryToActivatedRoute(t *testing.T) {
	db := adapterRuntimeDB(t)
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_released','org_adapter','prj_adapter','env_adapter','tgt_1','https://git.old.example',7,'secret','TOKEN','TOKEN','released','2026-08-17T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapters SET origin='https://git.next.example' WHERE id='adp_1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_targets SET destination_id=84 WHERE id='tgt_1'`); err != nil {
		t.Fatal(err)
	}
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	now := time.Now().UTC()
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_rebind", now, now.Add(adapter.LeaseTime))
	if err != nil || !ok {
		t.Fatalf("ClaimDue() = %+v, %v, %v", job, ok, err)
	}
	state, err := runtime.Journal(job).Reserve(t.Context(), adapter.Effect{Surface: adapter.Secret, EffectiveName: "TOKEN", Disposition: adapter.Create})
	if err != nil || state != adapter.Reserved {
		t.Fatalf("Reserve() = %q, %v", state, err)
	}
	var origin, ledgerState string
	var destinationID int64
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT provider_origin,destination_id,state FROM adapter_ledger WHERE id='led_released'`).Scan(&origin, &destinationID, &ledgerState); err != nil {
		t.Fatal(err)
	}
	if origin != "https://git.next.example" || destinationID != 84 || ledgerState != "reserved" {
		t.Fatalf("reactivated ledger = %q/%d/%q", origin, destinationID, ledgerState)
	}
}

func TestAdapterJournalRejectsTerminalWriteAfterLeaseLoss(t *testing.T) {
	db := adapterRuntimeDB(t)
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	now := time.Now().UTC()
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_1", now, now.Add(adapter.LeaseTime))
	if err != nil || !ok {
		t.Fatal(err)
	}
	effect := adapter.Effect{Surface: adapter.Secret, EffectiveName: "TOKEN", Disposition: adapter.Create}
	journal := runtime.Journal(job)
	state, err := journal.Reserve(t.Context(), effect)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Prepare(t.Context(), effect, state); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_effects SET outcome='failure' WHERE job_id='job_1'`); err != nil {
		t.Fatal(err)
	}
	err = journal.Finish(t.Context(), effect, adapter.Completion{Outcome: "success", State: adapter.Owned})
	if err == nil {
		t.Fatal("Finish accepted a non-exclusive terminal transition")
	}
	var stateAfter string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_ledger WHERE target_id='tgt_1' AND normalized_name='TOKEN'`).Scan(&stateAfter); err != nil {
		t.Fatal(err)
	}
	if stateAfter != "dispatched" {
		t.Fatalf("atomic rollback lost dispatched claim: %q", stateAfter)
	}
}

func TestAdapterFinishJobRequiresExactLeaseAndGeneration(t *testing.T) {
	db := adapterRuntimeDB(t)
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	now := time.Now().UTC()
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_1", now, now.Add(adapter.LeaseTime))
	if err != nil || !ok {
		t.Fatal(err)
	}
	job.LeaseOwner = "other-worker"
	if err := runtime.Succeed(t.Context(), job, 3, now); !errors.Is(err, adapter.ErrSuperseded) {
		t.Fatalf("Succeed() = %v, want superseded", err)
	}
	var state string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_outbox WHERE id='job_1'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "running" {
		t.Fatalf("stale finisher changed job to %q", state)
	}
}

func TestAdapterEnqueueSupersedesAndBumpsGenerationAtomically(t *testing.T) {
	db := adapterRuntimeDB(t)
	runtime := store.NewAdapterRuntime(db, nil)
	now := time.Now().UTC()
	newJob, err := runtime.Enqueue(t.Context(), adapter.Job{
		OrgID: "org_adapter", ProjectID: "prj_adapter", EnvironmentID: "env_adapter", TargetID: "tgt_1",
		Kind: adapter.Converge, AuthorityPrincipal: "usr_adapter",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	var oldState, activeJob string
	var generation int64
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_outbox WHERE id='job_1'`).Scan(&oldState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT generation,active_job_id FROM adapter_targets WHERE id='tgt_1'`).Scan(&generation, &activeJob); err != nil {
		t.Fatal(err)
	}
	if oldState != "superseded" || generation != 2 || activeJob != newJob.ID || newJob.Generation != 2 {
		t.Fatalf("old=%q generation=%d active=%q job=%+v", oldState, generation, activeJob, newJob)
	}
	var superseded int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.superseded' AND json_extract(payload,'$.previous_job_id')='job_1' AND json_extract(payload,'$.job_id')=?`, newJob.ID).Scan(&superseded); err != nil {
		t.Fatal(err)
	}
	if superseded != 1 {
		t.Fatalf("superseded audit rows = %d", superseded)
	}
}

func TestAdapterDeadCredentialScrubTerminatesAndEnumeratesOrphans(t *testing.T) {
	db := adapterRuntimeDB(t)
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_outbox SET kind='scrub' WHERE id='job_1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_1','org_adapter','prj_adapter','env_adapter','tgt_1','https://git.example',42,'secret','TOKEN','TOKEN','owned','2026-08-17T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	runtime := store.NewAdapterRuntime(db, nil)
	now := time.Now().UTC()
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_1", now, now.Add(adapter.LeaseTime))
	if err != nil || !ok {
		t.Fatalf("ClaimDue() = %+v, %v, %v", job, ok, err)
	}
	if _, err := runtime.LoadExecution(t.Context(), job); !errors.Is(err, adapter.ErrProviderAuth) {
		t.Fatalf("LoadExecution() = %v, want terminal provider auth for revoked credential", err)
	}
	if err := runtime.Fail(t.Context(), job, now, adapter.ErrProviderAuth); err != nil {
		t.Fatal(err)
	}
	var targetState, syncStatus, failureNames, outcome, payload string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state,sync_status,failure_names FROM adapter_targets WHERE id='tgt_1'`).Scan(&targetState, &syncStatus, &failureNames); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT outcome,payload FROM audit_tenant_events WHERE type='adapter.scrub' AND correlation_id='job_1'`).Scan(&outcome, &payload); err != nil {
		t.Fatal(err)
	}
	var ledgerState string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_ledger WHERE target_id='tgt_1'`).Scan(&ledgerState); err != nil {
		t.Fatal(err)
	}
	if targetState != "tombstoned" || syncStatus != "failed" || failureNames != `["secret:TOKEN"]` || outcome != "failure" || payload != `{"orphaned":["secret:TOKEN"]}` || ledgerState != "released" {
		t.Fatalf("target=%q status=%q failures=%s audit=%q %s ledger=%q", targetState, syncStatus, failureNames, outcome, payload, ledgerState)
	}
}

func TestAdapterEnqueueWaitsForProviderWriteFence(t *testing.T) {
	db := adapterRuntimeDB(t)
	runtime := store.NewAdapterRuntime(db, nil)
	future := time.Now().UTC().Add(time.Minute).Format("2006-01-02T15:04:05.000000Z")
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_targets SET provider_lease_job_id='job_1',provider_lease_effect_id='effect_1',provider_lease_expires_at=? WHERE id='tgt_1'`, future); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err := runtime.Enqueue(ctx, adapter.Job{
		OrgID: "org_adapter", ProjectID: "prj_adapter", EnvironmentID: "env_adapter", TargetID: "tgt_1",
		Kind: adapter.Scrub, AuthorityPrincipal: "usr_adapter",
	}, time.Now().UTC())
	if !errors.Is(err, adapter.ErrProviderBusy) {
		t.Fatalf("Enqueue() = %v, want provider busy", err)
	}
	var generation int64
	var state string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT generation,state FROM adapter_targets WHERE id='tgt_1'`).Scan(&generation, &state); err != nil {
		t.Fatal(err)
	}
	if generation != 1 || state != "active" {
		t.Fatalf("busy enqueue crossed fence: generation=%d state=%q", generation, state)
	}
}

func TestAdapterEnqueueClearsExpiredProviderWriteFence(t *testing.T) {
	db := adapterRuntimeDB(t)
	runtime := store.NewAdapterRuntime(db, nil)
	now := time.Now().UTC()
	past := now.Add(-time.Minute).Format("2006-01-02T15:04:05.000000Z")
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_targets SET provider_lease_job_id='crashed',provider_lease_effect_id='effect_1',provider_lease_expires_at=? WHERE id='tgt_1'`, past); err != nil {
		t.Fatal(err)
	}
	job, err := runtime.Enqueue(t.Context(), adapter.Job{
		OrgID: "org_adapter", ProjectID: "prj_adapter", EnvironmentID: "env_adapter", TargetID: "tgt_1",
		Kind: adapter.Converge, AuthorityPrincipal: "usr_adapter",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	var lease any
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT provider_lease_job_id FROM adapter_targets WHERE id='tgt_1'`).Scan(&lease); err != nil {
		t.Fatal(err)
	}
	if lease != nil || job.Generation != 2 {
		t.Fatalf("expired fence not cleared: lease=%v job=%+v", lease, job)
	}
}

func TestAdapterClaimDueReplaysExpiredLeaseOnly(t *testing.T) {
	db := adapterRuntimeDB(t)
	runtime := store.NewAdapterRuntime(db, nil)
	now := time.Now().UTC()
	first, ok, err := runtime.ClaimDue(t.Context(), "worker_1", now, now.Add(time.Minute))
	if err != nil || !ok {
		t.Fatal(err)
	}
	if _, ok, err := runtime.ClaimDue(t.Context(), "worker_2", now.Add(30*time.Second), now.Add(90*time.Second)); err != nil || ok {
		t.Fatalf("live lease was reclaimed: ok=%v err=%v", ok, err)
	}
	replay, ok, err := runtime.ClaimDue(t.Context(), "worker_2", now.Add(61*time.Second), now.Add(2*time.Minute))
	if err != nil || !ok {
		t.Fatalf("expired lease was not replayed: ok=%v err=%v", ok, err)
	}
	if replay.ID != first.ID || replay.Attempt != 2 || replay.LeaseOwner != "worker_2" {
		t.Fatalf("replay=%+v first=%+v", replay, first)
	}
}

func TestAdapterGateRechecksAuthorityAndGeneration(t *testing.T) {
	db := adapterRuntimeDB(t)
	authorized := true
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error {
		if !authorized {
			return errors.New("revoked")
		}
		return nil
	})
	now := time.Now().UTC()
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_1", now, now.Add(adapter.LeaseTime))
	if err != nil || !ok {
		t.Fatal(err)
	}
	journal := runtime.Journal(job)
	effect := adapter.Effect{Surface: adapter.Secret, EffectiveName: "TOKEN", Disposition: adapter.Update}
	if err := journal.Gate(t.Context(), effect); err != nil {
		t.Fatal(err)
	}
	authorized = false
	if err := journal.Gate(t.Context(), effect); !errors.Is(err, adapter.ErrUnauthorized) {
		t.Fatalf("revoked authority Gate() = %v", err)
	}
	authorized = true
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_targets SET generation=2 WHERE id='tgt_1'`); err != nil {
		t.Fatal(err)
	}
	if err := journal.Gate(t.Context(), effect); !errors.Is(err, adapter.ErrSuperseded) {
		t.Fatalf("stale generation Gate() = %v", err)
	}
}

func TestAdapterClaimDueSingleFlightsTargetAndCapsOrganizationAtFour(t *testing.T) {
	db := adapterRuntimeDB(t)
	now := time.Now().UTC()
	stamp := now.Add(-time.Minute).Format("2006-01-02T15:04:05.000000Z")
	// A corrupt/legacy alternate dedup key cannot bypass claim-time target
	// single-flight. The closed enqueue path never creates this shape.
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,authority_principal_id,generation,dedup_key,next_attempt_at,state,created_at) VALUES ('job_same','org_adapter','prj_adapter','env_adapter','tgt_1','converge','usr_adapter',1,'legacy-other-key',?,'queued',?)`, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	for i := 2; i <= 5; i++ {
		env := "env_adapter_" + string(rune('0'+i))
		target := "tgt_" + string(rune('0'+i))
		job := "job_" + string(rune('0'+i))
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO environments (id,org_id,project_id,name,note,created_at,display_order) VALUES (?,'org_adapter','prj_adapter',?,'',?,?)`, env, env, stamp, i); err != nil {
			t.Fatal(err)
		}
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO adapter_targets (id,org_id,project_id,environment_id,adapter_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,generation,state,sync_status,active_job_id,created_at) VALUES (?,'org_adapter','prj_adapter',?,'adp_1','repository','acme',?,?,'',1,'active','converging',?,?)`, target, env, target, 40+i, job, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,authority_principal_id,generation,dedup_key,next_attempt_at,state,created_at) VALUES (?,'org_adapter','prj_adapter',?,?,'converge','usr_adapter',1,?,?,'queued',?)`, job, env, target, target, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	runtime := store.NewAdapterRuntime(db, nil)
	claimedTargets := map[string]bool{}
	for i := 0; i < 4; i++ {
		job, ok, err := runtime.ClaimDue(t.Context(), "worker_"+string(rune('0'+i)), now, now.Add(time.Minute))
		if err != nil || !ok {
			t.Fatalf("claim %d: ok=%v err=%v", i, ok, err)
		}
		if claimedTargets[job.TargetID] {
			t.Fatalf("target %s claimed twice", job.TargetID)
		}
		claimedTargets[job.TargetID] = true
	}
	if _, ok, err := runtime.ClaimDue(t.Context(), "worker_5", now, now.Add(time.Minute)); err != nil || ok {
		t.Fatalf("fifth org claim: ok=%v err=%v", ok, err)
	}
}

func TestAdapterPlanArtifactAdoptionIsBoundAndAtomic(t *testing.T) {
	db := adapterRuntimeDB(t)
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_adapter','usr_adapter','manage-adapters','org_adapter','prj_adapter',NULL,'2026-08-17T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scope := domain.Scope{Org: "org_adapter", Project: "prj_adapter"}
	entry := store.AdapterConflictEntry{Surface: "secret", EffectiveName: "TOKEN"}
	if err := storetx.Write(t.Context(), db, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: "usr_adapter"}, authz.OpAdapterPlan, scope)
		if err != nil {
			return err
		}
		return repos.Adapters().RecordPlan(ctx, p, "tgt_1", "plan_1", 1, 42, []store.AdapterConflictEntry{entry}, now)
	}); err != nil {
		t.Fatal(err)
	}
	var result store.AdapterAdoptionResult
	if err := storetx.Write(t.Context(), db, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: "usr_adapter"}, authz.OpAdapterAdopt, scope)
		if err != nil {
			return err
		}
		result, err = repos.Adapters().Adopt(ctx, p, store.AdapterAdoption{
			TargetID: "tgt_1", ArtifactID: "plan_1", Entries: []store.AdapterConflictEntry{entry},
			AuthorityPrincipalID: "usr_adapter", LedgerIDs: []string{"led_adopt"}, JobID: "job_adopt", AuditAt: now,
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var generation int64
	var oldState, newState, ledgerState string
	var adoptedAt any
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT generation FROM adapter_targets WHERE id='tgt_1'`).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_outbox WHERE id='job_1'`).Scan(&oldState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_outbox WHERE id='job_adopt'`).Scan(&newState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_ledger WHERE id='led_adopt'`).Scan(&ledgerState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT adopted_at FROM adapter_conflicts WHERE artifact_id='plan_1'`).Scan(&adoptedAt); err != nil {
		t.Fatal(err)
	}
	if result.Generation != 2 || result.SupersededJobID != "job_1" || generation != 2 || oldState != "superseded" || newState != "queued" || ledgerState != "owned" || adoptedAt == nil {
		t.Fatalf("result=%+v generation=%d jobs=%q/%q ledger=%q adopted=%v", result, generation, oldState, newState, ledgerState, adoptedAt)
	}
}

func TestAdapterAdoptionRefusesStaleArtifactAndLiveProviderFence(t *testing.T) {
	tests := []struct {
		name   string
		mutate string
		want   error
	}{
		{name: "generation changed", mutate: `UPDATE adapter_targets SET generation=2 WHERE id='tgt_1'`, want: store.ErrConflict},
		{name: "destination changed", mutate: `UPDATE adapter_targets SET destination_id=99 WHERE id='tgt_1'`, want: store.ErrConflict},
		{name: "provider request active", mutate: `UPDATE adapter_targets SET provider_lease_job_id='job_1',provider_lease_effect_id='effect_1',provider_lease_expires_at='2999-01-01T00:00:00Z' WHERE id='tgt_1'`, want: adapter.ErrProviderBusy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := adapterRuntimeDB(t)
			if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_adapter','usr_adapter','manage-adapters','org_adapter','prj_adapter',NULL,'2026-08-17T00:00:00Z')`); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			scope := domain.Scope{Org: "org_adapter", Project: "prj_adapter"}
			entry := store.AdapterConflictEntry{Surface: "secret", EffectiveName: "TOKEN"}
			if err := storetx.Write(t.Context(), db, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
				p, err := az.Authorize(ctx, authz.Identity{Principal: "usr_adapter"}, authz.OpAdapterPlan, scope)
				if err != nil {
					return err
				}
				return repos.Adapters().RecordPlan(ctx, p, "tgt_1", "plan_stale", 1, 42, []store.AdapterConflictEntry{entry}, now)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.SQLiteWrite().ExecContext(t.Context(), tt.mutate); err != nil {
				t.Fatal(err)
			}
			err := storetx.Write(t.Context(), db, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
				p, err := az.Authorize(ctx, authz.Identity{Principal: "usr_adapter"}, authz.OpAdapterAdopt, scope)
				if err != nil {
					return err
				}
				_, err = repos.Adapters().Adopt(ctx, p, store.AdapterAdoption{TargetID: "tgt_1", ArtifactID: "plan_stale", Entries: []store.AdapterConflictEntry{entry}, AuthorityPrincipalID: "usr_adapter", LedgerIDs: []string{"led_stale"}, JobID: "job_stale", AuditAt: now})
				return err
			})
			if !errors.Is(err, tt.want) {
				t.Fatalf("Adopt() = %v, want %v", err, tt.want)
			}
			var rows int
			if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_ledger WHERE id='led_stale'`).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			if rows != 0 {
				t.Fatal("refused adoption leaked ownership")
			}
		})
	}
}

func TestAdapterAdoptionClearsExpiredProviderFence(t *testing.T) {
	db := adapterRuntimeDB(t)
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_adapter','usr_adapter','manage-adapters','org_adapter','prj_adapter',NULL,'2026-08-17T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_targets SET provider_lease_job_id='job_1',provider_lease_effect_id='effect_1',provider_lease_expires_at=? WHERE id='tgt_1'`, now.Add(-time.Minute).Format("2006-01-02T15:04:05.000000Z")); err != nil {
		t.Fatal(err)
	}
	scope := domain.Scope{Org: "org_adapter", Project: "prj_adapter"}
	entry := store.AdapterConflictEntry{Surface: "secret", EffectiveName: "TOKEN"}
	if err := storetx.Write(t.Context(), db, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: "usr_adapter"}, authz.OpAdapterPlan, scope)
		if err != nil {
			return err
		}
		return repos.Adapters().RecordPlan(ctx, p, "tgt_1", "plan_expired", 1, 42, []store.AdapterConflictEntry{entry}, now)
	}); err != nil {
		t.Fatal(err)
	}
	if err := storetx.Write(t.Context(), db, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: "usr_adapter"}, authz.OpAdapterAdopt, scope)
		if err != nil {
			return err
		}
		_, err = repos.Adapters().Adopt(ctx, p, store.AdapterAdoption{TargetID: "tgt_1", ArtifactID: "plan_expired", Entries: []store.AdapterConflictEntry{entry}, AuthorityPrincipalID: "usr_adapter", LedgerIDs: []string{"led_expired"}, JobID: "job_expired", AuditAt: now})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var lease any
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT provider_lease_job_id FROM adapter_targets WHERE id='tgt_1'`).Scan(&lease); err != nil {
		t.Fatal(err)
	}
	if lease != nil {
		t.Fatalf("expired provider fence survived adoption: %v", lease)
	}
}

func TestAdapterConcurrentAdoptionHasOneWinner(t *testing.T) {
	db := adapterRuntimeDB(t)
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_adapter','usr_adapter','manage-adapters','org_adapter','prj_adapter',NULL,'2026-08-17T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scope := domain.Scope{Org: "org_adapter", Project: "prj_adapter"}
	entry := store.AdapterConflictEntry{Surface: "secret", EffectiveName: "TOKEN"}
	if err := storetx.Write(t.Context(), db, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: "usr_adapter"}, authz.OpAdapterPlan, scope)
		if err != nil {
			return err
		}
		return repos.Adapters().RecordPlan(ctx, p, "tgt_1", "plan_race", 1, 42, []store.AdapterConflictEntry{entry}, now)
	}); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs <- storetx.Write(t.Context(), db, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
				p, err := az.Authorize(ctx, authz.Identity{Principal: "usr_adapter"}, authz.OpAdapterAdopt, scope)
				if err != nil {
					return err
				}
				_, err = repos.Adapters().Adopt(ctx, p, store.AdapterAdoption{TargetID: "tgt_1", ArtifactID: "plan_race", Entries: []store.AdapterConflictEntry{entry}, AuthorityPrincipalID: "usr_adapter", LedgerIDs: []string{fmt.Sprintf("led_race_%d", i)}, JobID: fmt.Sprintf("job_race_%d", i), AuditAt: now})
				return err
			})
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		} else if !errors.Is(err, store.ErrConflict) {
			t.Fatalf("race loser = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful adoptions = %d, want one", successes)
	}
}
