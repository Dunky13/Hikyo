package isolation

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

const auditAdapterEffectiveName = "AUDIT_SHARED_KEY"

// auditAdapterModule is the provider-side test double for the audit-core
// acceptance lifecycle. Configuration, planning, adoption, job ownership and
// audit writes still traverse the real service/store/runtime boundaries; only
// the external Forgejo HTTP peer is replaced.
type auditAdapterModule struct{}

func (auditAdapterModule) ValidateConfig(adapter.Config) error { return nil }

func (auditAdapterModule) TestConnection(ctx context.Context, request adapter.ConnectionRequest) (adapter.Connection, error) {
	for range 2 {
		if err := request.Gate(ctx); err != nil {
			return adapter.Connection{}, err
		}
	}
	return adapter.Connection{Version: "1.21.11", DestinationID: 65_001}, nil
}

func (auditAdapterModule) Plan(ctx context.Context, request adapter.PlanRequest) (adapter.Plan, error) {
	if err := request.Gate(ctx); err != nil {
		return adapter.Plan{}, err
	}
	return adapter.Plan{Changes: []adapter.Change{{
		Surface: adapter.Variable, EffectiveName: auditAdapterEffectiveName, Disposition: adapter.Conflict,
	}}}, nil
}

func (auditAdapterModule) Sync(ctx context.Context, _ adapter.SyncRequest, journal adapter.Journal) (adapter.SyncResult, error) {
	effect := adapter.Effect{
		Surface: adapter.Variable, EffectiveName: auditAdapterEffectiveName,
		Disposition: adapter.Update, KeyID: keyA1,
	}
	prior, err := journal.Reserve(ctx, effect)
	if err != nil {
		return adapter.SyncResult{}, err
	}
	if err := journal.Prepare(ctx, effect, prior); err != nil {
		return adapter.SyncResult{}, err
	}
	if err := journal.Gate(ctx, effect); err != nil {
		finishErr := journal.Finish(ctx, effect, adapter.Completion{Outcome: "failure", State: prior})
		if finishErr != nil {
			return adapter.SyncResult{}, finishErr
		}
		return adapter.SyncResult{}, err
	}
	if err := journal.Finish(ctx, effect, adapter.Completion{Outcome: "success", State: adapter.Owned}); err != nil {
		return adapter.SyncResult{}, err
	}
	return adapter.SyncResult{Changes: []adapter.Change{{
		Surface: adapter.Variable, EffectiveName: auditAdapterEffectiveName, Disposition: adapter.Update,
	}}}, nil
}

type auditAdapterLoader struct{}

func (auditAdapterLoader) Load(context.Context, adapter.Job, adapter.Journal) (adapter.LoadedSync, error) {
	return adapter.LoadedSync{Module: auditAdapterModule{}, Revision: 1}, nil
}

func runAdapterAuditLifecycle(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := tctx(t)
	// AdapterRuntime.Gate checks the provider lease against the real clock.
	// Keep this integration fixture on that clock too: a fixed timestamp turns
	// the claimed lease stale as soon as wall time passes the fixture date.
	now := store.CanonTime(time.Now().UTC())
	scope := domain.Scope{Org: orgA, Project: prjA1}

	// Fixture authority only. Every adapter mutation and every corresponding
	// audit write below goes through the public service or runtime seam.
	execRaw(t, db, `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('g_audit_adapter_manage','usr_alice','manage-adapters','org_a','prj_a1',NULL,`+ts+`)`)
	execRaw(t, db, `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('g_audit_adapter_reveal','usr_alice','reveal','org_a','prj_a1','env_a1',`+ts+`)`)

	svc := &service.Adapters{
		DB: db, Keyring: probeKeyring(t, db), Now: func() time.Time { return now },
		ModuleFactory: func(adapter.Provider, adapter.Config, string) (*adapter.ModuleLease, error) {
			return adapter.NewModuleLease(auditAdapterModule{}, func() {})
		},
	}
	created, err := svc.Create(ctx, service.LocalPrincipal(alice), scope, service.CreateAdapterRequest{
		Origin: "https://audit-forgejo.example", Credential: []byte("audit-provider-token"),
		Target: service.AdapterTargetInput{
			EnvironmentID: string(envA1), DestinationKind: string(adapter.Repository),
			DestinationOwner: "audit", DestinationName: "project", NamePrefix: "AUDIT_", KeyIDs: []string{keyA1},
		},
	})
	if err != nil {
		t.Fatalf("adapter audit create: %v", err)
	}
	adapterID := created.Adapter.ID
	target := created.Targets[0]

	if _, err := svc.Get(ctx, service.LocalPrincipal(alice), scope, adapterID); err != nil {
		t.Fatalf("adapter audit inspect: %v", err)
	}
	if _, err := svc.TestTarget(ctx, service.LocalPrincipal(alice), scope, target.ID); err != nil {
		t.Fatalf("adapter audit test: %v", err)
	}
	planned, err := svc.Plan(ctx, service.LocalPrincipal(alice), scope, target.ID)
	if err != nil {
		t.Fatalf("adapter audit plan: %v", err)
	}
	if planned.ArtifactID == "" {
		t.Fatal("adapter audit plan did not persist its conflict artifact")
	}
	adopted, err := svc.Adopt(ctx, service.LocalPrincipal(alice), scope, service.AdoptAdapterRequest{
		TargetID: target.ID, ArtifactID: planned.ArtifactID,
		ExpectedGeneration: target.Generation, ExpectedDestinationID: target.DestinationID,
		Entries: []store.AdapterConflictEntry{{Surface: string(adapter.Variable), EffectiveName: auditAdapterEffectiveName}},
	})
	if err != nil {
		t.Fatalf("adapter audit adopt: %v", err)
	}
	if _, err := svc.SyncTarget(ctx, service.LocalPrincipal(alice), scope, target.ID); err != nil {
		t.Fatalf("adapter audit sync request: %v", err)
	}

	authorizePush := func(ctx context.Context, job adapter.Job, _ adapter.Effect) error {
		return tx.Read(ctx, db, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
			_, err := az.Authorize(ctx, authz.Identity{Principal: domain.PrincipalID(job.AuthorityPrincipal), Class: domain.ClassHuman}, authz.OpAdapterPush, domain.Scope{
				Org: domain.OrgID(job.OrgID), Project: domain.ProjectID(job.ProjectID), Env: domain.EnvID(job.EnvironmentID),
			})
			return err
		})
	}
	runtime := store.NewAdapterRuntime(db, authorizePush)
	worker := &adapter.Worker{
		Store: runtime, Loader: auditAdapterLoader{}, ID: "audit-adapter-worker",
		Now: func() time.Time { return now.Add(time.Second) }, Jitter: func(time.Duration) time.Duration { return 0 },
	}
	worked, err := worker.RunOnce(ctx)
	if err != nil || !worked {
		t.Fatalf("adapter audit converge: worked=%t err=%v", worked, err)
	}

	if _, err := svc.ReplaceCredential(ctx, service.LocalPrincipal(alice), scope, adapterID, []byte("replacement-provider-token")); err != nil {
		t.Fatalf("adapter audit credential replace: %v", err)
	}
	if _, err := svc.SyncTarget(ctx, service.LocalPrincipal(alice), scope, target.ID); err != nil {
		t.Fatalf("adapter audit abort setup: %v", err)
	}
	deniedRuntime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error {
		return adapter.ErrUnauthorized
	})
	deniedWorker := &adapter.Worker{
		Store: deniedRuntime, Loader: auditAdapterLoader{}, ID: "audit-adapter-denied-worker",
		Now: func() time.Time { return now.Add(2 * time.Second) }, Jitter: func(time.Duration) time.Duration { return 0 },
	}
	worked, err = deniedWorker.RunOnce(ctx)
	if err != nil || !worked {
		t.Fatalf("adapter audit abort: worked=%t err=%v", worked, err)
	}

	removed, err := svc.RemoveTarget(ctx, service.LocalPrincipal(alice), scope, target.ID, true)
	if err != nil {
		t.Fatalf("adapter audit keep-remote removal: %v", err)
	}
	if len(removed.Orphaned) != 1 || removed.Orphaned[0] != string(adapter.Variable)+":"+auditAdapterEffectiveName {
		t.Fatalf("adapter audit keep-remote orphans = %v", removed.Orphaned)
	}
	if _, err := svc.RevokeCredential(ctx, service.LocalPrincipal(alice), scope, adapterID); err != nil {
		t.Fatalf("adapter audit credential revoke: %v", err)
	}
	// The CLI/browser handoff is part of #65's adapter surface. An invalid
	// start exercises its rollback-surviving failure settlement without
	// introducing a second factor-account fixture into the audit-core suite.
	if _, err := (&service.Auth{DB: db}).StartCLIReauth(ctx, "", service.ReauthIntent{}, "invalid", "invalid"); err == nil {
		t.Fatal("invalid CLI reauthentication handoff start succeeded")
	}

	for _, typ := range []string{
		"adapter.abort", "adapter.adopt", "adapter.configure", "adapter.credential_replace",
		"adapter.credential_revoke", "adapter.inspect", "adapter.key_delivered", "adapter.plan",
		"adapter.push_intent", "adapter.push_outcome", "adapter.scrub", "adapter.superseded",
		"adapter.sync_requested", "adapter.test",
	} {
		if got := queryInt(t, db, fmt.Sprintf("SELECT COUNT(*) FROM audit_tenant_events WHERE type='%s'", typ)); got == 0 {
			t.Errorf("adapter audit lifecycle did not emit %s", typ)
		}
	}
	if adopted.JobID == "" {
		t.Fatal("adapter audit adoption did not enqueue its converge job")
	}
}
