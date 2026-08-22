package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/keyring"
	"github.com/Hikyo-Org/hikyo/internal/store/migrate"
	storetx "github.com/Hikyo-Org/hikyo/internal/store/tx"
)

func adapterCLISession(t *testing.T, db *store.DB) string {
	t.Helper()
	value, verifier, err := crypto.NewArtifact(crypto.ArtifactCLISession)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	err = storetx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		return az.MintSession(ctx, authz.NewSession{
			ID: "ses_adapter", PrincipalID: "usr_adapter", Verifier: verifier,
			Artifact: "cli", SessionGeneration: 1, CredentialEpoch: 1,
			AuthMethod: "local-password", Factors: `["password","totp"]`,
			AuthenticatedAt: now, CreatedAt: now, IdleExpiresAt: now.Add(time.Hour),
			AbsoluteExpiresAt: now.Add(24 * time.Hour), SourceIP: "127.0.0.1", UserAgent: "test",
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func adapterServiceDB(t *testing.T) *store.DB {
	t.Helper()
	cfg := store.Config{Engine: store.EngineSQLite, Path: filepath.Join(t.TempDir(), "adapter-service.db")}
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
		`INSERT INTO environments (id,org_id,project_id,name,note,created_at,display_order) VALUES ('env_one','org_adapter','prj_adapter','one','','2026-08-17T00:00:00Z',0)`,
		`INSERT INTO environments (id,org_id,project_id,name,note,created_at,display_order) VALUES ('env_two','org_adapter','prj_adapter','two','','2026-08-17T00:00:00Z',1)`,
		`INSERT INTO principals (id,kind,created_at) VALUES ('usr_adapter','human','2026-08-17T00:00:00Z')`,
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_manage','usr_adapter','manage-adapters','org_adapter','prj_adapter',NULL,'2026-08-17T00:00:00Z')`,
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_reveal_one','usr_adapter','reveal','org_adapter','prj_adapter','env_one','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapters (id,org_id,project_id,provider,origin,authority_principal_id,state,created_at) VALUES ('adp_1','org_adapter','prj_adapter','forgejo','https://git.example','usr_adapter','active','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_targets (id,org_id,project_id,environment_id,adapter_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,generation,state,sync_status,created_at) VALUES ('tgt_one','org_adapter','prj_adapter','env_one','adp_1','repository','acme','app',42,'ONE_',1,'active','failed','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_targets (id,org_id,project_id,environment_id,adapter_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,generation,state,sync_status,created_at) VALUES ('tgt_two','org_adapter','prj_adapter','env_two','adp_1','repository','acme','app',42,'TWO_',1,'active','converged','2026-08-17T00:00:00Z')`,
	}
	for _, statement := range statements {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

type fakeAdapterPlanModule struct{ plan adapter.Plan }

func testModuleFactory(factory func(adapter.Provider, string, string) (adapter.Module, func(), error)) adapter.ModuleFactory {
	return func(provider adapter.Provider, config adapter.Config, credential string) (*adapter.ModuleLease, error) {
		module, release, err := factory(provider, config.Origin, credential)
		if err != nil {
			if release != nil {
				release()
			}
			return nil, err
		}
		return adapter.NewModuleLease(module, release)
	}
}

func providerBlindTestModuleFactory(factory func(string, string) (adapter.Module, func(), error)) adapter.ModuleFactory {
	return testModuleFactory(func(_ adapter.Provider, origin, credential string) (adapter.Module, func(), error) {
		return factory(origin, credential)
	})
}

func (m fakeAdapterPlanModule) ValidateConfig(adapter.Config) error { return nil }
func (m fakeAdapterPlanModule) TestConnection(context.Context, adapter.ConnectionRequest) (adapter.Connection, error) {
	return adapter.Connection{}, nil
}

type fakeAdapterTestModule struct {
	gates            *int
	credentialExpiry time.Time
}

func (fakeAdapterTestModule) ValidateConfig(adapter.Config) error { return nil }
func (m fakeAdapterTestModule) TestConnection(ctx context.Context, request adapter.ConnectionRequest) (adapter.Connection, error) {
	if err := request.Gate(ctx); err != nil {
		return adapter.Connection{}, err
	}
	*m.gates++
	if err := request.Gate(ctx); err != nil {
		return adapter.Connection{}, err
	}
	*m.gates++
	return adapter.Connection{Version: "1.21.11", DestinationID: request.Destination.NumericID, CredentialExpiresAt: m.credentialExpiry}, nil
}

type fakeAdapterConfigureModule struct {
	gates            *int
	err              error
	destinationID    int64
	credentialExpiry time.Time
}

type fakeEnvironmentConfigureModule struct{}

func (fakeEnvironmentConfigureModule) ValidateConfig(adapter.Config) error { return nil }
func (fakeEnvironmentConfigureModule) TestConnection(ctx context.Context, request adapter.ConnectionRequest) (adapter.Connection, error) {
	if request.BeforeEnvironmentCreate == nil || request.AfterEnvironmentCreate == nil {
		return adapter.Connection{}, errors.New("missing environment configure callbacks")
	}
	if err := request.Gate(ctx); err != nil {
		return adapter.Connection{}, err
	}
	if err := request.BeforeEnvironmentCreate(ctx); err != nil {
		return adapter.Connection{}, err
	}
	if err := request.AfterEnvironmentCreate(ctx, nil); err != nil {
		return adapter.Connection{}, err
	}
	return adapter.Connection{Version: "github-actions", DestinationID: 73, RepositoryID: 42}, nil
}
func (fakeEnvironmentConfigureModule) Plan(context.Context, adapter.PlanRequest) (adapter.Plan, error) {
	return adapter.Plan{}, nil
}
func (fakeEnvironmentConfigureModule) Sync(context.Context, adapter.SyncRequest, adapter.Journal) (adapter.SyncResult, error) {
	return adapter.SyncResult{}, nil
}

type fakeRoutingPreflightModule struct {
	seen *[]int64
	err  error
}

func (fakeRoutingPreflightModule) ValidateConfig(adapter.Config) error { return nil }
func (m fakeRoutingPreflightModule) TestConnection(_ context.Context, request adapter.ConnectionRequest) (adapter.Connection, error) {
	*m.seen = append([]int64(nil), request.Destination.SelectedRepositoryIDs...)
	if m.err != nil {
		return adapter.Connection{}, m.err
	}
	return adapter.Connection{Version: "github-actions", DestinationID: request.Destination.NumericID}, nil
}
func (fakeRoutingPreflightModule) Plan(context.Context, adapter.PlanRequest) (adapter.Plan, error) {
	return adapter.Plan{}, nil
}
func (fakeRoutingPreflightModule) Sync(context.Context, adapter.SyncRequest, adapter.Journal) (adapter.SyncResult, error) {
	return adapter.SyncResult{}, nil
}

func TestAdapterCreateAndAddTargetRefuseBeforeCredentialOrProviderWithoutCeremony(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		db := adapterServiceDB(t)
		bearer := adapterCLISession(t, db)
		providerCalls := 0
		svc := &Adapters{DB: db, Auth: &Auth{DB: db}, ModuleFactory: providerBlindTestModuleFactory(func(string, string) (adapter.Module, func(), error) {
			providerCalls++
			return fakeAdapterConfigureModule{gates: new(int)}, nil, nil
		})}
		_, err := svc.Create(t.Context(), Bearer(bearer), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, CreateAdapterRequest{
			Origin: "https://new.example", Credential: []byte("provider-token"),
			Target: AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "new", KeyIDs: []string{"key_create"}},
		})
		if !errors.Is(err, ErrReauthRequired) || providerCalls != 0 {
			t.Fatalf("Create() error=%v provider calls=%d", err, providerCalls)
		}
	})

	t.Run("add target", func(t *testing.T) {
		db := adapterServiceDB(t)
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_reveal_two_ceremony','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`); err != nil {
			t.Fatal(err)
		}
		bearer := adapterCLISession(t, db)
		providerCalls := 0
		svc := &Adapters{DB: db, Auth: &Auth{DB: db}, ModuleFactory: providerBlindTestModuleFactory(func(string, string) (adapter.Module, func(), error) {
			providerCalls++
			return fakeAdapterConfigureModule{gates: new(int)}, nil, nil
		})}
		_, err := svc.AddTarget(t.Context(), Bearer(bearer), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, "adp_1", AdapterTargetInput{
			EnvironmentID: "env_one", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "new", KeyIDs: []string{"key_create"},
		})
		if !errors.Is(err, ErrReauthRequired) || providerCalls != 0 {
			t.Fatalf("AddTarget() error=%v provider calls=%d", err, providerCalls)
		}
	})
}

func TestAdapterCreateRejectsUnknownProviderBeforeCredentialUse(t *testing.T) {
	factoryCalled := false
	svc := &Adapters{ModuleFactory: func(adapter.Provider, adapter.Config, string) (*adapter.ModuleLease, error) {
		factoryCalled = true
		return adapter.NewModuleLease(fakeAdapterPlanModule{}, nil)
	}}
	_, err := svc.Create(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, CreateAdapterRequest{
		Provider: "gitlab", Origin: "https://gitlab.example", Credential: []byte("provider-token"),
		Target: AdapterTargetInput{EnvironmentID: "env_one", KeyIDs: []string{"key_one"}},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown provider") {
		t.Fatalf("Create() = %v, want unknown provider refusal", err)
	}
	if factoryCalled {
		t.Fatal("unknown provider reached module factory")
	}
}

func (fakeAdapterConfigureModule) ValidateConfig(adapter.Config) error { return nil }
func (m fakeAdapterConfigureModule) TestConnection(ctx context.Context, request adapter.ConnectionRequest) (adapter.Connection, error) {
	if err := request.Gate(ctx); err != nil {
		return adapter.Connection{}, err
	}
	*m.gates++
	if err := request.Gate(ctx); err != nil {
		return adapter.Connection{}, err
	}
	*m.gates++
	if m.err != nil {
		return adapter.Connection{}, m.err
	}
	destinationID := m.destinationID
	if destinationID == 0 {
		destinationID = 77
	}
	return adapter.Connection{Version: "1.21.11", DestinationID: destinationID, CredentialExpiresAt: m.credentialExpiry}, nil
}
func (fakeAdapterConfigureModule) Plan(context.Context, adapter.PlanRequest) (adapter.Plan, error) {
	return adapter.Plan{}, nil
}
func (fakeAdapterConfigureModule) Sync(context.Context, adapter.SyncRequest, adapter.Journal) (adapter.SyncResult, error) {
	return adapter.SyncResult{}, nil
}

func TestAdapterCreateAtomicallyBootstrapsCredentialAndFirstTarget(t *testing.T) {
	db := adapterServiceDB(t)
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_create','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	root, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, root)
	if err != nil {
		t.Fatal(err)
	}
	gates := 0
	expires := time.Date(2026, 9, 30, 12, 34, 56, 0, time.UTC)
	svc := &Adapters{DB: db, Keyring: kr, ModuleFactory: providerBlindTestModuleFactory(func(origin, credential string) (adapter.Module, func(), error) {
		if origin != "https://new.example" || credential != "provider-token" {
			t.Fatalf("factory=%q/%q", origin, credential)
		}
		return fakeAdapterConfigureModule{gates: &gates, credentialExpiry: expires}, nil, nil
	})}
	view, err := svc.Create(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, CreateAdapterRequest{Origin: "https://new.example", Credential: []byte("provider-token"), Target: AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "new", NamePrefix: "PROD_", KeyIDs: []string{"key_create"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !view.Adapter.CredentialPresent || len(view.Targets) != 1 || view.Targets[0].DestinationID != 77 || gates != 2 {
		t.Fatalf("Create()=%+v gates=%d", view, gates)
	}
	storedExpiry, err := time.Parse(time.RFC3339Nano, view.Adapter.CredentialExpiresAt)
	if err != nil || !storedExpiry.Equal(expires) {
		t.Fatalf("credential expiry = %q (%v), want persisted provider metadata", view.Adapter.CredentialExpiresAt, err)
	}
	var stored []byte
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT credential_ciphertext FROM adapters WHERE id=?`, view.Adapter.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(stored) == "provider-token" || len(stored) == 0 {
		t.Fatal("credential was not envelope-encrypted")
	}
	var keys int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_target_keys WHERE target_id=? AND key_id='key_create'`, view.Targets[0].ID).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if keys != 1 {
		t.Fatalf("target keys=%d", keys)
	}
	shown, err := svc.Get(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, view.Adapter.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !shown.Adapter.CredentialPresent || len(shown.Targets) != 1 {
		t.Fatalf("Get()=%+v", shown)
	}
}

func TestEnvironmentCreatePersistsGenerationFenceAndCorrelatedAudit(t *testing.T) {
	db := adapterServiceDB(t)
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_env_create','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	root, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, root)
	if err != nil {
		t.Fatal(err)
	}
	svc := &Adapters{DB: db, Keyring: kr, ModuleFactory: testModuleFactory(func(provider adapter.Provider, _, _ string) (adapter.Module, func(), error) {
		if provider != adapter.GitHubActionsProvider {
			t.Fatalf("provider = %q, want persisted github-actions", provider)
		}
		return fakeEnvironmentConfigureModule{}, nil, nil
	})}
	view, err := svc.Create(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, CreateAdapterRequest{
		Provider: "github-actions", Origin: "https://api.github.com", Credential: []byte("github_pat_fine"),
		Target: AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "environment", DestinationOwner: "acme", DestinationName: "app", DestinationEnvironment: "production", KeyIDs: []string{"key_env_create"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	target := view.Targets[0]
	var generation int64
	var state, effectID string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT generation,state,effect_id FROM adapter_configure_fences WHERE target_id=?`, target.ID).Scan(&generation, &state, &effectID); err != nil {
		t.Fatal(err)
	}
	if generation != 1 || state != "succeeded" || effectID == "" {
		t.Fatalf("configure fence generation=%d state=%q effect=%q", generation, state, effectID)
	}
	var correlated int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events intent JOIN audit_tenant_events configured ON configured.id=intent.correlation_id WHERE intent.id=? AND intent.type='adapter.push_intent' AND intent.object_id=? AND configured.type='adapter.configure'`, effectID, target.ID).Scan(&correlated); err != nil {
		t.Fatal(err)
	}
	if correlated != 1 {
		t.Fatalf("correlated configure intent rows = %d", correlated)
	}
	var outcomes int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.push_outcome' AND correlation_id=(SELECT correlation_id FROM audit_tenant_events WHERE id=?) AND object_id=? AND outcome='success'`, effectID, target.ID).Scan(&outcomes); err != nil {
		t.Fatal(err)
	}
	if outcomes != 1 {
		t.Fatalf("correlated configure outcomes = %d", outcomes)
	}
}

func TestOrganizationSelectedRepositoryIDsAreVerifiedBeforeRoutingCommit(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_org_route','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_one','tgt_one','adp_1','key_org_route')`,
		`UPDATE adapters SET provider='github-actions' WHERE id='adp_1'`,
		`UPDATE adapter_targets SET destination_kind='organization',destination_name='',visibility='all' WHERE id='tgt_one'`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	root, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, root)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := kr.ForProject(t.Context(), "org_adapter", "prj_adapter")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.SealField(crypto.ProjectFieldAAD{OrgID: "org_adapter", ProjectID: "prj_adapter", OwnerTable: "adapters", OwnerRowID: "adp_1", FieldTag: "credential"}, []byte("github_pat_fine"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapters SET credential_ciphertext=?,credential_set_at='2026-08-17T00:00:00Z' WHERE id='adp_1'`, sealed); err != nil {
		t.Fatal(err)
	}
	seen := []int64{}
	svc := &Adapters{DB: db, Keyring: kr, ModuleFactory: testModuleFactory(func(provider adapter.Provider, _, _ string) (adapter.Module, func(), error) {
		if provider != adapter.GitHubActionsProvider {
			t.Fatalf("provider = %q", provider)
		}
		return fakeRoutingPreflightModule{seen: &seen}, nil, nil
	})}
	updated, err := svc.UpdateTarget(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, UpdateAdapterTargetRequest{
		TargetID: "tgt_one", ExpectedGeneration: 1,
		Target: AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "organization", DestinationOwner: "acme", Visibility: "selected", SelectedRepositoryIDs: []int64{11, 22}, NamePrefix: "ONE_", KeyIDs: []string{"key_org_route"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(seen, []int64{11, 22}) || !slices.Equal(updated.SelectedRepositoryIDs, []int64{11, 22}) {
		t.Fatalf("verified=%v stored=%v", seen, updated.SelectedRepositoryIDs)
	}
}

func TestAdapterRoutingStateRoundTripsFromStore(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO adapters (id,org_id,project_id,provider,origin,authority_principal_id,state,created_at) VALUES ('adp_github','org_adapter','prj_adapter','github-actions','https://api.github.com','usr_adapter','active','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_targets (id,org_id,project_id,environment_id,adapter_id,destination_kind,destination_owner,destination_name,destination_environment,destination_id,repository_id,visibility,selected_repository_ids,name_prefix,generation,state,sync_status,created_at) VALUES ('tgt_github','org_adapter','prj_adapter','env_one','adp_github','environment','acme','app','prod/blue',73,42,'','[]','',1,'active','never','2026-08-17T00:00:00Z')`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	view, err := (&Adapters{DB: db}).Get(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, "adp_github")
	if err != nil {
		t.Fatal(err)
	}
	target := view.Targets[0]
	if target.Provider != "github-actions" || target.DestinationEnvironment != "prod/blue" || target.DestinationID != 73 || target.RepositoryID != 42 {
		t.Fatalf("round-trip target = %+v", target)
	}
}

func TestAdapterTargetAddAuditsTransactionAuthorityTransition(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO environments (id,org_id,project_id,name,note,created_at,display_order) VALUES ('env_three','org_adapter','prj_adapter','three','','2026-08-17T00:00:00Z',2)`,
		`INSERT INTO principals (id,kind,created_at) VALUES ('usr_previous','human','2026-08-17T00:00:00Z')`,
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_add_reveal_two','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`,
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_add_reveal_three','usr_adapter','reveal','org_adapter','prj_adapter','env_three','2026-08-17T00:00:00Z')`,
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_add_authority','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`UPDATE adapters SET authority_principal_id='usr_previous' WHERE id='adp_1'`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	root, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, root)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := kr.ForProject(t.Context(), "org_adapter", "prj_adapter")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.SealField(crypto.ProjectFieldAAD{OrgID: "org_adapter", ProjectID: "prj_adapter", OwnerTable: "adapters", OwnerRowID: "adp_1", FieldTag: "credential"}, []byte("provider-token"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapters SET credential_ciphertext=?,credential_set_at='2026-08-17T00:00:00Z' WHERE id='adp_1'`, sealed); err != nil {
		t.Fatal(err)
	}
	expires := time.Date(2026, 10, 1, 2, 3, 4, 0, time.UTC)
	svc := &Adapters{DB: db, Keyring: kr, ModuleFactory: providerBlindTestModuleFactory(func(string, string) (adapter.Module, func(), error) {
		return fakeAdapterConfigureModule{gates: new(int), destinationID: 303, credentialExpiry: expires}, nil, nil
	})}
	target, err := svc.AddTarget(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, "adp_1", AdapterTargetInput{
		EnvironmentID: "env_three", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "next", NamePrefix: "THREE_", KeyIDs: []string{"key_add_authority"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var audited int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.configure' AND object_id=? AND json_extract(payload,'$.mutation')='target-add' AND json_extract(payload,'$.previous_authority')='usr_previous' AND json_extract(payload,'$.authority')='usr_adapter'`, target.ID).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if target.AuthorityPrincipalID != "usr_adapter" || audited != 1 {
		t.Fatalf("target=%+v authority audits=%d", target, audited)
	}
	var storedExpiry string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT credential_expires_at FROM adapters WHERE id='adp_1'`).Scan(&storedExpiry); err != nil {
		t.Fatal(err)
	}
	if parsed, err := time.Parse(time.RFC3339Nano, storedExpiry); err != nil || !parsed.Equal(expires) {
		t.Fatalf("add target credential expiry = %q (%v), want %s", storedExpiry, err, expires)
	}
}

func TestAdapterTargetAddRefusesDestinationEffectiveNameCollisionAtomically(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO environments (id,org_id,project_id,name,note,created_at,display_order) VALUES ('env_three','org_adapter','prj_adapter','three','','2026-08-17T00:00:00Z',2)`,
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_reveal_two','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`,
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_reveal_three','usr_adapter','reveal','org_adapter','prj_adapter','env_three','2026-08-17T00:00:00Z')`,
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_collision','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	root, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, root)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := kr.ForProject(t.Context(), "org_adapter", "prj_adapter")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.SealField(crypto.ProjectFieldAAD{OrgID: "org_adapter", ProjectID: "prj_adapter", OwnerTable: "adapters", OwnerRowID: "adp_1", FieldTag: "credential"}, []byte("provider-token"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapters SET credential_ciphertext=?,credential_set_at='2026-08-17T00:00:00Z' WHERE id='adp_1'`, sealed); err != nil {
		t.Fatal(err)
	}
	gates := 0
	svc := &Adapters{DB: db, Keyring: kr, ModuleFactory: providerBlindTestModuleFactory(func(string, string) (adapter.Module, func(), error) {
		return fakeAdapterConfigureModule{gates: &gates, destinationID: 42}, nil, nil
	})}
	_, err = svc.AddTarget(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, "adp_1", AdapterTargetInput{EnvironmentID: "env_three", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "app", NamePrefix: "ONE_", KeyIDs: []string{"key_collision"}})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("AddTarget() error = %v, want conflict", err)
	}
	var targets int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_targets`).Scan(&targets); err != nil {
		t.Fatal(err)
	}
	if targets != 2 {
		t.Fatalf("target rows = %d, want original rows only", targets)
	}
}

func TestTargetedKeyDeleteCascadesMembershipAndQueuesOwnedSlotPrune(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO project_schema_revisions (org_id,project_id,revision) VALUES ('org_adapter','prj_adapter',1)`,
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_definitions_delete','usr_adapter','definitions-edit','org_adapter','prj_adapter',NULL,'2026-08-17T00:00:00Z')`,
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_publish_delete_one','usr_adapter','publish','org_adapter','prj_adapter','env_one','2026-08-17T00:00:00Z')`,
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_publish_delete_two','usr_adapter','publish','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`,
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_delete','org_adapter','prj_adapter','DELETE_ME','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`UPDATE adapters SET credential_ciphertext=X'01',credential_set_at='2026-08-17T00:00:00Z' WHERE id='adp_1'`,
		`INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_one','tgt_one','adp_1','key_delete')`,
		`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_delete','org_adapter','prj_adapter','env_one','tgt_one','https://git.example',42,'secret','ONE_DELETE_ME','ONE_DELETE_ME','owned','2026-08-17T00:00:00Z')`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	root, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Keys{DB: db, Keyring: kr}).Delete(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, "key_delete"); err != nil {
		t.Fatal(err)
	}
	var memberships, queued int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_target_keys WHERE target_id='tgt_one' AND key_id='key_delete'`).Scan(&memberships); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_outbox WHERE target_id='tgt_one' AND kind='converge' AND state='queued'`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if memberships != 0 || queued != 1 {
		t.Fatalf("delete left memberships=%d queued converges=%d", memberships, queued)
	}
	var job adapter.Job
	var created string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT id,org_id,project_id,environment_id,target_id,kind,authority_principal_id,generation,created_at FROM adapter_outbox WHERE target_id='tgt_one' AND state='queued'`).Scan(
		&job.ID, &job.OrgID, &job.ProjectID, &job.EnvironmentID, &job.TargetID, &job.Kind, &job.AuthorityPrincipal, &job.Generation, &created,
	); err != nil {
		t.Fatal(err)
	}
	job.LeaseOwner = "worker_delete"
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_outbox SET state='running',lease_owner=?,lease_expires_at=? WHERE id=?`, job.LeaseOwner, "2026-08-17T01:00:00.000000Z", job.ID); err != nil {
		t.Fatal(err)
	}
	execution, err := store.NewAdapterRuntime(db, nil).LoadExecution(t.Context(), job)
	if err != nil {
		t.Fatal(err)
	}
	if len(execution.Entries) != 0 || len(execution.Ledger) != 1 || execution.Ledger[0].EffectiveName != "ONE_DELETE_ME" || execution.Ledger[0].State != adapter.Owned {
		t.Fatalf("post-delete execution entries=%+v ledger=%+v; owned remote slot was not isolated for prune", execution.Entries, execution.Ledger)
	}
}

func TestAdapterTargetAddRequiresRevealAcrossEveryAdapterEnvironmentBeforeCredentialOpen(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO environments (id,org_id,project_id,name,note,created_at,display_order) VALUES ('env_three','org_adapter','prj_adapter','three','','2026-08-17T00:00:00Z',2)`,
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_reveal_three','usr_adapter','reveal','org_adapter','prj_adapter','env_three','2026-08-17T00:00:00Z')`,
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_new_target','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	root, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, root)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := kr.ForProject(t.Context(), "org_adapter", "prj_adapter")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.SealField(crypto.ProjectFieldAAD{OrgID: "org_adapter", ProjectID: "prj_adapter", OwnerTable: "adapters", OwnerRowID: "adp_1", FieldTag: "credential"}, []byte("provider-token"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapters SET credential_ciphertext=?,credential_set_at='2026-08-17T00:00:00Z' WHERE id='adp_1'`, sealed); err != nil {
		t.Fatal(err)
	}
	gates := 0
	svc := &Adapters{DB: db, Keyring: kr, ModuleFactory: providerBlindTestModuleFactory(func(string, string) (adapter.Module, func(), error) {
		return fakeAdapterConfigureModule{gates: &gates, destinationID: 42}, nil, nil
	})}
	_, err = svc.AddTarget(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, "adp_1", AdapterTargetInput{EnvironmentID: "env_three", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "app", NamePrefix: "THREE_", KeyIDs: []string{"key_new_target"}})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("AddTarget() error = %v, want tenant-safe refusal without env_two reveal", err)
	}
	if gates != 0 {
		t.Fatalf("provider gates = %d, want zero before full-formula authorization", gates)
	}
}

func TestAdapterTargetDestinationMoveScrubsOldRouteBeforePendingRouteActivation(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_move_reveal_two','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`,
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_move','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_one','tgt_one','adp_1','key_move')`,
		`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_move','org_adapter','prj_adapter','env_one','tgt_one','https://git.example',42,'secret','ONE_API_TOKEN','ONE_API_TOKEN','owned','2026-08-17T00:00:00Z')`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	svc := &Adapters{DB: db}
	result, err := svc.MoveTarget(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, UpdateAdapterTargetRequest{
		TargetID: "tgt_one", ExpectedGeneration: 1,
		Target: AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "next", NamePrefix: "ONE_", KeyIDs: []string{"key_move"}},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.MoveID == "" || result.JobID == "" || result.Generation != 2 || len(result.Orphaned) != 0 {
		t.Fatalf("MoveTarget() = %+v", result)
	}
	var state, owner, name, moveState, pendingName, jobKind, jobMove string
	var destinationID, generation int64
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state,destination_owner,destination_name,destination_id,generation FROM adapter_targets WHERE id='tgt_one'`).Scan(&state, &owner, &name, &destinationID, &generation); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_route_moves WHERE id=?`, result.MoveID).Scan(&moveState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT destination_name FROM adapter_route_move_targets WHERE move_id=? AND target_id='tgt_one'`, result.MoveID).Scan(&pendingName); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT kind,route_move_id FROM adapter_outbox WHERE id=?`, result.JobID).Scan(&jobKind, &jobMove); err != nil {
		t.Fatal(err)
	}
	if state != "moving" || owner != "acme" || name != "app" || destinationID != 42 || generation != 2 || moveState != "scrubbing" || pendingName != "next" || jobKind != "scrub" || jobMove != result.MoveID {
		t.Fatalf("move state=%q old=%s/%s#%d gen=%d move=%q pending=%q job=%q/%q", state, owner, name, destinationID, generation, moveState, pendingName, jobKind, jobMove)
	}
	var ledgerState string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_ledger WHERE id='led_move'`).Scan(&ledgerState); err != nil {
		t.Fatal(err)
	}
	if ledgerState != "owned" {
		t.Fatalf("old-route custody changed before scrub: %q", ledgerState)
	}
	var pendingClaims, sentinelClaims, keyClaims int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_route_move_claims WHERE move_id=? AND target_id='tgt_one'`, result.MoveID).Scan(&pendingClaims); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_route_move_claims WHERE move_id=? AND target_id='tgt_one' AND key_id IS NULL`, result.MoveID).Scan(&sentinelClaims); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_route_move_claims WHERE move_id=? AND target_id='tgt_one' AND key_id='key_move'`, result.MoveID).Scan(&keyClaims); err != nil {
		t.Fatal(err)
	}
	if pendingClaims != 3 || sentinelClaims != 2 || keyClaims != 1 {
		t.Fatalf("pending route claims=%d sentinels=%d linked keys=%d", pendingClaims, sentinelClaims, keyClaims)
	}
}

func TestAdapterTargetDestinationMoveKeepRemoteReleasesBeforeActivation(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_keep_move_reveal_two','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`,
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_keep_move','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_one','tgt_one','adp_1','key_keep_move')`,
		`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_keep_move','org_adapter','prj_adapter','env_one','tgt_one','https://git.example',42,'secret','ONE_API_TOKEN','ONE_API_TOKEN','owned','2026-08-17T00:00:00Z')`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	result, err := (&Adapters{DB: db}).MoveTarget(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, UpdateAdapterTargetRequest{
		TargetID: "tgt_one", ExpectedGeneration: 1,
		Target: AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "next", NamePrefix: "ONE_", KeyIDs: []string{"key_keep_move"}},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.Orphaned, []string{"secret:ONE_API_TOKEN"}) {
		t.Fatalf("orphaned = %v", result.Orphaned)
	}
	var ledgerState, moveState, jobKind string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_ledger WHERE id='led_keep_move'`).Scan(&ledgerState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_route_moves WHERE id=?`, result.MoveID).Scan(&moveState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT kind FROM adapter_outbox WHERE id=?`, result.JobID).Scan(&jobKind); err != nil {
		t.Fatal(err)
	}
	if ledgerState != "released" || moveState != "activating" || jobKind != "activate" {
		t.Fatalf("keep-remote state ledger=%q move=%q job=%q", ledgerState, moveState, jobKind)
	}
	var audited int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.scrub' AND object_id='tgt_one' AND json_extract(payload,'$.orphaned[0]')='secret:ONE_API_TOKEN'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Fatalf("orphan audit rows=%d", audited)
	}
}

func TestAdapterTargetMoveScrubCompletionQueuesPendingRouteActivation(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_scrub_move_reveal_two','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`,
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_scrub_move','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_one','tgt_one','adp_1','key_scrub_move')`,
		`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_scrub_move','org_adapter','prj_adapter','env_one','tgt_one','https://git.example',42,'secret','ONE_API_TOKEN','ONE_API_TOKEN','owned','2026-08-17T00:00:00Z')`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 8, 17, 1, 0, 0, 0, time.UTC)
	svc := &Adapters{DB: db, Now: func() time.Time { return now }}
	move, err := svc.MoveTarget(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, UpdateAdapterTargetRequest{
		TargetID: "tgt_one", ExpectedGeneration: 1,
		Target: AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "next", NamePrefix: "ONE_", KeyIDs: []string{"key_scrub_move"}},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_move", now.Add(time.Second), now.Add(adapter.LeaseTime))
	if err != nil || !ok || job.ID != move.JobID || job.RouteMoveID != move.MoveID {
		var queuedState, nextAttempt string
		_ = db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state,next_attempt_at FROM adapter_outbox WHERE id=?`, move.JobID).Scan(&queuedState, &nextAttempt)
		t.Fatalf("ClaimDue() = %+v, %v, %v; stored=%q due=%q now=%q", job, ok, err, queuedState, nextAttempt, store.CanonTime(now).Format(time.RFC3339Nano))
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_ledger SET state='released' WHERE target_id='tgt_one'`); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Succeed(t.Context(), job, 0, nil, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	var targetState, targetName, moveState, nextKind, nextMove string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state,destination_name FROM adapter_targets WHERE id='tgt_one'`).Scan(&targetState, &targetName); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_route_moves WHERE id=?`, move.MoveID).Scan(&moveState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT kind,route_move_id FROM adapter_outbox WHERE target_id='tgt_one' AND state='queued'`).Scan(&nextKind, &nextMove); err != nil {
		t.Fatal(err)
	}
	if targetState != "moving" || targetName != "app" || moveState != "activating" || nextKind != "activate" || nextMove != move.MoveID {
		t.Fatalf("after scrub target=%q/%q move=%q next=%q/%q", targetState, targetName, moveState, nextKind, nextMove)
	}
}

func TestAdapterTargetMoveDeadCredentialReleasesOldCustodyThenActivates(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_dead_move_reveal_two','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`,
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_dead_move','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_one','tgt_one','adp_1','key_dead_move')`,
		`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_dead_move','org_adapter','prj_adapter','env_one','tgt_one','https://git.example',42,'secret','ONE_API_TOKEN','ONE_API_TOKEN','owned','2026-08-17T00:00:00Z')`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	move, err := (&Adapters{DB: db, Now: func() time.Time { return now }}).MoveTarget(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, UpdateAdapterTargetRequest{
		TargetID: "tgt_one", ExpectedGeneration: 1,
		Target: AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "next", NamePrefix: "ONE_", KeyIDs: []string{"key_dead_move"}},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_dead_move", now.Add(time.Second), now.Add(adapter.LeaseTime))
	if err != nil || !ok || job.ID != move.JobID {
		t.Fatalf("ClaimDue() = %+v, %v, %v", job, ok, err)
	}
	if err := runtime.Fail(t.Context(), job, now.Add(time.Second), adapter.ErrProviderAuth); err != nil {
		t.Fatal(err)
	}
	var ledgerState, targetState, moveState, nextKind string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_ledger WHERE id='led_dead_move'`).Scan(&ledgerState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_targets WHERE id='tgt_one'`).Scan(&targetState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_route_moves WHERE id=?`, move.MoveID).Scan(&moveState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT kind FROM adapter_outbox WHERE target_id='tgt_one' AND state='queued'`).Scan(&nextKind); err != nil {
		t.Fatal(err)
	}
	if ledgerState != "released" || targetState != "moving" || moveState != "activating" || nextKind != "activate" {
		t.Fatalf("dead credential state ledger=%q target=%q move=%q next=%q", ledgerState, targetState, moveState, nextKind)
	}
	var orphanAudit int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.scrub' AND outcome='failure' AND correlation_id=? AND json_extract(payload,'$.orphaned[0]')='secret:ONE_API_TOKEN'`, move.JobID).Scan(&orphanAudit); err != nil {
		t.Fatal(err)
	}
	if orphanAudit != 1 {
		t.Fatalf("dead credential orphan audit rows=%d", orphanAudit)
	}
}

func TestAdapterMoveCredentialFailureRequiresAttentionAndCancelReconvergesOldRoute(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_attention_reveal_two','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`,
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_attention','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_one','tgt_one','adp_1','key_attention')`,
		`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_attention','org_adapter','prj_adapter','env_one','tgt_one','https://git.example',42,'secret','ONE_API_TOKEN','ONE_API_TOKEN','owned','2026-08-17T00:00:00Z')`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 8, 17, 1, 0, 0, 0, time.UTC)
	svc := &Adapters{DB: db, Now: func() time.Time { return now }}
	move, err := svc.MoveTarget(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, UpdateAdapterTargetRequest{
		TargetID: "tgt_one", ExpectedGeneration: 1,
		Target: AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "next", NamePrefix: "ONE_", KeyIDs: []string{"key_attention"}},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_attention", now.Add(time.Second), now.Add(adapter.LeaseTime))
	if err != nil || !ok || job.ID != move.JobID || job.Kind != adapter.Activate {
		t.Fatalf("ClaimDue() = %+v, %v, %v", job, ok, err)
	}
	if err := runtime.Fail(t.Context(), job, now.Add(2*time.Second), adapter.ErrProviderAuth); err != nil {
		t.Fatal(err)
	}
	status, err := svc.Move(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, move.MoveID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "attention_required" || len(status.Targets) != 1 || len(status.Targets[0].Jobs) != 1 || status.Targets[0].Jobs[0].State != "failed" {
		t.Fatalf("attention status = %+v", status)
	}
	for _, statement := range []string{
		`INSERT INTO principals (id,kind,created_at) VALUES ('usr_previous','human','2026-08-17T00:00:00Z')`,
		`UPDATE adapters SET authority_principal_id='usr_previous' WHERE id='adp_1'`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	canceled, err := svc.CancelMove(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, move.MoveID)
	if err != nil {
		t.Fatal(err)
	}
	if canceled.State != "canceled" || len(canceled.Targets) != 1 || len(canceled.Targets[0].Jobs) != 2 || canceled.Targets[0].Jobs[1].Kind != "converge" || canceled.Targets[0].Jobs[1].State != "queued" {
		t.Fatalf("canceled status = %+v", canceled)
	}
	var targetState, targetName string
	var pendingClaims, authorityAudits int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state,destination_name FROM adapter_targets WHERE id='tgt_one'`).Scan(&targetState, &targetName); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_route_move_claims WHERE move_id=?`, move.MoveID).Scan(&pendingClaims); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.configure' AND object_id=? AND json_extract(payload,'$.mutation')='move-cancel' AND json_extract(payload,'$.previous_authority')='usr_previous' AND json_extract(payload,'$.authority')='usr_adapter'`, move.MoveID).Scan(&authorityAudits); err != nil {
		t.Fatal(err)
	}
	if targetState != "active" || targetName != "app" || pendingClaims != 0 || canceled.PreviousAuthorityPrincipalID != "usr_previous" || canceled.AuthorityPrincipalID != "usr_adapter" || authorityAudits != 1 {
		t.Fatalf("old route recovery target=%q/%q pending_claims=%d transition=%q->%q audits=%d", targetState, targetName, pendingClaims, canceled.PreviousAuthorityPrincipalID, canceled.AuthorityPrincipalID, authorityAudits)
	}
}

func TestAdapterAttentionTargetReplacementResumesActivation(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_resume_reveal_two','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`,
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_resume','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_one','tgt_one','adp_1','key_resume')`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 8, 17, 1, 0, 0, 0, time.UTC)
	svc := &Adapters{DB: db, Now: func() time.Time { return now }}
	move, err := svc.MoveTarget(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, UpdateAdapterTargetRequest{
		TargetID: "tgt_one", ExpectedGeneration: 1,
		Target: AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "bad", NamePrefix: "BAD_", KeyIDs: []string{"key_resume"}},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_resume", now.Add(time.Second), now.Add(adapter.LeaseTime))
	if err != nil || !ok || job.ID != move.JobID || job.Kind != adapter.Activate {
		t.Fatalf("ClaimDue() = %+v, %v, %v", job, ok, err)
	}
	if err := runtime.Fail(t.Context(), job, now.Add(2*time.Second), adapter.ErrProviderAuth); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO principals (id,kind,created_at) VALUES ('usr_previous','human','2026-08-17T00:00:00Z')`,
		`UPDATE adapters SET authority_principal_id='usr_previous' WHERE id='adp_1'`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	resumed, err := svc.ResumeTargetMove(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, move.MoveID, UpdateAdapterTargetRequest{
		TargetID: "tgt_one",
		Target:   AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "fixed", NamePrefix: "FIXED_", KeyIDs: []string{"key_resume"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.State != "activating" || len(resumed.Targets) != 1 || resumed.Targets[0].DestinationName != "fixed" || resumed.Targets[0].NamePrefix != "FIXED_" || len(resumed.Targets[0].Jobs) != 2 || resumed.Targets[0].Jobs[0].State != "failed" || resumed.Targets[0].Jobs[1].Kind != "activate" || resumed.Targets[0].Jobs[1].State != "queued" {
		t.Fatalf("resumed status = %+v", resumed)
	}
	var generation int64
	var activeJob string
	var fixedClaims, staleClaims, authorityAudits int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT generation,active_job_id FROM adapter_targets WHERE id='tgt_one'`).Scan(&generation, &activeJob); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_route_move_claims WHERE move_id=? AND destination_name='fixed'`, move.MoveID).Scan(&fixedClaims); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_route_move_claims WHERE move_id=? AND destination_name='bad'`, move.MoveID).Scan(&staleClaims); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.configure' AND object_id=? AND json_extract(payload,'$.mutation')='pending-target-replace' AND json_extract(payload,'$.previous_authority')='usr_previous' AND json_extract(payload,'$.authority')='usr_adapter'`, move.MoveID).Scan(&authorityAudits); err != nil {
		t.Fatal(err)
	}
	if generation != 3 || activeJob != resumed.Targets[0].Jobs[1].ID || fixedClaims != 3 || staleClaims != 0 || resumed.PreviousAuthorityPrincipalID != "usr_previous" || resumed.AuthorityPrincipalID != "usr_adapter" || authorityAudits != 1 {
		t.Fatalf("resumed generation=%d active_job=%q fixed_claims=%d stale_claims=%d transition=%q->%q audits=%d", generation, activeJob, fixedClaims, staleClaims, resumed.PreviousAuthorityPrincipalID, resumed.AuthorityPrincipalID, authorityAudits)
	}
}

func TestAdapterTargetMoveActivationTestsPendingRouteThenEnqueuesConverge(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_activate_move_reveal_two','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`,
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_activate_move','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_one','tgt_one','adp_1','key_activate_move')`,
		`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_activate_move','org_adapter','prj_adapter','env_one','tgt_one','https://git.example',42,'secret','ONE_API_TOKEN','ONE_API_TOKEN','released','2026-08-17T00:00:00Z')`,
		`UPDATE adapters SET credential_ciphertext=x'01',credential_set_at='2026-08-17T00:00:00Z' WHERE id='adp_1'`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	move, err := (&Adapters{DB: db, Now: func() time.Time { return now }}).MoveTarget(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, UpdateAdapterTargetRequest{
		TargetID: "tgt_one", ExpectedGeneration: 1,
		Target: AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "next", NamePrefix: "NEXT_", KeyIDs: []string{"key_activate_move"}},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_activate", now.Add(time.Second), now.Add(adapter.LeaseTime))
	if err != nil || !ok || job.ID != move.JobID || job.Kind != adapter.Activate {
		t.Fatalf("ClaimDue() = %+v, %v, %v", job, ok, err)
	}
	journal := runtime.Journal(job)
	if err := journal.Gate(t.Context(), adapter.Effect{}); err != nil {
		t.Fatal(err)
	}
	pending, err := runtime.LoadActivation(t.Context(), job)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Origin != "https://git.example" || pending.Target.Destination.Name != "next" || pending.Target.Destination.NumericID != 0 || len(pending.CredentialCiphertext) == 0 {
		t.Fatalf("LoadActivation() = %+v", pending)
	}
	expires := time.Date(2026, 12, 3, 4, 5, 6, 0, time.UTC)
	if err := runtime.Activate(t.Context(), job, adapter.Connection{Version: "1.21.11", DestinationID: 99, CredentialExpiresAt: expires}, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	var targetState, targetName, prefix, moveState, nextKind string
	var destinationID, generation, nextGeneration int64
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state,destination_name,destination_id,name_prefix,generation FROM adapter_targets WHERE id='tgt_one'`).Scan(&targetState, &targetName, &destinationID, &prefix, &generation); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_route_moves WHERE id=?`, move.MoveID).Scan(&moveState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT kind,generation FROM adapter_outbox WHERE target_id='tgt_one' AND state='queued'`).Scan(&nextKind, &nextGeneration); err != nil {
		t.Fatal(err)
	}
	var storedExpiry string
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT credential_expires_at FROM adapters WHERE id='adp_1'`).Scan(&storedExpiry); err != nil {
		t.Fatal(err)
	}
	if parsed, err := time.Parse(time.RFC3339Nano, storedExpiry); err != nil || !parsed.Equal(expires) {
		t.Fatalf("activation credential expiry = %q (%v), want %s", storedExpiry, err, expires)
	}
	if targetState != "active" || targetName != "next" || destinationID != 99 || prefix != "NEXT_" || generation != 3 || moveState != "completed" || nextKind != "converge" || nextGeneration != 3 {
		t.Fatalf("activated target=%q/%q#%d prefix=%q gen=%d move=%q next=%q/%d", targetState, targetName, destinationID, prefix, generation, moveState, nextKind, nextGeneration)
	}
}

func TestAdapterOriginMoveKeepsOldRouteAndCredentialThroughScrubBarrier(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_origin_move_reveal_two','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`,
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_origin_move','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_one','tgt_one','adp_1','key_origin_move')`,
		`INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_two','tgt_two','adp_1','key_origin_move')`,
		`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_origin_one','org_adapter','prj_adapter','env_one','tgt_one','https://git.example',42,'secret','ONE_API_TOKEN','ONE_API_TOKEN','owned','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_origin_two','org_adapter','prj_adapter','env_two','tgt_two','https://git.example',42,'secret','TWO_API_TOKEN','TWO_API_TOKEN','owned','2026-08-17T00:00:00Z')`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	root, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, root)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := kr.ForProject(t.Context(), "org_adapter", "prj_adapter")
	if err != nil {
		t.Fatal(err)
	}
	oldCredential, err := sealer.SealField(crypto.ProjectFieldAAD{OrgID: "org_adapter", ProjectID: "prj_adapter", OwnerTable: "adapters", OwnerRowID: "adp_1", FieldTag: "credential"}, []byte("old-token"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapters SET credential_ciphertext=?,credential_set_at='2026-08-17T00:00:00Z' WHERE id='adp_1'`, oldCredential); err != nil {
		t.Fatal(err)
	}
	svc := &Adapters{DB: db, Keyring: kr, ModuleFactory: providerBlindTestModuleFactory(func(origin, credential string) (adapter.Module, func(), error) {
		if origin != "https://git.next.example" || credential != "new-token" {
			t.Fatalf("pending factory=%q/%q", origin, credential)
		}
		return fakeAdapterConfigureModule{gates: new(int)}, nil, nil
	})}
	move, err := svc.MoveOrigin(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, "adp_1", "https://git.next.example", []byte("new-token"), false)
	if err != nil {
		t.Fatal(err)
	}
	if move.MoveID == "" || len(move.Targets) != 2 {
		t.Fatalf("MoveOrigin() = %+v", move)
	}
	var state, origin, pendingOrigin, moveState string
	var currentCredential, pendingCredential []byte
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state,origin,credential_ciphertext FROM adapters WHERE id='adp_1'`).Scan(&state, &origin, &currentCredential); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state,pending_origin,pending_credential_ciphertext FROM adapter_route_moves WHERE id=?`, move.MoveID).Scan(&moveState, &pendingOrigin, &pendingCredential); err != nil {
		t.Fatal(err)
	}
	if state != "moving" || origin != "https://git.example" || !slices.Equal(currentCredential, oldCredential) || moveState != "scrubbing" || pendingOrigin != "https://git.next.example" || len(pendingCredential) == 0 || string(pendingCredential) == "new-token" {
		t.Fatalf("origin move adapter=%q/%q old=%v move=%q/%q pending=%v", state, origin, slices.Equal(currentCredential, oldCredential), moveState, pendingOrigin, pendingCredential)
	}
	var scrubJobs int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_outbox WHERE route_move_id=? AND kind='scrub' AND state='queued'`, move.MoveID).Scan(&scrubJobs); err != nil {
		t.Fatal(err)
	}
	if scrubJobs != 2 {
		t.Fatalf("origin scrub jobs=%d", scrubJobs)
	}
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	now := time.Now().UTC().Add(time.Second)
	first, ok, err := runtime.ClaimDue(t.Context(), "worker_origin_one", now, now.Add(adapter.LeaseTime))
	if err != nil || !ok || first.RouteMoveID != move.MoveID || first.Kind != adapter.Scrub {
		t.Fatalf("ClaimDue(first) = %+v, %v, %v", first, ok, err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_ledger SET state='released' WHERE target_id=?`, first.TargetID); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Succeed(t.Context(), first, 0, nil, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var activationJobs int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_route_moves WHERE id=?`, move.MoveID).Scan(&moveState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_outbox WHERE route_move_id=? AND kind='activate' AND state='queued'`, move.MoveID).Scan(&activationJobs); err != nil {
		t.Fatal(err)
	}
	if moveState != "scrubbing" || activationJobs != 0 {
		t.Fatalf("barrier opened early: state=%q activations=%d", moveState, activationJobs)
	}
	second, ok, err := runtime.ClaimDue(t.Context(), "worker_origin_two", now.Add(2*time.Second), now.Add(adapter.LeaseTime))
	if err != nil || !ok || second.RouteMoveID != move.MoveID || second.Kind != adapter.Scrub || second.TargetID == first.TargetID {
		t.Fatalf("ClaimDue(second) = %+v, %v, %v", second, ok, err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_ledger SET state='released' WHERE target_id=?`, second.TargetID); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Succeed(t.Context(), second, 0, nil, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_route_moves WHERE id=?`, move.MoveID).Scan(&moveState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_outbox WHERE route_move_id=? AND kind='activate' AND state='queued'`, move.MoveID).Scan(&activationJobs); err != nil {
		t.Fatal(err)
	}
	if moveState != "activating" || activationJobs != 2 {
		t.Fatalf("barrier did not open: state=%q activations=%d", moveState, activationJobs)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT origin,credential_ciphertext FROM adapters WHERE id='adp_1'`).Scan(&origin, &currentCredential); err != nil {
		t.Fatal(err)
	}
	if origin != "https://git.example" || !slices.Equal(currentCredential, oldCredential) {
		t.Fatalf("old route changed before all activation probes: origin=%q old=%v", origin, slices.Equal(currentCredential, oldCredential))
	}
	firstActivation, ok, err := runtime.ClaimDue(t.Context(), "worker_origin_activate_one", now.Add(4*time.Second), now.Add(adapter.LeaseTime))
	if err != nil || !ok || firstActivation.RouteMoveID != move.MoveID || firstActivation.Kind != adapter.Activate {
		t.Fatalf("ClaimDue(first activation) = %+v, %v, %v", firstActivation, ok, err)
	}
	if err := runtime.Activate(t.Context(), firstActivation, adapter.Connection{DestinationID: 101, Version: "1.21.0"}, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	var convergeJobs int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_outbox WHERE route_move_id=? AND kind='converge' AND state='queued'`, move.MoveID).Scan(&convergeJobs); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_route_moves WHERE id=?`, move.MoveID).Scan(&moveState); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT origin,credential_ciphertext FROM adapters WHERE id='adp_1'`).Scan(&origin, &currentCredential); err != nil {
		t.Fatal(err)
	}
	if moveState != "activating" || convergeJobs != 0 || origin != "https://git.example" || !slices.Equal(currentCredential, oldCredential) {
		t.Fatalf("first probe crossed barrier: move=%q converges=%d origin=%q old=%v", moveState, convergeJobs, origin, slices.Equal(currentCredential, oldCredential))
	}
	secondActivation, ok, err := runtime.ClaimDue(t.Context(), "worker_origin_activate_two", now.Add(6*time.Second), now.Add(adapter.LeaseTime))
	if err != nil || !ok || secondActivation.RouteMoveID != move.MoveID || secondActivation.Kind != adapter.Activate || secondActivation.TargetID == firstActivation.TargetID {
		t.Fatalf("ClaimDue(second activation) = %+v, %v, %v", secondActivation, ok, err)
	}
	if err := runtime.Activate(t.Context(), secondActivation, adapter.Connection{DestinationID: 202, Version: "1.21.0"}, now.Add(7*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state,origin,credential_ciphertext FROM adapters WHERE id='adp_1'`).Scan(&state, &origin, &currentCredential); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_route_moves WHERE id=?`, move.MoveID).Scan(&moveState); err != nil {
		t.Fatal(err)
	}
	var activatedTargets, clearedPending int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_targets WHERE adapter_id='adp_1' AND state='active' AND destination_id IN (101,202)`).Scan(&activatedTargets); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_outbox WHERE route_move_id=? AND kind='converge' AND state='queued'`, move.MoveID).Scan(&convergeJobs); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_route_moves WHERE id=? AND pending_origin IS NULL AND pending_credential_ciphertext IS NULL`, move.MoveID).Scan(&clearedPending); err != nil {
		t.Fatal(err)
	}
	if state != "active" || origin != "https://git.next.example" || !slices.Equal(currentCredential, pendingCredential) || moveState != "completed" || activatedTargets != 2 || convergeJobs != 2 || clearedPending != 1 {
		t.Fatalf("activation barrier result adapter=%q/%q credential=%v move=%q targets=%d converges=%d cleared=%d", state, origin, slices.Equal(currentCredential, pendingCredential), moveState, activatedTargets, convergeJobs, clearedPending)
	}
}

func TestAdapterPendingOriginReplacementAuditsTransactionAuthorityTransition(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO principals (id,kind,created_at) VALUES ('usr_previous','human','2026-08-17T00:00:00Z')`,
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_origin_resume_reveal_two','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`,
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_origin_resume','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`UPDATE adapters SET state='moving',authority_principal_id='usr_previous' WHERE id='adp_1'`,
		`UPDATE adapter_targets SET state='moving',sync_status='failed',active_job_id=NULL WHERE adapter_id='adp_1'`,
		`INSERT INTO adapter_route_moves (id,org_id,project_id,adapter_id,kind,pending_origin,pending_credential_ciphertext,authority_principal_id,state,keep_remote,created_at) VALUES ('move_origin_resume','org_adapter','prj_adapter','adp_1','origin','https://git.bad.example',X'01','usr_adapter','attention_required',0,'2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_route_move_targets (move_id,org_id,project_id,environment_id,target_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix) VALUES ('move_origin_resume','org_adapter','prj_adapter','env_one','tgt_one','repository','acme','app',0,'ONE_')`,
		`INSERT INTO adapter_route_move_targets (move_id,org_id,project_id,environment_id,target_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix) VALUES ('move_origin_resume','org_adapter','prj_adapter','env_two','tgt_two','repository','acme','app',0,'TWO_')`,
		`INSERT INTO adapter_route_move_keys (move_id,org_id,project_id,environment_id,target_id,key_id) VALUES ('move_origin_resume','org_adapter','prj_adapter','env_one','tgt_one','key_origin_resume')`,
		`INSERT INTO adapter_route_move_keys (move_id,org_id,project_id,environment_id,target_id,key_id) VALUES ('move_origin_resume','org_adapter','prj_adapter','env_two','tgt_two','key_origin_resume')`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	root, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.ForProject(t.Context(), "org_adapter", "prj_adapter"); err != nil {
		t.Fatal(err)
	}
	svc := &Adapters{DB: db, Keyring: kr, ModuleFactory: providerBlindTestModuleFactory(func(origin, credential string) (adapter.Module, func(), error) {
		if origin != "https://git.fixed.example" || credential != "fixed-token" {
			t.Fatalf("pending origin factory=%q/%q", origin, credential)
		}
		return fakeAdapterConfigureModule{gates: new(int)}, nil, nil
	})}
	resumed, err := svc.ResumeOriginMove(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, "move_origin_resume", "https://git.fixed.example", []byte("fixed-token"))
	if err != nil {
		t.Fatal(err)
	}
	var audited, activateJobs int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.configure' AND object_id='move_origin_resume' AND json_extract(payload,'$.mutation')='pending-origin-replace' AND json_extract(payload,'$.previous_authority')='usr_previous' AND json_extract(payload,'$.authority')='usr_adapter'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_outbox WHERE route_move_id='move_origin_resume' AND kind='activate' AND state='queued'`).Scan(&activateJobs); err != nil {
		t.Fatal(err)
	}
	if resumed.State != "activating" || resumed.PendingOrigin != "https://git.fixed.example" || resumed.PreviousAuthorityPrincipalID != "usr_previous" || resumed.AuthorityPrincipalID != "usr_adapter" || activateJobs != 2 || audited != 1 {
		t.Fatalf("resumed=%+v activate jobs=%d authority audits=%d", resumed, activateJobs, audited)
	}
}

func TestAdapterTargetWidenRequiresRevealAcrossEveryAdapterEnvironment(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_existing','org_adapter','prj_adapter','EXISTING','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_widened','org_adapter','prj_adapter','WIDENED','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_one','tgt_one','adp_1','key_existing')`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	svc := &Adapters{DB: db}
	_, err := svc.UpdateTarget(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, UpdateAdapterTargetRequest{TargetID: "tgt_one", ExpectedGeneration: 1, Target: AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "app", NamePrefix: "ONE_", KeyIDs: []string{"key_existing", "key_widened"}}})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("UpdateTarget() error = %v, want tenant-safe refusal without env_two reveal", err)
	}
	var generation int64
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT generation FROM adapter_targets WHERE id='tgt_one'`).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if generation != 1 {
		t.Fatalf("generation = %d, want unchanged", generation)
	}
}

func seedAdapterUpdateKeys(t *testing.T, db *store.DB, includeSecond bool) {
	t.Helper()
	statements := []string{
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_update_a','org_adapter','prj_adapter','UPDATE_A','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_update_b','org_adapter','prj_adapter','UPDATE_B','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_one','tgt_one','adp_1','key_update_a')`,
	}
	if includeSecond {
		statements = append(statements, `INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_one','tgt_one','adp_1','key_update_b')`)
	}
	for _, statement := range statements {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAdapterTargetInPlaceClassificationAndReplacementConverge(t *testing.T) {
	t.Run("narrowing is manage-only and supersedes into converge", func(t *testing.T) {
		db := adapterServiceDB(t)
		seedAdapterUpdateKeys(t, db, true)
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,created_at) VALUES ('job_old','org_adapter','prj_adapter','env_one','tgt_one','converge','usr_adapter',1,'tgt_one',0,'2026-08-17T00:00:00Z','queued','2026-08-17T00:00:00Z')`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_targets SET active_job_id='job_old',sync_status='converging' WHERE id='tgt_one'`); err != nil {
			t.Fatal(err)
		}
		bearer := adapterCLISession(t, db)
		out, err := (&Adapters{DB: db, Auth: &Auth{DB: db}}).UpdateTarget(t.Context(), Bearer(bearer), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, UpdateAdapterTargetRequest{
			TargetID: "tgt_one", ExpectedGeneration: 1,
			Target: AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "app", NamePrefix: "ONE_", KeyIDs: []string{"key_update_a"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		var oldState, activeJob, syncStatus string
		var queued, requested, superseded, narrowedWithoutPrevious int
		if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state FROM adapter_outbox WHERE id='job_old'`).Scan(&oldState); err != nil {
			t.Fatal(err)
		}
		if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT active_job_id,sync_status FROM adapter_targets WHERE id='tgt_one'`).Scan(&activeJob, &syncStatus); err != nil {
			t.Fatal(err)
		}
		if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_outbox WHERE target_id='tgt_one' AND state='queued' AND id<>'job_old'`).Scan(&queued); err != nil {
			t.Fatal(err)
		}
		if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE object_id='tgt_one' AND type='adapter.sync_requested'`).Scan(&requested); err != nil {
			t.Fatal(err)
		}
		if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE object_id='tgt_one' AND type='adapter.superseded'`).Scan(&superseded); err != nil {
			t.Fatal(err)
		}
		if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE object_id='tgt_one' AND type='adapter.configure' AND json_extract(payload,'$.mutation')='target-update' AND json_type(payload,'$.previous_authority') IS NULL AND json_extract(payload,'$.authority')='usr_adapter'`).Scan(&narrowedWithoutPrevious); err != nil {
			t.Fatal(err)
		}
		if out.Generation != 2 || out.SyncStatus != "converging" || oldState != "superseded" || queued != 1 || activeJob == "" || activeJob == "job_old" || syncStatus != "converging" || requested != 1 || superseded != 1 || narrowedWithoutPrevious != 1 {
			t.Fatalf("out=%+v old=%q active=%q/%q queued=%d audits=%d/%d narrowing=%d", out, oldState, activeJob, syncStatus, queued, requested, superseded, narrowedWithoutPrevious)
		}
	})

	for _, tc := range []struct {
		name   string
		prefix string
		keys   []string
	}{
		{name: "widening requires adapter ceremony", prefix: "ONE_", keys: []string{"key_update_a", "key_update_b"}},
		{name: "prefix change requires adapter ceremony", prefix: "NEXT_", keys: []string{"key_update_a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := adapterServiceDB(t)
			seedAdapterUpdateKeys(t, db, false)
			if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_reveal_two_update','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`); err != nil {
				t.Fatal(err)
			}
			bearer := adapterCLISession(t, db)
			_, err := (&Adapters{DB: db, Auth: &Auth{DB: db}}).UpdateTarget(t.Context(), Bearer(bearer), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, UpdateAdapterTargetRequest{
				TargetID: "tgt_one", ExpectedGeneration: 1,
				Target: AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "app", NamePrefix: tc.prefix, KeyIDs: tc.keys},
			})
			if !errors.Is(err, ErrReauthRequired) {
				t.Fatalf("UpdateTarget() error=%v", err)
			}
			var generation, jobs int
			if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT generation FROM adapter_targets WHERE id='tgt_one'`).Scan(&generation); err != nil {
				t.Fatal(err)
			}
			if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_outbox WHERE target_id='tgt_one'`).Scan(&jobs); err != nil {
				t.Fatal(err)
			}
			if generation != 1 || jobs != 0 {
				t.Fatalf("failed ceremony mutated generation=%d jobs=%d", generation, jobs)
			}
		})
	}
}

func TestAdapterFullTargetUpdateAuditsTransactionAuthorityTransition(t *testing.T) {
	db := adapterServiceDB(t)
	seedAdapterUpdateKeys(t, db, false)
	for _, statement := range []string{
		`INSERT INTO principals (id,kind,created_at) VALUES ('usr_previous','human','2026-08-17T00:00:00Z')`,
		`INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_update_authority_reveal_two','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`,
		`UPDATE adapters SET authority_principal_id='usr_previous' WHERE id='adp_1'`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	out, err := (&Adapters{DB: db}).UpdateTarget(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, UpdateAdapterTargetRequest{
		TargetID: "tgt_one", ExpectedGeneration: 1,
		Target: AdapterTargetInput{EnvironmentID: "env_one", DestinationKind: "repository", DestinationOwner: "acme", DestinationName: "app", NamePrefix: "ONE_", KeyIDs: []string{"key_update_a", "key_update_b"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var audited int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.configure' AND object_id='tgt_one' AND json_extract(payload,'$.mutation')='target-update' AND json_extract(payload,'$.previous_authority')='usr_previous' AND json_extract(payload,'$.authority')='usr_adapter'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if out.AuthorityPrincipalID != "usr_adapter" || audited != 1 {
		t.Fatalf("target=%+v authority audits=%d", out, audited)
	}
}
func (fakeAdapterTestModule) Plan(context.Context, adapter.PlanRequest) (adapter.Plan, error) {
	return adapter.Plan{}, nil
}
func (fakeAdapterTestModule) Sync(context.Context, adapter.SyncRequest, adapter.Journal) (adapter.SyncResult, error) {
	return adapter.SyncResult{}, nil
}
func (m fakeAdapterPlanModule) Plan(context.Context, adapter.PlanRequest) (adapter.Plan, error) {
	return m.plan, nil
}
func (m fakeAdapterPlanModule) Sync(context.Context, adapter.SyncRequest, adapter.Journal) (adapter.SyncResult, error) {
	return adapter.SyncResult{}, nil
}

func recordAdapterPlanArtifact(t *testing.T, db *store.DB, artifactID string) {
	t.Helper()
	err := storetx.Write(t.Context(), db, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: "usr_adapter"}, authz.OpAdapterPlan, domain.Scope{Org: "org_adapter", Project: "prj_adapter"})
		if err != nil {
			return err
		}
		return repos.Adapters().RecordPlan(ctx, p, "tgt_one", artifactID, 1, 0, 42, []store.AdapterConflictEntry{{Surface: "secret", EffectiveName: "ONE_TOKEN"}}, time.Now().UTC())
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAdapterAdoptRequiresRevealAcrossEveryAdapterEnvironment(t *testing.T) {
	db := adapterServiceDB(t)
	recordAdapterPlanArtifact(t, db, "plan_all_envs")
	service := &Adapters{DB: db}
	_, err := service.Adopt(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, AdoptAdapterRequest{
		TargetID: "tgt_one", ArtifactID: "plan_all_envs", ExpectedGeneration: 1, ExpectedDestinationID: 42, Entries: []store.AdapterConflictEntry{{Surface: "secret", EffectiveName: "ONE_TOKEN"}},
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Adopt() = %v, want forbidden without reveal on env_two", err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_reveal_two','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	result, err := service.Adopt(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, AdoptAdapterRequest{
		TargetID: "tgt_one", ArtifactID: "plan_all_envs", ExpectedGeneration: 1, ExpectedDestinationID: 42, Entries: []store.AdapterConflictEntry{{Surface: "secret", EffectiveName: "ONE_TOKEN"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Generation != 2 || result.JobID == "" {
		t.Fatalf("Adopt() = %+v", result)
	}
	var auditRows int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.adopt' AND object_id='tgt_one'`).Scan(&auditRows); err != nil {
		t.Fatal(err)
	}
	if auditRows != 1 {
		t.Fatalf("adapter.adopt audit rows = %d", auditRows)
	}
}

func TestAdapterTargetKeepRemoteReleasesAndEnumeratesCustodyWithoutReveal(t *testing.T) {
	db := adapterServiceDB(t)
	statements := []string{
		`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_keep_owned','org_adapter','prj_adapter','env_one','tgt_one','https://git.example',42,'secret','ONE_TOKEN','ONE_TOKEN','owned','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_keep_dispatched','org_adapter','prj_adapter','env_one','tgt_one','https://git.example',42,'variable','ONE_CONFIG','ONE_CONFIG','dispatched','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_keep_reserved','org_adapter','prj_adapter','env_one','tgt_one','https://git.example',42,'secret','ONE_PENDING','ONE_PENDING','reserved','2026-08-17T00:00:00Z')`,
	}
	for _, statement := range statements {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	// The fixture deliberately grants reveal only in env_one and none in
	// env_two. Target deletion is the ADR's plain destructive formula, so it
	// must not consume or require reveal material.
	result, err := (&Adapters{DB: db}).RemoveTarget(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, "tgt_one", true)
	if err != nil {
		t.Fatal(err)
	}
	wantOrphans := []string{"secret:ONE_TOKEN", "variable:ONE_CONFIG"}
	if len(result.Targets) != 1 || !slices.Equal(result.Orphaned, wantOrphans) || result.Targets[0].JobID != "" || result.Targets[0].Generation != 2 {
		t.Fatalf("RemoveTarget(keep-remote) = %+v, want released names and no scrub job", result)
	}
	var targetState, syncStatus string
	var generation int64
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT generation,state,sync_status FROM adapter_targets WHERE id='tgt_one'`).Scan(&generation, &targetState, &syncStatus); err != nil {
		t.Fatal(err)
	}
	var activeLedger, releasedLedger, scrubAudits int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_ledger WHERE target_id='tgt_one' AND state<>'released'`).Scan(&activeLedger); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_ledger WHERE target_id='tgt_one' AND state='released'`).Scan(&releasedLedger); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.scrub' AND object_id='tgt_one' AND outcome='success' AND json_extract(payload,'$.orphaned[0]')='secret:ONE_TOKEN' AND json_extract(payload,'$.orphaned[1]')='variable:ONE_CONFIG'`).Scan(&scrubAudits); err != nil {
		t.Fatal(err)
	}
	if generation != 2 || targetState != "tombstoned" || syncStatus != "converged" || activeLedger != 0 || releasedLedger != 3 || scrubAudits != 1 {
		t.Fatalf("target=%d/%s/%s ledger active=%d released=%d scrub audits=%d", generation, targetState, syncStatus, activeLedger, releasedLedger, scrubAudits)
	}
	// A released global name is unowned. A different target can reserve the
	// same provider identity, while the old row remains as custody history.
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_reclaimed','org_adapter','prj_adapter','env_two','tgt_two','https://git.example',42,'secret','ONE_TOKEN','ONE_TOKEN','reserved','2026-08-17T00:01:00Z')`); err != nil {
		t.Fatalf("released name remained globally claimed: %v", err)
	}
}

func TestAdapterDeleteQueuesEveryScrubAndRetainsCredentialUntilLastTerminal(t *testing.T) {
	db := adapterServiceDB(t)
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapters SET credential_ciphertext=X'0102',credential_set_at='2026-08-17T00:00:00Z' WHERE id='adp_1'`); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_delete_one','org_adapter','prj_adapter','env_one','tgt_one','https://git.example',42,'secret','ONE_TOKEN','ONE_TOKEN','owned','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_delete_two','org_adapter','prj_adapter','env_two','tgt_two','https://git.example',42,'secret','TWO_TOKEN','TWO_TOKEN','owned','2026-08-17T00:00:00Z')`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	result, err := (&Adapters{DB: db}).Delete(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, "adp_1", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Targets) != 2 || result.Targets[0].JobID == "" || result.Targets[1].JobID == "" {
		t.Fatalf("Delete() = %+v, want one scrub per target", result)
	}
	var adapterState string
	var credential []byte
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT state,credential_ciphertext FROM adapters WHERE id='adp_1'`).Scan(&adapterState, &credential); err != nil {
		t.Fatal(err)
	}
	if adapterState != "tombstoned" || len(credential) == 0 {
		t.Fatalf("adapter state=%q credential=%x before scrubs", adapterState, credential)
	}

	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	now := time.Now().UTC()
	for i := 0; i < 2; i++ {
		job, ok, err := runtime.ClaimDue(t.Context(), fmt.Sprintf("scrubber_%d", i), now, now.Add(adapter.LeaseTime))
		if err != nil || !ok {
			t.Fatalf("ClaimDue(%d) = %+v, %v, %v", i, job, ok, err)
		}
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_ledger SET state='released' WHERE target_id=?`, job.TargetID); err != nil {
			t.Fatal(err)
		}
		if err := runtime.Succeed(t.Context(), job, 0, nil, now); err != nil {
			t.Fatal(err)
		}
		var present int
		if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT CASE WHEN credential_ciphertext IS NULL THEN 0 ELSE 1 END FROM adapters WHERE id='adp_1'`).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if i == 0 && present != 1 {
			t.Fatal("first terminal scrub erased credential while another target scrub was queued")
		}
		if i == 1 && present != 0 {
			t.Fatal("last terminal scrub did not erase tombstoned adapter credential")
		}
	}
}

func TestAdapterCredentialReplaceAndRevokeFenceWithoutAutoConverge(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO principals (id,kind,created_at) VALUES ('usr_previous','human','2026-08-17T00:00:00Z')`,
		`UPDATE adapters SET authority_principal_id='usr_previous' WHERE id='adp_1'`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	root, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, root)
	if err != nil {
		t.Fatal(err)
	}
	svc := &Adapters{DB: db, Keyring: kr}
	scope := domain.Scope{Org: "org_adapter", Project: "prj_adapter"}
	if _, err := svc.ReplaceCredential(t.Context(), LocalPrincipal("usr_adapter"), scope, "adp_1", []byte("provider-token")); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("ReplaceCredential() without reveal in every target env = %v, want uniform refusal", err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_reveal_two_credential','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	result, err := svc.ReplaceCredential(t.Context(), LocalPrincipal("usr_adapter"), scope, "adp_1", []byte("provider-token"))
	if err != nil {
		t.Fatal(err)
	}
	if result.TargetCount != 2 || result.PreviousAuthorityPrincipalID != "usr_previous" || result.AuthorityPrincipalID != "usr_adapter" {
		t.Fatalf("ReplaceCredential() = %+v", result)
	}
	var generations, jobs, replaceAudits int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT SUM(generation),COUNT(*) FROM adapter_targets WHERE adapter_id='adp_1'`).Scan(&generations, &jobs); err != nil {
		t.Fatal(err)
	}
	// jobs temporarily holds target count from the aggregate; query the real
	// outbox count separately to make the no-auto-converge rule explicit.
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_outbox WHERE target_id IN ('tgt_one','tgt_two')`).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.credential_replace' AND object_id='adp_1' AND json_extract(payload,'$.credential_present')=1 AND json_extract(payload,'$.previous_authority')='usr_previous' AND json_extract(payload,'$.authority')='usr_adapter'`).Scan(&replaceAudits); err != nil {
		t.Fatal(err)
	}
	if generations != 4 || jobs != 0 || replaceAudits != 1 {
		t.Fatalf("replace generations=%d jobs=%d audits=%d", generations, jobs, replaceAudits)
	}
	sealer, err := kr.ForProject(t.Context(), "org_adapter", "prj_adapter")
	if err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT credential_ciphertext FROM adapters WHERE id='adp_1'`).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	plain, err := sealer.OpenField(crypto.ProjectFieldAAD{OrgID: "org_adapter", ProjectID: "prj_adapter", OwnerTable: "adapters", OwnerRowID: "adp_1", FieldTag: "credential"}, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "provider-token" {
		t.Fatalf("stored credential = %q", plain)
	}
	crypto.Zero(plain)

	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,authority_principal_id,generation,dedup_key,next_attempt_at,state,created_at) VALUES ('job_before_revoke','org_adapter','prj_adapter','env_one','tgt_one','converge','usr_adapter',2,'tgt_one','2026-08-17T00:00:00Z','queued','2026-08-17T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_targets SET active_job_id='job_before_revoke' WHERE id='tgt_one'`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RevokeCredential(t.Context(), LocalPrincipal("usr_adapter"), scope, "adp_1"); err != nil {
		t.Fatal(err)
	}
	var credential any
	var revokeAudits int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT credential_ciphertext FROM adapters WHERE id='adp_1'`).Scan(&credential); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT SUM(generation) FROM adapter_targets WHERE adapter_id='adp_1'`).Scan(&generations); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_outbox WHERE target_id IN ('tgt_one','tgt_two')`).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.credential_revoke' AND object_id='adp_1' AND json_extract(payload,'$.credential_present')=0`).Scan(&revokeAudits); err != nil {
		t.Fatal(err)
	}
	if credential != nil || generations != 6 || jobs != 1 || revokeAudits != 1 {
		t.Fatalf("revoke credential=%v generations=%d jobs=%d audits=%d", credential, generations, jobs, revokeAudits)
	}
	runtime := store.NewAdapterRuntime(db, func(context.Context, adapter.Job, adapter.Effect) error { return nil })
	now := time.Now().UTC()
	job, ok, err := runtime.ClaimDue(t.Context(), "worker_revoke", now, now.Add(adapter.LeaseTime))
	if err != nil || !ok {
		t.Fatalf("ClaimDue() = %+v, %v, %v", job, ok, err)
	}
	gateErr := runtime.Journal(job).Gate(t.Context(), adapter.Effect{})
	if !errors.Is(gateErr, adapter.ErrSuperseded) {
		t.Fatalf("revoked queued job Gate() = %v, want generation stop", gateErr)
	}
	if err := runtime.Fail(t.Context(), job, now, gateErr); err != nil {
		t.Fatal(err)
	}
}

func TestAdapterManualSyncRequiresTargetRevealAndSupersedesNewest(t *testing.T) {
	db := adapterServiceDB(t)
	svc := &Adapters{DB: db}
	scope := domain.Scope{Org: "org_adapter", Project: "prj_adapter"}
	if _, err := svc.SyncTarget(t.Context(), LocalPrincipal("usr_adapter"), scope, "tgt_two"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("SyncTarget(env_two) = %v, want reveal refusal", err)
	}
	if _, err := svc.SyncTarget(t.Context(), LocalPrincipal("usr_adapter"), scope, "tgt_one"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("SyncTarget(env_one) = %v, want all-adapter-env reveal refusal", err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_reveal_two_sync','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	first, err := svc.SyncTarget(t.Context(), LocalPrincipal("usr_adapter"), scope, "tgt_one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.SyncTarget(t.Context(), LocalPrincipal("usr_adapter"), scope, "tgt_one")
	if err != nil {
		t.Fatal(err)
	}
	if first.Generation != 2 || second.Generation != 3 || second.SupersededJobID != first.JobID || second.AuthorityPrincipalID != "usr_adapter" {
		t.Fatalf("manual jobs first=%+v second=%+v", first, second)
	}
	var requested, superseded int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.sync_requested' AND object_id='tgt_one' AND authority_id='usr_adapter' AND json_extract(payload,'$.trigger')='manual'`).Scan(&requested); err != nil {
		t.Fatal(err)
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.superseded' AND object_id='tgt_one' AND json_extract(payload,'$.previous_job_id')=? AND json_extract(payload,'$.job_id')=?`, first.JobID, second.JobID).Scan(&superseded); err != nil {
		t.Fatal(err)
	}
	if requested != 2 || superseded != 1 {
		t.Fatalf("manual audit requested=%d superseded=%d", requested, superseded)
	}
}

func TestAdapterTargetConnectionReauthorizesEveryProviderRequest(t *testing.T) {
	db := adapterServiceDB(t)
	root, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, root)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := kr.ForProject(t.Context(), "org_adapter", "prj_adapter")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.SealField(crypto.ProjectFieldAAD{OrgID: "org_adapter", ProjectID: "prj_adapter", OwnerTable: "adapters", OwnerRowID: "adp_1", FieldTag: "credential"}, []byte("provider-token"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapters SET credential_ciphertext=?,credential_set_at='2026-08-17T00:00:00Z',credential_expires_at='2026-08-18T00:00:00Z' WHERE id='adp_1'`, sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('gr_reveal_two_test_expiry','usr_adapter','reveal','org_adapter','prj_adapter','env_two','2026-08-17T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	gates := 0
	expires := time.Date(2026, 11, 2, 3, 4, 5, 0, time.UTC)
	svc := &Adapters{DB: db, Keyring: kr, ModuleFactory: providerBlindTestModuleFactory(func(origin, credential string) (adapter.Module, func(), error) {
		if origin != "https://git.example" || credential != "provider-token" {
			t.Fatalf("factory origin=%q credential=%q", origin, credential)
		}
		return fakeAdapterTestModule{gates: &gates, credentialExpiry: expires}, nil, nil
	})}
	if _, err := svc.ReplaceCredential(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, "adp_1", []byte("provider-token")); err != nil {
		t.Fatal(err)
	}
	var clearedExpiry any
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT credential_expires_at FROM adapters WHERE id='adp_1'`).Scan(&clearedExpiry); err != nil {
		t.Fatal(err)
	}
	if clearedExpiry != nil {
		t.Fatalf("credential replacement retained stale expiry %v", clearedExpiry)
	}
	connection, err := svc.TestTarget(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, "tgt_one")
	if err != nil {
		t.Fatal(err)
	}
	if connection.Version != "1.21.11" || connection.DestinationID != 42 || gates != 2 {
		t.Fatalf("TestTarget() = %+v gates=%d", connection, gates)
	}
	shown, err := svc.Get(t.Context(), LocalPrincipal("usr_adapter"), domain.Scope{Org: "org_adapter", Project: "prj_adapter"}, "adp_1")
	if err != nil {
		t.Fatal(err)
	}
	storedExpiry, err := time.Parse(time.RFC3339Nano, shown.Adapter.CredentialExpiresAt)
	if err != nil || !storedExpiry.Equal(expires) {
		t.Fatalf("shown credential expiry = %q (%v), want %s", shown.Adapter.CredentialExpiresAt, err, expires)
	}
	var audits int
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_tenant_events WHERE type='adapter.test' AND object_id='tgt_one' AND json_extract(payload,'$.version')='1.21.11' AND json_extract(payload,'$.destination_id')=42`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("adapter.test audit rows = %d", audits)
	}
}

func TestAdapterPlanPersistsProviderConflictArtifactAndInspectReturnsIt(t *testing.T) {
	db := adapterServiceDB(t)
	for _, statement := range []string{
		`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_api','org_adapter','prj_adapter','API_TOKEN','','secret','',0,'','optional','none','none','2026-08-17T00:00:00Z')`,
		`INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_one','tgt_one','adp_1','key_api')`,
		`INSERT INTO snapshots (id,org_id,project_id,environment_id,revision,schema_revision,published_by,published_at) VALUES ('snp_adapter','org_adapter','prj_adapter','env_one',1,1,'usr_adapter','2026-08-17T00:00:00Z')`,
		`INSERT INTO snapshot_entries (id,org_id,project_id,environment_id,snapshot_id,key_id,key_name,classification,ciphertext,value_entry_id) VALUES ('sen_adapter','org_adapter','prj_adapter','env_one','snp_adapter','key_api','API_TOKEN','secret',X'00','val_adapter')`,
	} {
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	root, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, root)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := kr.ForProject(t.Context(), "org_adapter", "prj_adapter")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.SealField(crypto.ProjectFieldAAD{OrgID: "org_adapter", ProjectID: "prj_adapter", OwnerTable: "adapters", OwnerRowID: "adp_1", FieldTag: "credential"}, []byte("provider-token"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapters SET credential_ciphertext=?,credential_set_at='2026-08-17T00:00:00Z' WHERE id='adp_1'`, sealed); err != nil {
		t.Fatal(err)
	}
	wantChange := adapter.Change{Surface: adapter.Secret, EffectiveName: "ONE_API_TOKEN", Disposition: adapter.Conflict}
	svc := &Adapters{
		DB: db, Keyring: kr,
		ModuleFactory: testModuleFactory(func(provider adapter.Provider, origin, credential string) (adapter.Module, func(), error) {
			if provider != adapter.ForgejoProvider {
				t.Fatalf("factory got provider=%q, want forgejo", provider)
			}
			if origin != "https://git.example" || credential != "provider-token" {
				t.Fatalf("factory got origin=%q credential=%q", origin, credential)
			}
			return fakeAdapterPlanModule{plan: adapter.Plan{Changes: []adapter.Change{wantChange}}}, func() {}, nil
		}),
	}
	scope := domain.Scope{Org: "org_adapter", Project: "prj_adapter"}
	result, err := svc.Plan(t.Context(), LocalPrincipal("usr_adapter"), scope, "tgt_one")
	if err != nil {
		t.Fatal(err)
	}
	if result.ArtifactID == "" || len(result.Plan.Changes) != 1 || result.Plan.Changes[0] != wantChange {
		t.Fatalf("Plan() = %+v", result)
	}
	view, err := svc.InspectTarget(t.Context(), LocalPrincipal("usr_adapter"), scope, "tgt_one")
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Conflicts) != 1 || view.Conflicts[0].ID != result.ArtifactID || len(view.Conflicts[0].Entries) != 1 || view.Conflicts[0].Entries[0].EffectiveName != "ONE_API_TOKEN" {
		t.Fatalf("InspectTarget() conflicts = %+v", view.Conflicts)
	}
	shown, err := svc.Get(t.Context(), LocalPrincipal("usr_adapter"), scope, "adp_1")
	if err != nil {
		t.Fatal(err)
	}
	shownConflicts := shown.TargetConflicts["tgt_one"]
	if len(shownConflicts) != 1 || shownConflicts[0].ID != result.ArtifactID || len(shownConflicts[0].Entries) != 1 || shownConflicts[0].Entries[0].EffectiveName != "ONE_API_TOKEN" {
		t.Fatalf("Get() target conflicts = %+v", shownConflicts)
	}
	if view.Workflow != "env:\n  API_TOKEN: ${{ secrets.ONE_API_TOKEN }}\n" {
		t.Fatalf("workflow = %q", view.Workflow)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapters SET provider='github-actions' WHERE id='adp_1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapter_targets SET destination_kind='environment',destination_environment='prod/slash',repository_id=41 WHERE id='tgt_one'`); err != nil {
		t.Fatal(err)
	}
	environmentView, err := svc.InspectTarget(t.Context(), LocalPrincipal("usr_adapter"), scope, "tgt_one")
	if err != nil {
		t.Fatal(err)
	}
	wantWorkflow := "environment: \"prod/slash\"\nenv:\n  API_TOKEN: ${{ secrets.ONE_API_TOKEN }}\n"
	if environmentView.Workflow != wantWorkflow {
		t.Fatalf("environment workflow = %q, want %q", environmentView.Workflow, wantWorkflow)
	}
}

func TestCompleteRestoreClearsRestoredAdapterCredential(t *testing.T) {
	db := adapterServiceDB(t)
	if _, err := db.SQLiteWrite().ExecContext(t.Context(), `UPDATE adapters SET credential_ciphertext=X'010203',credential_set_at='2026-08-17T00:00:00Z' WHERE id='adp_1'`); err != nil {
		t.Fatal(err)
	}
	complete := CompleteRestore(time.Now().UTC(), store.Manifest{Engine: store.EngineSQLite, SchemaVersion: 24})
	if err := storetx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error { return complete(ctx, az) }); err != nil {
		t.Fatal(err)
	}
	var credential, setAt any
	if err := db.SQLiteRead().QueryRowContext(t.Context(), `SELECT credential_ciphertext,credential_set_at FROM adapters WHERE id='adp_1'`).Scan(&credential, &setAt); err != nil {
		t.Fatal(err)
	}
	if credential != nil || setAt != nil {
		t.Fatalf("restored adapter credential survived: credential=%v set_at=%v", credential, setAt)
	}
}
