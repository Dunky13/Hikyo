package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/Hikyo-Org/hikyo/internal/store"
)

func runAdapterEnvironmentChainRefusal(t *testing.T, cfg store.Config) {
	t.Helper()
	err := withProvider(t.Context(), cfg, func(provider *goose.Provider, db *sql.DB) error {
		if _, err := provider.Up(t.Context()); err != nil {
			return err
		}
		statements := []string{
			`INSERT INTO orgs (id,name,active,metadata,created_at) VALUES ('org_adapter','Adapter',TRUE,'{}','2026-08-17T00:00:00Z')`,
			`INSERT INTO projects (id,org_id,name,created_at) VALUES ('prj_adapter','org_adapter','Adapter','2026-08-17T00:00:00Z')`,
			`INSERT INTO environments (id,org_id,project_id,name,note,created_at,display_order) VALUES ('env_adapter_a','org_adapter','prj_adapter','a','','2026-08-17T00:00:00Z',0)`,
			`INSERT INTO environments (id,org_id,project_id,name,note,created_at,display_order) VALUES ('env_adapter_b','org_adapter','prj_adapter','b','','2026-08-17T00:00:00Z',1)`,
			`INSERT INTO principals (id,kind,created_at) VALUES ('usr_adapter','human','2026-08-17T00:00:00Z')`,
			`INSERT INTO adapters (id,org_id,project_id,provider,origin,authority_principal_id,state,created_at) VALUES ('adp_1','org_adapter','prj_adapter','forgejo','https://git.example','usr_adapter','active','2026-08-17T00:00:00Z')`,
			`INSERT INTO adapter_targets (id,org_id,project_id,environment_id,adapter_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,generation,state,sync_status,created_at) VALUES ('tgt_1','org_adapter','prj_adapter','env_adapter_a','adp_1','repository','acme','app',42,'',1,'active','never','2026-08-17T00:00:00Z')`,
			`INSERT INTO adapter_targets (id,org_id,project_id,environment_id,adapter_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,generation,state,sync_status,created_at) VALUES ('tgt_2','org_adapter','prj_adapter','env_adapter_b','adp_1','repository','acme','app',42,'TWO_',1,'active','never','2026-08-17T00:00:00Z')`,
		}
		for _, statement := range statements {
			if _, err := db.ExecContext(t.Context(), statement); err != nil {
				return err
			}
		}
		if _, err := db.ExecContext(t.Context(), `INSERT INTO adapter_route_moves (id,org_id,project_id,adapter_id,target_id,kind,authority_principal_id,state,keep_remote,created_at) VALUES ('move_bad_env','org_adapter','prj_adapter','adp_1','tgt_1','target','usr_adapter','scrubbing',FALSE,'2026-08-17T00:00:00Z')`); err != nil {
			return fmt.Errorf("insert route move fixture: %w", err)
		}
		_, err := db.ExecContext(t.Context(), `INSERT INTO adapter_route_move_targets (move_id,org_id,project_id,environment_id,target_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix) VALUES ('move_bad_env','org_adapter','prj_adapter','env_adapter_b','tgt_1','repository','acme','next',0,'')`)
		if err == nil {
			return fmt.Errorf("cross-environment adapter route-move target was accepted")
		}
		_, err = db.ExecContext(t.Context(), `INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_bad','org_adapter','prj_adapter','env_adapter_b','tgt_1','https://git.example',42,'secret','TOKEN','TOKEN','owned','2026-08-17T00:00:00Z')`)
		if err == nil {
			return fmt.Errorf("cross-environment adapter ledger row was accepted")
		}
		if _, err := db.ExecContext(t.Context(), `INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_released','org_adapter','prj_adapter','env_adapter_a','tgt_1','https://git.example',42,'secret','TOKEN','TOKEN','released','2026-08-17T00:00:00Z')`); err != nil {
			return fmt.Errorf("insert released custody history: %w", err)
		}
		if _, err := db.ExecContext(t.Context(), `INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ('led_reclaimed','org_adapter','prj_adapter','env_adapter_b','tgt_2','https://git.example',42,'secret','TOKEN','TOKEN','reserved','2026-08-17T00:01:00Z')`); err != nil {
			return fmt.Errorf("released provider name remained claimed: %w", err)
		}
		if _, err := db.ExecContext(t.Context(), `UPDATE adapter_ledger SET state='owned' WHERE id='led_released'`); err == nil {
			return fmt.Errorf("active provider name uniqueness admitted a second owner")
		}
		if _, err := db.ExecContext(t.Context(), `DELETE FROM adapter_route_moves WHERE id='move_bad_env'`); err != nil {
			return fmt.Errorf("clear cross-environment move fixture: %w", err)
		}
		// A targeted key deletion is a narrowing operation. Both the live target
		// membership and an attention-required move's pending snapshot must yield
		// to the catalogue delete rather than pinning the key forever.
		for _, statement := range []string{
			`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_delete','org_adapter','prj_adapter','DELETE_ME','','secret','',FALSE,'','optional','none','none','2026-08-17T00:00:00Z')`,
			`INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ('org_adapter','prj_adapter','env_adapter_a','tgt_1','adp_1','key_delete')`,
			`INSERT INTO adapter_route_moves (id,org_id,project_id,adapter_id,target_id,kind,authority_principal_id,state,keep_remote,created_at) VALUES ('move_key_delete','org_adapter','prj_adapter','adp_1','tgt_1','target','usr_adapter','attention_required',FALSE,'2026-08-17T00:00:00Z')`,
			`INSERT INTO adapter_route_move_targets (move_id,org_id,project_id,environment_id,target_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix) VALUES ('move_key_delete','org_adapter','prj_adapter','env_adapter_a','tgt_1','repository','acme','next',0,'NEXT_')`,
			`INSERT INTO adapter_route_move_keys (move_id,org_id,project_id,environment_id,target_id,key_id) VALUES ('move_key_delete','org_adapter','prj_adapter','env_adapter_a','tgt_1','key_delete')`,
			`INSERT INTO adapter_route_move_claims (move_id,org_id,project_id,environment_id,target_id,key_id,provider_origin,destination_kind,destination_owner,destination_name,surface,effective_name,normalized_name) VALUES ('move_key_delete','org_adapter','prj_adapter','env_adapter_a','tgt_1',NULL,'https://git.example','repository','acme','next','secret','NEXT_MANAGED_BY_WENV','NEXT_MANAGED_BY_WENV')`,
			`INSERT INTO adapter_route_move_claims (move_id,org_id,project_id,environment_id,target_id,key_id,provider_origin,destination_kind,destination_owner,destination_name,surface,effective_name,normalized_name) VALUES ('move_key_delete','org_adapter','prj_adapter','env_adapter_a','tgt_1',NULL,'https://git.example','repository','acme','next','variable','NEXT_MANAGED_BY_WENV','NEXT_MANAGED_BY_WENV')`,
			`INSERT INTO adapter_route_move_claims (move_id,org_id,project_id,environment_id,target_id,key_id,provider_origin,destination_kind,destination_owner,destination_name,surface,effective_name,normalized_name) VALUES ('move_key_delete','org_adapter','prj_adapter','env_adapter_a','tgt_1','key_delete','https://git.example','repository','acme','next','secret','NEXT_DELETE_ME','NEXT_DELETE_ME')`,
		} {
			if _, err := db.ExecContext(t.Context(), statement); err != nil {
				return fmt.Errorf("seed adapter key-delete fixture: %w", err)
			}
		}
		if _, err := db.ExecContext(t.Context(), `DELETE FROM keys WHERE org_id='org_adapter' AND project_id='prj_adapter' AND id='key_delete'`); err != nil {
			return fmt.Errorf("delete targeted key: %w", err)
		}
		var liveMemberships, pendingMemberships, sentinelClaims, keyClaims int
		if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_target_keys WHERE key_id='key_delete'`).Scan(&liveMemberships); err != nil {
			return err
		}
		if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_route_move_keys WHERE key_id='key_delete'`).Scan(&pendingMemberships); err != nil {
			return err
		}
		if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_route_move_claims WHERE move_id='move_key_delete' AND key_id IS NULL`).Scan(&sentinelClaims); err != nil {
			return err
		}
		if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM adapter_route_move_claims WHERE move_id='move_key_delete' AND key_id='key_delete'`).Scan(&keyClaims); err != nil {
			return err
		}
		if liveMemberships != 0 || pendingMemberships != 0 || sentinelClaims != 2 || keyClaims != 0 {
			return fmt.Errorf("targeted key delete retained live=%d pending=%d memberships, sentinels=%d key_claims=%d", liveMemberships, pendingMemberships, sentinelClaims, keyClaims)
		}
		for _, statement := range []string{
			`INSERT INTO keys (id,org_id,project_id,name,folder_path,classification,description,deprecated,deprecation_note,declaration,required_mode,forbidden_mode,created_at) VALUES ('key_reclaim','org_adapter','prj_adapter','DELETE_ME','','secret','',FALSE,'','optional','none','none','2026-08-17T00:01:00Z')`,
			`INSERT INTO adapter_route_move_targets (move_id,org_id,project_id,environment_id,target_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix) VALUES ('move_key_delete','org_adapter','prj_adapter','env_adapter_b','tgt_2','repository','acme','next',0,'NEXT_')`,
			`INSERT INTO adapter_route_move_keys (move_id,org_id,project_id,environment_id,target_id,key_id) VALUES ('move_key_delete','org_adapter','prj_adapter','env_adapter_b','tgt_2','key_reclaim')`,
			`INSERT INTO adapter_route_move_claims (move_id,org_id,project_id,environment_id,target_id,key_id,provider_origin,destination_kind,destination_owner,destination_name,surface,effective_name,normalized_name) VALUES ('move_key_delete','org_adapter','prj_adapter','env_adapter_b','tgt_2','key_reclaim','https://git.example','repository','acme','next','secret','NEXT_DELETE_ME','NEXT_DELETE_ME')`,
		} {
			if _, err := db.ExecContext(t.Context(), statement); err != nil {
				return fmt.Errorf("reclaim deleted pending effective name: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAdapterEnvironmentChainRefusalSQLite(t *testing.T) {
	runAdapterEnvironmentChainRefusal(t, store.Config{Engine: store.EngineSQLite, Path: filepath.Join(t.TempDir(), "adapter.db")})
}

func TestAdapterEnvironmentChainRefusalPostgres(t *testing.T) {
	dsn := os.Getenv("HIKYO_TEST_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI run without HIKYO_TEST_POSTGRES_DSN: the postgres migration leg must not silently skip in CI")
		}
		t.Skip("HIKYO_TEST_POSTGRES_DSN not set")
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	base := strings.TrimPrefix(parsed.Path, "/")
	database := fmt.Sprintf("%s_adapter_migration_%d", base, time.Now().UnixNano())
	admin, err := store.Open(t.Context(), store.Config{Engine: store.EnginePostgres, DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.PG().Exec(context.Background(), `DROP DATABASE IF EXISTS "`+strings.ReplaceAll(database, `"`, ``)+`" WITH (FORCE)`)
		admin.Close()
	})
	if _, err := admin.PG().Exec(t.Context(), `CREATE DATABASE "`+strings.ReplaceAll(database, `"`, ``)+`"`); err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + database
	runAdapterEnvironmentChainRefusal(t, store.Config{Engine: store.EnginePostgres, DSN: parsed.String()})
}
