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

	"github.com/Dunky13/wenv/internal/store"
)

func runSAMLIdentityBackfill(t *testing.T, cfg store.Config) {
	t.Helper()
	ctx := t.Context()
	err := withProvider(ctx, cfg, func(provider *goose.Provider, db *sql.DB) error {
		if _, err := provider.UpTo(ctx, 9); err != nil {
			return err
		}
		const created = "2026-08-09T12:00:00Z"
		for _, statement := range []string{
			`INSERT INTO principals (id, kind, created_at) VALUES ('usr_saml_migration', 'human', '` + created + `')`,
			`INSERT INTO accounts (id, principal_id, username, display_name, created_at) VALUES ('acc_saml_migration', 'usr_saml_migration', 'migration-user', 'Migration User', '` + created + `')`,
			`INSERT INTO external_identities (id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at) VALUES ('eid_oidc_before_saml', 'acc_saml_migration', 'oidc', 'https://idp.example/realm', 'byte-exact-subject', 'oidcp_old', 7, '` + created + `')`,
		} {
			if _, err := db.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		if _, err := provider.UpTo(ctx, 10); err != nil {
			return err
		}
		var kind, issuer, subject string
		var epoch int64
		if err := db.QueryRowContext(ctx, `SELECT kind, issuer, subject, credential_epoch FROM external_identities WHERE id = 'eid_oidc_before_saml'`).Scan(&kind, &issuer, &subject, &epoch); err != nil {
			return err
		}
		if kind != "oidc" || issuer != "https://idp.example/realm" || subject != "byte-exact-subject" || epoch != 7 {
			return fmt.Errorf("backfilled identity = (%q, %q, %q, %d)", kind, issuer, subject, epoch)
		}
		_, err := db.ExecContext(ctx, `INSERT INTO external_identities (id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at) VALUES ('eid_saml_after_migration', 'acc_saml_migration', 'saml', 'https://idp.example/realm', 'byte-exact-subject', 'samlp_new', 7, '`+created+`')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSAMLIdentityBackfillSQLite(t *testing.T) {
	runSAMLIdentityBackfill(t, store.Config{Engine: store.EngineSQLite, Path: filepath.Join(t.TempDir(), "saml-migration.db")})
}

func TestSAMLIdentityBackfillPostgres(t *testing.T) {
	dsn := os.Getenv("WENV_TEST_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI run without WENV_TEST_POSTGRES_DSN: the postgres migration leg must not silently skip in CI")
		}
		t.Skip("WENV_TEST_POSTGRES_DSN not set")
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	base := strings.TrimPrefix(parsed.Path, "/")
	database := fmt.Sprintf("%s_saml_migration_%d", base, time.Now().UnixNano())
	admin, err := store.Open(t.Context(), store.Config{Engine: store.EnginePostgres, DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.PG().Exec(context.Background(), `DROP DATABASE IF EXISTS "`+strings.ReplaceAll(database, `"`, `""`)+`" WITH (FORCE)`)
		admin.Close()
	})
	if _, err := admin.PG().Exec(t.Context(), `CREATE DATABASE "`+strings.ReplaceAll(database, `"`, `""`)+`"`); err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + database
	runSAMLIdentityBackfill(t, store.Config{Engine: store.EnginePostgres, DSN: parsed.String()})
}
