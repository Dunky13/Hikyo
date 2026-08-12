package isolation

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/authn"
	"github.com/Dunky13/hikyo/internal/store/migrate"
)

func TestSAMLArtifactsAreSingleUseAndDurable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg := store.Config{Engine: store.EngineSQLite, Path: t.TempDir() + "/saml.db"}
	if err := migrate.Run(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", store.SQLiteDSN(cfg.Path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		t.Fatal(err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	r := authn.NewSQLite(tx)
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	provider := authn.NewSAMLProvider{
		ID: "sp-1", Slug: "corp", DisplayName: "Corp SSO",
		EntityID: "https://idp.example/saml", ACSURL: "https://hikyo.example/saml/corp/acs",
		SSORedirectURL: "https://idp.example/sso", SigningCertificates: []byte(`[{"fingerprint":"sha256:01"}]`),
		MetadataSource: "file", Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := r.CreateSAMLProvider(ctx, provider); err != nil {
		t.Fatal(err)
	}
	transaction := authn.NewSAMLTransaction{
		ID: "tx-1", RequestID: "_request-1", RelayStateVerifier: []byte("relay-hash"),
		InitiatorVerifier: []byte("initiator-hash"), ProviderID: provider.ID,
		EntityID: provider.EntityID, ACSURL: provider.ACSURL, Purpose: "login",
		CredentialEpoch: 1, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}
	if err := r.CreateSAMLTransaction(ctx, transaction); err != nil {
		t.Fatal(err)
	}
	byRelay, err := r.SAMLTransactionByRelayState(ctx, transaction.RelayStateVerifier)
	if err != nil {
		t.Fatal(err)
	}
	if byRelay.ID != transaction.ID {
		t.Fatalf("relay-state lookup returned %q, want %q", byRelay.ID, transaction.ID)
	}
	claimed, err := r.ConsumeSAMLTransaction(ctx, transaction.ID, now.Add(time.Second))
	if err != nil || !claimed {
		t.Fatalf("first consume = %v, %v; want true, nil", claimed, err)
	}
	claimed, err = r.ConsumeSAMLTransaction(ctx, transaction.ID, now.Add(2*time.Second))
	if err != nil || claimed {
		t.Fatalf("second consume = %v, %v; want false, nil", claimed, err)
	}

	claimed, err = r.ClaimSAMLReplay(ctx, authn.NewSAMLReplay{
		Issuer: provider.EntityID, AssertionID: "_assertion-1",
		ExpiresAt: now.Add(11 * time.Minute), CreatedAt: now,
	})
	if err != nil || !claimed {
		t.Fatalf("first replay claim = %v, %v; want true, nil", claimed, err)
	}
	claimed, err = r.ClaimSAMLReplay(ctx, authn.NewSAMLReplay{
		Issuer: provider.EntityID, AssertionID: "_assertion-1",
		ExpiresAt: now.Add(11 * time.Minute), CreatedAt: now,
	})
	if err != nil || claimed {
		t.Fatalf("second replay claim = %v, %v; want false, nil", claimed, err)
	}
	claimed, err = r.ClaimSAMLReplay(ctx, authn.NewSAMLReplay{
		Issuer: provider.EntityID, AssertionID: "_expired-assertion",
		ExpiresAt: now.Add(-time.Second), CreatedAt: now.Add(-time.Minute),
	})
	if err != nil || !claimed {
		t.Fatalf("expired replay claim = %v, %v; want true, nil", claimed, err)
	}
	deleted, err := r.DeleteExpiredSAMLReplay(ctx, now)
	if err != nil || deleted != 1 {
		t.Fatalf("expired replay GC = %d, %v; want 1, nil", deleted, err)
	}
	claimed, err = r.ClaimSAMLReplay(ctx, authn.NewSAMLReplay{
		Issuer: provider.EntityID, AssertionID: "_expired-assertion",
		ExpiresAt: now.Add(time.Minute), CreatedAt: now,
	})
	if err != nil || !claimed {
		t.Fatalf("reclaim after replay GC = %v, %v; want true, nil", claimed, err)
	}

	if err := r.CreateSAMLSPKey(ctx, authn.NewSAMLSPKey{
		ID: "key-1", State: "active", EncryptedPrivateKey: []byte("sealed"),
		CertificateDER: []byte("certificate"), Fingerprint: "sha256:02",
		DEKVersion: 1, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	key, err := r.ActiveSAMLSPKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if key.ID != "key-1" || key.State != "active" {
		t.Fatalf("SP key mismatch: %#v", key)
	}

	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
