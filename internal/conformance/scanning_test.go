package conformance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/scanning"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// The secret-scanning dismissal-row store surface (#74, secret-scanning ADR
// section 4), cross-engine: the keyed value fingerprint through the crypto
// package, the (org, project, env, key, rule digest, fingerprint) uniqueness,
// and the ADR section 4 lifecycle deletes — each through authorize() and a
// proof-bound repo method, exactly as production reaches them.
func init() {
	corpus = append(corpus,
		scenario{"scanning_dismissal_uniqueness_and_lifecycle", scenarioScanningDismissals},
		scenario{"scanning_key_rotation_drops_all_and_refingerprints", scenarioScanningKeyRotation},
		scenario{"scanning_key_delete_drops_dismissals", scenarioScanningKeyDeleteDropsDismissals},
		scenario{"scanning_surface2_block_mints_no_project_key", scenarioScanningPreflightNoOrphanKey},
	)
}

// countProjectDEK reads how many active tier-3 project DEK rows exist for a
// scope, straight from the keystore table, on either engine.
func countProjectDEK(t *testing.T, db *store.DB, scope domain.Scope) int {
	t.Helper()
	var n int
	if db.Engine() == store.EnginePostgres {
		if err := db.PG().QueryRow(t.Context(),
			`SELECT COUNT(*) FROM tier3_keys WHERE purpose='project' AND org_id=$1 AND project_id=$2 AND state='active'`,
			string(scope.Org), string(scope.Project)).Scan(&n); err != nil {
			t.Fatalf("count project DEK: %v", err)
		}
		return n
	}
	if err := db.SQLiteRead().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM tier3_keys WHERE purpose='project' AND org_id=? AND project_id=? AND state='active'`,
		string(scope.Org), string(scope.Project)).Scan(&n); err != nil {
		t.Fatalf("count project DEK: %v", err)
	}
	return n
}

// scenarioScanningPreflightNoOrphanKey is the F2a regression fixture (#74, ADR
// §7): a Surface-2 refusal must persist NOTHING but the finding_blocked events —
// in particular no wrapped project-DEK row. Environment create and key create
// are the two first-mint ingresses: on a fresh project (no key, no value) their
// sealer resolution mints the project DEK. If the scan ran only inside the write
// transaction, a block would roll the write back but leave the separately
// committed DEK row behind. The pre-flight reaches the verdict before the mint,
// so a blocked create leaves the project with zero DEK rows. Both engines.
func scenarioScanningPreflightNoOrphanKey(t *testing.T, db *store.DB) {
	ctx := t.Context()
	who, scope := tenantFixture(t, db, "scanpf")
	kr := sharedKeyring(t, db)
	rs, err := scanning.Load()
	if err != nil {
		t.Fatalf("load ruleset: %v", err)
	}
	actor := service.LocalPrincipal(who)
	// A classic non-live AWS access key id — the aws-access-token rule matches it.
	const planted = "AKIAIOSFODNN7EXAMPLE"

	// Fresh project: no DEK has been minted yet, so the assertions below mean
	// something.
	if n := countProjectDEK(t, db, scope); n != 0 {
		t.Fatalf("fresh project already has %d DEK rows; test premise broken", n)
	}

	envs := &service.Environments{DB: db, Keyring: kr, Scan: rs}
	keys := &service.Keys{DB: db, Keyring: kr, Scan: rs}

	// Blocked environment create: the env name carries a credential.
	_, envErr := envs.Create(ctx, actor, scope, planted, nil)
	if !errors.Is(envErr, domain.ErrInvalid) {
		t.Fatalf("credential-named env create: err = %v, want invalid refusal", envErr)
	}
	if n := countProjectDEK(t, db, scope); n != 0 {
		t.Fatalf("blocked env create left %d project DEK row(s) behind — pre-transaction mint leaked", n)
	}

	// Blocked key create: the credential lands in the description.
	_, keyErr := keys.Create(ctx, actor, scope, service.KeySpec{
		Name: "OK_NAME", Classification: string(schema.Config), Description: planted,
		Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}},
		Presence:    schema.DefaultPresenceRules(),
	}, nil)
	if !errors.Is(keyErr, domain.ErrInvalid) {
		t.Fatalf("credential-carrying key create: err = %v, want invalid refusal", keyErr)
	}
	if n := countProjectDEK(t, db, scope); n != 0 {
		t.Fatalf("blocked key create left %d project DEK row(s) behind — pre-transaction mint leaked", n)
	}

	// The block events landed (nothing else): one finding_blocked per refusal.
	var blocked int
	if db.Engine() == store.EnginePostgres {
		err = db.PG().QueryRow(ctx, `SELECT COUNT(*) FROM audit_tenant_events WHERE type='scanning.finding_blocked' AND org_id=$1`, string(scope.Org)).Scan(&blocked)
	} else {
		err = db.SQLiteRead().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_tenant_events WHERE type='scanning.finding_blocked' AND org_id=?`, string(scope.Org)).Scan(&blocked)
	}
	if err != nil {
		t.Fatalf("count finding_blocked: %v", err)
	}
	if blocked < 2 {
		t.Fatalf("finding_blocked events = %d, want ≥2 (one per refused create)", blocked)
	}
}

// scenarioScanningKeyDeleteDropsDismissals drives the SERVICE Keys.Delete path
// with a dismissal present (#74, ADR §4 lifecycle: "key deletion deletes
// them"). The dismissal row carries a non-cascading composite FK to the key, so
// without Keys.Delete dropping the rows first the delete FAILS on the FK — this
// asserts the whole service ceremony completes and the row is gone, on both
// engines. Distinct from scenarioScanningDismissals, which exercises the repo's
// DeleteByKey directly rather than the service call site.
func scenarioScanningKeyDeleteDropsDismissals(t *testing.T, db *store.DB) {
	ctx := t.Context()
	who, scope := tenantFixture(t, db, "scandel")
	kr := sharedKeyring(t, db)
	actor := service.LocalPrincipal(who)

	env, err := (&service.Environments{DB: db, Keyring: kr}).Create(ctx, actor, scope, "scandel-env", nil)
	if err != nil {
		t.Fatal(err)
	}
	envScope := scope
	envScope.Env = domain.EnvID(env.ID)
	keys := &service.Keys{DB: db, Keyring: kr}
	key, err := keys.Create(ctx, actor, scope, service.KeySpec{
		Name: "DELETE_ME", Classification: string(schema.Config),
		Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}},
		Presence:    schema.DefaultPresenceRules(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Plant a dismissal row for the key (the warn→keep-as-config outcome) via the
	// same proof-bound repo the stage path uses.
	fp := kr.ScanningFingerprint(string(scope.Org), string(scope.Project), env.ID, key.ID, []byte("AKIAIOSFODNN7EXAMPLE"))
	if err := tx.Write(ctx, db, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: who}, authz.OpValueStage, envScope)
		if err != nil {
			return err
		}
		return r.ScanningDismissals().Insert(ctx, p, store.NewDismissal{
			ID: "sdm_del", KeyID: key.ID, RuleDigest: "sha256:rule-aws-access-token", Fingerprint: fp,
			CreatedBy: string(who), CreatedAt: store.CanonTime(time.Now()),
		})
	}); err != nil {
		t.Fatalf("plant dismissal: %v", err)
	}

	// The key holds no value, so the delete is not refused for delivered
	// material; without the dismissal drop it would still fail on the FK.
	if err := keys.Delete(ctx, actor, scope, key.ID); err != nil {
		t.Fatalf("Keys.Delete with a dismissal present failed (FK not dropped?): %v", err)
	}

	// The dismissal is gone: its key no longer exists, and the row went with it.
	if err := tx.Write(ctx, db, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: who}, authz.OpValueStage, envScope)
		if err != nil {
			return err
		}
		if ok, err := r.ScanningDismissals().Exists(ctx, p, key.ID, "sha256:rule-aws-access-token", fp); err != nil || ok {
			return fmt.Errorf("dismissal survived Keys.Delete: exists=%v err=%v", ok, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// scenarioScanningKeyRotation drives the service rotate-scanning-key end to end
// (#74): it drops every dismissal in one transaction and installs a new key so
// the same value re-fingerprints differently — the re-fire the operation exists
// to cause.
func scenarioScanningKeyRotation(t *testing.T, db *store.DB) {
	ctx := t.Context()
	who, scope := tenantFixture(t, db, "scanrot")
	seed(t, db, []string{
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
		 VALUES ('grt_scanrot_rotate', '` + string(who) + `', 'rotate-dek', NULL, NULL, NULL, '2026-01-01T00:00:00Z')`,
	})
	kr := sharedKeyring(t, db)
	actor := service.LocalPrincipal(who)
	env, err := (&service.Environments{DB: db, Keyring: kr}).Create(ctx, actor, scope, "scanrot-env", nil)
	if err != nil {
		t.Fatal(err)
	}
	envScope := scope
	envScope.Env = domain.EnvID(env.ID)
	key, err := (&service.Keys{DB: db, Keyring: kr}).Create(ctx, actor, scope, service.KeySpec{
		Name: "TOKEN_URL", Classification: string(schema.Config),
		Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}},
		Presence:    schema.DefaultPresenceRules(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	before := kr.ScanningFingerprint(string(scope.Org), string(scope.Project), env.ID, key.ID, []byte("AKIAIOSFODNN7EXAMPLE"))
	if err := tx.Write(ctx, db, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: who}, authz.OpValueStage, envScope)
		if err != nil {
			return err
		}
		return r.ScanningDismissals().Insert(ctx, p, store.NewDismissal{
			ID: "sdm_rot", KeyID: key.ID, RuleDigest: "sha256:rule", Fingerprint: before,
			CreatedBy: string(who), CreatedAt: store.CanonTime(time.Now()),
		})
	}); err != nil {
		t.Fatal(err)
	}

	// The rotation must run on the SAME keyring instance the fingerprint is read
	// from, so its post-commit adopt updates the handle this test then reads.
	rotation, err := (&service.Revisions{DB: db, Keyring: kr}).RotateScanningKey(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	if rotation.DismissalsDropped != 1 {
		t.Fatalf("rotation dropped %d dismissals, want 1", rotation.DismissalsDropped)
	}

	after := kr.ScanningFingerprint(string(scope.Org), string(scope.Project), env.ID, key.ID, []byte("AKIAIOSFODNN7EXAMPLE"))
	if bytes.Equal(before, after) {
		t.Fatal("fingerprint unchanged after rotation — old fingerprints must die")
	}
	// The dropped dismissal is gone: the same value now re-warns (Exists false
	// even against the pre-rotation fingerprint, which no longer matches anything).
	if err := tx.Write(ctx, db, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: who}, authz.OpValueStage, envScope)
		if err != nil {
			return err
		}
		if ok, err := r.ScanningDismissals().Exists(ctx, p, key.ID, "sha256:rule", before); err != nil || ok {
			return fmt.Errorf("dismissal survived rotation: exists=%v err=%v", ok, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func scenarioScanningDismissals(t *testing.T, db *store.DB) {
	ctx := t.Context()
	who, scope := tenantFixture(t, db, "scanning")
	// DeleteAll rides rotate-scanning-key, an instance operation, so the caller
	// needs rotate-dek at instance scope (org/project/env all NULL).
	seed(t, db, []string{
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
		 VALUES ('grt_scanning_rotate', '` + string(who) + `', 'rotate-dek', NULL, NULL, NULL, '2026-01-01T00:00:00Z')`,
	})
	kr := sharedKeyring(t, db)
	actor := service.LocalPrincipal(who)
	envs := &service.Environments{DB: db, Keyring: kr}
	keys := &service.Keys{DB: db, Keyring: kr}

	env, err := envs.Create(ctx, actor, scope, "scanning-env", nil)
	if err != nil {
		t.Fatal(err)
	}
	envScope := scope
	envScope.Env = domain.EnvID(env.ID)
	key, err := keys.Create(ctx, actor, scope, service.KeySpec{
		Name: "API_URL", Classification: string(schema.Config),
		Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}},
		Presence:    schema.DefaultPresenceRules(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// The fingerprint is keyed and scope-bound: a bare hash of "AKIA..." is NOT
	// what lands in the row (SS4's stolen-dump property is asserted here — the
	// stored bytes differ from any unkeyed digest because they are HMAC output
	// under the instance's scanning key, which a dump does not carry live).
	fp := kr.ScanningFingerprint(string(scope.Org), string(scope.Project), env.ID, key.ID, []byte("AKIAIOSFODNN7EXAMPLE"))
	fpOther := kr.ScanningFingerprint(string(scope.Org), string(scope.Project), env.ID, key.ID, []byte("AKIAI44QH8DHBEXAMPLE"))
	const digest = "sha256:rule-aws-access-token"
	now := store.CanonTime(time.Now())

	stage := func(fn func(context.Context, store.ScanningDismissalRepo, authz.Proof) error) error {
		return tx.Write(ctx, db, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
			p, err := az.Authorize(ctx, authz.Identity{Principal: who}, authz.OpValueStage, envScope)
			if err != nil {
				return err
			}
			return fn(ctx, r.ScanningDismissals(), p)
		})
	}

	// Insert one dismissal.
	if err := stage(func(ctx context.Context, d store.ScanningDismissalRepo, p authz.Proof) error {
		return d.Insert(ctx, p, store.NewDismissal{
			ID: "sdm_1", KeyID: key.ID, RuleDigest: digest, Fingerprint: fp,
			CreatedBy: string(who), CreatedAt: now,
		})
	}); err != nil {
		t.Fatalf("insert dismissal: %v", err)
	}

	// A second insert of the identical identity tuple is refused by the UNIQUE
	// constraint (its own transaction, since a constraint hit aborts the tx on
	// postgres). This is the sticky-dismissal property: one row per accepted value.
	dupErr := stage(func(ctx context.Context, d store.ScanningDismissalRepo, p authz.Proof) error {
		return d.Insert(ctx, p, store.NewDismissal{
			ID: "sdm_2", KeyID: key.ID, RuleDigest: digest, Fingerprint: fp,
			CreatedBy: string(who), CreatedAt: now,
		})
	})
	if !errors.Is(dupErr, domain.ErrConflict) {
		t.Fatalf("duplicate dismissal error = %v, want conflict", dupErr)
	}

	// Exists: the exact tuple matches; a distinct fingerprint and a distinct
	// rule digest do not (the scope coordinates each participate in the identity).
	if err := stage(func(ctx context.Context, d store.ScanningDismissalRepo, p authz.Proof) error {
		if ok, err := d.Exists(ctx, p, key.ID, digest, fp); err != nil || !ok {
			return fmt.Errorf("exists(exact) = %v, %v; want true", ok, err)
		}
		if ok, err := d.Exists(ctx, p, key.ID, digest, fpOther); err != nil || ok {
			return fmt.Errorf("exists(other fingerprint) = %v, %v; want false", ok, err)
		}
		if ok, err := d.Exists(ctx, p, key.ID, "sha256:rule-other", fp); err != nil || ok {
			return fmt.Errorf("exists(other digest) = %v, %v; want false", ok, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// DeleteByKey (reclassify-to-secret / key deletion): the key's rows go, and
	// the warn will re-fire.
	if err := tx.Write(ctx, db, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: who}, authz.OpKeyDelete, scope)
		if err != nil {
			return err
		}
		n, err := r.ScanningDismissals().DeleteByKey(ctx, p, key.ID)
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("DeleteByKey removed %d rows, want 1", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := stage(func(ctx context.Context, d store.ScanningDismissalRepo, p authz.Proof) error {
		if ok, err := d.Exists(ctx, p, key.ID, digest, fp); err != nil || ok {
			return fmt.Errorf("exists after DeleteByKey = %v, %v; want false", ok, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// DeleteByProject (project deletion): re-insert, then drop by project.
	if err := stage(func(ctx context.Context, d store.ScanningDismissalRepo, p authz.Proof) error {
		return d.Insert(ctx, p, store.NewDismissal{
			ID: "sdm_3", KeyID: key.ID, RuleDigest: digest, Fingerprint: fp,
			CreatedBy: string(who), CreatedAt: now,
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Write(ctx, db, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: who}, authz.OpProjectDelete, scope)
		if err != nil {
			return err
		}
		n, err := r.ScanningDismissals().DeleteByProject(ctx, p)
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("DeleteByProject removed %d rows, want 1", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// DeleteAll (scanning-key rotation): re-insert, then drop instance-wide.
	if err := stage(func(ctx context.Context, d store.ScanningDismissalRepo, p authz.Proof) error {
		return d.Insert(ctx, p, store.NewDismissal{
			ID: "sdm_4", KeyID: key.ID, RuleDigest: digest, Fingerprint: fp,
			CreatedBy: string(who), CreatedAt: now,
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Write(ctx, db, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: who}, authz.OpRotateScanningKey, domain.Scope{})
		if err != nil {
			return err
		}
		n, err := r.ScanningDismissals().DeleteAll(ctx, p)
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("DeleteAll removed %d rows, want 1", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
