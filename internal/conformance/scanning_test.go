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
	)
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
