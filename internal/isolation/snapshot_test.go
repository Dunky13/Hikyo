package isolation

// A proof certifies what authorize() saw. That claim only holds if chain
// resolution, grant evaluation and the store read observe ONE snapshot: a
// grant committed by another connection mid-transaction must be invisible
// for the rest of that transaction, on both engines (sqlite WAL reader
// snapshot; postgres REPEATABLE READ). Under postgres's default READ
// COMMITTED this test fails — each statement would take a fresh snapshot,
// so the minted proof could certify a policy no single snapshot held.

import (
	"context"
	"errors"
	"testing"

	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/service"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/tx"
)

func runReadSnapshotStability(t *testing.T, db *store.DB) {
	const late = domain.PrincipalID("usr_late")
	scope := domain.Scope{Org: orgA, Project: prjA1, Env: envA1}
	execRaw(t, db, `INSERT INTO principals (id, kind, created_at) VALUES ('usr_late', 'human', `+ts+`)`)

	// Inside one read transaction: authorize before the grant exists, then
	// grant it from another connection and commit, then authorize again.
	// Both attempts must see the same (empty) grant set.
	var first, second error
	err := tx.Read(t.Context(), db, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		_, first = az.Authorize(ctx, authz.Identity{Principal: late}, authz.OpEnvRead, scope)

		execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
			VALUES ('g_late_read', 'usr_late', 'read', 'org_a', NULL, NULL, `+ts+`)`)

		_, second = az.Authorize(ctx, authz.Identity{Principal: late}, authz.OpEnvRead, scope)
		return nil
	})
	if err != nil {
		t.Fatalf("read transaction: %v", err)
	}
	if !errors.Is(first, domain.ErrNotFound) {
		t.Fatalf("pre-grant authorize = %v, want ErrNotFound", first)
	}
	if !errors.Is(second, domain.ErrNotFound) {
		t.Fatalf("a grant committed mid-transaction became visible to the same transaction (%v) — the proof no longer certifies one snapshot", second)
	}

	// The next transaction sees it: the snapshot is per-transaction, not a
	// cache. Granting and revoking both take effect on the next operation,
	// which is what "no authorization cache" means.
	_, _, envs := services(db)
	if _, err := envs.Get(t.Context(), service.LocalPrincipal(late), scope); err != nil {
		t.Fatalf("the grant must take effect in the next transaction: %v", err)
	}
}
