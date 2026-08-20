package isolation

import (
	"errors"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// The per-project machine-reveal opt-in (source-of-truth ADR: "Granting
// `reveal` to a machine identity is an explicit, documented, per-project
// operator opt-in, never a default"; machine-identities ADR § Authentication,
// authorization and the fetch path; compose-integration ADR § Authorization
// and delivery). Four properties, each asserted here on both engines:
//
//  1. The grant API refuses `reveal` on a workload while the opt-in is off,
//     naming the opt-in, and admits it once the opt-in is on.
//  2. Delivery reads the opt-in LIVE: a machine holding `reveal` is delivered
//     secret plaintext only while the opt-in is on; withdrawing it returns the
//     same principal to presence-only on the next fetch without any grant row
//     moving.
//  3. The flip moves the machine's cursor both ways (the authorized delivery
//     projection changed), so a withdrawn workload is never told "current".
//  4. The setting is a project-settings act carrying `reveal`: a project
//     administrator without `reveal` cannot enable it, and both directions are
//     audited.

func TestMachineRevealOptInSQLite(t *testing.T) { runMachineRevealOptIn(t, seededDB(t, openSQLite)) }
func TestMachineRevealOptInPostgres(t *testing.T) {
	runMachineRevealOptIn(t, seededDB(t, openPostgres))
}

func runMachineRevealOptIn(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	seedDeliveryCatalogue(t, db)
	ctx := t.Context()
	del := deliverySvc(t, db)
	ident := identitySvc(db)
	settings := settingsSvc(t, db)
	env := scopeEnv(orgA, prjA1, envA1)

	sa, err := ident.CreateServiceAccount(ctx, service.LocalPrincipal(identAdmin), prjScope(), "optin-workload", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	minted, err := ident.MintCredential(ctx, service.LocalPrincipal(identAdmin), prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatal(err)
	}
	grantMachineRead(t, db, sa.Principal, envA1)
	// The operator who may flip the opt-in: project-settings AND reveal at
	// project depth (the write's formula). usr_idrev already holds reveal at
	// env_a1 for the widening ceremony; these two rows give it the project-wide
	// authority the opt-in demands.
	for _, row := range [][2]string{{"g_mr_ps", "project-settings"}, {"g_mr_rv", "reveal"}} {
		execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
			`VALUES ('`+row[0]+`', 'usr_idrev', '`+row[1]+`', 'org_a', 'prj_a1', NULL, `+ts+`)`)
		execRaw(t, db, `INSERT INTO grant_origins (id, grant_id, kind, subject, created_at) `+
			`VALUES ('gor_`+row[0]+`', '`+row[0]+`', 'manual', 'usr_idrev', `+ts+`)`)
	}
	operator := service.LocalPrincipal("usr_idrev")

	// 1. Off by default, and the grant API says which act admits it.
	got, err := settings.GetMachineReveal(ctx, operator, prjScope())
	if err != nil {
		t.Fatalf("read opt-in: %v", err)
	}
	if got.Enabled {
		t.Fatal("a fresh project has the machine-reveal opt-in on")
	}
	_, err = grantSvcWithAuth(db).Create(ctx, service.LocalPrincipal("usr_idrev"),
		service.GrantSpec{Target: sa.Principal, Capability: domain.CapReveal, Scope: envScope(envA1)})
	if !errors.Is(err, service.ErrMachineRevealOptIn) {
		t.Fatalf("reveal on a workload with the opt-in off: got %v, want ErrMachineRevealOptIn", err)
	}

	// 4a. A project administrator without `reveal` cannot confer it by flipping
	// the opt-in: usr_ident holds manage-identities and deliberately no
	// disclosure capability.
	if _, err := settings.SetMachineReveal(ctx, service.LocalPrincipal(identAdmin), prjScope(), true); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("enabling without reveal: got %v, want the uniform nonexistent refusal", err)
	}
	if queryInt(t, db, `SELECT COUNT(*) FROM projects WHERE id = 'prj_a1' AND machine_reveal = TRUE`) != 0 {
		t.Fatal("a refused enable wrote the column")
	}

	// Enable under root (project-settings ∧ reveal at project depth, no session
	// so no assurance leg), then the grant lands through the normal widening
	// ceremony path.
	if _, err := settings.SetMachineReveal(ctx, operator, prjScope(), true); err != nil {
		t.Fatalf("enable opt-in: %v", err)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'settings.machine_reveal_changed' AND payload LIKE '%"enabled":true%'`); n != 1 {
		t.Fatalf("enable audited %d times, want 1", n)
	}
	// With the opt-in on, the allowlist admits the grant and the ONLY thing
	// left standing is the widening ceremony (machine-identities ADR: a grant
	// whose post-state reaches plaintext reauthenticates over what it reaches).
	// That refusal proves the opt-in gate passed; the ceremony is exercised by
	// the identities suite, so the grant itself is seeded beside the opt-in.
	_, err = grantSvcWithAuth(db).Create(ctx, service.LocalPrincipal("usr_idrev"),
		service.GrantSpec{Target: sa.Principal, Capability: domain.CapReveal, Scope: envScope(envA1)})
	if errors.Is(err, service.ErrMachineRevealOptIn) || err == nil || !strings.Contains(err.Error(), "reauthenticate") {
		t.Fatalf("reveal on a workload with the opt-in on: got %v, want the widening-ceremony refusal", err)
	}
	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
		`VALUES ('g_mr_wl', '`+string(sa.Principal)+`', 'reveal', 'org_a', 'prj_a1', 'env_a1', `+ts+`)`)
	execRaw(t, db, `INSERT INTO grant_origins (id, grant_id, kind, subject, created_at) `+
		`VALUES ('gor_g_mr_wl', 'g_mr_wl', 'manual', 'usr_idrev', `+ts+`)`)

	// 2/3. Delivered plaintext while on; presence-only and a moved cursor once
	// withdrawn; plaintext and a moved cursor again once re-enabled.
	on, err := del.Fetch(ctx, minted.Value, env, "", service.FetchOptions{})
	if err != nil {
		t.Fatalf("fetch with the opt-in on: %v", err)
	}
	if v := valueOf(on.Keys, "DATABASE_PASSWORD"); v == nil || *v == "" {
		t.Fatal("a workload holding reveal under the opt-in was not delivered secret plaintext")
	}
	if _, err := settings.SetMachineReveal(ctx, operator, prjScope(), false); err != nil {
		t.Fatalf("withdraw opt-in: %v", err)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM grants WHERE principal_id = '`+string(sa.Principal)+`' AND capability = 'reveal'`); n != 1 {
		t.Fatalf("withdrawal moved grant rows (%d reveal rows), want the grant untouched", n)
	}
	off, err := del.Fetch(ctx, minted.Value, env, on.Cursor, service.FetchOptions{})
	if err != nil {
		t.Fatalf("fetch after withdrawal: %v", err)
	}
	if off.Current {
		t.Fatal("withdrawing the opt-in left the workload's cursor current")
	}
	if v := valueOf(off.Keys, "DATABASE_PASSWORD"); v != nil {
		t.Fatal("a workload was delivered secret plaintext after the opt-in was withdrawn")
	}
	if v := valueOf(off.Keys, "DATABASE_URL"); v == nil {
		t.Fatal("withdrawal removed config delivery; only secret plaintext is governed by the opt-in")
	}
	// The CHANGE TOKEN is content-bound and must NOT move: nothing was
	// published. It is the cursor's projection component that moved, which is
	// exactly the machine-identities ADR's reason for binding the cursor to
	// the authorized projection rather than to content alone.
	if off.ChangeToken != on.ChangeToken {
		t.Fatal("withdrawing the opt-in moved the change token: the fixture changed content, not authorization")
	}
	if _, err := settings.SetMachineReveal(ctx, operator, prjScope(), true); err != nil {
		t.Fatalf("re-enable opt-in: %v", err)
	}
	again, err := del.Fetch(ctx, minted.Value, env, off.Cursor, service.FetchOptions{})
	if err != nil {
		t.Fatalf("fetch after re-enable: %v", err)
	}
	if again.Current {
		t.Fatal("re-enabling the opt-in left the presence-only cursor current")
	}
	if v := valueOf(again.Keys, "DATABASE_PASSWORD"); v == nil || *v == "" {
		t.Fatal("re-enabling the opt-in did not restore secret delivery on the next fetch")
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'settings.machine_reveal_changed'`); n != 3 {
		t.Fatalf("opt-in flips audited %d times, want 3", n)
	}
	// An idempotent write is not a flip and is not audited as one.
	if _, err := settings.SetMachineReveal(ctx, operator, prjScope(), true); err != nil {
		t.Fatal(err)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'settings.machine_reveal_changed'`); n != 3 {
		t.Fatalf("an idempotent write was audited as a flip (%d events)", n)
	}
}

func valueOf(keys []service.DeliveredKey, name string) *string {
	for _, k := range keys {
		if k.Name == name {
			return k.Value
		}
	}
	return nil
}

// runMachineRevealAuditLifecycle gives settings.machine_reveal_changed its
// real emitter for the audit registry's closure check: one operator holding
// project-settings and reveal at project depth flips the opt-in on and off.
func runMachineRevealAuditLifecycle(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := t.Context()
	execRaw(t, db, `INSERT INTO principals (id, kind, created_at) VALUES ('usr_mra', 'human', `+ts+`)`)
	for _, row := range [][2]string{{"g_mra_ps", "project-settings"}, {"g_mra_rv", "reveal"}} {
		execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
			`VALUES ('`+row[0]+`', 'usr_mra', '`+row[1]+`', 'org_a', 'prj_a1', NULL, `+ts+`)`)
		execRaw(t, db, `INSERT INTO grant_origins (id, grant_id, kind, subject, created_at) `+
			`VALUES ('gor_`+row[0]+`', '`+row[0]+`', 'manual', 'usr_mra', `+ts+`)`)
	}
	settings := settingsSvc(t, db)
	operator := service.LocalPrincipal("usr_mra")
	for _, enabled := range []bool{true, false} {
		if _, err := settings.SetMachineReveal(ctx, operator, prjScope(), enabled); err != nil {
			t.Fatalf("machine-reveal opt-in -> %t: %v", enabled, err)
		}
	}
}
