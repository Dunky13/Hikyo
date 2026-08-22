package isolation

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/api"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// The permission model's own fixtures (#55): the grant-authority rules, the
// lockout invariant, dedup, template expansion, the normative machine
// allowlists, revocation killing a live session, and the protected-environment
// cap. Every one runs against a real datastore on both engines.

func grantSvc(db *store.DB) *service.Grants { return &service.Grants{DB: db} }

func settingsSvc(_ *testing.T, db *store.DB) *service.ProjectSettings {
	return &service.ProjectSettings{DB: db, Auth: &service.Auth{DB: db}}
}

func envScope(env domain.EnvID) domain.Scope {
	return domain.Scope{Org: orgA, Project: prjA1, Env: env}
}

func prjScope() domain.Scope { return domain.Scope{Org: orgA, Project: prjA1} }

// held reports whether the principal currently holds the triple, read through
// the same resolution surface authorize() uses.
func held(t *testing.T, db *store.DB, p domain.PrincipalID, c domain.Capability, scope domain.Scope) bool {
	t.Helper()
	var found bool
	err := tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		rows, err := az.GrantRowsForPrincipal(ctx, p)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.Grant.Capability == c && row.Grant.Scope == scope {
				found = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func originCount(t *testing.T, db *store.DB, p domain.PrincipalID, c domain.Capability, scope domain.Scope) int {
	t.Helper()
	var n int
	err := tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		rows, err := az.GrantRowsForPrincipal(ctx, p)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.Grant.Capability != c || row.Grant.Scope != scope {
				continue
			}
			origins, err := az.GrantOriginsFor(ctx, row.ID)
			if err != nil {
				return err
			}
			n = len(origins)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestGrantAuthoritySQLite(t *testing.T)   { runGrantAuthority(t, seededDB(t, openSQLite)) }
func TestGrantAuthorityPostgres(t *testing.T) { runGrantAuthority(t, seededDB(t, openPostgres)) }

// runGrantAuthority: `manage-members` at ORG scope may grant a capability the
// grantor does not hold; the same capability at PROJECT scope may not. This is
// the ADR's administrative bound and the reason a stolen project-admin account
// is not automatic full compromise of the project's secrets.
func runGrantAuthority(t *testing.T, db *store.DB) {
	g := grantSvc(db)
	ctx := t.Context()

	// orgAdmin holds no `publish` anywhere, and grants it anyway — the
	// escalation path the threat model accepts at org scope.
	if _, err := g.Create(ctx, service.LocalPrincipal(orgAdmin), service.GrantSpec{
		Target: grantee, Capability: domain.CapPublish, Scope: prjScope(),
	}); err != nil {
		t.Fatalf("org-scope manage-members must be able to grant an unheld capability: %v", err)
	}
	if !held(t, db, grantee, domain.CapPublish, prjScope()) {
		t.Fatal("the unheld-capability grant did not land")
	}

	// prjAdmin holds `manage-members` only at project scope, and `read` is
	// the only capability they hold there.
	if _, err := g.Create(ctx, service.LocalPrincipal(prjAdmin), service.GrantSpec{
		Target: grantee, Capability: domain.CapEdit, Scope: prjScope(),
	}); !errors.Is(err, service.ErrGrantorLacksCapability) {
		t.Fatalf("project-scope manage-members granting an unheld capability: got %v, want ErrGrantorLacksCapability", err)
	}
	if _, err := g.Create(ctx, service.LocalPrincipal(prjAdmin), service.GrantSpec{
		Target: grantee, Capability: domain.CapRead, Scope: prjScope(),
	}); err != nil {
		t.Fatalf("project-scope manage-members granting a HELD capability must succeed: %v", err)
	}
}

func TestGrantPerOrgCapSQLite(t *testing.T)   { runGrantPerOrgCap(t, seededDB(t, openSQLite)) }
func TestGrantPerOrgCapPostgres(t *testing.T) { runGrantPerOrgCap(t, seededDB(t, openPostgres)) }

// runGrantPerOrgCap: the ops-spec § 8 loud sanity cap. Once an org holds
// MaxGrantsPerOrg grant rows, a new grant is refused by name — the cap exists
// to make runaway minting loud, not to ration. Counted inside the granting
// transaction, so it holds on both engines.
func runGrantPerOrgCap(t *testing.T, db *store.DB) {
	g := grantSvc(db)
	ctx := t.Context()

	// Fill org_a to the cap with org-scope filler rows. The table carries no
	// uniqueness over the triple (see runGrantDedup), so one principal and one
	// capability suffice; raw-seeded so the test does not pay for
	// MaxGrantsPerOrg real grant transactions.
	var b strings.Builder
	b.WriteString("INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ")
	for i := 0; i < service.MaxGrantsPerOrg; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "('grt_fill_%d', 'usr_grantee', 'read', 'org_a', NULL, NULL, '2026-01-01T00:00:00.000000Z')", i)
	}
	execRaw(t, db, b.String())

	// A genuinely new grant now exceeds the cap and is refused by name.
	if _, err := g.Create(ctx, service.LocalPrincipal(orgAdmin), service.GrantSpec{
		Target: grantee, Capability: domain.CapPublish, Scope: prjScope(),
	}); !errors.Is(err, domain.ErrLimitExceeded) {
		t.Fatalf("granting past the per-org cap must be refused with ErrLimitExceeded: %v", err)
	}
}

func TestGrantDedupSQLite(t *testing.T)   { runGrantDedup(t, seededDB(t, openSQLite)) }
func TestGrantDedupPostgres(t *testing.T) { runGrantDedup(t, seededDB(t, openPostgres)) }

// runGrantDedup: the table carries no uniqueness over the triple on purpose,
// so dedup is the API's job. Two grantors granting the same triple leave ONE
// row held by TWO origins; one revoking leaves the row alive for the other.
func runGrantDedup(t *testing.T, db *store.DB) {
	g := grantSvc(db)
	ctx := t.Context()
	spec := service.GrantSpec{Target: grantee, Capability: domain.CapRead, Scope: prjScope()}

	var grantID string
	for _, tc := range []struct {
		name        string
		actor       domain.PrincipalID
		want        service.GrantOutcome
		wantOrigins int
	}{
		{name: "new grant", actor: orgAdmin, want: service.GrantCreated(), wantOrigins: 1},
		{name: "idempotent repeat", actor: orgAdmin, want: service.GrantUnchanged(), wantOrigins: 1},
		{name: "second origin", actor: prjAdmin, want: service.GrantOriginAdded(), wantOrigins: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := g.Create(ctx, service.LocalPrincipal(tc.actor), spec)
			if err != nil {
				t.Fatal(err)
			}
			if grantID == "" {
				grantID = result.GrantID
			}
			if result.Outcome != tc.want || result.GrantID != grantID {
				t.Fatalf("grant result = %+v, want outcome %q and id %q", result, tc.want, grantID)
			}
			if got := originCount(t, db, grantee, domain.CapRead, prjScope()); got != tc.wantOrigins {
				t.Fatalf("origin count = %d, want %d", got, tc.wantOrigins)
			}
		})
	}

	// A grant at a DIFFERENT scope is a different row, not a dedup: the two
	// have different blast radii and revoking one must not take the other.
	if _, err := g.Create(ctx, service.LocalPrincipal(orgAdmin), service.GrantSpec{
		Target: grantee, Capability: domain.CapRead, Scope: envScope(envA1),
	}); err != nil {
		t.Fatal(err)
	}
	if !held(t, db, grantee, domain.CapRead, envScope(envA1)) || !held(t, db, grantee, domain.CapRead, prjScope()) {
		t.Fatal("a narrower grant must not collapse into the wider one")
	}
}

func TestGrantRevokeReleasesOneOriginSQLite(t *testing.T) {
	runGrantRevokeOrigins(t, seededDB(t, openSQLite))
}
func TestGrantRevokeReleasesOneOriginPostgres(t *testing.T) {
	runGrantRevokeOrigins(t, seededDB(t, openPostgres))
}

// runGrantRevokeOrigins: a revoke releases the origins this surface owns and
// deletes the row only when the LAST one is gone.
func runGrantRevokeOrigins(t *testing.T, db *store.DB) {
	g := grantSvc(db)
	ctx := t.Context()
	spec := service.GrantSpec{Target: grantee, Capability: domain.CapRead, Scope: prjScope()}
	if _, err := g.Create(ctx, service.LocalPrincipal(orgAdmin), spec); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Create(ctx, service.LocalPrincipal(prjAdmin), spec); err != nil {
		t.Fatal(err)
	}
	// One revoke releases every origin this surface owns, so the row dies —
	// the deliberate v1 semantic, stated in the handoff: only #73's
	// system-owned origins survive a human revocation.
	if err := g.Revoke(ctx, service.LocalPrincipal(orgAdmin), spec); err != nil {
		t.Fatal(err)
	}
	if held(t, db, grantee, domain.CapRead, prjScope()) {
		t.Fatal("releasing the last origin must delete the grant row")
	}
	if err := g.Revoke(ctx, service.LocalPrincipal(orgAdmin), spec); !errors.Is(err, service.ErrNoSuchGrant) {
		t.Fatalf("revoking a grant that is not held: got %v, want ErrNoSuchGrant", err)
	}
}

func TestLockoutInvariantSQLite(t *testing.T)   { runLockoutInvariant(t, seededDB(t, openSQLite)) }
func TestLockoutInvariantPostgres(t *testing.T) { runLockoutInvariant(t, seededDB(t, openPostgres)) }

// runLockoutInvariant: removing the LAST `manage-members` holder is refused at
// org scope and at instance scope. An unadministrable org is a support incident
// with no in-product recovery, so the API must not be able to produce one.
func runLockoutInvariant(t *testing.T, db *store.DB) {
	g := grantSvc(db)
	ctx := t.Context()

	// org A's manage-members holders are orgAdmin (org scope) and root
	// (instance scope, inheriting downward). Revoking orgAdmin's is allowed
	// while root's covers the org...
	if err := g.Revoke(ctx, service.LocalPrincipal(root), service.GrantSpec{
		Target: orgAdmin, Capability: domain.CapManageMembers, Scope: orgAScope,
	}); err != nil {
		t.Fatalf("revoking one of two org member managers must be allowed: %v", err)
	}
	// ...and revoking root's instance-scope grant is then refused twice over:
	// it is the last instance holder AND the last one covering org A.
	if err := g.Revoke(ctx, service.LocalPrincipal(root), service.GrantSpec{
		Target: root, Capability: domain.CapManageMembers, Scope: domain.Scope{},
	}); !errors.Is(err, service.ErrLastMemberManager) {
		t.Fatalf("revoking the last instance manage-members holder: got %v, want ErrLastMemberManager", err)
	}
	// The invariant does not bind project scope: an org with no project-scope
	// member manager is still administrable from the org.
	if err := g.Revoke(ctx, service.LocalPrincipal(root), service.GrantSpec{
		Target: prjAdmin, Capability: domain.CapManageMembers, Scope: prjScope(),
	}); err != nil {
		t.Fatalf("project-scope manage-members is not the lockout invariant's subject: %v", err)
	}
}

func TestMachineAllowlistSQLite(t *testing.T)   { runMachineAllowlist(t, seededDB(t, openSQLite)) }
func TestMachineAllowlistPostgres(t *testing.T) { runMachineAllowlist(t, seededDB(t, openPostgres)) }

// runMachineAllowlist: the allowlists are NORMATIVE — the grant API refuses,
// it does not merely document. No machine principal holds `manage-members`,
// `manage-projects`, `project-settings` or any instance capability; a workload
// credential holds `read` and nothing else; `scim-provision` is system-created
// and refused here outright; an unclassified machine principal holds nothing.
func runMachineAllowlist(t *testing.T, db *store.DB) {
	g := grantSvc(db)
	ctx := t.Context()
	for _, tc := range []struct {
		name    string
		target  domain.PrincipalID
		cap     domain.Capability
		scope   domain.Scope
		wantErr error
	}{
		{"workload_manage_members", mchWork, domain.CapManageMembers, prjScope(), service.ErrMachineCapability},
		{"workload_project_settings", mchWork, domain.CapProjectSettings, prjScope(), service.ErrMachineCapability},
		{"workload_manage_projects", mchWork, domain.CapManageProjects, orgAScope, service.ErrMachineCapability},
		{"workload_instance_config", mchWork, domain.CapInstanceConfig, domain.Scope{}, service.ErrMachineCapability},
		// `reveal` is admitted onto a workload only under the source-of-truth
		// ADR's per-project operator opt-in; the seeded project has it off, so
		// the refusal names the opt-in (machine_reveal_e2e_test covers the on
		// side). `reveal-history` stays off the workload allowlist outright.
		{"workload_reveal", mchWork, domain.CapReveal, envScope(envA1), service.ErrMachineRevealOptIn},
		{"workload_reveal_history", mchWork, domain.CapRevealHistory, envScope(envA1), service.ErrMachineCapability},
		{"workload_edit", mchWork, domain.CapEdit, prjScope(), service.ErrMachineCapability},
		// The automation class holds edit/publish/definitions-edit; mch_a1 is
		// backfilled to that class by migration 00010.
		{"automation_manage_members", mchA1, domain.CapManageMembers, prjScope(), service.ErrMachineCapability},
		// scim-provision is system-created with its binding (#73), never
		// grantable through this API — to a human OR a machine.
		{"scim_provision_machine", mchWork, domain.CapSCIMProvision, orgAScope, service.ErrSystemCreatedOnly},
		{"scim_provision_human", grantee, domain.CapSCIMProvision, orgAScope, service.ErrSystemCreatedOnly},
		// An unclassified machine principal is not "unrestricted", it is
		// "holds nothing" — fail-closed, never widened by omission.
		{"unclassified_read", mchNoCls, domain.CapRead, prjScope(), service.ErrMachineCapability},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := g.Create(ctx, service.LocalPrincipal(root), service.GrantSpec{
				Target: tc.target, Capability: tc.cap, Scope: tc.scope,
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
	// The positive control: the allowlist admits what it should, so the
	// refusals above are the rule firing rather than the surface being broken.
	if _, err := g.Create(ctx, service.LocalPrincipal(root), service.GrantSpec{
		Target: mchWork, Capability: domain.CapRead, Scope: envScope(envA1),
	}); err != nil {
		t.Fatalf("a workload credential must be grantable `read`: %v", err)
	}
}

func TestTemplateExpansionSQLite(t *testing.T)   { runTemplateExpansion(t, seededDB(t, openSQLite)) }
func TestTemplateExpansionPostgres(t *testing.T) { runTemplateExpansion(t, seededDB(t, openPostgres)) }

// runTemplateExpansion: a template expands AT GRANT TIME into independent
// rows. Nothing stores "the grantee is an admin"; what is stored is the
// capabilities, each separately visible and separately revocable — including
// `reveal` and `reveal-history`, which `admin` seeds and `operator` does not.
func runTemplateExpansion(t *testing.T, db *store.DB) {
	g := grantSvc(db)
	ctx := t.Context()
	generationBefore := queryInt(t, db,
		"SELECT session_generation FROM principals WHERE id = '"+string(grantee)+"'")

	results, err := g.ApplyTemplate(ctx, service.LocalPrincipal(root), domain.TemplateAdmin, grantee, orgAScope)
	if err != nil {
		t.Fatalf("apply admin at org scope: %v", err)
	}
	want, err := domain.ExpandTemplate(domain.TemplateAdmin, domain.LevelOrg)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(want) {
		t.Fatalf("admin expanded into %d grants, want %d", len(results), len(want))
	}
	for _, c := range want {
		if !held(t, db, grantee, c, orgAScope) {
			t.Errorf("admin template did not create %q as its own row", c)
		}
	}
	generationAfter := queryInt(t, db,
		"SELECT session_generation FROM principals WHERE id = '"+string(grantee)+"'")
	if generationAfter != generationBefore+1 {
		t.Fatalf("admin template advanced session generation from %d to %d, want one atomic advance",
			generationBefore, generationAfter)
	}
	if _, err := g.ApplyTemplate(ctx, service.LocalPrincipal(root), domain.TemplateAdmin, grantee, orgAScope); err != nil {
		t.Fatalf("reapply admin at org scope: %v", err)
	}
	if got := queryInt(t, db,
		"SELECT session_generation FROM principals WHERE id = '"+string(grantee)+"'"); got != generationAfter {
		t.Fatalf("idempotent template reapply advanced session generation from %d to %d", generationAfter, got)
	}
	// The ADR's amendment to the revision-model ADR: `reveal` and `reveal-history`
	// are separate revocable rows inside `admin`, so an installation can strip
	// one without dismantling the administrative authority.
	if err := g.Revoke(ctx, service.LocalPrincipal(root), service.GrantSpec{
		Target: grantee, Capability: domain.CapReveal, Scope: orgAScope,
	}); err != nil {
		t.Fatalf("stripping reveal from an administrator: %v", err)
	}
	if held(t, db, grantee, domain.CapReveal, orgAScope) {
		t.Error("reveal survived its own revocation — the template is behaving as a bundle")
	}
	if !held(t, db, grantee, domain.CapManageMembers, orgAScope) {
		t.Error("stripping reveal dismantled the administrative authority")
	}

	// `manage-projects` is org-scope only, so the SAME template at project
	// scope must not create it.
	if _, err := g.ApplyTemplate(ctx, service.LocalPrincipal(root), domain.TemplateAdmin, grantee, prjScope()); err != nil {
		t.Fatalf("apply admin at project scope: %v", err)
	}
	if held(t, db, grantee, domain.CapManageProjects, prjScope()) {
		t.Error("admin at project scope created manage-projects, which is an org-only row")
	}

	// `operator` seeds NEITHER reveal nor reveal-history: crypto custody is
	// not data reading, and the encryption-model ADR forbids the bundle.
	if _, err := g.ApplyTemplate(ctx, service.LocalPrincipal(root), domain.TemplateOperator, grantee, domain.Scope{}); err != nil {
		t.Fatalf("apply operator at instance scope: %v", err)
	}
	for _, c := range []domain.Capability{domain.CapReveal, domain.CapRevealHistory} {
		if held(t, db, grantee, c, domain.Scope{}) {
			t.Errorf("operator seeded %q — the operator set is custody, not disclosure", c)
		}
	}
	// A template applied at a level its ADR row does not admit is refused.
	if _, err := g.ApplyTemplate(ctx, service.LocalPrincipal(root), domain.TemplateOperator, grantee, orgAScope); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("operator at org scope: got %v, want the invalid-request refusal", err)
	}
	if _, err := g.ApplyTemplate(ctx, service.LocalPrincipal(root), domain.TemplateMaintainer, grantee, envScope(envA1)); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("maintainer at env scope: got %v, want the invalid-request refusal", err)
	}
}

func TestMembershipListingSQLite(t *testing.T)   { runMembershipListing(t, seededDB(t, openSQLite)) }
func TestMembershipListingPostgres(t *testing.T) { runMembershipListing(t, seededDB(t, openPostgres)) }

// runMembershipListing: the surface answers per CAPABILITY LINE with its
// origin chips, which is what makes "who can read production secrets?"
// answerable by inspection.
func runMembershipListing(t *testing.T, db *store.DB) {
	g := grantSvc(db)
	ctx := t.Context()
	spec := service.GrantSpec{Target: grantee, Capability: domain.CapReveal, Scope: envScope(envProd)}
	if _, err := g.Create(ctx, service.LocalPrincipal(orgAdmin), spec); err != nil {
		t.Fatal(err)
	}
	lines, err := g.List(ctx, service.LocalPrincipal(orgAdmin), orgAScope)
	if err != nil {
		t.Fatal(err)
	}
	var found *service.Membership
	for i := range lines {
		if lines[i].Principal == grantee && lines[i].Capability == domain.CapReveal {
			found = &lines[i]
		}
	}
	if found == nil {
		t.Fatal("the reveal grant is absent from the org membership surface")
	}
	if len(found.Origins) != 1 || found.Origins[0].Kind != domain.OriginManual ||
		found.Origins[0].Subject != string(orgAdmin) {
		t.Fatalf("origin chips = %+v, want exactly manual(orgAdmin)", found.Origins)
	}
	if found.Scope != envScope(envProd) {
		t.Fatalf("line scope = %+v, want the environment it was granted at", found.Scope)
	}
	// A principal with no `manage-members` cannot read the surface at all: it
	// answers the uniform nonexistent response, like every tenant refusal.
	if _, err := g.List(ctx, service.LocalPrincipal(reader), orgAScope); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("membership listing without manage-members: got %v, want the uniform nonexistent response", err)
	}
}

func TestBreakGlassGrantSQLite(t *testing.T)   { runBreakGlassGrant(t, seededDB(t, openSQLite)) }
func TestBreakGlassGrantPostgres(t *testing.T) { runBreakGlassGrant(t, seededDB(t, openPostgres)) }

// runBreakGlassGrant: the local-host recovery path names its grantee principal
// and capability explicitly, writes a durable recovery record, and carries a
// `break-glass` origin — distinguishable on the membership surface from an
// ordinary manual grant, which is exactly what an auditor looks for after an
// incident.
func runBreakGlassGrant(t *testing.T, db *store.DB) {
	g := grantSvc(db)
	ctx := t.Context()
	res, err := g.BreakGlassGrant(ctx, service.GrantSpec{
		Target: grantee, Capability: domain.CapManageMembers, Scope: orgAScope,
	})
	if err != nil {
		t.Fatalf("break-glass grant: %v", err)
	}
	if res.Outcome != service.GrantCreated() {
		t.Fatalf("break-glass outcome = %q, want %q", res.Outcome, service.GrantCreated())
	}
	lines, err := g.List(ctx, service.LocalPrincipal(root), orgAScope)
	if err != nil {
		t.Fatal(err)
	}
	var origins []authz.Origin
	for _, l := range lines {
		if l.GrantID == res.GrantID {
			origins = l.Origins
		}
	}
	if len(origins) != 1 || origins[0].Kind != domain.OriginBreakGlass {
		t.Fatalf("break-glass origin chips = %+v, want exactly one break-glass origin", origins)
	}
	// The recovery record is durable and in the instance trail.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_instance_events WHERE type = 'recovery.break_glass_grant'`); n != 1 {
		t.Fatalf("recovery.break_glass_grant rows = %d, want 1", n)
	}
	// The machine allowlists bind break-glass too: local authority is not
	// permission to hand a CI runner an instance capability.
	if _, err := g.BreakGlassGrant(ctx, service.GrantSpec{
		Target: mchWork, Capability: domain.CapInstanceConfig, Scope: domain.Scope{},
	}); !errors.Is(err, service.ErrMachineCapability) {
		t.Fatalf("break-glass to a machine principal: got %v, want ErrMachineCapability", err)
	}
}

func TestProtectedEnvironmentSQLite(t *testing.T) {
	runProtectedEnvironment(t, seededDB(t, openSQLite))
}
func TestProtectedEnvironmentPostgres(t *testing.T) {
	runProtectedEnvironment(t, seededDB(t, openPostgres))
}

// runProtectedEnvironment: marking an environment protected CAPS its window at
// the protected default; raising it above the cap is refused; the effective
// window the reveal guard reads follows, through the same seam the window
// openers use.
func runProtectedEnvironment(t *testing.T, db *store.DB) {
	s := settingsSvc(t, db)
	s.Auth.ReauthWindow = 5 * time.Minute
	ctx := t.Context()
	scope := envScope(envProd)

	// A plain window change first, so the widening/narrowing arm is exercised
	// before protection enters the picture.
	if _, err := s.SetEnvironment(ctx, service.LocalPrincipal(orgAdmin), scope, service.EnvironmentSettings{
		HasWindow: true, Window: 2 * time.Minute,
	}); err != nil {
		t.Fatalf("setting a per-environment window: %v", err)
	}
	got, err := s.GetEnvironment(ctx, service.LocalPrincipal(orgAdmin), scope)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasWindow || got.Window != 2*time.Minute || got.Protected {
		t.Fatalf("settings after the window change = %+v", got)
	}

	// Raising a PROTECTED environment's window above the cap is refused —
	// not silently clamped: the caller asked for a weaker gate on the
	// environment that exists to have the strongest one.
	if _, err := s.SetEnvironment(ctx, service.LocalPrincipal(orgAdmin), scope, service.EnvironmentSettings{
		Protected: true, HasWindow: true, Window: time.Minute,
	}); !errors.Is(err, service.ErrProtectedWindowCap) {
		t.Fatalf("raising a protected window above the cap: got %v, want ErrProtectedWindowCap", err)
	}

	// Marking protected with no explicit window writes the cap rather than
	// leaving the environment to inherit the instance default.
	after, err := s.SetEnvironment(ctx, service.LocalPrincipal(orgAdmin), scope, service.EnvironmentSettings{
		Protected: true,
	})
	if err != nil {
		t.Fatalf("marking protected: %v", err)
	}
	if !after.Protected || !after.HasWindow || after.Window != service.ProtectedWindowCap {
		t.Fatalf("settings after marking protected = %+v, want the capped window", after)
	}
	// The effective-window transition is audited, including the stranded list
	// the #54 library computes.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_instance_events WHERE type = 'auth.effective_window_lowered'`); n == 0 {
		t.Error("lowering the effective window to the protected cap emitted no transition event")
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'settings.protected_flag_changed'`); n != 1 {
		t.Errorf("settings.protected_flag_changed rows = %d, want 1", n)
	}

	// F7: the STORED configuration change is audited, not only the effective
	// duration. Moving from "inherits 5m" to "explicitly 5m" changes no
	// effective value today and every one of them the moment the instance
	// default moves — a policy change that must not be invisible.
	fresh := envScope(envA1)
	s.Auth.ReauthWindow = 5 * time.Minute
	before := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'settings.reauthentication_window_changed'`)
	if _, err := s.SetEnvironment(ctx, service.LocalPrincipal(orgAdmin), fresh, service.EnvironmentSettings{
		HasWindow: true, Window: 5 * time.Minute,
	}); err != nil {
		t.Fatalf("pinning the inherited value explicitly: %v", err)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'settings.reauthentication_window_changed'`); n != before+1 {
		t.Errorf("inherited->explicit at the SAME duration emitted %d events, want one", n-before)
	}
	// And back: explicit 5m -> inherited, again no effective change.
	if _, err := s.SetEnvironment(ctx, service.LocalPrincipal(orgAdmin), fresh, service.EnvironmentSettings{}); err != nil {
		t.Fatalf("clearing back to inherited: %v", err)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'settings.reauthentication_window_changed'`); n != before+2 {
		t.Errorf("explicit->inherited at the SAME duration emitted %d events, want one more", n-before-1)
	}

	// `project-settings` is the capability, not `definitions-edit`: alice
	// holds definitions-edit across org A and must still be refused.
	if _, err := s.SetEnvironment(ctx, service.LocalPrincipal(alice), scope, service.EnvironmentSettings{}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("definitions-edit must not reach project-settings: got %v", err)
	}
}

func TestRevokeKillsSessionSQLite(t *testing.T) { runRevokeKillsSession(t, seededDB(t, openSQLite)) }
func TestRevokeKillsSessionPostgres(t *testing.T) {
	runRevokeKillsSession(t, seededDB(t, openPostgres))
}

// runRevokeKillsSession IS the acceptance demo, in the order the criterion
// states it: grant a template role, watch it expand into independent grants,
// revoke one of them and see the session die. All three happen to the SAME
// principal — the administrator's own — so the demo reads as one story rather
// than two halves about two people.
func runRevokeKillsSession(t *testing.T, db *store.DB) {
	auth, boot, password := bootstrapFactorAdmin(t, db)
	ctx := t.Context()
	g := &service.Grants{DB: db}

	// 1. Grant a template role. The first administrator is an instance-scope
	//    member manager, so it can apply a template inside org A — to itself.
	results, err := g.ApplyTemplate(ctx, service.LocalPrincipal(boot.PrincipalID),
		domain.TemplatePublisher, boot.PrincipalID, orgAScope)
	if err != nil {
		t.Fatalf("apply publisher: %v", err)
	}

	// 2. Watch it expand into grants — four independent rows, each visible on
	//    its own line and revocable on its own. Nothing stored says "publisher".
	want, err := domain.ExpandTemplate(domain.TemplatePublisher, domain.LevelOrg)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(want) || len(want) != 4 {
		t.Fatalf("publisher expanded into %d grants, want 4 (read, edit, publish, pin)", len(results))
	}
	for _, c := range want {
		if !held(t, db, boot.PrincipalID, c, orgAScope) {
			t.Fatalf("the template did not create %q as its own row", c)
		}
	}

	login, err := auth.LocalLogin(ctx, boot.Username, password, service.ArtifactCLI)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := auth.Identity(ctx, login.SessionToken); err != nil {
		t.Fatalf("precondition: the fresh session resolves: %v", err)
	}

	// 3. Revoke ONE of the template-created grants and see the session die.
	//    The generation advance and the session-row deletion commit in the same
	//    transaction as the grant change — there is no cache to invalidate and
	//    no expiry to wait for.
	if err := g.Revoke(ctx, service.LocalPrincipal(boot.PrincipalID), service.GrantSpec{
		Target: boot.PrincipalID, Capability: domain.CapPublish, Scope: orgAScope,
	}); err != nil {
		t.Fatalf("revoke a template-created grant: %v", err)
	}
	if held(t, db, boot.PrincipalID, domain.CapPublish, orgAScope) {
		t.Fatal("the revoked grant survived")
	}
	if !held(t, db, boot.PrincipalID, domain.CapRead, orgAScope) {
		t.Fatal("revoking one template-created grant took its siblings with it — the template behaved as a bundle")
	}
	if _, err := auth.Identity(ctx, login.SessionToken); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("the session survived a grant revocation: %v", err)
	}
}

// runGrantLifecycle drives every grant.* and project-settings audit type once,
// so the audit suite's emitter check finds each one actually reached a trail.
// It is deliberately the SERVICE path, not a direct insert: an operation that
// drops its audit write while keeping its `events:` declaration must fail.
func runGrantLifecycle(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := t.Context()
	g := grantSvc(db)
	spec := service.GrantSpec{Target: grantee, Capability: domain.CapPin, Scope: prjScope()}

	if _, err := g.Create(ctx, service.LocalPrincipal(orgAdmin), spec); err != nil {
		t.Fatalf("grant.created: %v", err)
	}
	// A second grantor on the same triple is the `modified` case: one row,
	// two origins.
	if _, err := g.Create(ctx, service.LocalPrincipal(root), spec); err != nil {
		t.Fatalf("grant.modified: %v", err)
	}
	if err := g.Revoke(ctx, service.LocalPrincipal(orgAdmin), spec); err != nil {
		t.Fatalf("grant.revoked: %v", err)
	}
	if _, err := g.ApplyTemplate(ctx, service.LocalPrincipal(orgAdmin), domain.TemplateViewer, grantee, prjScope()); err != nil {
		t.Fatalf("grant.template_applied: %v", err)
	}
	if _, err := g.List(ctx, service.LocalPrincipal(orgAdmin), orgAScope); err != nil {
		t.Fatalf("grant.membership_read: %v", err)
	}
	if _, err := g.BreakGlassGrant(ctx, service.GrantSpec{
		Target: grantee, Capability: domain.CapRevealHistory, Scope: envScope(envA1),
	}); err != nil {
		t.Fatalf("recovery.break_glass_grant: %v", err)
	}

	// The settings knob needs the Auth service only for the window value and
	// the LowerEffectiveWindow ceremony — neither touches the keyring, and a
	// second keyring on this datastore would mint a second root key.
	s := &service.ProjectSettings{DB: db, Auth: &service.Auth{DB: db}}
	s.Auth.ReauthWindow = 5 * time.Minute
	if _, err := s.SetEnvironment(ctx, service.LocalPrincipal(orgAdmin), envScope(envA1), service.EnvironmentSettings{
		HasWindow: true, Window: time.Minute,
	}); err != nil {
		t.Fatalf("settings.reauthentication_window_changed: %v", err)
	}
	if _, err := s.SetEnvironment(ctx, service.LocalPrincipal(orgAdmin), envScope(envA1), service.EnvironmentSettings{
		Protected: true,
	}); err != nil {
		t.Fatalf("settings.protected_flag_changed: %v", err)
	}
}

// TestBreakGlassGrantHasNoNetworkRoute is the contract half of "break-glass is
// local host authority only": the whole HTTP surface carries no path that
// creates a grant under local authority, and `cli:admin` — the verb group
// `hikyo admin grant` belongs to — is ClassSystem, whose probe contract is
// network unreachability (invariant 1 asserts it by finding no route).
func TestBreakGlassGrantHasNoNetworkRoute(t *testing.T) {
	ops, err := api.Operations()
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		lower := strings.ToLower(op.ID + " " + op.Path + " " + op.AuthzOp)
		if strings.Contains(lower, "breakglass") || strings.Contains(lower, "break-glass") {
			t.Errorf("break-glass reachable over the network: %s %s", op.Method, op.Path)
		}
	}
	if facts.Wire()["cli:admin"] != authz.ClassSystem {
		t.Error("cli:admin must stay ClassSystem — that classification is what keeps break-glass off the network")
	}
}

func TestLockoutCensusSQLite(t *testing.T)   { runLockoutCensus(t, seededDB(t, openSQLite)) }
func TestLockoutCensusPostgres(t *testing.T) { runLockoutCensus(t, seededDB(t, openPostgres)) }

// runLockoutCensus is the regression for the two ways the org census got the
// lockout invariant wrong, both of which the ordinary fixture cannot show:
// while ANY instance-scope `manage-members` holder exists it covers every org
// by inheritance, so the org refusal never fires and neither bug is
// observable. The test therefore removes the instance holder by raw SQL first
// — a deployment whose grants were built by hand rather than by bootstrap —
// and only then asks the census real questions.
func runLockoutCensus(t *testing.T, db *store.DB) {
	g := grantSvc(db)
	ctx := t.Context()

	// The census counts holders AT the org or ABOVE it. A project-scope
	// manage-members row lives at org_id = 'org_a' too, so a query missing the
	// `project_id IS NULL` conjunct counts prjAdmin as an org holder.
	holders := manageMembersHolders(t, db, "org_a")
	if slices.Contains(holders, prjAdmin) {
		t.Fatalf("org census %v includes the PROJECT-scope member manager; the ADR draws the lockout line at org and instance scope", holders)
	}
	if !slices.Contains(holders, orgAdmin) || !slices.Contains(holders, root) {
		t.Fatalf("org census %v is missing the org-scope or the instance-scope holder", holders)
	}

	// Remove the instance holder's grant so the org census is the only thing
	// standing between org A and an unadministrable state.
	execRaw(t, db, `DELETE FROM grant_origins WHERE grant_id = 'g_ro_mm'`)
	execRaw(t, db, `DELETE FROM grants WHERE id = 'g_ro_mm'`)

	// P1: orgAdmin is now org A's LAST org-or-above member manager. prjAdmin's
	// project-scope grant must not stand in for them.
	if err := g.Revoke(ctx, service.LocalPrincipal(orgAdmin), service.GrantSpec{
		Target: orgAdmin, Capability: domain.CapManageMembers, Scope: orgAScope,
	}); !errors.Is(err, service.ErrLastMemberManager) {
		t.Fatalf("revoking the last ORG-or-above member manager: got %v, want ErrLastMemberManager", err)
	}

	// P2: give orgAdmin a SECOND manage-members grant, at instance scope, and
	// the org-scope one becomes revocable — the org stays administrable, by
	// the same person, through the grant that remains. Refusing here was an
	// over-refusal: the invariant asks what survives the revocation, not
	// whether the principal is named anywhere in the census.
	if _, err := g.BreakGlassGrant(ctx, service.GrantSpec{
		Target: orgAdmin, Capability: domain.CapManageMembers, Scope: domain.Scope{},
	}); err != nil {
		t.Fatalf("break-glass instance grant: %v", err)
	}
	if err := g.Revoke(ctx, service.LocalPrincipal(orgAdmin), service.GrantSpec{
		Target: orgAdmin, Capability: domain.CapManageMembers, Scope: orgAScope,
	}); err != nil {
		t.Fatalf("revoking an org-scope grant from a principal who still covers the org at instance scope: %v", err)
	}
	if held(t, db, orgAdmin, domain.CapManageMembers, orgAScope) {
		t.Fatal("the org-scope grant survived its own revocation")
	}
	if !held(t, db, orgAdmin, domain.CapManageMembers, domain.Scope{}) {
		t.Fatal("the instance-scope grant that made the revocation legal was taken with it")
	}

	// P3: the revocation trail records the kind actually released. The
	// break-glass grant above is the distinguishable one, and erasing that
	// from the revocation record would defeat the reason it exists.
	if _, err := g.BreakGlassGrant(ctx, service.GrantSpec{
		Target: grantee, Capability: domain.CapRevealHistory, Scope: envScope(envA1),
	}); err != nil {
		t.Fatal(err)
	}
	if err := g.Revoke(ctx, service.LocalPrincipal(orgAdmin), service.GrantSpec{
		Target: grantee, Capability: domain.CapRevealHistory, Scope: envScope(envA1),
	}); err != nil {
		t.Fatalf("revoking a break-glass grant: %v", err)
	}
	kinds := queryStrings(t, db,
		`SELECT payload FROM audit_tenant_events WHERE type = 'grant.revoked' ORDER BY id`)
	if !strings.Contains(kinds, `"origin_kind":"break-glass"`) {
		t.Fatalf("the revocation trail does not record the break-glass origin it released:\n%s", kinds)
	}
}

// manageMembersHolders reads the census the lockout invariant counts.
func manageMembersHolders(t *testing.T, db *store.DB, org string) []domain.PrincipalID {
	t.Helper()
	var out []domain.PrincipalID
	err := tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		var err error
		out, err = az.ManageMembersHolders(ctx, org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMachineScopeBoundsSQLite(t *testing.T) { runMachineScopeBounds(t, seededDB(t, openSQLite)) }
func TestMachineScopeBoundsPostgres(t *testing.T) {
	runMachineScopeBounds(t, seededDB(t, openPostgres))
}

// runMachineScopeBounds is F1's regression: the normative machine rules bound
// WHERE a machine principal may hold a capability, not only WHICH one. A
// capability allowlist alone left `read` at org or instance scope on the
// workload list — reaching every environment in the org, the opposite of the
// ADR's "explicit (project, environment)" — and let automation hold grants
// across unrelated projects.
//
// Every refusal is asserted through ALL THREE writers: the individual grant,
// the template expansion, and break-glass. They share one enforcement point,
// and this is what proves it.
func runMachineScopeBounds(t *testing.T, db *store.DB) {
	g := grantSvc(db)
	ctx := t.Context()

	// Three ways to write a grant. Each returns the refusal so one table can
	// drive all of them.
	writers := map[string]func(spec service.GrantSpec) error{
		"individual": func(spec service.GrantSpec) error {
			_, err := g.Create(ctx, service.LocalPrincipal(root), spec)
			return err
		},
		"break-glass": func(spec service.GrantSpec) error {
			_, err := g.BreakGlassGrant(ctx, spec)
			return err
		},
		"template": func(spec service.GrantSpec) error {
			// `viewer` expands to exactly `read`, which both machine classes
			// admit — so a refusal here is the SCOPE rule, not the capability
			// allowlist answering first.
			_, err := g.ApplyTemplate(ctx, service.LocalPrincipal(root), domain.TemplateViewer, spec.Target, spec.Scope)
			return err
		},
	}

	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			// A workload must be granted at an explicit (project, environment).
			if err := write(service.GrantSpec{
				Target: mchWork, Capability: domain.CapRead, Scope: orgAScope,
			}); !errors.Is(err, service.ErrMachineScope) {
				t.Errorf("workload read at ORG scope: got %v, want ErrMachineScope", err)
			}
			// At INSTANCE scope the template writer refuses one step earlier
			// and for its own good reason — no tenant template is applicable
			// there at all — so the assertion is that it refuses, naming which
			// rule spoke, rather than pretending both paths reach the same one.
			err := write(service.GrantSpec{
				Target: mchWork, Capability: domain.CapRead, Scope: domain.Scope{},
			})
			if name == "template" {
				if !errors.Is(err, domain.ErrInvalid) {
					t.Errorf("workload template at INSTANCE scope: got %v, want the template-scope refusal", err)
				}
			} else if !errors.Is(err, service.ErrMachineScope) {
				t.Errorf("workload read at INSTANCE scope: got %v, want ErrMachineScope", err)
			}
			if err := write(service.GrantSpec{
				Target: mchWork, Capability: domain.CapRead, Scope: prjScope(),
			}); !errors.Is(err, service.ErrMachineScope) {
				t.Errorf("workload read at PROJECT scope: got %v, want ErrMachineScope (the ADR says explicit environment)", err)
			}
			// Automation is bounded at project depth.
			if err := write(service.GrantSpec{
				Target: mchA1, Capability: domain.CapRead, Scope: orgAScope,
			}); !errors.Is(err, service.ErrMachineScope) {
				t.Errorf("automation read at ORG scope: got %v, want ErrMachineScope", err)
			}
			err = write(service.GrantSpec{
				Target: mchA1, Capability: domain.CapRead, Scope: domain.Scope{},
			})
			if name == "template" {
				if !errors.Is(err, domain.ErrInvalid) {
					t.Errorf("automation template at INSTANCE scope: got %v, want the template-scope refusal", err)
				}
			} else if !errors.Is(err, service.ErrMachineScope) {
				t.Errorf("automation read at INSTANCE scope: got %v, want ErrMachineScope", err)
			}
			// One project: mch_a1's fixture grants sit in prj_a1, so prj_a2 is
			// a foreign project for it.
			if err := write(service.GrantSpec{
				Target: mchA1, Capability: domain.CapRead, Scope: domain.Scope{Org: orgA, Project: prjA2},
			}); !errors.Is(err, service.ErrMachineProject) {
				t.Errorf("automation read in a FOREIGN project: got %v, want ErrMachineProject", err)
			}
		})
	}

	// Positive controls, so every refusal above is the rule firing rather than
	// the surface being broken: automation inside its own project, and a
	// workload at an explicit environment inside the project its first grant
	// fixed.
	if _, err := g.Create(ctx, service.LocalPrincipal(root), service.GrantSpec{
		Target: mchA1, Capability: domain.CapPublish, Scope: prjScope(),
	}); err != nil {
		t.Fatalf("automation inside its own project must be grantable: %v", err)
	}
	if _, err := g.Create(ctx, service.LocalPrincipal(root), service.GrantSpec{
		Target: mchWork, Capability: domain.CapRead, Scope: envScope(envA1),
	}); err != nil {
		t.Fatalf("workload at an explicit environment must be grantable: %v", err)
	}
}

func TestGrantLifecycleEventsSQLite(t *testing.T) {
	runGrantLifecycleEvents(t, seededDB(t, openSQLite))
}
func TestGrantLifecycleEventsPostgres(t *testing.T) {
	runGrantLifecycleEvents(t, seededDB(t, openPostgres))
}

// runGrantLifecycleEvents is F5's regression: the lifecycle event must match
// the state transition, not the code path that reached it.
func runGrantLifecycleEvents(t *testing.T, db *store.DB) {
	g := grantSvc(db)
	ctx := t.Context()
	count := func(typ string) int64 {
		return queryInt(t, db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = '`+typ+`'`)
	}
	spec := service.GrantSpec{Target: grantee, Capability: domain.CapRead, Scope: prjScope()}

	if _, err := g.Create(ctx, service.LocalPrincipal(orgAdmin), spec); err != nil {
		t.Fatal(err)
	}
	if n := count("grant.created"); n != 1 {
		t.Fatalf("grant.created = %d, want 1", n)
	}

	// The same grantor, again: no row created, no origin attached, nothing
	// changed — so no lifecycle event at all. Emitting `grant.modified` here
	// would let an investigator count polls as modifications.
	beforeModified := count("grant.modified")
	res, err := g.Create(ctx, service.LocalPrincipal(orgAdmin), spec)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != service.GrantUnchanged() {
		t.Fatalf("the idempotent repeat changed state: %+v", res)
	}
	if n := count("grant.modified"); n != beforeModified {
		t.Fatalf("an idempotent repeat emitted a lifecycle event (grant.modified %d -> %d)", beforeModified, n)
	}

	// A second grantor joins the row: that IS a modification.
	if _, err := g.Create(ctx, service.LocalPrincipal(root), spec); err != nil {
		t.Fatal(err)
	}
	if n := count("grant.modified"); n != beforeModified+1 {
		t.Fatalf("a second origin on an existing row emitted %d modifications, want one more", n-beforeModified)
	}

	// A release that leaves the row alive is a MODIFICATION, not a
	// revocation. #73's origins are the real case; a `scim` origin is planted
	// here by raw SQL because only #73 can mint one, and the surface must
	// already behave correctly when it meets one.
	var grantID string
	for _, row := range grantRows(t, db, grantee) {
		if row.Grant.Capability == domain.CapRead && row.Grant.Scope == prjScope() {
			grantID = row.ID
		}
	}
	if grantID == "" {
		t.Fatal("the grant under test disappeared")
	}
	execRaw(t, db, `INSERT INTO grant_origins (id, grant_id, kind, subject, created_at) VALUES `+
		`('gor_scim_x', '`+grantID+`', 'scim', 'bnd_x', `+ts+`)`)

	beforeRevoked, beforeModified := count("grant.revoked"), count("grant.modified")
	if err := g.Revoke(ctx, service.LocalPrincipal(orgAdmin), spec); err != nil {
		t.Fatal(err)
	}
	if !held(t, db, grantee, domain.CapRead, prjScope()) {
		t.Fatal("the row died although a scim origin still held it")
	}
	if n := count("grant.revoked"); n != beforeRevoked {
		t.Errorf("a release that left the row alive was filed as a revocation (grant.revoked %d -> %d)", beforeRevoked, n)
	}
	if n := count("grant.modified"); n != beforeModified+1 {
		t.Errorf("a release that left the row alive emitted %d modifications, want one more", n-beforeModified)
	}

	// Releasing the last origin IS a revocation.
	execRaw(t, db, `DELETE FROM grant_origins WHERE id = 'gor_scim_x'`)
	execRaw(t, db, `INSERT INTO grant_origins (id, grant_id, kind, subject, created_at) VALUES `+
		`('gor_manual_x', '`+grantID+`', 'manual', '`+string(orgAdmin)+`', `+ts+`)`)
	if err := g.Revoke(ctx, service.LocalPrincipal(orgAdmin), spec); err != nil {
		t.Fatal(err)
	}
	if held(t, db, grantee, domain.CapRead, prjScope()) {
		t.Fatal("the row survived the release of its last origin")
	}
	if n := count("grant.revoked"); n != beforeRevoked+1 {
		t.Errorf("the last-origin release emitted %d revocations, want one more", n-beforeRevoked)
	}
}

func TestOriginAddKeepsSessionAliveSQLite(t *testing.T) {
	runOriginAddKeepsSessionAlive(t, seededDB(t, openSQLite))
}
func TestOriginAddKeepsSessionAlivePostgres(t *testing.T) {
	runOriginAddKeepsSessionAlive(t, seededDB(t, openPostgres))
}

// runOriginAddKeepsSessionAlive is F5's remaining arm: a SECOND origin joining
// a grant the holder ALREADY had changes no effective policy — the capability
// was held before and is held after — so it must not advance the holder's
// generation or delete their sessions. Doing so would let one administrator's
// bookkeeping log another principal out.
//
// The control below is what makes it an assertion rather than a coincidence:
// the same holder's session DOES die when the same grant is revoked, so the
// session-kill machinery is demonstrably wired to this principal.
func runOriginAddKeepsSessionAlive(t *testing.T, db *store.DB) {
	auth, boot, password := bootstrapFactorAdmin(t, db)
	ctx := t.Context()
	g := grantSvc(db)

	// The bootstrap administrator holds instance `manage-members`, so it can
	// grant to itself; `read` at org scope is a capability it does not have.
	spec := service.GrantSpec{Target: boot.PrincipalID, Capability: domain.CapRead, Scope: orgAScope}
	if _, err := g.Create(ctx, service.LocalPrincipal(boot.PrincipalID), spec); err != nil {
		t.Fatalf("first grant: %v", err)
	}

	login, err := auth.LocalLogin(ctx, boot.Username, password, service.ArtifactCLI)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := auth.Identity(ctx, login.SessionToken); err != nil {
		t.Fatalf("precondition: the fresh session resolves: %v", err)
	}

	// A second grantor joins the SAME triple. One row, two origins, identical
	// effective authority.
	res, err := g.Create(ctx, service.LocalPrincipal(root), spec)
	if err != nil {
		t.Fatalf("second origin: %v", err)
	}
	if res.Outcome != service.GrantOriginAdded() {
		t.Fatalf("expected an origin join on an existing row, got %+v", res)
	}
	if _, err := auth.Identity(ctx, login.SessionToken); err != nil {
		t.Fatalf("an origin join on an already-effective grant killed the holder's session: %v", err)
	}

	// Control: revoking the grant DOES kill it, so the assertion above is the
	// gate working rather than the machinery being disconnected.
	if err := g.Revoke(ctx, service.LocalPrincipal(root), spec); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := auth.Identity(ctx, login.SessionToken); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("the session survived a revocation that deleted the grant row: %v", err)
	}
}

// grantRows reads a principal's grant rows with their ids.
func grantRows(t *testing.T, db *store.DB, p domain.PrincipalID) []authz.GrantRow {
	t.Helper()
	var out []authz.GrantRow
	err := tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		var err error
		out, err = az.GrantRowsForPrincipal(ctx, p)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
