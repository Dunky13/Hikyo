package isolation

import (
	"errors"
	"testing"

	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/service"
	"github.com/Dunky13/wenv/internal/store"
)

// Probe axes (invariant 2): removing either fixture axis fails the
// harness's own self-check in TestInvariant02 below.
const (
	axisCrossOrgHuman       = "cross-org-human"
	axisCrossProjectMachine = "cross-project-machine"
	axisCapabilityDenial    = "capability-denial"
)

// tenantProbe is one cross-tenant probe: run must come back as the uniform
// nonexistent response, byte-identical to its genuinely-missing twin, and a
// mutation probe must leave no row behind (row diff; the effect-port half of
// invariant 4 is vacuously zero because the adapter transport, SSE sink and
// outbox registries are empty — asserted by TestInvariant01).
type tenantProbe struct {
	name     string
	axis     string
	mutation bool
	run      func(t *testing.T, db *store.DB) error
	missing  func(t *testing.T, db *store.DB) error
}

var tenantProbes = []tenantProbe{
	{
		name: "env_read_cross_org", axis: axisCrossOrgHuman,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Get(tctx(t), service.LocalPrincipal(bob), domain.Scope{Org: orgA, Project: prjA1, Env: envA1})
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Get(tctx(t), service.LocalPrincipal(alice), domain.Scope{Org: orgA, Project: prjA1, Env: "env_missing"})
			return err
		},
	},
	{
		name: "env_read_cross_project_machine", axis: axisCrossProjectMachine,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Get(tctx(t), service.LocalPrincipal(mchA1), domain.Scope{Org: orgA, Project: prjA2, Env: envA2})
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Get(tctx(t), service.LocalPrincipal(mchA1), domain.Scope{Org: orgA, Project: prjA1, Env: "env_missing"})
			return err
		},
	},
	{
		name: "env_read_no_grants", axis: axisCapabilityDenial,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Get(tctx(t), service.LocalPrincipal(nobody), domain.Scope{Org: orgA, Project: prjA1, Env: envA1})
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Get(tctx(t), service.LocalPrincipal(alice), domain.Scope{Org: orgA, Project: prjA1, Env: "env_missing"})
			return err
		},
	},
	{
		name: "env_update_note_cross_org", axis: axisCrossOrgHuman, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			return envs.UpdateNote(tctx(t), service.LocalPrincipal(bob), domain.Scope{Org: orgA, Project: prjA1, Env: envA1}, "pwned")
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			return envs.UpdateNote(tctx(t), service.LocalPrincipal(alice), domain.Scope{Org: orgA, Project: prjA1, Env: "env_missing"}, "pwned")
		},
	},
	{
		name: "env_update_note_cross_project_machine", axis: axisCrossProjectMachine, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			return envs.UpdateNote(tctx(t), service.LocalPrincipal(mchA1), domain.Scope{Org: orgA, Project: prjA2, Env: envA2}, "pwned")
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			return envs.UpdateNote(tctx(t), service.LocalPrincipal(mchA1), domain.Scope{Org: orgA, Project: prjA1, Env: "env_missing"}, "pwned")
		},
	},
	{
		name: "env_create_cross_org", axis: axisCrossOrgHuman, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Create(tctx(t), service.LocalPrincipal(bob), domain.Scope{Org: orgA, Project: prjA1}, "intruder")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Create(tctx(t), service.LocalPrincipal(alice), domain.Scope{Org: orgA, Project: "prj_missing"}, "intruder")
			return err
		},
	},
	{
		name: "env_create_cross_project_machine", axis: axisCrossProjectMachine, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Create(tctx(t), service.LocalPrincipal(mchA1), domain.Scope{Org: orgA, Project: prjA2}, "intruder")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Create(tctx(t), service.LocalPrincipal(mchA1), domain.Scope{Org: orgA, Project: "prj_missing"}, "intruder")
			return err
		},
	},
	// Least-privilege probes: `reader` holds exactly `read` in org A and
	// addresses objects that genuinely exist, so each of these fails only
	// because the operation's formula demands a capability they lack.
	// Widening any of these formulas to `read` turns a probe green-to-red.
	{
		name: "env_update_note_read_only_principal", axis: axisCapabilityDenial, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			return envs.UpdateNote(tctx(t), service.LocalPrincipal(reader), domain.Scope{Org: orgA, Project: prjA1, Env: envA1}, "pwned")
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			return envs.UpdateNote(tctx(t), service.LocalPrincipal(alice), domain.Scope{Org: orgA, Project: prjA1, Env: "env_missing"}, "pwned")
		},
	},
	{
		name: "env_create_read_only_principal", axis: axisCapabilityDenial, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Create(tctx(t), service.LocalPrincipal(reader), domain.Scope{Org: orgA, Project: prjA1}, "intruder")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Create(tctx(t), service.LocalPrincipal(alice), domain.Scope{Org: orgA, Project: "prj_missing"}, "intruder")
			return err
		},
	},
	{
		name: "project_create_read_only_principal", axis: axisCapabilityDenial, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			_, err := projects.Create(tctx(t), service.LocalPrincipal(reader), orgA, "intruder")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			_, err := projects.Create(tctx(t), service.LocalPrincipal(alice), "org_missing", "intruder")
			return err
		},
	},
	{
		name: "project_create_cross_org", axis: axisCrossOrgHuman, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			_, err := projects.Create(tctx(t), service.LocalPrincipal(bob), orgA, "intruder")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			_, err := projects.Create(tctx(t), service.LocalPrincipal(alice), "org_missing", "intruder")
			return err
		},
	},
}

func runTenantProbes(t *testing.T, db *store.DB) {
	for _, p := range tenantProbes {
		t.Run(p.name, func(t *testing.T) {
			before := rowCounts(t, db)
			beforeNote := queryInt(t, db, "SELECT COUNT(*) FROM environments WHERE note = 'pwned'")
			if beforeNote != 0 {
				t.Fatal("fixture polluted: pwned note already present")
			}
			probeErr := p.run(t, db)
			missingErr := p.missing(t, db)
			assertUniformNotFound(t, probeErr, missingErr)
			if p.mutation {
				after := rowCounts(t, db)
				for table, n := range before {
					if after[table] != n {
						t.Errorf("side effect: %s rows %d -> %d", table, n, after[table])
					}
				}
				if got := queryInt(t, db, "SELECT COUNT(*) FROM environments WHERE note = 'pwned'"); got != 0 {
					t.Errorf("side effect: a probe's note update landed (%d rows)", got)
				}
			}
		})
	}
}

// runInstanceProbes: instance-scoped operations are probed for grant
// refusal, not tenancy — bob (an org administrator, the strongest
// non-instance fixture) must get the uniform denial from every instance
// operation, and nothing may be written.
func runInstanceProbes(t *testing.T, db *store.DB) {
	orgs, _, _ := services(db)
	before := rowCounts(t, db)
	if _, err := orgs.Create(tctx(t), service.LocalPrincipal(bob), "bob-empire", true, []byte(`{}`)); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("org.create as org admin: err = %v, want ErrUnauthorized", err)
	}
	if _, err := orgs.List(tctx(t), service.LocalPrincipal(bob)); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("org.list as org admin: err = %v, want ErrUnauthorized", err)
	}
	if _, err := orgs.Get(tctx(t), service.LocalPrincipal(bob), string(orgA)); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("org.get as org admin: err = %v, want ErrUnauthorized", err)
	}
	if _, err := orgs.Count(tctx(t), service.LocalPrincipal(nobody)); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("org.count with no grants: err = %v, want ErrUnauthorized", err)
	}
	after := rowCounts(t, db)
	for table, n := range before {
		if after[table] != n {
			t.Errorf("side effect: %s rows %d -> %d", table, n, after[table])
		}
	}
}

// runPositiveControls proves the probes above fail because of the boundary,
// not because the surface is broken: the same operations succeed for
// principals whose grants cover them, and every written row's chain comes
// from the proof (invariant 8's provenance half).
func runPositiveControls(t *testing.T, db *store.DB) {
	orgs, projects, envs := services(db)

	got, err := envs.Get(tctx(t), service.LocalPrincipal(alice), domain.Scope{Org: orgA, Project: prjA1, Env: envA1})
	if err != nil {
		t.Fatalf("alice reading her own env: %v", err)
	}
	// The least-privilege prober must SUCCEED on the one operation whose
	// formula it holds. Without this, the read-only denial probes above
	// would pass even if `reader`'s grant were broken or missing entirely.
	if _, err := envs.Get(tctx(t), service.LocalPrincipal(reader), domain.Scope{Org: orgA, Project: prjA1, Env: envA1}); err != nil {
		t.Fatalf("read-only principal denied on environment.read (formula is read(E)): %v", err)
	}
	if got.ID != string(envA1) || got.OrgID != string(orgA) || got.ProjectID != string(prjA1) {
		t.Fatalf("env chain mismatch: %+v", got)
	}
	if _, err := envs.Get(tctx(t), service.LocalPrincipal(mchA1), domain.Scope{Org: orgA, Project: prjA1, Env: envA1}); err != nil {
		t.Fatalf("machine principal reading its own project's env: %v", err)
	}
	if err := envs.UpdateNote(tctx(t), service.LocalPrincipal(alice), domain.Scope{Org: orgA, Project: prjA1, Env: envA1}, "alice was here"); err != nil {
		t.Fatalf("alice updating note: %v", err)
	}

	proj, err := projects.Create(tctx(t), service.LocalPrincipal(alice), orgA, "alice-project")
	if err != nil {
		t.Fatalf("alice creating a project: %v", err)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM projects WHERE id = '"+proj.ID+"' AND org_id = 'org_a'"); n != 1 {
		t.Fatalf("created project's chain did not come from the proof (org_a rows = %d)", n)
	}

	env, err := envs.Create(tctx(t), service.LocalPrincipal(mchA1), domain.Scope{Org: orgA, Project: prjA1}, "machine-env")
	if err != nil {
		t.Fatalf("machine creating an env in its own project: %v", err)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM environments WHERE id = '"+env.ID+"' AND org_id = 'org_a' AND project_id = 'prj_a1'"); n != 1 {
		t.Fatalf("created env's chain did not come from the proof")
	}

	org, err := orgs.Create(tctx(t), service.LocalPrincipal(root), "root-org", true, []byte(`{}`))
	if err != nil {
		t.Fatalf("root creating an org: %v", err)
	}
	if _, err := orgs.Get(tctx(t), service.LocalPrincipal(root), org.ID); err != nil {
		t.Fatalf("root reading the created org: %v", err)
	}
}

func runSuite(t *testing.T, db *store.DB) {
	t.Run("tenant_probes", func(t *testing.T) { runTenantProbes(t, db) })
	t.Run("instance_probes", func(t *testing.T) { runInstanceProbes(t, db) })
	t.Run("chain_constraints", func(t *testing.T) { runChainConstraintChecks(t, db) })
	t.Run("query_count", func(t *testing.T) { runQueryCountChecks(t, db) })
	t.Run("proof_lifecycle_e2e", func(t *testing.T) { runProofLifecycleE2E(t, db) })
	// These run last: they mutate the fixture set.
	t.Run("positive_controls", func(t *testing.T) { runPositiveControls(t, db) })
	t.Run("read_snapshot_stability", func(t *testing.T) { runReadSnapshotStability(t, db) })
}

func TestIsolationSQLite(t *testing.T) {
	runSuite(t, seededDB(t, openSQLite))
}

func TestIsolationPostgres(t *testing.T) {
	runSuite(t, seededDB(t, openPostgres))
}
