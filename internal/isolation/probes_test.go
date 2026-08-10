package isolation

import (
	"errors"
	"strings"
	"testing"

	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
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
			// alice, not mchA1: the twin must be AUTHORIZED-but-missing. mchA1's
			// grant stops at project A1, so mchA1 against prj_missing is a
			// second unauthorized call, and comparing two denials proves nothing
			// about the genuinely-nonexistent answer. (The mchA1 twins that
			// address prjA1 with a missing CHILD are already authorized — the
			// grant covers the project, only the child is absent.)
			_, _, envs := services(db)
			_, err := envs.Create(tctx(t), service.LocalPrincipal(alice), domain.Scope{Org: orgA, Project: "prj_missing"}, "intruder")
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
	// ---------------------------------------------------------------------
	// The hierarchy surface (#48). mvp-boundary C1 requires the uniform
	// nonexistent shape at EVERY level, so every level gets probes on all
	// three axes, and every mutation is flagged so the no-side-effect
	// assertion covers it.
	//
	// The `missing` twin of each probe is a legitimately-authorized principal
	// addressing something that is not there — that is what makes "byte
	// identical to genuinely nonexistent" a real comparison rather than two
	// refusals that merely look alike.
	// ---------------------------------------------------------------------

	// Organization. Read is `read(org)`; rename and delete are
	// instance-config, so even an org administrator is refused — and cannot
	// tell the org apart from one that does not exist.
	{
		name: "org_get_cross_org", axis: axisCrossOrgHuman,
		run: func(t *testing.T, db *store.DB) error {
			orgs, _, _ := services(db)
			_, err := orgs.Get(tctx(t), service.LocalPrincipal(bob), orgA)
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			orgs, _, _ := services(db)
			_, err := orgs.Get(tctx(t), service.LocalPrincipal(root), "org_missing")
			return err
		},
	},
	{
		name: "org_rename_org_admin_refused", axis: axisCapabilityDenial, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			orgs, _, _ := services(db)
			_, err := orgs.Rename(tctx(t), service.LocalPrincipal(alice), orgA, "pwned")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			orgs, _, _ := services(db)
			_, err := orgs.Rename(tctx(t), service.LocalPrincipal(root), "org_missing", "pwned")
			return err
		},
	},
	{
		name: "org_rename_cross_org", axis: axisCrossOrgHuman, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			orgs, _, _ := services(db)
			_, err := orgs.Rename(tctx(t), service.LocalPrincipal(bob), orgA, "pwned")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			orgs, _, _ := services(db)
			_, err := orgs.Rename(tctx(t), service.LocalPrincipal(root), "org_missing", "pwned")
			return err
		},
	},
	{
		name: "org_delete_org_admin_refused", axis: axisCapabilityDenial, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			orgs, _, _ := services(db)
			return orgs.Delete(tctx(t), service.LocalPrincipal(alice), orgA)
		},
		missing: func(t *testing.T, db *store.DB) error {
			orgs, _, _ := services(db)
			return orgs.Delete(tctx(t), service.LocalPrincipal(root), "org_missing")
		},
	},

	// Project.
	{
		name: "project_get_cross_org", axis: axisCrossOrgHuman,
		run: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			_, err := projects.Get(tctx(t), service.LocalPrincipal(bob), scopeProject(orgA, prjA1))
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			_, err := projects.Get(tctx(t), service.LocalPrincipal(alice), scopeProject(orgA, "prj_missing"))
			return err
		},
	},
	{
		name: "project_get_cross_project_machine", axis: axisCrossProjectMachine,
		run: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			_, err := projects.Get(tctx(t), service.LocalPrincipal(mchA1), scopeProject(orgA, prjA2))
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			// alice, not mchA1: the twin must be AUTHORIZED-but-missing. mchA1's
			// grant stops at project A1, so mchA1 against prj_missing is a
			// second unauthorized call, and comparing two denials proves nothing
			// about the genuinely-nonexistent answer. (The mchA1 twins that
			// address prjA1 with a missing CHILD are already authorized — the
			// grant covers the project, only the child is absent.)
			_, projects, _ := services(db)
			_, err := projects.Get(tctx(t), service.LocalPrincipal(alice), scopeProject(orgA, "prj_missing"))
			return err
		},
	},
	{
		name: "project_list_cross_org", axis: axisCrossOrgHuman,
		run: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			_, err := projects.List(tctx(t), service.LocalPrincipal(bob), orgA)
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			_, err := projects.List(tctx(t), service.LocalPrincipal(alice), "org_missing")
			return err
		},
	},
	{
		name: "project_rename_read_only_principal", axis: axisCapabilityDenial, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			_, err := projects.Rename(tctx(t), service.LocalPrincipal(reader), scopeProject(orgA, prjA1), "pwned")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			_, err := projects.Rename(tctx(t), service.LocalPrincipal(alice), scopeProject(orgA, "prj_missing"), "pwned")
			return err
		},
	},
	{
		name: "project_rename_cross_project_machine", axis: axisCrossProjectMachine, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			_, err := projects.Rename(tctx(t), service.LocalPrincipal(mchA1), scopeProject(orgA, prjA2), "pwned")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			// alice, not mchA1: the twin must be AUTHORIZED-but-missing. mchA1's
			// grant stops at project A1, so mchA1 against prj_missing is a
			// second unauthorized call, and comparing two denials proves nothing
			// about the genuinely-nonexistent answer. (The mchA1 twins that
			// address prjA1 with a missing CHILD are already authorized — the
			// grant covers the project, only the child is absent.)
			_, projects, _ := services(db)
			_, err := projects.Rename(tctx(t), service.LocalPrincipal(alice), scopeProject(orgA, "prj_missing"), "pwned")
			return err
		},
	},
	{
		name: "project_delete_cross_org", axis: axisCrossOrgHuman, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			return projects.Delete(tctx(t), service.LocalPrincipal(bob), scopeProject(orgA, prjA1))
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			return projects.Delete(tctx(t), service.LocalPrincipal(alice), scopeProject(orgA, "prj_missing"))
		},
	},
	{
		name: "project_delete_read_only_principal", axis: axisCapabilityDenial, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			return projects.Delete(tctx(t), service.LocalPrincipal(reader), scopeProject(orgA, prjA1))
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, projects, _ := services(db)
			return projects.Delete(tctx(t), service.LocalPrincipal(alice), scopeProject(orgA, "prj_missing"))
		},
	},

	// Environment.
	{
		name: "env_list_cross_project_machine", axis: axisCrossProjectMachine,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.List(tctx(t), service.LocalPrincipal(mchA1), scopeProject(orgA, prjA2))
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			// Authorized-but-missing: see project_get_cross_project_machine.
			_, _, envs := services(db)
			_, err := envs.List(tctx(t), service.LocalPrincipal(alice), scopeProject(orgA, "prj_missing"))
			return err
		},
	},
	{
		name: "env_rename_cross_org", axis: axisCrossOrgHuman, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Rename(tctx(t), service.LocalPrincipal(bob), scopeEnv(orgA, prjA1, envA1), "pwned")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Rename(tctx(t), service.LocalPrincipal(alice), scopeEnv(orgA, prjA1, "env_missing"), "pwned")
			return err
		},
	},
	{
		name: "env_rename_read_only_principal", axis: axisCapabilityDenial, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Rename(tctx(t), service.LocalPrincipal(reader), scopeEnv(orgA, prjA1, envA1), "pwned")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Rename(tctx(t), service.LocalPrincipal(alice), scopeEnv(orgA, prjA1, "env_missing"), "pwned")
			return err
		},
	},
	{
		name: "env_reorder_cross_project_machine", axis: axisCrossProjectMachine, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Reorder(tctx(t), service.LocalPrincipal(mchA1), scopeProject(orgA, prjA2), []string{string(envA2)})
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			// alice, not mchA1: the twin must be AUTHORIZED-but-missing. mchA1's
			// grant stops at project A1, so mchA1 against prj_missing is a
			// second unauthorized call, and comparing two denials proves nothing
			// about the genuinely-nonexistent answer. (The mchA1 twins that
			// address prjA1 with a missing CHILD are already authorized — the
			// grant covers the project, only the child is absent.)
			_, _, envs := services(db)
			_, err := envs.Reorder(tctx(t), service.LocalPrincipal(alice), scopeProject(orgA, "prj_missing"), []string{string(envA2)})
			return err
		},
	},
	{
		name: "env_reorder_read_only_principal", axis: axisCapabilityDenial, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Reorder(tctx(t), service.LocalPrincipal(reader), scopeProject(orgA, prjA1), []string{string(envA1)})
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			_, err := envs.Reorder(tctx(t), service.LocalPrincipal(alice), scopeProject(orgA, "prj_missing"), []string{string(envA1)})
			return err
		},
	},
	{
		name: "env_delete_cross_org", axis: axisCrossOrgHuman, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			return envs.Delete(tctx(t), service.LocalPrincipal(bob), scopeEnv(orgA, prjA1, envA1))
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			return envs.Delete(tctx(t), service.LocalPrincipal(alice), scopeEnv(orgA, prjA1, "env_missing"))
		},
	},
	{
		name: "env_delete_read_only_principal", axis: axisCapabilityDenial, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			return envs.Delete(tctx(t), service.LocalPrincipal(reader), scopeEnv(orgA, prjA1, envA1))
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, _, envs := services(db)
			return envs.Delete(tctx(t), service.LocalPrincipal(alice), scopeEnv(orgA, prjA1, "env_missing"))
		},
	},

	// Folder. Every folder operation addresses PROJECT depth, so a folder id
	// from another project is refused by the chain predicate rather than by a
	// folder-level check that does not exist.
	{
		name: "folder_get_cross_org", axis: axisCrossOrgHuman,
		run: func(t *testing.T, db *store.DB) error {
			_, err := folderSvc(db).Get(tctx(t), service.LocalPrincipal(bob), scopeProject(orgA, prjA1), "fld_a1")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, err := folderSvc(db).Get(tctx(t), service.LocalPrincipal(alice), scopeProject(orgA, prjA1), "fld_missing")
			return err
		},
	},
	{
		name: "folder_get_cross_project_machine", axis: axisCrossProjectMachine,
		run: func(t *testing.T, db *store.DB) error {
			// The folder exists — in the sibling project this machine cannot
			// reach. Addressed through prjA1, which it CAN reach, so the refusal
			// comes from the chain predicate, not from the scope check.
			_, err := folderSvc(db).Get(tctx(t), service.LocalPrincipal(mchA1), scopeProject(orgA, prjA1), "fld_a2")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, err := folderSvc(db).Get(tctx(t), service.LocalPrincipal(mchA1), scopeProject(orgA, prjA1), "fld_missing")
			return err
		},
	},
	{
		name: "folder_list_cross_project_machine", axis: axisCrossProjectMachine,
		run: func(t *testing.T, db *store.DB) error {
			_, err := folderSvc(db).List(tctx(t), service.LocalPrincipal(mchA1), scopeProject(orgA, prjA2))
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			// Authorized-but-missing: see project_get_cross_project_machine.
			_, err := folderSvc(db).List(tctx(t), service.LocalPrincipal(alice), scopeProject(orgA, "prj_missing"))
			return err
		},
	},
	{
		name: "folder_create_cross_org", axis: axisCrossOrgHuman, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, err := folderSvc(db).Create(tctx(t), service.LocalPrincipal(bob), scopeProject(orgA, prjA1), "intruder")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, err := folderSvc(db).Create(tctx(t), service.LocalPrincipal(alice), scopeProject(orgA, "prj_missing"), "intruder")
			return err
		},
	},
	{
		name: "folder_create_read_only_principal", axis: axisCapabilityDenial, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, err := folderSvc(db).Create(tctx(t), service.LocalPrincipal(reader), scopeProject(orgA, prjA1), "intruder")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, err := folderSvc(db).Create(tctx(t), service.LocalPrincipal(alice), scopeProject(orgA, "prj_missing"), "intruder")
			return err
		},
	},
	{
		name: "folder_rename_cross_project_machine", axis: axisCrossProjectMachine, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			_, err := folderSvc(db).Rename(tctx(t), service.LocalPrincipal(mchA1), scopeProject(orgA, prjA1), "fld_a2", "pwned")
			return err
		},
		missing: func(t *testing.T, db *store.DB) error {
			_, err := folderSvc(db).Rename(tctx(t), service.LocalPrincipal(mchA1), scopeProject(orgA, prjA1), "fld_missing", "pwned")
			return err
		},
	},
	{
		name: "folder_delete_read_only_principal", axis: axisCapabilityDenial, mutation: true,
		run: func(t *testing.T, db *store.DB) error {
			return folderSvc(db).Delete(tctx(t), service.LocalPrincipal(reader), scopeProject(orgA, prjA1), "fld_a1")
		},
		missing: func(t *testing.T, db *store.DB) error {
			return folderSvc(db).Delete(tctx(t), service.LocalPrincipal(alice), scopeProject(orgA, prjA1), "fld_missing")
		},
	},
}

func runTenantProbes(t *testing.T, db *store.DB) {
	for _, p := range tenantProbes {
		t.Run(p.name, func(t *testing.T) {
			before := rowCounts(t, db)
			beforeState := contentSnapshot(t, db)
			beforeAudit := queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE type LIKE 'settings.%'")
			probeErr := p.run(t, db)
			missingErr := p.missing(t, db)
			assertUniformNotFound(t, probeErr, missingErr)
			if !p.mutation {
				return
			}
			after := rowCounts(t, db)
			for table, n := range before {
				if after[table] != n {
					t.Errorf("side effect: %s rows %d -> %d", table, n, after[table])
				}
			}
			// Row COUNTS alone cannot see an in-place mutation: an unauthorized
			// rename or reorder that commits and then answers ErrNotFound leaves
			// every count untouched and would pass. The snapshot carries every
			// mutable field this surface can write — names, notes, paths and
			// display order — so a commit-then-lie is a diff.
			if got := contentSnapshot(t, db); got != beforeState {
				t.Errorf("side effect: a refused mutation changed stored content\n before: %s\n after:  %s", beforeState, got)
			}
			// A refusal that rolled back leaves no domain event either; one that
			// committed its audit row and then rolled back the write would be a
			// trail that lies about what happened.
			if got := queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE type LIKE 'settings.%'"); got != beforeAudit {
				t.Errorf("side effect: a refused mutation left %d new settings.* audit rows", got-beforeAudit)
			}
		})
	}
}

// contentSnapshot renders every mutable field of the hierarchy fixture as one
// comparable string, ordered deterministically. It is the mutation probes'
// real assertion: the uniform nonexistent RESPONSE is only half the contract,
// the other half is that nothing moved.
func contentSnapshot(t *testing.T, db *store.DB) string {
	t.Helper()
	var out strings.Builder
	for _, q := range []string{
		"SELECT id || '=' || name || '|' FROM orgs ORDER BY id",
		"SELECT id || '=' || name || '|' FROM projects ORDER BY id",
		"SELECT id || '=' || name || ':' || note || ':' || display_order || '|' FROM environments ORDER BY id",
		"SELECT id || '=' || path || '|' FROM folders ORDER BY id",
	} {
		out.WriteString(queryStrings(t, db, q))
		out.WriteString(";")
	}
	return out.String()
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
	// org.get is NOT probed here: it is tenant-class at org depth (#48), so its
	// refusal is the uniform nonexistent shape and it rides in tenantProbes.
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
	if _, err := orgs.Get(tctx(t), service.LocalPrincipal(root), domain.OrgID(org.ID)); err != nil {
		t.Fatalf("root reading the created org: %v", err)
	}
	if _, err := orgs.Rename(tctx(t), service.LocalPrincipal(root), domain.OrgID(org.ID), "root-org-renamed"); err != nil {
		t.Fatalf("root renaming the created org: %v", err)
	}
	if err := orgs.Delete(tctx(t), service.LocalPrincipal(root), domain.OrgID(org.ID)); err != nil {
		t.Fatalf("root deleting the org it just created: %v", err)
	}

	// The hierarchy surface's own positive controls (#48). Without these, every
	// denial probe above would still pass if the operation were simply broken
	// for everyone — the least-privilege prober must SUCCEED on exactly the
	// operations whose formula it holds, and fail on the rest.
	folders := folderSvc(db)
	readerActor := service.LocalPrincipal(reader)
	if _, err := projects.Get(tctx(t), readerActor, scopeProject(orgA, prjA1)); err != nil {
		t.Fatalf("read-only principal denied on project.read (formula is read(project)): %v", err)
	}
	if _, err := projects.List(tctx(t), readerActor, orgA); err != nil {
		t.Fatalf("read-only principal denied on project.list: %v", err)
	}
	if _, err := envs.List(tctx(t), readerActor, scopeProject(orgA, prjA1)); err != nil {
		t.Fatalf("read-only principal denied on environment.list: %v", err)
	}
	if _, err := folders.List(tctx(t), readerActor, scopeProject(orgA, prjA1)); err != nil {
		t.Fatalf("read-only principal denied on folder.list: %v", err)
	}
	if _, err := folders.Get(tctx(t), readerActor, scopeProject(orgA, prjA1), "fld_a1"); err != nil {
		t.Fatalf("read-only principal denied on folder.read: %v", err)
	}

	// alice holds definitions-edit and manage-projects in org A, so the
	// topology and lifecycle mutations must succeed for her.
	aliceActor := service.LocalPrincipal(alice)
	folder, err := folders.Create(tctx(t), aliceActor, scopeProject(orgA, prjA1), "positive/control")
	if err != nil {
		t.Fatalf("alice creating a folder: %v", err)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM folders WHERE id = '"+folder.ID+"' AND org_id = 'org_a' AND project_id = 'prj_a1'"); n != 1 {
		t.Fatal("created folder's chain did not come from the proof")
	}
	if _, err := folders.Rename(tctx(t), aliceActor, scopeProject(orgA, prjA1), folder.ID, "positive/renamed"); err != nil {
		t.Fatalf("alice renaming a folder: %v", err)
	}
	if err := folders.Delete(tctx(t), aliceActor, scopeProject(orgA, prjA1), folder.ID); err != nil {
		t.Fatalf("alice deleting a folder: %v", err)
	}
	if _, err := envs.Rename(tctx(t), aliceActor, scopeEnv(orgA, prjA1, envA1), "renamed-dev"); err != nil {
		t.Fatalf("alice renaming an environment: %v", err)
	}
	live, err := envs.List(tctx(t), aliceActor, scopeProject(orgA, prjA1))
	if err != nil {
		t.Fatalf("alice listing environments: %v", err)
	}
	ids := make([]string, 0, len(live))
	for i := len(live) - 1; i >= 0; i-- {
		ids = append(ids, live[i].ID)
	}
	reordered, err := envs.Reorder(tctx(t), aliceActor, scopeProject(orgA, prjA1), ids)
	if err != nil {
		t.Fatalf("alice reordering environments: %v", err)
	}
	for i, e := range reordered {
		if e.DisplayOrder != int64(i) {
			t.Fatalf("reorder left a non-dense display order: %+v", reordered)
		}
	}
	if _, err := projects.Rename(tctx(t), aliceActor, scopeProject(orgA, prjA1), "renamed-a1"); err != nil {
		t.Fatalf("alice renaming a project: %v", err)
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
