package isolation

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

func TestDefinitionsSQLite(t *testing.T) { runDefinitions(t, seededDB(t, openSQLite)) }

func TestDefinitionsPostgres(t *testing.T) { runDefinitions(t, seededDB(t, openPostgres)) }

func runDefinitions(t *testing.T, db *store.DB) {
	t.Run("export plan apply round trip", func(t *testing.T) { definitionsRoundTrip(t, db) })
	t.Run("all plan pins reject without side effects", func(t *testing.T) { definitionsPins(t, db) })
	t.Run("key deletion requires acknowledgement", func(t *testing.T) { definitionsKeyDeletion(t, db) })
	t.Run("live environment deletion is unconditional", func(t *testing.T) { definitionsEnvironmentDeletion(t, db) })
	t.Run("git mode guards direct writes and admits apply", func(t *testing.T) { definitionsGitMode(t, db) })
	t.Run("additive bundles", func(t *testing.T) { definitionsAdditive(t, db) })
	t.Run("identity matching and swaps", func(t *testing.T) { definitionsMatching(t, db) })
	t.Run("stale base check classification", func(t *testing.T) { definitionsStaleBase(t, db) })
	t.Run("reveal inheritance", func(t *testing.T) { definitionsReveal(t, db) })
	t.Run("quota expiry and garbage collection", func(t *testing.T) { definitionsPlanLifecycle(t, db) })
	t.Run("secret declaration literal boundary", func(t *testing.T) { definitionsSecretDeclarationBoundary(t, db) })
	t.Run("stored digest tamper", func(t *testing.T) { definitionsStoredDigestTamper(t, db) })
	t.Run("key deletion discards pending drafts", func(t *testing.T) { definitionsPendingDraftDeletion(t, db) })
	t.Run("apply emits constituent audit events", func(t *testing.T) { definitionsConstituentAudit(t, db) })
}

// runDefinitionsAuditLifecycle drives every #70 audit type through its real
// service flow. It is shared with the audit-core emitter check so registering
// an event without a reachable emitter fails on both database engines.
func runDefinitionsAuditLifecycle(t *testing.T, db *store.DB) {
	t.Helper()
	f := seedDefinitionsProject(t, db, "audit", true)
	svc := definitionsService(t, db)

	if _, err := svc.SetSettings(t.Context(), service.LocalPrincipal(orgAdmin), f.scope(), "git"); err != nil {
		t.Fatalf("emit definitions source change: %v", err)
	}
	if _, err := svc.SetSettings(t.Context(), service.LocalPrincipal(orgAdmin), f.scope(), "db"); err != nil {
		t.Fatalf("restore definitions source: %v", err)
	}

	bundle := parseDefinitions(t, exportDefinitions(t, svc, f))
	bundle.Keys = append(bundle.Keys, definitionKey("AUDIT_CREATED", "config"))
	plan := planDefinitions(t, svc, f, encodeDefinitions(t, bundle))
	if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{}); err != nil {
		t.Fatalf("emit definitions applied: %v", err)
	}

	stale := planDefinitions(t, svc, f, exportDefinitions(t, svc, f))
	if _, err := keySvc(t, db).Rename(t.Context(), service.LocalPrincipal(alice), f.scope(), f.key, "AUDIT_KEY"); err != nil {
		t.Fatalf("move definitions revision: %v", err)
	}
	if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), stale.ID, service.ApplyOptions{}); err == nil || !strings.Contains(safeError(err), "definitions revision") {
		t.Fatalf("emit stale apply refusal: %v", err)
	}

	bundle = parseDefinitions(t, exportDefinitions(t, svc, f))
	bundle.Keys = nil
	deletion := planDefinitions(t, svc, f, encodeDefinitions(t, bundle))
	if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), deletion.ID, service.ApplyOptions{}); err == nil || !strings.Contains(safeError(err), "pass --allow-delete") {
		t.Fatalf("emit deletion refusal: %v", err)
	}

	additive := parseDefinitions(t, exportPortableDefinitions(t, svc, f))
	additive.Keys[0].Description = "changed"
	if _, err := svc.Plan(t.Context(), service.LocalPrincipal(alice), f.scope(), encodeDefinitions(t, additive)); err == nil || !strings.Contains(safeError(err), "additive bundle may not modify") {
		t.Fatalf("emit additive modification refusal: %v", err)
	}
}

func definitionsRoundTrip(t *testing.T, db *store.DB) {
	f := seedDefinitionsProject(t, db, "roundtrip", true)
	svc := definitionsService(t, db)
	raw := exportDefinitions(t, svc, f)
	bundle := parseDefinitions(t, raw)
	digest, err := definitions.Digest(bundle)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := svc.Plan(t.Context(), service.LocalPrincipal(alice), f.scope(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Digest != digest || plan.CurrentRevision != 0 || plan.BaseRevision == nil || *plan.BaseRevision != 0 {
		t.Fatalf("plan pins = digest %q revision %d base %v", plan.Digest, plan.CurrentRevision, plan.BaseRevision)
	}
	beforeApply := captureDefinitionsState(t, db, f.project)
	result, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{Digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	if result.Revision != 0 || result.PlanID != plan.ID || len(result.Published) != 0 {
		t.Fatalf("apply result = %+v", result)
	}
	afterApply := captureDefinitionsState(t, db, f.project)
	if !reflect.DeepEqual(afterApply, beforeApply) {
		t.Fatalf("no-op apply changed state\nbefore=%+v\nafter=%+v", beforeApply, afterApply)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE project_id = '"+string(f.project)+"' AND type = 'definitions.applied'"); got != 0 {
		t.Fatalf("no-op apply emitted definitions.applied = %d", got)
	}
	after := exportDefinitions(t, svc, f)
	check, err := svc.Check(t.Context(), service.LocalPrincipal(alice), f.scope(), after)
	if err != nil {
		t.Fatal(err)
	}
	if check.State != string(definitions.DriftEqual) {
		t.Fatalf("re-export check = %s, want equal", check.State)
	}
}

func definitionsPins(t *testing.T, db *store.DB) {
	t.Run("value revision", func(t *testing.T) {
		f := seedDefinitionsProject(t, db, "pinvalue", true)
		svc := definitionsService(t, db)
		plan := planDefinitions(t, svc, f, exportDefinitions(t, svc, f))
		publishDefinitionValue(t, db, f, "BASE_KEY", ptr("moved"))
		before := captureDefinitionsState(t, db, f.project)
		_, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{})
		assertRefusalUnchanged(t, db, f, before, err, `environment "dev" value revision`)
	})
	t.Run("schema revision", func(t *testing.T) {
		f := seedDefinitionsProject(t, db, "pinschema", true)
		svc := definitionsService(t, db)
		plan := planDefinitions(t, svc, f, exportDefinitions(t, svc, f))
		if _, err := keySvc(t, db).Rename(t.Context(), service.LocalPrincipal(alice), f.scope(), f.key, "MOVED_KEY"); err != nil {
			t.Fatal(err)
		}
		before := captureDefinitionsState(t, db, f.project)
		_, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{})
		assertRefusalUnchanged(t, db, f, before, err, "definitions revision")
	})
	t.Run("digest", func(t *testing.T) {
		f := seedDefinitionsProject(t, db, "pindigest", true)
		svc := definitionsService(t, db)
		plan := planDefinitions(t, svc, f, exportDefinitions(t, svc, f))
		before := captureDefinitionsState(t, db, f.project)
		_, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{Digest: strings.Repeat("0", 64)})
		assertRefusalUnchanged(t, db, f, before, err, "bundle digest")
	})
	t.Run("environment topology", func(t *testing.T) {
		f := seedDefinitionsProject(t, db, "pintopology", true)
		svc := definitionsService(t, db)
		plan := planDefinitions(t, svc, f, exportDefinitions(t, svc, f))
		if _, err := cloneSvc(t, db).Create(t.Context(), service.LocalPrincipal(alice), f.scope(), "created-later"); err != nil {
			t.Fatal(err)
		}
		before := captureDefinitionsState(t, db, f.project)
		_, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{})
		assertRefusalUnchanged(t, db, f, before, err, "environment topology")
	})
}

func definitionsKeyDeletion(t *testing.T, db *store.DB) {
	f := seedDefinitionsProject(t, db, "keydelete", true)
	svc := definitionsService(t, db)
	publishDefinitionValue(t, db, f, "BASE_KEY", ptr("live"))
	bundle := parseDefinitions(t, exportDefinitions(t, svc, f))
	bundle.Keys = nil
	raw := encodeDefinitions(t, bundle)
	plan := planDefinitions(t, svc, f, raw)
	if len(plan.Diff.KeyDeletions) != 1 || plan.Diff.KeyDeletions[0].Name != "BASE_KEY" || strings.Join(plan.Diff.KeyDeletions[0].LiveIn, ",") != "dev" {
		t.Fatalf("deletion impact = %+v", plan.Diff.KeyDeletions)
	}
	before := captureDefinitionsState(t, db, f.project)
	_, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{})
	assertRefusalUnchanged(t, db, f, before, err, "pass --allow-delete")
	if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{AllowDelete: true}); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM keys WHERE project_id = '"+string(f.project)+"'"); got != 0 {
		t.Fatalf("keys after deletion = %d", got)
	}
}

func definitionsEnvironmentDeletion(t *testing.T, db *store.DB) {
	f := seedDefinitionsProject(t, db, "envdelete", true)
	svc := definitionsService(t, db)
	publishDefinitionValue(t, db, f, "BASE_KEY", ptr("live"))
	bundle := parseDefinitions(t, exportDefinitions(t, svc, f))
	bundle.Environments = nil
	raw := encodeDefinitions(t, bundle)
	plan := planDefinitions(t, svc, f, raw)
	if len(plan.Diff.EnvDeletions) != 1 || plan.Diff.EnvDeletions[0].Occurrences != 1 {
		t.Fatalf("environment impact = %+v", plan.Diff.EnvDeletions)
	}
	before := captureDefinitionsState(t, db, f.project)
	_, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{AllowDelete: true})
	assertRefusalUnchanged(t, db, f, before, err, "must be emptied")
	publishDefinitionValue(t, db, f, "BASE_KEY", nil)
	plan = planDefinitions(t, svc, f, raw)
	if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{AllowDelete: true}); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM environments WHERE project_id = '"+string(f.project)+"'"); got != 0 {
		t.Fatalf("environments after deletion = %d", got)
	}
}

func definitionsGitMode(t *testing.T, db *store.DB) {
	f := seedDefinitionsProject(t, db, "gitmode", true)
	svc := definitionsService(t, db)
	if _, err := svc.SetSettings(t.Context(), service.LocalPrincipal(orgAdmin), f.scope(), "git"); err != nil {
		t.Fatal(err)
	}
	baseline := captureDefinitionsState(t, db, f.project)
	keys := keySvc(t, db)
	groups := keyGroupSvc(t, db)
	envs := cloneSvc(t, db)
	folders := folderSvc(db)
	description := "changed"
	decl := stringDeclaration()
	checks := []struct {
		name string
		call func() error
	}{
		{"key create", func() error {
			_, err := keys.Create(t.Context(), service.LocalPrincipal(alice), f.scope(), keySpec("NEW_KEY", "config"))
			return err
		}},
		{"key rename", func() error {
			_, err := keys.Rename(t.Context(), service.LocalPrincipal(alice), f.scope(), f.key, "RENAMED_KEY")
			return err
		}},
		{"key metadata", func() error {
			_, err := keys.UpdateMetadata(t.Context(), service.LocalPrincipal(alice), f.scope(), f.key, service.KeyMetadataUpdate{Description: &description})
			return err
		}},
		{"key declaration", func() error {
			_, err := keys.UpdateDeclaration(t.Context(), service.LocalPrincipal(alice), f.scope(), f.key, service.KeyDeclarationUpdate{Declaration: decl, Presence: schema.DefaultPresenceRules()})
			return err
		}},
		{"key reclassify", func() error {
			_, err := keys.Reclassify(t.Context(), service.LocalPrincipal(alice), f.scope(), f.key, "secret")
			return err
		}},
		{"key set group", func() error {
			_, err := keys.SetGroup(t.Context(), service.LocalPrincipal(alice), f.scope(), f.key, f.group)
			return err
		}},
		{"key delete", func() error { return keys.Delete(t.Context(), service.LocalPrincipal(alice), f.scope(), f.key) }},
		{"group create", func() error {
			_, err := groups.Create(t.Context(), service.LocalPrincipal(alice), f.scope(), "new-group")
			return err
		}},
		{"group rename", func() error {
			_, err := groups.Rename(t.Context(), service.LocalPrincipal(alice), f.scope(), f.group, "renamed-group")
			return err
		}},
		{"group delete", func() error { return groups.Delete(t.Context(), service.LocalPrincipal(alice), f.scope(), f.group) }},
		{"environment create", func() error {
			_, err := envs.Create(t.Context(), service.LocalPrincipal(alice), f.scope(), "new-env")
			return err
		}},
		{"environment clone", func() error {
			_, _, err := envs.Clone(t.Context(), service.LocalPrincipal(alice), f.scope(), "clone-env", f.env)
			return err
		}},
		{"environment rename", func() error {
			_, err := envs.Rename(t.Context(), service.LocalPrincipal(alice), f.envScope(), "renamed-env")
			return err
		}},
		{"environment reorder", func() error {
			_, err := envs.Reorder(t.Context(), service.LocalPrincipal(alice), f.scope(), []string{f.env})
			return err
		}},
		{"environment delete", func() error { return envs.Delete(t.Context(), service.LocalPrincipal(alice), f.envScope()) }},
		{"folder create", func() error {
			_, err := folders.Create(t.Context(), service.LocalPrincipal(alice), f.scope(), "new/path")
			return err
		}},
		{"folder rename", func() error {
			_, err := folders.Rename(t.Context(), service.LocalPrincipal(alice), f.scope(), f.folder, "renamed/path")
			return err
		}},
		{"folder delete", func() error { return folders.Delete(t.Context(), service.LocalPrincipal(alice), f.scope(), f.folder) }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			err := check.call()
			assertSafeDetail(t, err, "Definitions for this project are managed in Git — changes arrive through `definitions plan` / `definitions apply`.")
			if got := captureDefinitionsState(t, db, f.project); !reflect.DeepEqual(got, baseline) {
				t.Fatalf("guarded write changed state\nbefore=%+v\nafter=%+v", baseline, got)
			}
		})
	}
	if _, err := svc.SetSettings(t.Context(), service.LocalPrincipal(alice), f.scope(), "db"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("definitions-edit-only setting flip = %v, want uniform not found", err)
	}
	bundle := parseDefinitions(t, exportDefinitions(t, svc, f))
	bundle.Keys = append(bundle.Keys, definitionKey("GIT_APPLIED", "config"))
	plan := planDefinitions(t, svc, f, encodeDefinitions(t, bundle))
	if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{}); err != nil {
		t.Fatalf("apply in git mode: %v", err)
	}
}

func definitionsAdditive(t *testing.T, db *store.DB) {
	t.Run("fresh create", func(t *testing.T) {
		f := seedDefinitionsProject(t, db, "addfresh", false)
		svc := definitionsService(t, db)
		bundle := definitions.Bundle{
			FormatVersion: definitions.FormatVersion,
			Environments:  []definitions.Environment{{Name: "dev"}},
			KeyGroups:     []definitions.KeyGroup{{Name: "database"}},
			Keys:          []definitions.Key{definitionKey("CREATED_KEY", "config")},
		}
		bundle.Keys[0].Group = "database"
		plan := planDefinitions(t, svc, f, encodeDefinitions(t, bundle))
		if !plan.Additive {
			t.Fatal("additive plan lost additive marker")
		}
		if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{}); err != nil {
			t.Fatal(err)
		}
		if got := queryInt(t, db, "SELECT COUNT(*) FROM keys WHERE project_id = '"+string(f.project)+"'"); got != 1 {
			t.Fatalf("created keys = %d", got)
		}
	})
	t.Run("modification refused", func(t *testing.T) {
		f := seedDefinitionsProject(t, db, "addmodify", true)
		svc := definitionsService(t, db)
		portable := parseDefinitions(t, exportPortableDefinitions(t, svc, f))
		portable.Keys[0].Description = "modified"
		before := captureDefinitionsState(t, db, f.project)
		_, err := svc.Plan(t.Context(), service.LocalPrincipal(alice), f.scope(), encodeDefinitions(t, portable))
		assertRefusalUnchanged(t, db, f, before, err, "additive bundle may not modify existing key")
	})
	t.Run("allow delete meaningless", func(t *testing.T) {
		f := seedDefinitionsProject(t, db, "addallow", true)
		svc := definitionsService(t, db)
		portable := exportPortableDefinitions(t, svc, f)
		plan := planDefinitions(t, svc, f, portable)
		before := captureDefinitionsState(t, db, f.project)
		_, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{AllowDelete: true})
		assertRefusalUnchanged(t, db, f, before, err, "additive bundle derives no deletion")
	})
}

func definitionsMatching(t *testing.T, db *store.DB) {
	f := seedDefinitionsProject(t, db, "matching", true)
	svc := definitionsService(t, db)
	bundle := parseDefinitions(t, exportDefinitions(t, svc, f))
	bundle.Keys[0].Name = "RENAMED_KEY"
	bundle.Keys = append(bundle.Keys, definitionKey("BASE_KEY", "config"))
	bundle.Environments[0].Name = "renamed-env"
	bundle.Environments = append(bundle.Environments, definitions.Environment{Name: "dev"})
	bundle.KeyGroups[0].Name = "renamed-group"
	bundle.KeyGroups = append(bundle.KeyGroups, definitions.KeyGroup{Name: "base-group"})
	plan := planDefinitions(t, svc, f, encodeDefinitions(t, bundle))
	if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM environments WHERE project_id = '"+string(f.project)+"' AND name IN ('dev','renamed-env')"); got != 2 {
		t.Fatalf("environment rename+replacement = %d rows", got)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM key_groups WHERE project_id = '"+string(f.project)+"' AND name IN ('base-group','renamed-group')"); got != 2 {
		t.Fatalf("group rename+replacement = %d rows", got)
	}

	bundle = parseDefinitions(t, exportDefinitions(t, svc, f))
	for i := range bundle.Keys {
		switch bundle.Keys[i].Name {
		case "BASE_KEY":
			bundle.Keys[i].Name = "RENAMED_KEY"
		case "RENAMED_KEY":
			bundle.Keys[i].Name = "BASE_KEY"
		}
	}
	plan = planDefinitions(t, svc, f, encodeDefinitions(t, bundle))
	if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{}); err != nil {
		t.Fatalf("swap apply: %v", err)
	}

	t.Run("stale id", func(t *testing.T) {
		bad := parseDefinitions(t, exportDefinitions(t, svc, f))
		bad.Keys[0].ID = "key_stale"
		before := captureDefinitionsState(t, db, f.project)
		_, err := svc.Plan(t.Context(), service.LocalPrincipal(alice), f.scope(), encodeDefinitions(t, bad))
		assertRefusalUnchanged(t, db, f, before, err, "stale")
	})
	t.Run("duplicate final name", func(t *testing.T) {
		bad := parseDefinitions(t, exportDefinitions(t, svc, f))
		bad.Keys[0].Name, bad.Keys[1].Name = "DUPLICATE", "DUPLICATE"
		before := captureDefinitionsState(t, db, f.project)
		_, err := svc.Plan(t.Context(), service.LocalPrincipal(alice), f.scope(), encodeDefinitions(t, bad))
		assertRefusalUnchanged(t, db, f, before, err, "DUPLICATE")
	})

	portable := exportPortableDefinitions(t, svc, f)
	count := queryInt(t, db, "SELECT COUNT(*) FROM keys WHERE project_id = '"+string(f.project)+"'")
	plan = planDefinitions(t, svc, f, portable)
	if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{}); err != nil {
		t.Fatalf("portable own-project apply: %v", err)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM keys WHERE project_id = '"+string(f.project)+"'"); got != count {
		t.Fatalf("portable apply duplicated keys: %d -> %d", count, got)
	}
}

func definitionsStaleBase(t *testing.T, db *store.DB) {
	f := seedDefinitionsProject(t, db, "stalebase", true)
	svc := definitionsService(t, db)
	old := exportDefinitions(t, svc, f)
	temporary, restored := "temporary", ""
	if _, err := keySvc(t, db).UpdateMetadata(t.Context(), service.LocalPrincipal(alice), f.scope(), f.key,
		service.KeyMetadataUpdate{Description: &temporary}); err != nil {
		t.Fatal(err)
	}
	if _, err := keySvc(t, db).UpdateMetadata(t.Context(), service.LocalPrincipal(alice), f.scope(), f.key,
		service.KeyMetadataUpdate{Description: &restored}); err != nil {
		t.Fatal(err)
	}
	before := captureDefinitionsState(t, db, f.project)
	_, err := svc.Plan(t.Context(), service.LocalPrincipal(alice), f.scope(), old)
	assertRefusalUnchanged(t, db, f, before, err, "re-export and rebase")
	check, err := svc.Check(t.Context(), service.LocalPrincipal(alice), f.scope(), old)
	if err != nil || check.State != string(definitions.DriftDBAhead) {
		t.Fatalf("stale equal-content check = %+v, %v", check, err)
	}
	if _, err := keySvc(t, db).Rename(t.Context(), service.LocalPrincipal(alice), f.scope(), f.key, "DIVERGED_KEY"); err != nil {
		t.Fatal(err)
	}
	check, err = svc.Check(t.Context(), service.LocalPrincipal(alice), f.scope(), old)
	if err != nil || check.State != string(definitions.DriftDiverged) {
		t.Fatalf("stale changed-content check = %+v, %v", check, err)
	}
}

func definitionsSecretDeclarationBoundary(t *testing.T, db *store.DB) {
	literal := schema.Declaration{Rule: &schema.Rule{Type: schema.TypeEnum, Members: []string{"live-value"}}}

	t.Run("create", func(t *testing.T) {
		f := seedDefinitionsProject(t, db, "literalcreate", false)
		spec := keySpec("SECRET_ENUM", "secret")
		spec.Declaration = literal
		_, err := keySvc(t, db).Create(t.Context(), service.LocalPrincipal(alice), f.scope(), spec)
		assertSafeContains(t, err, "use `pattern`, or declassify the key")
	})

	t.Run("update declaration", func(t *testing.T) {
		f := seedDefinitionsProject(t, db, "literalupdate", true)
		execRaw(t, db, "UPDATE keys SET classification = 'secret' WHERE id = '"+f.key+"'")
		_, err := keySvc(t, db).UpdateDeclaration(t.Context(), service.LocalPrincipal(custodian), f.scope(), f.key,
			service.KeyDeclarationUpdate{Declaration: literal, Presence: schema.DefaultPresenceRules()})
		assertSafeContains(t, err, "use `pattern`, or declassify the key")
	})

	t.Run("reclassify", func(t *testing.T) {
		f := seedDefinitionsProject(t, db, "literalreclassify", true)
		if _, err := keySvc(t, db).UpdateDeclaration(t.Context(), service.LocalPrincipal(alice), f.scope(), f.key,
			service.KeyDeclarationUpdate{Declaration: literal, Presence: schema.DefaultPresenceRules()}); err != nil {
			t.Fatal(err)
		}
		_, err := keySvc(t, db).Reclassify(t.Context(), service.LocalPrincipal(alice), f.scope(), f.key, "secret")
		assertSafeContains(t, err, "use `pattern`, or declassify the key")
	})

	t.Run("plan nested const", func(t *testing.T) {
		f := seedDefinitionsProject(t, db, "literalplan", true)
		execRaw(t, db, "UPDATE keys SET classification = 'secret' WHERE id = '"+f.key+"'")
		svc := definitionsService(t, db)
		bundle := parseDefinitions(t, exportDefinitions(t, svc, f))
		bundle.Keys[0].Declaration = schema.Declaration{Rule: &schema.Rule{Type: schema.TypeJSON,
			JSONSchema: []byte(`{"properties":{"nested":{"const":"live-value"}}}`)}}
		raw, err := definitions.Encode(bundle)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.Plan(t.Context(), service.LocalPrincipal(alice), f.scope(), raw)
		assertSafeContains(t, err, "BASE_KEY")
		assertSafeContains(t, err, "use `pattern`, or declassify the key")
	})
}

func definitionsStoredDigestTamper(t *testing.T, db *store.DB) {
	f := seedDefinitionsProject(t, db, "digesttamper", true)
	svc := definitionsService(t, db)
	bundle := parseDefinitions(t, exportDefinitions(t, svc, f))
	bundle.Keys = append(bundle.Keys, definitionKey("DIGEST_CREATED", "config"))
	plan := planDefinitions(t, svc, f, encodeDefinitions(t, bundle))
	execRaw(t, db, "UPDATE definitions_plans SET digest = '"+strings.Repeat("0", 64)+"' WHERE id = '"+plan.ID+"'")
	before := captureDefinitionsState(t, db, f.project)
	_, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{})
	assertRefusalUnchanged(t, db, f, before, err, "bundle digest")
}

func definitionsPendingDraftDeletion(t *testing.T, db *store.DB) {
	f := seedDefinitionsProject(t, db, "pendingdelete", true)
	svc := definitionsService(t, db)
	if _, err := valueSvc(t, db).Set(t.Context(), service.LocalPrincipal(custodian), f.envScope(), "BASE_KEY", "draft"); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM pending_changes WHERE project_id = '"+string(f.project)+"'"); got != 1 {
		t.Fatalf("pending drafts before apply = %d", got)
	}
	bundle := parseDefinitions(t, exportDefinitions(t, svc, f))
	bundle.Keys = nil
	plan := planDefinitions(t, svc, f, encodeDefinitions(t, bundle))
	if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{AllowDelete: true}); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM pending_changes WHERE project_id = '"+string(f.project)+"'"); got != 0 {
		t.Fatalf("pending drafts after apply = %d", got)
	}
}

func definitionsConstituentAudit(t *testing.T, db *store.DB) {
	f := seedDefinitionsProject(t, db, "constituentaudit", false)
	svc := definitionsService(t, db)
	created := definitions.Bundle{
		FormatVersion: definitions.FormatVersion,
		Environments:  []definitions.Environment{{Name: "dev"}},
		KeyGroups:     []definitions.KeyGroup{{Name: "database"}},
		Keys:          []definitions.Key{definitionKey("AUDIT_KEY", "config")},
	}
	created.Keys[0].Group = "database"
	plan := planDefinitions(t, svc, f, encodeDefinitions(t, created))
	if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}

	updated := parseDefinitions(t, exportDefinitions(t, svc, f))
	updated.Environments[0].Name = "production"
	updated.KeyGroups[0].Name = "runtime"
	updated.Keys[0].Name = "RENAMED_KEY"
	updated.Keys[0].Description = "renamed metadata"
	updated.Keys[0].Classification = "secret"
	updated.Keys[0].Group = ""
	minimum := 2
	updated.Keys[0].Declaration = schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString, MinLength: &minimum}}
	updated.Keys[0].ForbiddenIn = definitions.Presence{Mode: "explicit", Environments: []string{"production"}}
	plan = planDefinitions(t, svc, f, encodeDefinitions(t, updated))
	if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}

	deleted := parseDefinitions(t, exportDefinitions(t, svc, f))
	deleted.Environments, deleted.KeyGroups, deleted.Keys = nil, nil, nil
	plan = planDefinitions(t, svc, f, encodeDefinitions(t, deleted))
	if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{AllowDelete: true}); err != nil {
		t.Fatal(err)
	}

	for _, eventType := range []string{
		"settings.environment_created", "settings.environment_renamed", "settings.environment_deleted",
		"settings.key_group_created", "settings.key_group_renamed", "settings.key_group_deleted",
		"settings.key_created", "settings.key_renamed", "settings.key_deleted",
		"settings.key_metadata_changed", "settings.key_declaration_changed",
		"settings.key_reclassified", "settings.key_group_membership_changed",
	} {
		if got := queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE project_id = '"+string(f.project)+"' AND type = '"+eventType+"'"); got == 0 {
			t.Fatalf("apply did not emit %s", eventType)
		}
	}
}

func definitionsReveal(t *testing.T, db *store.DB) {
	f := seedDefinitionsProject(t, db, "reveal", true)
	execRaw(t, db, "UPDATE keys SET classification = 'secret' WHERE id = '"+f.key+"'")
	svc := definitionsService(t, db)
	bundle := parseDefinitions(t, exportDefinitions(t, svc, f))
	minimum := 2
	bundle.Keys[0].Declaration = schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString, MinLength: &minimum}}
	plan := planDefinitions(t, svc, f, encodeDefinitions(t, bundle))
	if strings.Join(plan.RevealRequired, ",") != "BASE_KEY" {
		t.Fatalf("reveal preview = %v", plan.RevealRequired)
	}
	before := captureDefinitionsState(t, db, f.project)
	_, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{})
	assertRefusalUnchanged(t, db, f, before, err, "BASE_KEY")
	if _, err := svc.Apply(t.Context(), service.LocalPrincipal(custodian), f.scope(), plan.ID, service.ApplyOptions{}); err != nil {
		t.Fatalf("revealer apply: %v", err)
	}
}

func definitionsPlanLifecycle(t *testing.T, db *store.DB) {
	f := seedDefinitionsProject(t, db, "lifecycle", true)
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	svc := definitionsService(t, db)
	svc.Now = func() time.Time { return now }
	raw := exportDefinitions(t, svc, f)
	plans := make([]service.PlanView, 0, service.MaxOpenPlansPerProject)
	for range service.MaxOpenPlansPerProject {
		plans = append(plans, planDefinitions(t, svc, f, raw))
	}
	before := captureDefinitionsState(t, db, f.project)
	_, err := svc.Plan(t.Context(), service.LocalPrincipal(alice), f.scope(), raw)
	assertRefusalUnchanged(t, db, f, before, err, "max 20")
	now = now.Add(service.PlanTTL)
	before = captureDefinitionsState(t, db, f.project)
	_, err = svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plans[0].ID, service.ApplyOptions{})
	assertRefusalUnchanged(t, db, f, before, err, "plan expired; re-plan")
	retention := &service.Retention{DB: db, Now: func() time.Time { return now }}
	if _, err := retention.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM definitions_plans WHERE project_id = '"+string(f.project)+"'"); got != 0 {
		t.Fatalf("expired plans after GC = %d", got)
	}
}

type definitionsFixture struct {
	project domain.ProjectID
	env     string
	key     string
	group   string
	folder  string
}

func (f definitionsFixture) scope() domain.Scope { return scopeProject(orgA, f.project) }
func (f definitionsFixture) envScope() domain.Scope {
	return scopeEnv(orgA, f.project, domain.EnvID(f.env))
}

func seedDefinitionsProject(t *testing.T, db *store.DB, label string, populated bool) definitionsFixture {
	t.Helper()
	f := definitionsFixture{
		project: domain.ProjectID("prj_def_" + label), env: "env_def_" + label,
		key: "key_def_" + label, group: "kg_def_" + label, folder: "fld_def_" + label,
	}
	execRaw(t, db, fmt.Sprintf("INSERT INTO projects (id, org_id, name, created_at) VALUES ('%s', 'org_a', '%s', %s)", f.project, label, ts))
	execRaw(t, db, fmt.Sprintf("INSERT INTO project_schema_revisions (org_id, project_id, revision) VALUES ('org_a', '%s', 0)", f.project))
	if !populated {
		return f
	}
	execRaw(t, db, fmt.Sprintf("INSERT INTO environments (id, org_id, project_id, name, note, created_at, display_order) VALUES ('%s', 'org_a', '%s', 'dev', '', %s, 0)", f.env, f.project, ts))
	execRaw(t, db, fmt.Sprintf("INSERT INTO folders (id, org_id, project_id, path, created_at) VALUES ('%s', 'org_a', '%s', 'base', %s)", f.folder, f.project, ts))
	execRaw(t, db, fmt.Sprintf("INSERT INTO key_groups (id, org_id, project_id, name, created_at) VALUES ('%s', 'org_a', '%s', 'base-group', %s)", f.group, f.project, ts))
	execRaw(t, db, fmt.Sprintf("INSERT INTO keys (id, org_id, project_id, name, folder_path, classification, description, deprecated, deprecation_note, declaration, required_mode, forbidden_mode, group_id, created_at) VALUES ('%s', 'org_a', '%s', 'BASE_KEY', '', 'config', '', FALSE, '', '{\"rule\":{\"type\":\"string\"}}', 'none', 'none', NULL, %s)", f.key, f.project, ts))
	return f
}

func definitionsService(t *testing.T, db *store.DB) *service.Definitions {
	t.Helper()
	return &service.Definitions{DB: db, Keyring: probeKeyring(t, db), Advisory: service.NewAdvisory()}
}

func exportDefinitions(t *testing.T, svc *service.Definitions, f definitionsFixture) []byte {
	t.Helper()
	raw, err := svc.Export(t.Context(), service.LocalPrincipal(alice), f.scope(), false)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func exportPortableDefinitions(t *testing.T, svc *service.Definitions, f definitionsFixture) []byte {
	t.Helper()
	raw, err := svc.Export(t.Context(), service.LocalPrincipal(alice), f.scope(), true)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func planDefinitions(t *testing.T, svc *service.Definitions, f definitionsFixture, raw []byte) service.PlanView {
	t.Helper()
	plan, err := svc.Plan(t.Context(), service.LocalPrincipal(alice), f.scope(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func parseDefinitions(t *testing.T, raw []byte) definitions.Bundle {
	t.Helper()
	bundle, err := definitions.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func encodeDefinitions(t *testing.T, bundle definitions.Bundle) []byte {
	t.Helper()
	normalized, err := definitions.Normalize(bundle)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := definitions.Encode(normalized)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func definitionKey(name, classification string) definitions.Key {
	return definitions.Key{
		Name: name, Classification: classification, Declaration: stringDeclaration(),
		RequiredIn:  definitions.Presence{Mode: string(schema.PresenceNone), Environments: []string{}},
		ForbiddenIn: definitions.Presence{Mode: string(schema.PresenceNone), Environments: []string{}},
	}
}

func stringDeclaration() schema.Declaration {
	return schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}}
}

func keySpec(name, classification string) service.KeySpec {
	return service.KeySpec{Name: name, Classification: classification, Declaration: stringDeclaration(), Presence: schema.DefaultPresenceRules()}
}

func publishDefinitionValue(t *testing.T, db *store.DB, f definitionsFixture, name string, value *string) {
	t.Helper()
	values := valueSvc(t, db)
	var staged service.StagedChange
	var err error
	if value == nil {
		staged, err = values.Unset(t.Context(), service.LocalPrincipal(custodian), f.envScope(), name)
	} else {
		staged, err = values.Set(t.Context(), service.LocalPrincipal(custodian), f.envScope(), name, *value)
	}
	if err != nil {
		t.Fatal(err)
	}
	revisions := &service.Revisions{DB: db, Keyring: probeKeyring(t, db)}
	if _, err := revisions.Publish(t.Context(), service.LocalPrincipal(custodian), f.envScope(), []string{staged.VersionID}); err != nil {
		t.Fatal(err)
	}
}

type definitionsState struct {
	keys, groups, environments, folders, plans   string
	revision, values, snapshots, snapshotEntries int64
}

func captureDefinitionsState(t *testing.T, db *store.DB, project domain.ProjectID) definitionsState {
	t.Helper()
	p := string(project)
	return definitionsState{
		keys:            queryStrings(t, db, "SELECT id || ':' || name || ':' || classification || ':' || description || ':' || COALESCE(group_id, '') FROM keys WHERE project_id = '"+p+"' ORDER BY id"),
		groups:          queryStrings(t, db, "SELECT id || ':' || name FROM key_groups WHERE project_id = '"+p+"' ORDER BY id"),
		environments:    queryStrings(t, db, "SELECT id || ':' || name FROM environments WHERE project_id = '"+p+"' ORDER BY id"),
		folders:         queryStrings(t, db, "SELECT id || ':' || path FROM folders WHERE project_id = '"+p+"' ORDER BY id"),
		plans:           queryStrings(t, db, "SELECT id || ':' || COALESCE(CAST(applied_at AS TEXT), '') FROM definitions_plans WHERE project_id = '"+p+"' ORDER BY id"),
		revision:        queryInt(t, db, "SELECT revision FROM project_schema_revisions WHERE project_id = '"+p+"'"),
		values:          queryInt(t, db, "SELECT COUNT(*) FROM value_entries WHERE project_id = '"+p+"'"),
		snapshots:       queryInt(t, db, "SELECT COUNT(*) FROM snapshots WHERE project_id = '"+p+"'"),
		snapshotEntries: queryInt(t, db, "SELECT COUNT(*) FROM snapshot_entries WHERE project_id = '"+p+"'"),
	}
}

func assertRefusalUnchanged(t *testing.T, db *store.DB, f definitionsFixture, before definitionsState, err error, contains string) {
	t.Helper()
	if err == nil || !strings.Contains(safeError(err), contains) {
		t.Fatalf("refusal = %v (safe %q), want text %q", err, safeError(err), contains)
	}
	after := captureDefinitionsState(t, db, f.project)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("refusal changed state\nbefore=%+v\nafter=%+v", before, after)
	}
}

func assertSafeDetail(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatal("guarded write succeeded")
	}
	var carrier interface{ SafeDetail() string }
	if !errors.As(err, &carrier) || carrier.SafeDetail() != want {
		t.Fatalf("safe detail = %q from %v, want %q", safeError(err), err, want)
	}
}

func assertSafeContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(safeError(err), want) {
		t.Fatalf("safe error = %q, want %q", safeError(err), want)
	}
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	var carrier interface{ SafeDetail() string }
	if errors.As(err, &carrier) {
		return carrier.SafeDetail()
	}
	return err.Error()
}

func ptr[T any](v T) *T { return &v }
