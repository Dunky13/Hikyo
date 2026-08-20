package isolation

// Secret-scanning at the definitions Git-flow chokepoints (#74 SS3, ADR §7
// (b)/(c)), end-to-end on both engines through TestDefinitions{SQLite,Postgres}:
//
//   - SS3.plan: `definitions plan` scans every author-controlled bundle leaf
//     BEFORE the immutable plan persists. A planted credential refuses the plan
//     (finding_blocked, ingress `plan`) with NO plan row written; an acknowledged
//     resubmission commits the plan and emits finding_overridden.
//   - SS3.apply: `definitions apply` re-scans IFF the running ruleset snapshot
//     differs from the one the plan recorded. A same-version apply adds NO second
//     scan (proven token-free: a plan carrying an acknowledged credential applies
//     with no tokens, which is only possible if nothing re-scanned). A
//     version-skewed apply re-scans and refuses (ingress `apply`); the same apply
//     presenting the re-scan's fresh tokens commits, emitting finding_overridden.
//
// These are the two legs that waited on #70's plan/apply verbs; the service seam
// (internal/service/scan.go) is verb-agnostic and these drive it through the real
// Definitions service with a live ruleset — no stubs.

import (
	"errors"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/scanning"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// definitionsScanningService is the Definitions service with a live ruleset
// wired, as app.go wires it in production.
func definitionsScanningService(t *testing.T, db *store.DB) *service.Definitions {
	t.Helper()
	rs, err := scanning.Load()
	if err != nil {
		t.Fatalf("load ruleset: %v", err)
	}
	return &service.Definitions{DB: db, Keyring: probeKeyring(t, db), Advisory: service.NewAdvisory(), Scan: rs}
}

// credentialBundle exports the project's clean bundle and appends a config key
// whose description carries the planted credential — the author-controlled leaf
// the scan must catch.
func credentialBundle(t *testing.T, svc *service.Definitions, f definitionsFixture) []byte {
	t.Helper()
	bundle := parseDefinitions(t, exportDefinitions(t, svc, f))
	k := definitionKey("CRED_KEY", "config")
	k.Description = "see the runbook token " + plantedCredential
	bundle.Keys = append(bundle.Keys, k)
	return encodeDefinitions(t, bundle)
}

func planCount(t *testing.T, db *store.DB, f definitionsFixture) int64 {
	return queryInt(t, db, "SELECT COUNT(*) FROM definitions_plans WHERE project_id = '"+string(f.project)+"'")
}

func scanRefusalTokens(t *testing.T, err error) []string {
	t.Helper()
	var refusal interface{ Findings() []service.Finding }
	if !errors.As(err, &refusal) {
		t.Fatalf("error is not a scan refusal: %v", err)
	}
	if len(refusal.Findings()) == 0 {
		t.Fatal("scan refusal names no finding")
	}
	tokens := make([]string, 0, len(refusal.Findings()))
	for _, finding := range refusal.Findings() {
		if finding.Acknowledgement == "" {
			t.Fatal("blocked finding carries no override token")
		}
		tokens = append(tokens, finding.Acknowledgement)
	}
	return tokens
}

// runScanningDefinitionsPlanBlock is SS3.plan: a credential in a bundle
// description refuses `definitions plan` before the plan persists, and an
// acknowledged resubmission commits it.
func runScanningDefinitionsPlanBlock(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := tctx(t)
	f := seedDefinitionsProject(t, db, "scanplan", true)
	svc := definitionsScanningService(t, db)
	raw := credentialBundle(t, svc, f)

	blockedBefore := scanEventCount(t, db, "scanning.finding_blocked")
	_, err := svc.Plan(ctx, service.LocalPrincipal(alice), f.scope(), raw, nil)
	if err == nil {
		t.Fatal("SS3.plan: a bundle carrying a credential was not refused")
	}
	tokens := scanRefusalTokens(t, err)

	// The block event landed (ingress plan), and NOTHING else: no plan row.
	if scanEventCount(t, db, "scanning.finding_blocked") <= blockedBefore {
		t.Fatal("SS3.plan: no finding_blocked event committed")
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'scanning.finding_blocked' AND payload LIKE '%\"ingress\":\"plan\"%'"); n == 0 {
		t.Fatal("SS3.plan: the block event does not carry ingress plan")
	}
	if n := planCount(t, db, f); n != 0 {
		t.Fatalf("SS3.plan: a refused plan persisted %d plan row(s); the block must leave nothing but the event", n)
	}

	// Acknowledged resubmission: the SAME bundle presenting the override token(s)
	// commits the plan and emits finding_overridden (ingress plan).
	overriddenBefore := scanEventCount(t, db, "scanning.finding_overridden")
	plan, err := svc.Plan(ctx, service.LocalPrincipal(alice), f.scope(), raw, tokens)
	if err != nil {
		t.Fatalf("SS3.plan: acknowledged resubmission was refused: %v", err)
	}
	if plan.ID == "" || planCount(t, db, f) != 1 {
		t.Fatalf("SS3.plan: acknowledged plan did not persist (id=%q, rows=%d)", plan.ID, planCount(t, db, f))
	}
	if scanEventCount(t, db, "scanning.finding_overridden") <= overriddenBefore {
		t.Fatal("SS3.plan: no finding_overridden event committed on the acknowledged plan")
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'scanning.finding_overridden' AND payload LIKE '%\"ingress\":\"plan\"%'"); n == 0 {
		t.Fatal("SS3.plan: the override event does not carry ingress plan")
	}
}

// acknowledgedCredentialPlan persists a plan carrying the planted credential by
// blocking once (to receive the tokens) and re-planning with them. It returns the
// committed plan id.
func acknowledgedCredentialPlan(t *testing.T, db *store.DB, svc *service.Definitions, f definitionsFixture) (string, []byte) {
	t.Helper()
	ctx := tctx(t)
	raw := credentialBundle(t, svc, f)
	_, err := svc.Plan(ctx, service.LocalPrincipal(alice), f.scope(), raw, nil)
	if err == nil {
		t.Fatal("credential plan was not refused on the first pass")
	}
	tokens := scanRefusalTokens(t, err)
	plan, err := svc.Plan(ctx, service.LocalPrincipal(alice), f.scope(), raw, tokens)
	if err != nil {
		t.Fatalf("acknowledged credential plan was refused: %v", err)
	}
	return plan.ID, raw
}

// runScanningDefinitionsApplySkew is SS3.apply: a same-version apply runs no
// second scan, and a ruleset-snapshot-skewed apply re-scans and refuses until the
// re-scan's fresh tokens are presented.
func runScanningDefinitionsApplySkew(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := tctx(t)

	// --- same-version apply adds NO second scan (proven token-free) ----------
	same := seedDefinitionsProject(t, db, "scanapplysame", true)
	svc := definitionsScanningService(t, db)
	samePlanID, _ := acknowledgedCredentialPlan(t, db, svc, same)
	// The plan carries the acknowledged credential and the running ruleset matches
	// the one it was scanned under, so apply must NOT re-scan. Presenting no tokens
	// succeeds only because nothing re-scanned; a re-scan would block here.
	if _, err := svc.Apply(ctx, service.LocalPrincipal(alice), same.scope(), samePlanID, service.ApplyOptions{}); err != nil {
		t.Fatalf("SS3.apply: same-version apply re-scanned (refused a plan it must apply untouched): %v", err)
	}

	// --- version-skewed apply re-scans and refuses, then commits on ack ------
	skew := seedDefinitionsProject(t, db, "scanapplyskew", true)
	skewPlanID, _ := acknowledgedCredentialPlan(t, db, svc, skew)
	// Force snapshot skew: the recorded snapshot no longer equals the running one,
	// exactly what a ruleset upgrade produces. The tokens minted at plan time stay
	// valid against the unchanged live ruleset, so the re-scan is real but the
	// content still binds.
	execRaw(t, db, "UPDATE definitions_plans SET scan_snapshot = 'stale-v0' WHERE id = '"+skewPlanID+"'")

	blockedBefore := scanEventCount(t, db, "scanning.finding_blocked")
	_, err := svc.Apply(ctx, service.LocalPrincipal(alice), skew.scope(), skewPlanID, service.ApplyOptions{})
	if err == nil {
		t.Fatal("SS3.apply: a version-skewed apply did not re-scan and refuse")
	}
	tokens := scanRefusalTokens(t, err)
	if scanEventCount(t, db, "scanning.finding_blocked") <= blockedBefore {
		t.Fatal("SS3.apply: skew re-scan committed no finding_blocked event")
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'scanning.finding_blocked' AND payload LIKE '%\"ingress\":\"apply\"%'"); n == 0 {
		t.Fatal("SS3.apply: the block event does not carry ingress apply")
	}
	// The refused apply persisted nothing: the plan is still unapplied.
	if n := queryInt(t, db, "SELECT COUNT(*) FROM definitions_plans WHERE id = '"+skewPlanID+"' AND NOT applied"); n != 1 {
		t.Fatal("SS3.apply: a skew-refused apply stamped the plan applied")
	}
	// And no orphan project DEK: the skew re-scan runs in a read pre-flight BEFORE
	// prepareSchemaPublish mints the key, so a refused apply on this raw-SQL-seeded
	// project (which never minted a DEK) leaves zero. A refactor that moved the scan
	// inside the write transaction would leak the separately-committed DEK row here.
	if n := queryInt(t, db, "SELECT COUNT(*) FROM tier3_keys WHERE purpose = 'project' AND org_id = '"+string(orgA)+"' AND project_id = '"+string(skew.project)+"' AND state = 'active'"); n != 0 {
		t.Fatalf("SS3.apply: a skew-refused apply left %d project DEK row(s) — the scan ran after the mint", n)
	}

	// Acknowledged apply: the re-scan's tokens commit the apply and emit
	// finding_overridden (ingress apply).
	overriddenBefore := scanEventCount(t, db, "scanning.finding_overridden")
	if _, err := svc.Apply(ctx, service.LocalPrincipal(alice), skew.scope(), skewPlanID, service.ApplyOptions{Acknowledgements: tokens}); err != nil {
		t.Fatalf("SS3.apply: acknowledged skew apply was refused: %v", err)
	}
	if scanEventCount(t, db, "scanning.finding_overridden") <= overriddenBefore {
		t.Fatal("SS3.apply: no finding_overridden event committed on the acknowledged apply")
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'scanning.finding_overridden' AND payload LIKE '%\"ingress\":\"apply\"%'"); n == 0 {
		t.Fatal("SS3.apply: the override event does not carry ingress apply")
	}
}

func seedDefinitionDismissal(t *testing.T, db *store.DB, f definitionsFixture) {
	t.Helper()
	execRaw(t, db, "INSERT INTO scanning_dismissals "+
		"(id, org_id, project_id, environment_id, key_id, rule_digest, value_fingerprint, created_at, created_by) VALUES "+
		"('dismiss_"+f.key+"', 'org_a', '"+string(f.project)+"', '"+f.env+"', '"+f.key+"', "+
		"'test-rule-digest', 'test-fingerprint', '2026-08-20T12:00:00Z', '"+string(alice)+"')")
}

func definitionDismissalCount(t *testing.T, db *store.DB, f definitionsFixture) int64 {
	t.Helper()
	return queryInt(t, db, "SELECT COUNT(*) FROM scanning_dismissals WHERE project_id = '"+
		string(f.project)+"' AND key_id = '"+f.key+"'")
}

func runScanningDefinitionsApplyLifecycle(t *testing.T, db *store.DB) {
	t.Helper()

	t.Run("key delete drops dismissals before catalogue row", func(t *testing.T) {
		f := seedDefinitionsProject(t, db, "scandismissdelete", true)
		svc := definitionsScanningService(t, db)
		seedDefinitionDismissal(t, db, f)

		bundle := parseDefinitions(t, exportDefinitions(t, svc, f))
		bundle.Keys = nil
		plan := planDefinitions(t, svc, f, encodeDefinitions(t, bundle))
		if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{AllowDelete: true}); err != nil {
			t.Fatalf("apply key delete with dismissal: %v", err)
		}
		if got := definitionDismissalCount(t, db, f); got != 0 {
			t.Fatalf("dismissals after key delete = %d, want 0", got)
		}
		if got := queryInt(t, db, "SELECT COUNT(*) FROM keys WHERE id = '"+f.key+"'"); got != 0 {
			t.Fatalf("key rows after delete = %d, want 0", got)
		}
	})

	t.Run("config to secret drops dismissals", func(t *testing.T) {
		f := seedDefinitionsProject(t, db, "scandismisstighten", true)
		svc := definitionsScanningService(t, db)
		seedDefinitionDismissal(t, db, f)

		bundle := parseDefinitions(t, exportDefinitions(t, svc, f))
		bundle.Keys[0].Classification = "secret"
		plan := planDefinitions(t, svc, f, encodeDefinitions(t, bundle))
		if _, err := svc.Apply(t.Context(), service.LocalPrincipal(alice), f.scope(), plan.ID, service.ApplyOptions{}); err != nil {
			t.Fatalf("apply config to secret: %v", err)
		}
		if got := definitionDismissalCount(t, db, f); got != 0 {
			t.Fatalf("dismissals after config to secret = %d, want 0", got)
		}
		if got := queryInt(t, db, "SELECT COUNT(*) FROM keys WHERE id = '"+f.key+"' AND classification = 'secret'"); got != 1 {
			t.Fatalf("secret key rows after reclassification = %d, want 1", got)
		}
	})

	t.Run("secret to config requires interactive declassification", func(t *testing.T) {
		f := seedDefinitionsProject(t, db, "scandeclassnoop", true)
		execRaw(t, db, "UPDATE keys SET classification = 'secret' WHERE id = '"+f.key+"'")
		publishDefinitionValue(t, db, f, "BASE_KEY", ptr(plantedCredential))
		svc := definitionsScanningService(t, db)

		bundle := parseDefinitions(t, exportDefinitions(t, svc, f))
		bundle.Keys[0].Classification = "config"
		plan := planDefinitions(t, svc, f, encodeDefinitions(t, bundle))
		before := captureDefinitionsState(t, db, f.project)
		_, err := svc.Apply(t.Context(), service.LocalPrincipal(custodian), f.scope(), plan.ID, service.ApplyOptions{})
		assertRefusalUnchanged(t, db, f, before, err, "BASE_KEY")
		assertSafeContains(t, err, "`key reclassify` / declassification ceremony")
	})
}
