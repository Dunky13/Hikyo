package isolation

// Secret-scanning end-to-end acceptance (#74, ADR §§2,4,5,7; SS2/SS3/SS4), on
// both engines through the audit core suite. It drives the real
// scanning-enabled services — no stubs — and asserts:
//
//   - SS2 Surface 1: a config value carrying a planted credential SAVES, returns
//     a finding, and emits finding_warned; the keep-as-config token records a
//     dismissal (finding_dismissed) and the identical value no longer re-fires;
//   - SS3 Surface 2: a declaration field carrying the credential is REFUSED
//     before any state persists (finding_blocked), and a content-bound override
//     token commits the write (finding_overridden);
//   - SS4 non-disclosure: a secret-classified value carrying the same credential
//     is never scanned (zero findings, zero events), and the planted credential
//     appears in no audit payload.
//
// It is invoked from the audit closure gate so the four scanning.* types each
// have a real emitter behind them (audit_e2e_test.go).

import (
	"context"
	"errors"
	"strconv"
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

// plantedCredential is a well-known, non-live AWS example access key id — a
// true-positive for the aws-access-token rule, used everywhere as the canary.
const plantedCredential = "AKIAIOSFODNN7EXAMPLE"

func stringDeclaration() schema.Declaration {
	return schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}}
}

func nonePresence() schema.PresenceRules {
	return schema.PresenceRules{
		Required:  schema.Presence{Mode: schema.PresenceNone},
		Forbidden: schema.Presence{Mode: schema.PresenceNone},
	}
}

// scanFindingsCount reads the tenant trail for one scanning.* type.
func scanEventCount(t *testing.T, db *store.DB, typ string) int64 {
	return queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE type = '"+typ+"'")
}

func runScanningLifecycle(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := tctx(t)
	rs, err := scanning.Load()
	if err != nil {
		t.Fatalf("load ruleset: %v", err)
	}
	kr := probeKeyring(t, db)
	orgs := &service.Orgs{DB: db, Keyring: kr, Scan: rs}
	projects := &service.Projects{DB: db, Keyring: kr, Scan: rs}
	envs := &service.Environments{DB: db, Keyring: kr, Scan: rs}
	folders := &service.Folders{DB: db, Keyring: kr, Scan: rs}
	keys := &service.Keys{DB: db, Keyring: kr, Scan: rs}
	values := &service.Values{DB: db, Keyring: kr, Scan: rs, Auth: authServiceWithKeyring(t, db)}

	org, err := orgs.Create(ctx, service.LocalPrincipal(root), "scanning-audit-org", true, []byte(`{}`), nil)
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	const who = domain.PrincipalID("usr_scanning_audit")
	execRaw(t, db, `INSERT INTO principals (id, kind, created_at) VALUES ('usr_scanning_audit', 'human', `+ts+`)`)
	for i, capability := range []string{"manage-projects", "definitions-edit", "read", "edit", "publish", "reveal"} {
		execRaw(t, db, "INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ("+
			"'grt_scan_"+strconv.Itoa(i)+"', 'usr_scanning_audit', '"+capability+"', '"+org.ID+"', NULL, NULL, "+ts+")")
	}
	actor := service.LocalPrincipal(who)

	proj, err := projects.Create(ctx, actor, domain.OrgID(org.ID), "scanning-proj", nil)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	scope := domain.Scope{Org: domain.OrgID(org.ID), Project: domain.ProjectID(proj.ID)}
	env, err := envs.Create(ctx, actor, scope, "scanning-env", nil)
	if err != nil {
		t.Fatalf("create env: %v", err)
	}
	envScope := scope
	envScope.Env = domain.EnvID(env.ID)

	// A config key and a secret key sharing the same clean declaration.
	if _, err := keys.Create(ctx, actor, scope, service.KeySpec{
		Name: "CONFIG_KEY", Classification: "config", Declaration: stringDeclaration(), Presence: nonePresence()}, nil); err != nil {
		t.Fatalf("create config key: %v", err)
	}
	if _, err := keys.Create(ctx, actor, scope, service.KeySpec{
		Name: "SECRET_KEY", Classification: "secret", Declaration: stringDeclaration(), Presence: nonePresence()}, nil); err != nil {
		t.Fatalf("create secret key: %v", err)
	}

	// --- SS4: a secret value is never scanned -----------------------------
	secretBefore := scanEventCount(t, db, "scanning.finding_warned")
	secretStaged, err := values.Set(ctx, actor, envScope, "SECRET_KEY", plantedCredential, nil)
	if err != nil {
		t.Fatalf("stage secret value: %v", err)
	}
	if len(secretStaged.Findings) != 0 {
		t.Errorf("SS4: a secret value produced %d finding(s); it must never be scanned", len(secretStaged.Findings))
	}
	if after := scanEventCount(t, db, "scanning.finding_warned"); after != secretBefore {
		t.Errorf("SS4: a secret value emitted %d finding_warned event(s); zero expected", after-secretBefore)
	}

	// --- SS2: config warn, then keep-as-config dismissal ------------------
	staged, err := values.Set(ctx, actor, envScope, "CONFIG_KEY", plantedCredential, nil)
	if err != nil {
		t.Fatalf("stage config value: %v", err)
	}
	if len(staged.Findings) == 0 {
		t.Fatal("SS2: a config value carrying a credential returned no finding")
	}
	f := staged.Findings[0]
	if f.Acknowledgement == "" {
		t.Fatal("SS2: the stage finding carries no keep-as-config token")
	}
	if scanEventCount(t, db, "scanning.finding_warned") == 0 {
		t.Fatal("SS2: no finding_warned event committed")
	}
	// Keep-as-config: resubmit presenting the token → dismissal recorded.
	dismissed, err := values.Set(ctx, actor, envScope, "CONFIG_KEY", plantedCredential, []string{f.Acknowledgement})
	if err != nil {
		t.Fatalf("resubmit with keep-as-config token: %v", err)
	}
	if len(dismissed.Findings) != 0 {
		t.Errorf("SS2: the acknowledged resubmission still warned (%d finding(s))", len(dismissed.Findings))
	}
	if scanEventCount(t, db, "scanning.finding_dismissed") == 0 {
		t.Fatal("SS2: no finding_dismissed event committed")
	}
	// Sticky: the identical value no longer re-fires.
	resaved, err := values.Set(ctx, actor, envScope, "CONFIG_KEY", plantedCredential, nil)
	if err != nil {
		t.Fatalf("re-save identical value: %v", err)
	}
	if len(resaved.Findings) != 0 {
		t.Errorf("SS2: a dismissed value re-fired on re-save (%d finding(s))", len(resaved.Findings))
	}
	// A DISTINCT offending value re-fires (different fingerprint).
	distinct, err := values.Set(ctx, actor, envScope, "CONFIG_KEY", plantedCredential+"XY", nil)
	if err != nil {
		t.Fatalf("stage distinct value: %v", err)
	}
	if len(distinct.Findings) == 0 {
		t.Error("SS2: a distinct offending value did not re-fire")
	}

	// --- SS3: declaration block, then content-bound override --------------
	blockedSpec := service.KeySpec{
		Name: "BLOCKED_KEY", Classification: "config",
		Description: "see the runbook token " + plantedCredential,
		Declaration: stringDeclaration(),
		Presence:    nonePresence(),
	}
	_, err = keys.Create(ctx, actor, scope, blockedSpec, nil)
	if err == nil {
		t.Fatal("SS3: a declaration carrying a credential was not refused")
	}
	var refusal interface{ Findings() []service.Finding }
	if !errors.As(err, &refusal) {
		t.Fatalf("SS3: the refusal is not a scan refusal: %v", err)
	}
	if len(refusal.Findings()) == 0 {
		t.Fatal("SS3: the refusal names no finding")
	}
	if scanEventCount(t, db, "scanning.finding_blocked") == 0 {
		t.Fatal("SS3: no finding_blocked event committed")
	}
	// Nothing else persisted: the key was NOT created.
	listed, _, err := keys.List(ctx, actor, scope)
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	for _, k := range listed {
		if k.Name == "BLOCKED_KEY" {
			t.Fatal("SS3: the refused key persisted; the block must leave nothing but the event")
		}
	}
	// A surplus / stale token is rejected: present a token for a field whose
	// content has changed.
	otok := refusal.Findings()[0].Acknowledgement
	if otok == "" {
		t.Fatal("SS3: the block finding carries no override token")
	}
	// Accepted resubmission: the SAME content presenting the override token
	// commits the write and emits finding_overridden.
	if _, err := keys.Create(ctx, actor, scope, blockedSpec, []string{otok}); err != nil {
		t.Fatalf("SS3: acknowledged resubmission was refused: %v", err)
	}
	if scanEventCount(t, db, "scanning.finding_overridden") == 0 {
		t.Fatal("SS3: no finding_overridden event committed")
	}

	// --- SS3: a surplus token is rejected by name -------------------------
	// A clean declaration presenting an override token that no current finding
	// claims is refused, naming the rejected token — a standing pre-authorization
	// is structurally impossible (ADR §4).
	_, surplusErr := keys.Create(ctx, actor, scope, service.KeySpec{
		Name: "CLEAN_KEY", Classification: "config", Declaration: stringDeclaration(), Presence: nonePresence(),
	}, []string{otok})
	if surplusErr == nil {
		t.Fatal("SS3: a clean write presenting a surplus token was accepted; surplus tokens must be rejected")
	}
	var surplusRefusal interface {
		Rejections() []string
	}
	if !errors.As(surplusErr, &surplusRefusal) || len(surplusRefusal.Rejections()) == 0 {
		t.Fatalf("SS3: the surplus token was not rejected by name: %v", surplusErr)
	}

	// --- SS3: a hierarchy ingress (folder) also blocks --------------------
	if _, err := folders.Create(ctx, actor, scope, "creds/"+plantedCredential, nil); err == nil {
		t.Fatal("SS3: a folder path carrying a credential was not refused")
	}

	// --- SS2: import surfaces findings (surface import_value) --------------
	importWarnBefore := scanEventCount(t, db, "scanning.finding_warned")
	importRes, err := values.Import(ctx, actor, envScope, service.ImportRequest{
		Entries: []service.ImportEntry{{Key: "CONFIG_KEY", Value: plantedCredential + "IMPORT"}},
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(importRes.Findings) == 0 {
		t.Fatal("SS2: import of a config credential surfaced no finding")
	}
	if importRes.Findings[0].Surface != "import_value" {
		t.Errorf("SS2: import finding surface = %q, want import_value", importRes.Findings[0].Surface)
	}
	if scanEventCount(t, db, "scanning.finding_warned") <= importWarnBefore {
		t.Fatal("SS2: import emitted no finding_warned")
	}

	// --- SS2: reclassify (config→secret) drops the key's dismissals --------
	// RECLASS_KEY gets a value dismissed, is tightened to secret (dropping the
	// dismissal), returned to config, and the identical value re-fires.
	reclassKey, err := keys.Create(ctx, actor, scope, service.KeySpec{
		Name: "RECLASS_KEY", Classification: "config", Declaration: stringDeclaration(), Presence: nonePresence(),
	}, nil)
	if err != nil {
		t.Fatalf("create reclass key: %v", err)
	}
	rWarn, err := values.Set(ctx, actor, envScope, "RECLASS_KEY", plantedCredential, nil)
	if err != nil || len(rWarn.Findings) == 0 {
		t.Fatalf("reclass key warn: err=%v findings=%d", err, len(rWarn.Findings))
	}
	if _, err := values.Set(ctx, actor, envScope, "RECLASS_KEY", plantedCredential, []string{rWarn.Findings[0].Acknowledgement}); err != nil {
		t.Fatalf("reclass key dismiss: %v", err)
	}
	if _, _, err := keys.Reclassify(ctx, actor, scope, reclassKey.ID, "secret"); err != nil {
		t.Fatalf("tighten to secret: %v", err)
	}
	if _, _, err := keys.Reclassify(ctx, actor, scope, reclassKey.ID, "config"); err != nil {
		t.Fatalf("declassify back to config: %v", err)
	}
	refire, err := values.Set(ctx, actor, envScope, "RECLASS_KEY", plantedCredential, nil)
	if err != nil {
		t.Fatalf("re-save after reclassify: %v", err)
	}
	if len(refire.Findings) == 0 {
		t.Error("SS2: reclassify-as-secret did not drop the dismissal; the value should re-fire")
	}

	// --- SS2: declassification warns inside the ceremony ------------------
	// A secret key with a PUBLISHED value carrying a credential; declassifying it
	// re-materialises the value as config and warns (surface declassification).
	declassKey, err := keys.Create(ctx, actor, scope, service.KeySpec{
		Name: "DECLASS_KEY", Classification: "secret", Declaration: stringDeclaration(), Presence: nonePresence(),
	}, nil)
	if err != nil {
		t.Fatalf("create declass key: %v", err)
	}
	if _, _, err := values.Declare(ctx, actor, scope, []string{env.ID}, "DECLASS_KEY", plantedCredential); err != nil {
		t.Fatalf("declare secret value: %v", err)
	}
	declassBefore := scanEventCount(t, db, "scanning.finding_warned")
	_, declassFindings, err := keys.Reclassify(ctx, actor, scope, declassKey.ID, "config")
	if err != nil {
		t.Fatalf("declassify: %v", err)
	}
	if len(declassFindings) == 0 {
		t.Fatal("SS2: declassifying a secret value carrying a credential produced no finding in the ceremony")
	}
	if declassFindings[0].Surface != "declassification" {
		t.Errorf("SS2: declassification finding surface = %q, want declassification", declassFindings[0].Surface)
	}
	if scanEventCount(t, db, "scanning.finding_warned") <= declassBefore {
		t.Fatal("SS2: declassification emitted no finding_warned")
	}

	// --- SS2: a dismissal keyed by a STALE rule digest does not suppress ---
	// Simulate a pin bump: a dismissal exists for the value under an old digest;
	// the current scan uses the current digest, finds no matching dismissal, and
	// re-fires. Proves rule-id reuse cannot silently carry old dismissals forward.
	digestKey, err := keys.Create(ctx, actor, scope, service.KeySpec{
		Name: "DIGEST_KEY", Classification: "config", Declaration: stringDeclaration(), Presence: nonePresence(),
	}, nil)
	if err != nil {
		t.Fatalf("create digest key: %v", err)
	}
	fingerprint := kr.ScanningFingerprint(org.ID, proj.ID, env.ID, digestKey.ID, []byte(schema.Normalize(plantedCredential)))
	if err := tx.Write(ctx, db, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: who}, authz.OpValueStage, envScope)
		if err != nil {
			return err
		}
		return r.ScanningDismissals().Insert(ctx, p, store.NewDismissal{
			ID: "dsm_stale_digest", KeyID: digestKey.ID, RuleDigest: "sha256:stale-from-old-pin",
			Fingerprint: fingerprint, CreatedBy: string(who), CreatedAt: store.CanonTime(time.Now()),
		})
	}); err != nil {
		t.Fatalf("seed stale-digest dismissal: %v", err)
	}
	staleFire, err := values.Set(ctx, actor, envScope, "DIGEST_KEY", plantedCredential, nil)
	if err != nil {
		t.Fatalf("save under stale-digest dismissal: %v", err)
	}
	if len(staleFire.Findings) == 0 {
		t.Error("SS2: a dismissal keyed by a stale rule digest suppressed the warn; it must re-fire")
	}

	// --- SS2: induced post-scan commit failure leaves neither value nor event
	warnBefore := scanEventCount(t, db, "scanning.finding_warned")
	pendingBefore := queryInt(t, db, "SELECT COUNT(*) FROM pending_changes")
	execRaw(t, db, "ALTER TABLE audit_tenant_events RENAME TO audit_tenant_events_hold")
	_, failErr := values.Set(ctx, actor, envScope, "CONFIG_KEY", plantedCredential+"FAIL", nil)
	execRaw(t, db, "ALTER TABLE audit_tenant_events_hold RENAME TO audit_tenant_events")
	if failErr == nil {
		t.Fatal("SS2: a value write survived an audit-write failure; the warn must be atomic with the write")
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM pending_changes"); got != pendingBefore {
		t.Errorf("SS2: induced commit failure left %d extra pending row(s); neither value nor event may persist", got-pendingBefore)
	}
	if got := scanEventCount(t, db, "scanning.finding_warned"); got != warnBefore {
		t.Errorf("SS2: induced commit failure left %d extra finding_warned event(s)", got-warnBefore)
	}

	// --- SS4: the planted credential appears in no audit payload ----------
	for _, table := range []string{"audit_tenant_events", "audit_instance_events"} {
		if n := queryInt(t, db, "SELECT COUNT(*) FROM "+table+" WHERE payload LIKE '%"+plantedCredential+"%'"); n != 0 {
			t.Errorf("SS4: the planted credential leaked into %d %s row(s)", n, table)
		}
		if n := queryInt(t, db, "SELECT COUNT(*) FROM "+table+" WHERE payload LIKE '%AKIA%'"); n != 0 {
			t.Errorf("SS4: an AWS-key prefix leaked into %d %s row(s)", n, table)
		}
	}
}
