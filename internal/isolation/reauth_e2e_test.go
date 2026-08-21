package isolation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
	"github.com/Hikyo-Org/hikyo/internal/webauthntest"
)

// TestBreakGlassHasNoNetworkRoute asserts the break-glass reset
// (`hikyo admin reset-credential`) has no HTTP path at all: the ONLY
// credential-reset route the contract carries is the network account path, and
// break-glass is host-local (ClassSystem, network-unreachable) by construction.
func TestBreakGlassHasNoNetworkRoute(t *testing.T) {
	ops, err := api.Operations()
	if err != nil {
		t.Fatal(err)
	}
	var resetRoutes []string
	for _, op := range ops {
		if strings.Contains(op.Path, "credential-reset") {
			resetRoutes = append(resetRoutes, op.Method+" "+op.Path)
		}
	}
	if len(resetRoutes) != 1 || !strings.Contains(resetRoutes[0], "/api/v1/accounts/") {
		t.Errorf("credential-reset routes = %v, want exactly the network account path and no host-local route", resetRoutes)
	}
}

// Reauthentication-window CONSUMPTION at disclosure, the effective-window
// transition, and administrator-issued / break-glass credential reset (#54,
// human-auth ADR - Reauthentication, Recovery). The OIDC/WebAuthn/TOTP verticals
// OPEN windows; these exercise the disclosure-time consumption library (#50/#58's
// reveal path will call it), LowerEffectiveWindow (#55's project-settings knob
// will call it) and the recovery tier, all on a real datastore, both engines.

// tsMicro is the microsecond-width timestamp the authn resolver's decodeTime
// expects; account rows this suite seeds are read back through it (the fixture
// `ts` is only ever read by columns that are not time-parsed).
const tsMicro = "'2026-01-01T00:00:00.000000Z'"

// grantRead gives a principal INSTANCE-scope `read`, which the reauth routes
// now require before they will discuss an environment's reauthentication
// policy at all.
//
// Instance rather than org scope, and that is not arbitrary: `listMyOrgs`
// projects the orgs a caller's own grants NAME, so an org-scoped grant would
// put org A in every bootstrap administrator's rail and break the fixtures
// that assert a purely instance-scoped principal sees none. Instance scope
// reaches the same environments by the ordinary downward inheritance.
func grantRead(t *testing.T, db *store.DB, p domain.PrincipalID) {
	t.Helper()
	id := "g_rd_" + string(p)
	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
		`VALUES ('`+id+`', '`+string(p)+`', 'read', NULL, NULL, NULL, `+ts+`)`)
	execRaw(t, db, `INSERT INTO grant_origins (id, grant_id, kind, subject, created_at) `+
		`VALUES ('gor_`+id+`', '`+id+`', 'manual', '`+string(p)+`', `+ts+`)`)
}

// consumeWindow runs ConsumeReauthWindow inside its own transaction, as the
// reveal path will, and returns the refusal (or nil) unwrapped for errors.Is.
func consumeWindow(t *testing.T, auth *service.Auth, db *store.DB, sessionID, env string, keys []string, now time.Time) error {
	t.Helper()
	return consumeWindowFor(t, auth, db, sessionID, env, "", keys, now)
}

// consumeWindowFor is consumeWindow with the operation named, for the windows a
// workspace step-up binds to one.
func consumeWindowFor(t *testing.T, auth *service.Auth, db *store.DB, sessionID, env, operation string, keys []string, now time.Time) error {
	t.Helper()
	return tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		// PurposeReveal is the disclosure consumption these helpers model (#58);
		// it is only consulted on the single-decision leg, where it is matched
		// byte-exact against the ceremony's binding. The workspace step-up
		// windows these helpers also drive are sliding, so the purpose is inert
		// for them and the OPERATION is what their binding turns on.
		return auth.ConsumeReauthWindow(ctx, az, sessionID, service.PurposeReveal, env, operation, keys, now)
	})
}

func consumeAdapterWindowFor(t *testing.T, auth *service.Auth, db *store.DB, sessionID, env string, operation authz.Operation, environmentIDs []string, now time.Time) error {
	t.Helper()
	return tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		return auth.ConsumeAdapterReauthWindow(ctx, az, sessionID, env, operation, environmentIDs, now)
	})
}

func TestAdapterReauthWindowExactBindingSQLite(t *testing.T) {
	runAdapterReauthWindowExactBinding(t, seededDB(t, openSQLite))
}

func TestAdapterReauthWindowExactBindingPostgres(t *testing.T) {
	runAdapterReauthWindowExactBinding(t, seededDB(t, openPostgres))
}

func TestAdapterReauthTOTPMixedPolicySQLite(t *testing.T) {
	runAdapterReauthTOTPMixedPolicy(t, seededDB(t, openSQLite))
}

func TestAdapterReauthTOTPMixedPolicyPostgres(t *testing.T) {
	runAdapterReauthTOTPMixedPolicy(t, seededDB(t, openPostgres))
}

func TestAdapterReauthWebAuthnBindsFullEnvironmentSetSQLite(t *testing.T) {
	runAdapterReauthWebAuthnBindsFullEnvironmentSet(t, seededDB(t, openSQLite))
}

func TestAdapterReauthWebAuthnBindsFullEnvironmentSetPostgres(t *testing.T) {
	runAdapterReauthWebAuthnBindsFullEnvironmentSet(t, seededDB(t, openPostgres))
}

func TestCLIAdapterReauthHandoffSQLite(t *testing.T) {
	runCLIAdapterReauthHandoff(t, seededDB(t, openSQLite))
}

func TestCLIAdapterReauthHandoffPostgres(t *testing.T) {
	runCLIAdapterReauthHandoff(t, seededDB(t, openPostgres))
}

func runCLIAdapterReauthHandoff(t *testing.T, db *store.DB) {
	auth, boot, password := bootstrapFactorAdmin(t, db)
	execRaw(t, db, `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('g_cli_adapter_manage','`+string(boot.PrincipalID)+`','manage-adapters','org_a','prj_a1',NULL,`+ts+`)`)
	execRaw(t, db, `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('g_cli_adapter_reveal','`+string(boot.PrincipalID)+`','reveal','org_a','prj_a1','env_prod',`+ts+`)`)
	execRaw(t, db, `INSERT INTO grant_origins (id,grant_id,kind,subject,created_at) VALUES ('gor_cli_adapter_manage','g_cli_adapter_manage','manual','`+string(boot.PrincipalID)+`',`+ts+`)`)
	execRaw(t, db, `INSERT INTO grant_origins (id,grant_id,kind,subject,created_at) VALUES ('gor_cli_adapter_reveal','g_cli_adapter_reveal','manual','`+string(boot.PrincipalID)+`',`+ts+`)`)
	base := time.Date(2026, 8, 17, 3, 0, 0, 0, time.UTC)
	clock := base
	auth.Now = func() time.Time { return clock }
	auth.ReauthWindow = 5 * time.Minute
	cliLogin, err := auth.LocalLogin(t.Context(), "factor-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := auth.EnrolTOTPStart(t.Context(), cliLogin.SessionToken, password)
	if err != nil {
		t.Fatal(err)
	}
	clock = base.Add(30 * time.Second)
	cliConfirmed, err := auth.EnrolTOTPConfirm(t.Context(), cliLogin.SessionToken, totpCode(t, uri, clock))
	if err != nil {
		t.Fatal(err)
	}
	browser, err := auth.LocalLogin(t.Context(), "factor-admin", password, service.ArtifactBrowser)
	if err != nil {
		t.Fatal(err)
	}
	clock = base.Add(time.Minute)
	browserWindows, err := auth.ReauthAdapterTOTP(t.Context(), browser.SessionToken, string(authz.OpAdapterSync), []string{"env_prod"}, totpCode(t, uri, clock))
	if err != nil {
		t.Fatal(err)
	}
	verifierBytes := sha256.Sum256([]byte("cli adapter reauth pkce verifier"))
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes[:])
	challengeBytes := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])
	if got := queryInt(t, db, "SELECT COUNT(*) FROM grants WHERE principal_id = '"+string(boot.PrincipalID)+"' AND capability = 'reveal' AND env_id = 'env_prod'"); got != 1 {
		t.Fatalf("reveal grants = %d", got)
	}
	if got := queryString(t, db, "SELECT principal_id FROM sessions WHERE id = '"+cliConfirmed.SessionID+"'"); got != string(boot.PrincipalID) {
		t.Fatalf("CLI principal = %q, bootstrap = %q", got, boot.PrincipalID)
	}
	start, err := auth.StartCLIReauth(t.Context(), cliConfirmed.SessionToken, string(service.PurposeAdapter), string(authz.OpAdapterSync), []string{"env_prod"}, nil, challenge, "http://127.0.0.1:40123/callback")
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := auth.CLIReauthTransaction(t.Context(), service.Bearer(browserWindows[0].SessionToken), start.State)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.State != start.State || transaction.Operation != string(authz.OpAdapterSync) || transaction.RedirectURI != "http://127.0.0.1:40123/callback" || len(transaction.Environments) != 1 || transaction.Environments[0].EnvironmentID != "env_prod" || transaction.Environments[0].RequiresWebAuthn {
		t.Fatalf("CLIReauthTransaction() = %+v", transaction)
	}
	// Policy is authoritative again at approval. A TOTP window opened while the
	// environment had a nonzero window cannot satisfy a later effective-zero
	// policy, which requires a WebAuthn-bound single-decision window.
	execRaw(t, db, `UPDATE environments SET protected=TRUE,reauth_window_seconds=0 WHERE id='env_prod'`)
	if _, err := auth.ApproveCLIReauth(t.Context(), service.Bearer(browserWindows[0].SessionToken), start.State); !errors.Is(err, service.ErrReauthRequired) {
		t.Fatalf("approval after policy drift = %v, want WebAuthn reauth required", err)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM cli_reauth_handoffs WHERE code_verifier IS NULL AND consumed_at IS NULL"); got != 1 {
		t.Fatalf("failed approval mutated handoff rows=%d, want 1 untouched", got)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type='auth.cli_reauth_handoff' AND outcome='failure' AND CAST(payload AS TEXT) LIKE '%\"phase\":\"approve\"%' AND CAST(payload AS TEXT) LIKE '%\"cause\":\"reauth_required\"%'"); got != 1 {
		t.Fatalf("failed approval settlement rows=%d, want durable before response", got)
	}
	execRaw(t, db, `UPDATE environments SET protected=FALSE,reauth_window_seconds=NULL WHERE id='env_prod'`)
	approved, err := auth.ApproveCLIReauth(t.Context(), service.Bearer(browserWindows[0].SessionToken), start.State)
	if err != nil {
		t.Fatal(err)
	}
	if start.State == "" || approved.Code == "" || strings.Contains(start.State, cliConfirmed.SessionToken) || strings.Contains(approved.Code, cliConfirmed.SessionToken) {
		t.Fatal("front-channel state/code missing or disclosed the CLI bearer")
	}
	if approved.State != start.State || approved.RedirectURI != transaction.RedirectURI {
		t.Fatalf("approval binding = %+v", approved)
	}
	wrongVerifierBytes := sha256.Sum256([]byte("different cli adapter reauth pkce verifier"))
	wrongVerifier := base64.RawURLEncoding.EncodeToString(wrongVerifierBytes[:])
	if _, err := auth.RedeemCLIReauth(t.Context(), approved.Code, wrongVerifier); !errors.Is(err, service.ErrCLIReauthInvalid) {
		t.Fatalf("wrong PKCE redeem = %v", err)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM cli_reauth_handoffs WHERE code_verifier IS NOT NULL AND consumed_at IS NULL"); got != 1 {
		t.Fatalf("failed PKCE redemption consumed handoff rows=%d, want 1 unconsumed", got)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type='auth.cli_reauth_handoff' AND outcome='failure' AND CAST(payload AS TEXT) LIKE '%\"cause\":\"pkce_mismatch\"%'"); got != 1 {
		t.Fatalf("failed PKCE settlement rows=%d, want durable before response", got)
	}
	redeemed, err := auth.RedeemCLIReauth(t.Context(), approved.Code, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if redeemed.SessionToken == "" || redeemed.SessionToken == cliConfirmed.SessionToken || len(redeemed.Windows) != 1 || redeemed.Windows[0].EnvironmentID != "env_prod" {
		t.Fatalf("redeemed = %+v", redeemed)
	}
	if _, err := auth.Identity(t.Context(), cliConfirmed.SessionToken); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("old CLI bearer after rotation = %v", err)
	}
	if _, err := auth.Identity(t.Context(), redeemed.SessionToken); err != nil {
		t.Fatalf("rotated CLI bearer = %v", err)
	}
	if _, err := auth.RedeemCLIReauth(t.Context(), approved.Code, verifier); !errors.Is(err, service.ErrCLIReauthInvalid) {
		t.Fatalf("second redeem = %v", err)
	}
	for _, want := range []struct {
		phase, outcome string
		count          int64
	}{
		{"start", "success", 1}, {"inspect", "success", 1},
		{"approve", "success", 1}, {"approve", "failure", 1},
		{"redeem", "success", 1}, {"redeem", "failure", 2},
	} {
		got := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type='auth.cli_reauth_handoff' AND outcome='"+want.outcome+"' AND CAST(payload AS TEXT) LIKE '%\"phase\":\""+want.phase+"\"%'")
		if got != want.count {
			t.Errorf("%s/%s audit rows=%d, want %d", want.phase, want.outcome, got, want.count)
		}
	}
	for _, cause := range []string{"reauth_required", "pkce_mismatch", "already_consumed"} {
		if got := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type='auth.cli_reauth_handoff' AND outcome='failure' AND CAST(payload AS TEXT) LIKE '%\"cause\":\""+cause+"\"%'"); got != 1 {
			t.Errorf("failure cause %s rows=%d, want 1", cause, got)
		}
	}
	for _, forbidden := range []string{start.State, approved.Code, verifier, cliConfirmed.SessionToken, redeemed.SessionToken} {
		if got := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type='auth.cli_reauth_handoff' AND CAST(payload AS TEXT) LIKE '%"+forbidden+"%'"); got != 0 {
			t.Errorf("handoff audit payload disclosed forbidden artifact: rows=%d", got)
		}
	}
}

func runAdapterReauthWebAuthnBindsFullEnvironmentSet(t *testing.T, db *store.DB) {
	auth, _, token := bootstrapWebAuthnAdmin(t, db)
	auth.ReauthWindow = 5 * time.Minute
	auth.ReauthHardCap = 10 * time.Minute
	ctx := t.Context()
	device := webauthntest.New(waRPID, waOrigin)
	token = enrolPasskey(t, auth, ctx, token, waPassword, device)
	token = stepUpPasskey(t, auth, ctx, token, device)
	execRaw(t, db, `INSERT INTO environments (id, org_id, project_id, name, note, protected, reauth_window_seconds, created_at, display_order) VALUES ('env_adapter_zero', 'org_a', 'prj_a1', 'adapter-zero', '', TRUE, 0, `+ts+`, 2)`)
	environments := []string{"env_prod", "env_adapter_zero"}
	options, err := auth.ReauthAdapterPasskeyStart(ctx, token, authz.OpAdapterConfigure, "env_adapter_zero", environments)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := device.Assert(options)
	if err != nil {
		t.Fatal(err)
	}
	result, err := auth.ReauthPasskeyFinish(ctx, token, assertion)
	if err != nil {
		t.Fatal(err)
	}
	if !result.SingleDecision || result.EnvironmentID != "env_adapter_zero" {
		t.Fatalf("adapter WebAuthn result = %+v", result)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM reauth_windows WHERE session_id = '"+result.SessionID+"' AND environment_id = 'env_adapter_zero' AND factor_class = 'webauthn' AND single_decision = 1 AND bound_purpose = 'adapter' AND bound_operation = 'adapter.configure' AND bound_environment_set = 'env_adapter_zero"+"\n"+"env_prod'"); got != 1 {
		t.Fatalf("exact adapter WebAuthn windows = %d, want 1", got)
	}
	if err := consumeAdapterWindowFor(t, auth, db, result.SessionID, "env_adapter_zero", authz.OpAdapterConfigure, environments, time.Now().UTC()); err != nil {
		t.Fatalf("consume exact adapter WebAuthn window: %v", err)
	}
	if err := consumeAdapterWindowFor(t, auth, db, result.SessionID, "env_adapter_zero", authz.OpAdapterConfigure, environments, time.Now().UTC()); !errors.Is(err, service.ErrReauthWindowSpent) {
		t.Fatalf("reuse adapter WebAuthn window: %v, want ErrReauthWindowSpent", err)
	}
}

func runAdapterReauthTOTPMixedPolicy(t *testing.T, db *store.DB) {
	auth, boot, password := bootstrapFactorAdmin(t, db)
	base := time.Date(2026, 8, 17, 2, 0, 0, 0, time.UTC)
	clock := base
	auth.Now = func() time.Time { return clock }
	auth.ReauthWindow = 5 * time.Minute
	auth.ReauthHardCap = 10 * time.Minute
	login, err := auth.LocalLogin(t.Context(), "factor-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := auth.EnrolTOTPStart(t.Context(), login.SessionToken, password)
	if err != nil {
		t.Fatal(err)
	}
	clock = base.Add(30 * time.Second)
	confirmed, err := auth.EnrolTOTPConfirm(t.Context(), login.SessionToken, totpCode(t, uri, clock))
	if err != nil {
		t.Fatal(err)
	}
	execRaw(t, db, `INSERT INTO environments (id, org_id, project_id, name, note, protected, reauth_window_seconds, created_at, display_order) VALUES ('env_adapter_zero', 'org_a', 'prj_a1', 'adapter-zero', '', TRUE, 0, `+ts+`, 2)`)
	environments := []string{"env_prod", "env_adapter_zero"}
	clock = base.Add(time.Minute)
	results, err := auth.ReauthAdapterTOTP(t.Context(), confirmed.SessionToken, string(authz.OpAdapterSync), environments, totpCode(t, uri, clock))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].EnvironmentID != "env_prod" || results[0].SessionToken == "" {
		t.Fatalf("mixed-policy TOTP results = %+v", results)
	}
	sessionID := results[0].SessionID
	if got := queryInt(t, db, "SELECT COUNT(*) FROM reauth_windows WHERE session_id = '"+sessionID+"' AND bound_purpose = 'adapter' AND bound_operation = 'adapter.sync' AND bound_environment_set = 'env_adapter_zero"+"\n"+"env_prod'"); got != 1 {
		t.Fatalf("purpose-bound TOTP windows = %d, want 1", got)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM reauth_windows WHERE session_id = '"+sessionID+"' AND environment_id = 'env_adapter_zero'"); got != 0 {
		t.Fatalf("effective-zero TOTP windows = %d, want 0", got)
	}
	if err := consumeAdapterWindowFor(t, auth, db, sessionID, "env_prod", authz.OpAdapterSync, environments, clock.Add(time.Second)); err != nil {
		t.Fatalf("consume exact mixed-policy TOTP window: %v", err)
	}
	if boot.PrincipalID == "" {
		t.Fatal("bootstrap principal missing")
	}
}

func runAdapterReauthWindowExactBinding(t *testing.T, db *store.DB) {
	auth, boot, password := bootstrapFactorAdmin(t, db)
	now := time.Now().UTC()
	auth.Now = func() time.Time { return now }
	auth.ReauthWindow = 5 * time.Minute
	_, err := auth.LocalLogin(t.Context(), "factor-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	execRaw(t, db, `INSERT INTO environments (id, org_id, project_id, name, note, created_at, display_order) VALUES ('env_stage', 'org_a', 'prj_a1', 'stage', '', `+ts+`, 2)`)
	sessionID := queryString(t, db, "SELECT id FROM sessions WHERE principal_id = '"+string(boot.PrincipalID)+"' ORDER BY created_at DESC LIMIT 1")
	environments := []string{"env_prod", "env_stage"}
	err = tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		for index, environmentID := range environments {
			if err := az.OpenReauthWindow(ctx, authz.NewReauthWindow{
				ID: fmt.Sprintf("raw_adapter_%d", index), SessionID: sessionID, EnvironmentID: environmentID,
				CeremonyID: "totp_adapter", FactorClass: "totp", AuthenticatedAt: now,
				WindowExpiresAt: now.Add(5 * time.Minute), HardExpiresAt: now.Add(10 * time.Minute),
				CredentialEpoch: epoch, CreatedAt: now, BoundPurpose: string(service.PurposeAdapter),
				BoundOperation: string(authz.OpAdapterSync), BoundEnvironmentSet: service.CanonicalEnvironmentSet(environments),
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := consumeWindow(t, auth, db, sessionID, "env_prod", nil, now.Add(time.Second)); !errors.Is(err, service.ErrReauthUnitMismatch) {
		t.Fatalf("adapter window spent as reveal: %v, want ErrReauthUnitMismatch", err)
	}
	if err := consumeAdapterWindowFor(t, auth, db, sessionID, "env_prod", authz.OpAdapterAdopt, environments, now.Add(time.Second)); !errors.Is(err, service.ErrReauthUnitMismatch) {
		t.Fatalf("adapter window spent for wrong operation: %v, want ErrReauthUnitMismatch", err)
	}
	if err := consumeAdapterWindowFor(t, auth, db, sessionID, "env_prod", authz.OpAdapterSync, []string{"env_prod"}, now.Add(time.Second)); !errors.Is(err, service.ErrReauthUnitMismatch) {
		t.Fatalf("adapter window spent for partial environment set: %v, want ErrReauthUnitMismatch", err)
	}
	for _, environmentID := range environments {
		if err := consumeAdapterWindowFor(t, auth, db, sessionID, environmentID, authz.OpAdapterSync, environments, now.Add(time.Second)); err != nil {
			t.Fatalf("consume exact adapter window for %s: %v", environmentID, err)
		}
	}
}

func TestReauthConsumeSingleDecisionSQLite(t *testing.T) {
	runReauthConsumeSingleDecision(t, seededDB(t, openSQLite))
}
func TestReauthConsumeSingleDecisionPostgres(t *testing.T) {
	runReauthConsumeSingleDecision(t, seededDB(t, openPostgres))
}

// runReauthConsumeSingleDecision: a 0-effective-window WebAuthn ceremony opens a
// single-decision window bound to an enumerated unit; the disclosure consumes it
// exactly once, the wrong unit is refused, and a second decision is refused
// (B11 double-spend). A single-decision window needs a bounded life, so the hard
// cap is set (the flag limits it to one decision; the clock keeps it alive).
func runReauthConsumeSingleDecision(t *testing.T, db *store.DB) {
	auth, _, token := bootstrapWebAuthnAdmin(t, db)
	auth.ReauthWindow = 0 // 0 effective window -> single-decision
	auth.ReauthHardCap = 5 * time.Minute
	ctx := t.Context()
	dev := webauthntest.New(waRPID, waOrigin)
	token = enrolPasskey(t, auth, ctx, token, waPassword, dev)

	stepped := stepUpPasskey(t, auth, ctx, token, dev)
	token = stepped

	ropts, err := auth.ReauthPasskeyStart(ctx, token, service.PurposeReveal, "env_prod", []string{"key_b", "key_a"})
	if err != nil {
		t.Fatalf("reauth start: %v", err)
	}
	rresp, err := dev.Assert(ropts)
	if err != nil {
		t.Fatalf("device assert: %v", err)
	}
	reauth, err := auth.ReauthPasskeyFinish(ctx, token, rresp)
	if err != nil {
		t.Fatalf("reauth finish: %v", err)
	}
	if !reauth.SingleDecision {
		t.Fatal("a 0-window reauth must open a single-decision window")
	}
	sessionID := queryString(t, db, "SELECT session_id FROM reauth_windows WHERE environment_id = 'env_prod'")
	now := time.Now().UTC()

	// No window on a different environment: fail closed.
	if err := consumeWindow(t, auth, db, sessionID, "env_dev", []string{"key_a", "key_b"}, now); !errors.Is(err, service.ErrNoReauthWindow) {
		t.Fatalf("consume on an env with no window: %v, want ErrNoReauthWindow", err)
	}
	// Wrong enumerated unit: the ceremony bound {key_a,key_b}; a disclosure of
	// {key_a} alone is a different unit and is refused before the claim.
	if err := consumeWindow(t, auth, db, sessionID, "env_prod", []string{"key_a"}, now); !errors.Is(err, service.ErrReauthUnitMismatch) {
		t.Fatalf("consume with the wrong unit: %v, want ErrReauthUnitMismatch", err)
	}
	// The bound unit succeeds exactly once (key order is canonicalised).
	if err := consumeWindow(t, auth, db, sessionID, "env_prod", []string{"key_a", "key_b"}, now); err != nil {
		t.Fatalf("consume with the bound unit: %v, want success", err)
	}
	// A second decision on a single-decision window is refused (double-spend).
	if err := consumeWindow(t, auth, db, sessionID, "env_prod", []string{"key_a", "key_b"}, now); !errors.Is(err, service.ErrReauthWindowSpent) {
		t.Fatalf("second consume: %v, want ErrReauthWindowSpent", err)
	}
}

func TestReauthConsumeSlidingHardCapSQLite(t *testing.T) {
	runReauthConsumeSlidingHardCap(t, seededDB(t, openSQLite))
}
func TestReauthConsumeSlidingHardCapPostgres(t *testing.T) {
	runReauthConsumeSlidingHardCap(t, seededDB(t, openPostgres))
}

// runReauthConsumeSlidingHardCap: at a non-zero effective window a WebAuthn reauth
// opens a sliding window; each disclosure slides the idle clock forward, but the
// hard cap (measured from the ceremony, never extended) bounds it, and a
// disclosure past the hard cap fails closed. An epoch-inert window is also refused.
func runReauthConsumeSlidingHardCap(t *testing.T, db *store.DB) {
	auth, _, token := bootstrapWebAuthnAdmin(t, db)
	base := time.Now().UTC().Truncate(time.Second)
	clk := base
	auth.Now = func() time.Time { return clk }
	auth.ReauthWindow = 5 * time.Minute
	auth.ReauthHardCap = 10 * time.Minute
	ctx := t.Context()
	dev := webauthntest.New(waRPID, waOrigin)
	token = enrolPasskey(t, auth, ctx, token, waPassword, dev)
	token = stepUpPasskey(t, auth, ctx, token, dev)

	ropts, err := auth.ReauthPasskeyStart(ctx, token, service.PurposeReveal, "env_prod", []string{"key_a"})
	if err != nil {
		t.Fatalf("reauth start: %v", err)
	}
	rresp, err := dev.Assert(ropts)
	if err != nil {
		t.Fatalf("device assert: %v", err)
	}
	reauth, err := auth.ReauthPasskeyFinish(ctx, token, rresp)
	if err != nil {
		t.Fatalf("reauth finish: %v", err)
	}
	if reauth.SingleDecision {
		t.Fatal("a non-zero effective window must open a sliding window, not single-decision")
	}
	sessionID := queryString(t, db, "SELECT session_id FROM reauth_windows WHERE environment_id = 'env_prod'")

	// The window opened to base+5m. A disclosure at +4m slides it forward to +9m.
	if err := consumeWindow(t, auth, db, sessionID, "env_prod", nil, base.Add(4*time.Minute)); err != nil {
		t.Fatalf("consume at +4m: %v", err)
	}
	// A +8m disclosure (< the +9m slid window) would slide to +13m, but the hard
	// cap (base+10m, measured from the ceremony) caps it there.
	if err := consumeWindow(t, auth, db, sessionID, "env_prod", nil, base.Add(8*time.Minute)); err != nil {
		t.Fatalf("consume at +8m: %v", err)
	}
	// +9m30s is still inside the (capped) window: sliding kept it alive well past
	// the original +5m, proving the slide works.
	if err := consumeWindow(t, auth, db, sessionID, "env_prod", nil, base.Add(9*time.Minute+30*time.Second)); err != nil {
		t.Fatalf("consume at +9m30s: %v", err)
	}
	// +10m30s is past the hard cap: fail closed despite the recent +9m30s
	// activity. Had the slide not been capped it would run to ~+14m and this would
	// wrongly succeed — so this failure is the proof the hard cap bounds the slide.
	if err := consumeWindow(t, auth, db, sessionID, "env_prod", nil, base.Add(10*time.Minute+30*time.Second)); !errors.Is(err, service.ErrReauthWindowExpired) {
		t.Fatalf("consume past the hard cap: %v, want ErrReauthWindowExpired", err)
	}

	// An epoch-inert window (its recorded epoch no longer the instance epoch) is
	// refused even inside its clocks: a restored artifact cannot be
	// reauthenticated against. Bump only the epoch, leaving the timestamps valid,
	// and disclose at +1m (well inside the +10m hard cap).
	execRaw(t, db, "UPDATE reauth_windows SET credential_epoch = credential_epoch + 99 WHERE environment_id = 'env_prod'")
	if err := consumeWindow(t, auth, db, sessionID, "env_prod", nil, base.Add(1*time.Minute)); !errors.Is(err, service.ErrReauthWindowExpired) {
		t.Fatalf("consume against an epoch-inert window: %v, want ErrReauthWindowExpired", err)
	}
}

func TestReauthWebAuthnOpenClampsHardCapSQLite(t *testing.T) {
	runReauthWebAuthnOpenClampsHardCap(t, seededDB(t, openSQLite))
}
func TestReauthWebAuthnOpenClampsHardCapPostgres(t *testing.T) {
	runReauthWebAuthnOpenClampsHardCap(t, seededDB(t, openPostgres))
}

// runReauthWebAuthnOpenClampsHardCap (A2 residual): the WebAuthn opener clamps
// window_expires_at to hard_expires_at on OPEN, exactly as the TOTP/OIDC openers
// do — a sliding window must never exceed the hard cap even at the moment it
// opens. The effective window (30m) exceeds the hard cap (10m), so the clamp is
// load-bearing: without it the row would open to +30m, past its +10m cap.
func runReauthWebAuthnOpenClampsHardCap(t *testing.T, db *store.DB) {
	auth, _, token := bootstrapWebAuthnAdmin(t, db)
	auth.ReauthWindow = 30 * time.Minute
	auth.ReauthHardCap = 10 * time.Minute
	ctx := t.Context()
	dev := webauthntest.New(waRPID, waOrigin)
	token = enrolPasskey(t, auth, ctx, token, waPassword, dev)
	token = stepUpPasskey(t, auth, ctx, token, dev)

	ropts, err := auth.ReauthPasskeyStart(ctx, token, service.PurposeReveal, "env_prod", []string{"key_a"})
	if err != nil {
		t.Fatalf("reauth start: %v", err)
	}
	rresp, err := dev.Assert(ropts)
	if err != nil {
		t.Fatalf("device assert: %v", err)
	}
	reauth, err := auth.ReauthPasskeyFinish(ctx, token, rresp)
	if err != nil {
		t.Fatalf("reauth finish: %v", err)
	}
	if reauth.SingleDecision {
		t.Fatal("a 30m effective window must open a sliding window, not single-decision")
	}
	// No row exceeds its hard cap, and this window sits exactly at it: the opener
	// clamped the 30m idle window down to the 10m cap. Column-vs-column comparison
	// is dialect-neutral (no timestamp text parsing).
	if n := queryInt(t, db, "SELECT COUNT(*) FROM reauth_windows WHERE environment_id = 'env_prod' AND window_expires_at > hard_expires_at"); n != 0 {
		t.Errorf("%d reauth window(s) have window_expires_at past hard_expires_at — the open clamp failed", n)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM reauth_windows WHERE environment_id = 'env_prod' AND window_expires_at = hard_expires_at"); n != 1 {
		t.Error("the WebAuthn window was not clamped to the hard cap on open")
	}
}

func TestReauthSlideUsesEffectiveWindowSQLite(t *testing.T) {
	runReauthSlideUsesEffectiveWindow(t, seededDB(t, openSQLite))
}
func TestReauthSlideUsesEffectiveWindowPostgres(t *testing.T) {
	runReauthSlideUsesEffectiveWindow(t, seededDB(t, openPostgres))
}

// runReauthSlideUsesEffectiveWindow (NEW HIGH): the slide amount is resolved
// through effectiveReauthWindow — the SAME seam the openers use — never the
// global s.ReauthWindow. Lowering the effective window (as #55 will) both makes
// a sliding window non-extendable at effective-0 (fail closed) and, above 0,
// bounds the slide to the lowered value rather than the value the window opened
// with. The seam is thus the single source shared by open and consume.
func runReauthSlideUsesEffectiveWindow(t *testing.T, db *store.DB) {
	auth, _, token := bootstrapWebAuthnAdmin(t, db)
	base := time.Now().UTC().Truncate(time.Second)
	clk := base
	auth.Now = func() time.Time { return clk }
	auth.ReauthWindow = 5 * time.Minute
	auth.ReauthHardCap = 30 * time.Minute
	ctx := t.Context()
	dev := webauthntest.New(waRPID, waOrigin)
	token = enrolPasskey(t, auth, ctx, token, waPassword, dev)
	token = stepUpPasskey(t, auth, ctx, token, dev)

	ropts, err := auth.ReauthPasskeyStart(ctx, token, service.PurposeReveal, "env_prod", []string{"key_a"})
	if err != nil {
		t.Fatalf("reauth start: %v", err)
	}
	rresp, err := dev.Assert(ropts)
	if err != nil {
		t.Fatalf("device assert: %v", err)
	}
	if _, err := auth.ReauthPasskeyFinish(ctx, token, rresp); err != nil {
		t.Fatalf("reauth finish: %v", err)
	}
	sessionID := queryString(t, db, "SELECT session_id FROM reauth_windows WHERE environment_id = 'env_prod'")

	// #55 lowers env_prod's effective window to 0. The consume path reads the same
	// seam the opener did: a live sliding window (opened to base+5m) is now NOT
	// extendable — the only valid 0-window is a single_decision WebAuthn one, which
	// is consumed not slid — so a disclosure at +1m fails closed WITHOUT sliding.
	auth.ReauthWindow = 0
	if err := consumeWindow(t, auth, db, sessionID, "env_prod", nil, base.Add(1*time.Minute)); !errors.Is(err, service.ErrReauthWindowExpired) {
		t.Fatalf("consume a sliding window at effective-0: %v, want ErrReauthWindowExpired (non-extendable, fail closed)", err)
	}

	// #55 now sets a lower non-zero effective window (2m). The window was NOT slid
	// above, so it still sits at base+5m. A disclosure at +4m slides by the 2m
	// effective value -> base+6m, NOT the 5m the window opened with (which would be
	// base+9m).
	auth.ReauthWindow = 2 * time.Minute
	if err := consumeWindow(t, auth, db, sessionID, "env_prod", nil, base.Add(4*time.Minute)); err != nil {
		t.Fatalf("consume at +4m under a 2m effective window: %v", err)
	}
	// +6m30s is past the base+6m the 2m slide produced: fail closed. Had the slide
	// used the 5m the window opened with it would sit at base+9m and this would
	// wrongly succeed — so this failure proves the slide read effectiveReauthWindow
	// at consume time, not the opener's s.ReauthWindow.
	if err := consumeWindow(t, auth, db, sessionID, "env_prod", nil, base.Add(6*time.Minute+30*time.Second)); !errors.Is(err, service.ErrReauthWindowExpired) {
		t.Fatalf("consume at +6m30s: %v, want ErrReauthWindowExpired (slide bounded by the 2m effective window)", err)
	}
}

func TestReauthConsumeInvalidationFailsClosedSQLite(t *testing.T) {
	runReauthConsumeInvalidationFailsClosed(t, seededDB(t, openSQLite))
}
func TestReauthConsumeInvalidationFailsClosedPostgres(t *testing.T) {
	runReauthConsumeInvalidationFailsClosed(t, seededDB(t, openPostgres))
}

// runReauthConsumeInvalidationFailsClosed (A1): a disclosure that reads a live
// sliding window but whose slide matches 0 rows — because a concurrent
// LowerEffectiveWindow invalidation / single-decision claim landed between the
// liveness read and the slide — must fail CLOSED, never proceeding against a
// window the CAS could not refresh. Simulated deterministically on both engines
// by marking the window consumed after it is opened: ReauthWindowFor has no
// consumed_at filter, so the read succeeds and the liveness check passes, but the
// slide's `consumed_at IS NULL` guard matches 0 rows — which the fix now refuses
// (before the fix, the dropped rows-affected result let the disclosure proceed).
func runReauthConsumeInvalidationFailsClosed(t *testing.T, db *store.DB) {
	auth, _, token := bootstrapWebAuthnAdmin(t, db)
	base := time.Now().UTC().Truncate(time.Second)
	clk := base
	auth.Now = func() time.Time { return clk }
	auth.ReauthWindow = 5 * time.Minute
	auth.ReauthHardCap = 10 * time.Minute
	ctx := t.Context()
	dev := webauthntest.New(waRPID, waOrigin)
	token = enrolPasskey(t, auth, ctx, token, waPassword, dev)
	token = stepUpPasskey(t, auth, ctx, token, dev)

	ropts, err := auth.ReauthPasskeyStart(ctx, token, service.PurposeReveal, "env_prod", []string{"key_a"})
	if err != nil {
		t.Fatalf("reauth start: %v", err)
	}
	rresp, err := dev.Assert(ropts)
	if err != nil {
		t.Fatalf("device assert: %v", err)
	}
	if _, err := auth.ReauthPasskeyFinish(ctx, token, rresp); err != nil {
		t.Fatalf("reauth finish: %v", err)
	}
	sessionID := queryString(t, db, "SELECT session_id FROM reauth_windows WHERE environment_id = 'env_prod'")

	// A concurrent invalidation claims the window (consumed_at set) between the
	// liveness read and the slide; the disclosure at +1m must refuse rather than
	// succeed against a window the slide could not refresh.
	execRaw(t, db, "UPDATE reauth_windows SET consumed_at = "+ts+" WHERE environment_id = 'env_prod'")
	if err := consumeWindow(t, auth, db, sessionID, "env_prod", nil, base.Add(1*time.Minute)); !errors.Is(err, service.ErrReauthWindowExpired) {
		t.Fatalf("disclosure whose slide lost the CAS: %v, want ErrReauthWindowExpired (fail closed)", err)
	}
}

func TestReauthTOTPZeroWindowSQLite(t *testing.T) {
	runReauthTOTPZeroWindow(t, seededDB(t, openSQLite))
}
func TestReauthTOTPZeroWindowPostgres(t *testing.T) {
	runReauthTOTPZeroWindow(t, seededDB(t, openPostgres))
}

// runReauthTOTPZeroWindow: TOTP cannot bind the enumerated unit, so at a 0
// effective window it refuses reauth naming the remedy (only WebAuthn opens a
// 0-window gate); at a non-zero window it opens a sliding window.
func runReauthTOTPZeroWindow(t *testing.T, db *store.DB) {
	auth, _, password := bootstrapFactorAdmin(t, db)
	base := time.Now().UTC()
	clk := base
	auth.Now = func() time.Time { return clk }
	ctx := t.Context()

	login, err := auth.LocalLogin(ctx, "factor-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := auth.EnrolTOTPStart(ctx, login.SessionToken, password)
	if err != nil {
		t.Fatalf("enrol start: %v", err)
	}
	clk = base.Add(30 * time.Second)
	confirmed, err := auth.EnrolTOTPConfirm(ctx, login.SessionToken, totpCode(t, uri, clk))
	if err != nil {
		t.Fatalf("enrol confirm: %v", err)
	}
	token := confirmed.SessionToken

	// 0 effective window: TOTP refuses, naming the WebAuthn remedy.
	auth.ReauthWindow = 0
	clk = base.Add(60 * time.Second)
	if _, err := auth.ReauthTOTP(ctx, token, "env_prod", totpCode(t, uri, clk)); !errors.Is(err, service.ErrReauthWindowClosed) {
		t.Fatalf("TOTP reauth at a 0 window: %v, want ErrReauthWindowClosed", err)
	}

	// Non-zero window: TOTP opens a sliding window over the environment.
	auth.ReauthWindow = 5 * time.Minute
	auth.ReauthHardCap = 10 * time.Minute
	clk = base.Add(120 * time.Second)
	res, err := auth.ReauthTOTP(ctx, token, "env_prod", totpCode(t, uri, clk))
	if err != nil {
		t.Fatalf("TOTP reauth at a non-zero window: %v", err)
	}
	if res.SingleDecision {
		t.Error("a TOTP window is never single-decision")
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM reauth_windows WHERE environment_id = 'env_prod' AND factor_class = 'totp' AND single_decision = 0"); got != 1 {
		t.Errorf("totp reauth window count = %d, want 1", got)
	}
}

func TestLowerEffectiveWindowStrandingSQLite(t *testing.T) {
	runLowerEffectiveWindowStranding(t, seededDB(t, openSQLite))
}
func TestLowerEffectiveWindowStrandingPostgres(t *testing.T) {
	runLowerEffectiveWindowStranding(t, seededDB(t, openPostgres))
}

// runLowerEffectiveWindowStranding (finding B6): lowering an environment's
// effective window to 0 enumerates the reveal/reveal-history holders there
// without a WebAuthn authenticator (they are stranded until they enrol), RETAINS
// their grants (a settings change never revokes a capability), and audits the
// stranded list. A reveal holder WITH a WebAuthn authenticator is not stranded.
func runLowerEffectiveWindowStranding(t *testing.T, db *store.DB) {
	auth := authService(t, db)
	// reader holds reveal on env_a1's org and no passkey -> stranded.
	execRaw(t, db, "INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_rd_rev', 'usr_reader', 'reveal', 'org_a', NULL, NULL, "+ts+")")
	// alice holds reveal-history on env_a1 directly AND has an enabled passkey ->
	// not stranded. Give her an account and a WebAuthn credential.
	execRaw(t, db, "INSERT INTO accounts (id, principal_id, username, display_name, created_at) VALUES ('acc_alice', 'usr_alice', 'alice', 'Alice', "+ts+")")
	execRaw(t, db, "INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_al_rev', 'usr_alice', 'reveal-history', 'org_a', 'prj_a1', 'env_a1', "+ts+")")
	execRaw(t, db, "INSERT INTO webauthn_credentials (id, account_id, credential_id, public_key, aaguid, sign_count, transports, discoverable, backup_eligible, backup_state, label, credential_epoch, row_version, disabled_at, created_at, last_used_at) VALUES ('wac_alice', 'acc_alice', "+blobLit(db, []byte("cred-alice"))+", "+blobLit(db, []byte("pk"))+", "+blobLit(db, []byte("aa"))+", 0, '[]', 1, 0, 0, 'k', 1, 0, NULL, "+ts+", NULL)")

	var stranded []domain.PrincipalID
	var invalidated int
	err := tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		var e error
		stranded, invalidated, e = auth.LowerEffectiveWindow(ctx, az, "env_a1", 0, time.Now().UTC())
		return e
	})
	if err != nil {
		t.Fatalf("lower effective window: %v", err)
	}
	if invalidated != 0 {
		t.Errorf("invalidated = %d, want 0 (no open windows on env_a1)", invalidated)
	}
	if !containsPrincipal(stranded, "usr_reader") {
		t.Errorf("stranded = %v, want it to include usr_reader (reveal holder, no passkey)", stranded)
	}
	if containsPrincipal(stranded, "usr_alice") {
		t.Errorf("stranded = %v, want it to EXCLUDE usr_alice (has a passkey)", stranded)
	}
	// Grants are RETAINED: the settings change revoked nothing.
	if n := queryInt(t, db, "SELECT COUNT(*) FROM grants WHERE id = 'g_rd_rev'"); n != 1 {
		t.Error("LowerEffectiveWindow revoked a grant — it must retain them")
	}
	// The audit event carries the stranded list.
	if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'auth.effective_window_lowered' AND payload LIKE '%usr_reader%'"); n != 1 {
		t.Error("auth.effective_window_lowered did not record the stranded principal")
	}
}

func TestCredentialResetNetworkSQLite(t *testing.T) {
	runCredentialResetNetwork(t, seededDB(t, openSQLite))
}
func TestCredentialResetNetworkPostgres(t *testing.T) {
	runCredentialResetNetwork(t, seededDB(t, openPostgres))
}

// grantInstanceCapability seeds a capability the bootstrap template no longer
// bundles. Since #55 the first administrator is seeded with `operator`
// (operator set + manage-members, no tenant data by bundle), so anything else
// — `credential-reset` here — arrives as an EXPLICIT AUDITED GRANT, which is
// exactly the ADR's "never by bundle". It goes through the real grant surface
// under local authority, so the fixture exercises the path it documents.
func grantInstanceCapability(t *testing.T, db *store.DB, target domain.PrincipalID, c domain.Capability) {
	t.Helper()
	if _, err := (&service.Grants{DB: db}).Create(t.Context(), service.LocalPrincipal(target), service.GrantSpec{
		Target: target, Capability: c,
	}); err != nil {
		t.Fatalf("seed %s at instance scope: %v", c, err)
	}
}

// runCredentialResetNetwork (ADR - Recovery): a stepped-up credential-reset
// holder resets an org-bounded target over the network, minting a session-less
// authority that establishes only a password; the target then logs in with it. An
// instance-capability target has no network path and is refused uniformly (B2),
// but break-glass on the host reaches it. The org-bounded test runs under the target
// principal-row lock every grant writer also takes (B14, analyzer-enforced), so a
// concurrent grant landing serializes against the reset.
func runCredentialResetNetwork(t *testing.T, db *store.DB) {
	auth, boot, password := bootstrapFactorAdmin(t, db)
	grantInstanceCapability(t, db, boot.PrincipalID, domain.CapCredentialReset)
	base := time.Now().UTC()
	clk := base
	auth.Now = func() time.Time { return clk }
	ctx := t.Context()

	// Step the admin up to multi-factor: credential-reset is MFA-mandatory.
	login, err := auth.LocalLogin(ctx, "factor-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := auth.EnrolTOTPStart(ctx, login.SessionToken, password)
	if err != nil {
		t.Fatalf("enrol start: %v", err)
	}
	clk = base.Add(30 * time.Second)
	confirmed, err := auth.EnrolTOTPConfirm(ctx, login.SessionToken, totpCode(t, uri, clk))
	if err != nil {
		t.Fatalf("enrol confirm: %v", err)
	}
	clk = base.Add(60 * time.Second)
	stepped, err := auth.StepUpTOTP(ctx, confirmed.SessionToken, totpCode(t, uri, clk))
	if err != nil {
		t.Fatalf("step-up: %v", err)
	}
	adminToken := stepped.SessionToken

	// An org-bounded target: grants within org_a, no instance capability.
	execRaw(t, db, "INSERT INTO principals (id, kind, created_at) VALUES ('usr_target', 'human', "+ts+")")
	execRaw(t, db, "INSERT INTO accounts (id, principal_id, username, display_name, created_at) VALUES ('acc_target', 'usr_target', 'target', 'Target', "+tsMicro+")")
	execRaw(t, db, "INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_tg_rev', 'usr_target', 'reveal', 'org_a', NULL, NULL, "+ts+")")

	res, err := auth.ResetCredential(ctx, service.Bearer(adminToken), "usr_target", "response")
	if err != nil {
		t.Fatalf("reset an org-bounded target: %v", err)
	}
	// The authority is session-less and establishes only a password.
	const targetPassword = "the target's brand new password"
	if err := auth.EstablishCredential(ctx, res.Authority, targetPassword); err != nil {
		t.Fatalf("establish with the reset authority: %v", err)
	}
	if _, err := auth.LocalLogin(ctx, "target", targetPassword, service.ArtifactCLI); err != nil {
		t.Fatalf("the target cannot log in with the established credential: %v", err)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'auth.credential_reset_issued' AND payload LIKE '%usr_target%'"); n != 1 {
		t.Error("the network reset was not audited as auth.credential_reset_issued")
	}

	// An instance-capability target has no network path: refused UNIFORMLY (B2) —
	// the same sentinel a nonexistent target returns, so a reset holder cannot
	// probe which principals hold instance capabilities off a differential
	// response. The true cause is durable in the trail (asserted below).
	execRaw(t, db, "INSERT INTO principals (id, kind, created_at) VALUES ('usr_op', 'human', "+ts+")")
	execRaw(t, db, "INSERT INTO accounts (id, principal_id, username, display_name, created_at) VALUES ('acc_op', 'usr_op', 'op', 'Operator', "+tsMicro+")")
	execRaw(t, db, "INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_op_ic', 'usr_op', 'instance-config', NULL, NULL, NULL, "+ts+")")
	if _, err := auth.ResetCredential(ctx, service.Bearer(adminToken), "usr_op", "response"); !errors.Is(err, service.ErrNoResetTarget) {
		t.Fatalf("network reset of an instance-capability target: %v, want the uniform ErrNoResetTarget", err)
	}
	// The refusal is audited (ADR - Recovery: failures are audited), by cause,
	// while the wire stays uniform — the commit-then-refuse plumbing.
	if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'auth.credential_reset_issued' AND outcome = 'failure' AND payload LIKE '%instance-capability-target%'"); n != 1 {
		t.Error("the instance-capability-target refusal was not audited as a failure")
	}

	// Break-glass on the host reaches the instance-capability target.
	bg, err := auth.BreakGlassResetCredential(ctx, "usr_op", "terminal")
	if err != nil {
		t.Fatalf("break-glass reset of an instance-capability target: %v", err)
	}
	const opPassword = "the operator's brand new password"
	if err := auth.EstablishCredential(ctx, bg.Authority, opPassword); err != nil {
		t.Fatalf("establish with the break-glass authority: %v", err)
	}
	if _, err := auth.LocalLogin(ctx, "op", opPassword, service.ArtifactCLI); err != nil {
		t.Fatalf("the operator cannot log in after break-glass: %v", err)
	}
}

func TestCredentialResetMFAMandatorySQLite(t *testing.T) {
	runCredentialResetMFAMandatory(t, seededDB(t, openSQLite))
}
func TestCredentialResetMFAMandatoryPostgres(t *testing.T) {
	runCredentialResetMFAMandatory(t, seededDB(t, openPostgres))
}

// runCredentialResetMFAMandatory (B1/B3): the network reset route authorizes
// through the credential-reset operations, so the chokepoint authorize() enforces
// CapCredentialReset AND its MFA-mandatory rule — not merely the handler's manual
// dispatch. A holder on a single-factor (password-only) session is refused, no
// authority is minted, and the refusal is cause-audited as a grant denial naming
// the credential-reset operation: uniform on the wire (mapped to 401), detailed
// in the trail.
func runCredentialResetMFAMandatory(t *testing.T, db *store.DB) {
	auth, boot, password := bootstrapFactorAdmin(t, db)
	grantInstanceCapability(t, db, boot.PrincipalID, domain.CapCredentialReset)
	ctx := t.Context()

	// An org-bounded target within org_a.
	execRaw(t, db, "INSERT INTO principals (id, kind, created_at) VALUES ('usr_t2', 'human', "+ts+")")
	execRaw(t, db, "INSERT INTO accounts (id, principal_id, username, display_name, created_at) VALUES ('acc_t2', 'usr_t2', 'target2', 'Target Two', "+tsMicro+")")
	execRaw(t, db, "INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_t2_rev', 'usr_t2', 'reveal', 'org_a', NULL, NULL, "+ts+")")

	// The admin holds credential-reset (granted explicitly above) but logs in with the
	// password alone — a single-factor session that the MFA-mandatory rule refuses.
	login, err := auth.LocalLogin(ctx, "factor-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.ResetCredential(ctx, service.Bearer(login.SessionToken), "usr_t2", "response"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("single-factor credential reset: %v, want domain.ErrUnauthorized (MFA-mandatory at the chokepoint)", err)
	}
	// Cause-audited as a grant denial naming the credential-reset operation (B3);
	// a resolvable org-scoped denial lands in the tenant trail.
	if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'grant.denied' AND payload LIKE '%credential-reset%'"); n != 1 {
		t.Errorf("insufficient-MFA reset was not cause-audited as a grant denial (got %d)", n)
	}
	// No authority was minted for the refused reset.
	if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'auth.authority_minted'"); n != 0 {
		t.Errorf("a refused reset minted an authority (got %d)", n)
	}
}

// containsPrincipal reports set membership.
func containsPrincipal(ids []domain.PrincipalID, want domain.PrincipalID) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// stepUpPasskey elevates a password-only session with the passkey and returns the
// rotated token, so a reauth ceremony (an account-security-adjacent step) rides an
// adequately assured session.
func stepUpPasskey(t *testing.T, auth *service.Auth, ctx context.Context, token string, dev *webauthntest.Device) string {
	t.Helper()
	opts, err := auth.StepUpPasskeyStart(ctx, token)
	if err != nil {
		t.Fatalf("step-up start: %v", err)
	}
	resp, err := dev.Assert(opts)
	if err != nil {
		t.Fatalf("device assert (step-up): %v", err)
	}
	stepped, err := auth.StepUpPasskeyFinish(ctx, token, resp)
	if err != nil {
		t.Fatalf("step-up finish: %v", err)
	}
	return stepped.SessionToken
}

// blobLit renders a BLOB/bytea literal for the engine under test, so a fixture
// can seed a WebAuthn credential's binary columns on both dialects.
func blobLit(db *store.DB, b []byte) string {
	const hexdigits = "0123456789abcdef"
	var sb []byte
	for _, c := range b {
		sb = append(sb, hexdigits[c>>4], hexdigits[c&0x0f])
	}
	if db.Engine() == store.EnginePostgres {
		return `'\x` + string(sb) + `'`
	}
	return `x'` + string(sb) + `'`
}

func TestCLIDisclosureReauthHandoffSQLite(t *testing.T) {
	runCLIDisclosureReauthHandoff(t, seededDB(t, openSQLite))
}

func TestCLIDisclosureReauthHandoffPostgres(t *testing.T) {
	runCLIDisclosureReauthHandoff(t, seededDB(t, openPostgres))
}

// runCLIDisclosureReauthHandoff: the handoff carries a DISCLOSURE purpose
// with its enumerated key set (api-cli-surface ADR § Login and reauth
// transports). The start refuses a disclosure without a unit and an adapter
// with one; the transaction reports purpose and unit; the browser's
// environment-wide window satisfies the approval; redemption hands the CLI an
// UNBOUND window mirroring the browser's, under which the CLI's reveal
// succeeds, while the adapter-bound shape is untouched.
func runCLIDisclosureReauthHandoff(t *testing.T, db *store.DB) {
	auth, boot, password := bootstrapFactorAdmin(t, db)
	identityFixtures(t, db)
	seedDeliveryCatalogue(t, db)
	for _, row := range [][2]string{{"read", "g_cli_disc_read"}, {"reveal", "g_cli_disc_reveal"}} {
		execRaw(t, db, `INSERT INTO grants (id,principal_id,capability,org_id,project_id,env_id,created_at) VALUES ('`+row[1]+`','`+string(boot.PrincipalID)+`','`+row[0]+`','org_a','prj_a1','env_a1',`+ts+`)`)
		execRaw(t, db, `INSERT INTO grant_origins (id,grant_id,kind,subject,created_at) VALUES ('gor_`+row[1]+`','`+row[1]+`','manual','`+string(boot.PrincipalID)+`',`+ts+`)`)
	}
	base := time.Date(2026, 8, 21, 3, 0, 0, 0, time.UTC)
	clock := base
	auth.Now = func() time.Time { return clock }
	auth.ReauthWindow = 5 * time.Minute
	cliLogin, err := auth.LocalLogin(t.Context(), "factor-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := auth.EnrolTOTPStart(t.Context(), cliLogin.SessionToken, password)
	if err != nil {
		t.Fatal(err)
	}
	clock = base.Add(30 * time.Second)
	cliConfirmed, err := auth.EnrolTOTPConfirm(t.Context(), cliLogin.SessionToken, totpCode(t, uri, clock))
	if err != nil {
		t.Fatal(err)
	}
	browser, err := auth.LocalLogin(t.Context(), "factor-admin", password, service.ArtifactBrowser)
	if err != nil {
		t.Fatal(err)
	}
	clock = base.Add(time.Minute)
	browserWindow, err := auth.ReauthTOTP(t.Context(), browser.SessionToken, "env_a1", totpCode(t, uri, clock))
	if err != nil {
		t.Fatal(err)
	}
	secretKeys := strings.Split(queryStrings(t, db, `SELECT id FROM keys WHERE project_id = 'prj_a1' AND classification = 'secret' ORDER BY id`), "\n")
	if len(secretKeys) == 0 || secretKeys[0] == "" {
		t.Fatal("the seeded catalogue has no secret key to bind")
	}
	verifierBytes := sha256.Sum256([]byte("cli disclosure reauth pkce verifier"))
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes[:])
	challengeBytes := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])
	redirect := "http://127.0.0.1:40124/callback"

	if _, err := auth.StartCLIReauth(t.Context(), cliConfirmed.SessionToken, string(service.PurposeReveal), string(authz.OpValueReveal), []string{"env_a1"}, nil, challenge, redirect); !errors.Is(err, service.ErrReauthUnitMismatch) {
		t.Fatalf("disclosure handoff without a key set = %v, want unit mismatch", err)
	}
	if _, err := auth.StartCLIReauth(t.Context(), cliConfirmed.SessionToken, string(service.PurposeAdapter), string(authz.OpAdapterSync), []string{"env_a1"}, secretKeys, challenge, redirect); !errors.Is(err, service.ErrReauthUnitMismatch) {
		t.Fatalf("adapter handoff with a key set = %v, want unit mismatch", err)
	}
	if _, err := auth.StartCLIReauth(t.Context(), cliConfirmed.SessionToken, string(service.PurposeReveal), string(authz.OpAdapterSync), []string{"env_a1"}, secretKeys, challenge, redirect); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("reveal purpose with an adapter operation = %v, want invalid", err)
	}
	start, err := auth.StartCLIReauth(t.Context(), cliConfirmed.SessionToken, string(service.PurposeReveal), string(authz.OpValueReveal), []string{"env_a1"}, secretKeys, challenge, redirect)
	if err != nil {
		t.Fatalf("start disclosure handoff: %v", err)
	}
	transaction, err := auth.CLIReauthTransaction(t.Context(), service.Bearer(browserWindow.SessionToken), start.State)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.Purpose != string(service.PurposeReveal) || transaction.Operation != string(authz.OpValueReveal) || strings.Join(transaction.KeyIDs, "\n") != service.CanonicalKeySet(secretKeys) {
		t.Fatalf("transaction = %+v", transaction)
	}
	approved, err := auth.ApproveCLIReauth(t.Context(), service.Bearer(browserWindow.SessionToken), start.State)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	redeemed, err := auth.RedeemCLIReauth(t.Context(), approved.Code, verifier)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if len(redeemed.Windows) != 1 || redeemed.Windows[0].EnvironmentID != "env_a1" || redeemed.Windows[0].SingleDecision {
		t.Fatalf("redeemed windows = %+v", redeemed.Windows)
	}
	if got := queryString(t, db, "SELECT COALESCE(bound_purpose, '') FROM reauth_windows WHERE session_id = '"+cliConfirmed.SessionID+"'"); got != "" {
		t.Fatalf("the CLI's disclosure window is bound to purpose %q; a mirrored sliding window must be unbound", got)
	}
	values := valueSvc(t, db)
	values.Auth = auth
	cells, err := values.List(t.Context(), service.Bearer(redeemed.SessionToken), scopeEnv(orgA, prjA1, envA1), true)
	if err != nil {
		t.Fatalf("reveal under the redeemed bearer: %v", err)
	}
	revealed := 0
	for _, c := range cells {
		if c.Classification == "secret" && c.Revealed {
			revealed++
		}
	}
	if revealed != len(secretKeys) {
		t.Fatalf("revealed %d secrets under the handoff window, want %d", revealed, len(secretKeys))
	}
}
