package isolation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Dunky13/wenv/api"
	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/service"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/tx"
	"github.com/Dunky13/wenv/internal/webauthntest"
)

// TestBreakGlassHasNoNetworkRoute asserts the break-glass reset
// (`wenv admin reset-credential`) has no HTTP path at all: the ONLY
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

// consumeWindow runs ConsumeReauthWindow inside its own transaction, as the
// reveal path will, and returns the refusal (or nil) unwrapped for errors.Is.
func consumeWindow(t *testing.T, auth *service.Auth, db *store.DB, sessionID, env string, keys []string, now time.Time) error {
	t.Helper()
	return tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		return auth.ConsumeReauthWindow(ctx, az, sessionID, env, keys, now)
	})
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

	ropts, err := auth.ReauthPasskeyStart(ctx, token, "env_prod", []string{"key_b", "key_a"})
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

	ropts, err := auth.ReauthPasskeyStart(ctx, token, "env_prod", []string{"key_a"})
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

	login, err := auth.LocalLogin(ctx, "factor-admin", password)
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

// runCredentialResetNetwork (ADR - Recovery): a stepped-up credential-reset
// holder resets an org-bounded target over the network, minting a session-less
// authority that establishes only a password; the target then logs in with it. An
// instance-capability target has no network path and is refused by name, but
// break-glass on the host reaches it. The org-bounded test runs under the target
// principal-row lock every grant writer also takes (B14, analyzer-enforced), so a
// concurrent grant landing serializes against the reset.
func runCredentialResetNetwork(t *testing.T, db *store.DB) {
	auth, _, password := bootstrapFactorAdmin(t, db)
	base := time.Now().UTC()
	clk := base
	auth.Now = func() time.Time { return clk }
	ctx := t.Context()

	// Step the admin up to multi-factor: credential-reset is MFA-mandatory.
	login, err := auth.LocalLogin(ctx, "factor-admin", password)
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
	if _, err := auth.LocalLogin(ctx, "target", targetPassword); err != nil {
		t.Fatalf("the target cannot log in with the established credential: %v", err)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'auth.credential_reset_issued' AND payload LIKE '%usr_target%'"); n != 1 {
		t.Error("the network reset was not audited as auth.credential_reset_issued")
	}

	// An instance-capability target has no network path: refused by name.
	execRaw(t, db, "INSERT INTO principals (id, kind, created_at) VALUES ('usr_op', 'human', "+ts+")")
	execRaw(t, db, "INSERT INTO accounts (id, principal_id, username, display_name, created_at) VALUES ('acc_op', 'usr_op', 'op', 'Operator', "+tsMicro+")")
	execRaw(t, db, "INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_op_ic', 'usr_op', 'instance-config', NULL, NULL, NULL, "+ts+")")
	if _, err := auth.ResetCredential(ctx, service.Bearer(adminToken), "usr_op", "response"); !errors.Is(err, service.ErrCredentialResetInstanceTarget) {
		t.Fatalf("network reset of an instance-capability target: %v, want ErrCredentialResetInstanceTarget", err)
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
	if _, err := auth.LocalLogin(ctx, "op", opPassword); err != nil {
		t.Fatalf("the operator cannot log in after break-glass: %v", err)
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
