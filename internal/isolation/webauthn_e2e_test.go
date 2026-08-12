package isolation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Dunky13/hikyo/internal/admission"
	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/tx"
	"github.com/Dunky13/hikyo/internal/webauthntest"
)

// The WebAuthn / passkey slice end to end on a real datastore (#54, human-auth
// ADR § WebAuthn relying-party policy, § Passkey login). These exercise the
// locked mechanisms Investigation B named: enrol + discoverable login yielding
// multi-factor assurance, UV verified server-side, the sign-count clone response
// (B9) versus a synced credential that must not be flagged, the passkey-only
// post-state invariant (B4/B13), and that a new passkey cannot authorize its own
// enrolment. descope/virtualwebauthn plays the authenticator against the real
// go-webauthn validation path.

const (
	waRPID     = "hikyo.test"
	waOrigin   = "https://hikyo.test"
	waAdmin    = "wa-admin"
	waPassword = "correct horse battery staple webauthn"
)

func webauthnAuthService(t *testing.T, db *store.DB) *service.Auth {
	t.Helper()
	auth := authService(t, db)
	auth.ExternalOrigin = waOrigin
	if err := auth.ConfigureWebAuthnRP(); err != nil {
		t.Fatalf("configuring the webauthn relying party: %v", err)
	}
	return auth
}

// bootstrapWebAuthnAdmin mints a first administrator, establishes its password
// and logs in, returning the acting service, the account id and a live session.
func bootstrapWebAuthnAdmin(t *testing.T, db *store.DB) (*service.Auth, string, string) {
	t.Helper()
	auth := webauthnAuthService(t, db)
	ctx := t.Context()
	boot, err := auth.BootstrapAdmin(ctx, waAdmin, "WA Admin", "terminal")
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.EstablishCredential(ctx, boot.Authority, waPassword); err != nil {
		t.Fatal(err)
	}
	login, err := auth.LocalLogin(ctx, waAdmin, waPassword, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	accountID := queryString(t, db, "SELECT id FROM accounts WHERE username = '"+waAdmin+"'")
	return auth, accountID, login.SessionToken
}

// enrolPasskey runs a full enrolment with the given device and returns the
// reissued session token (the mutation reissues the acting session).
func enrolPasskey(t *testing.T, auth *service.Auth, ctx context.Context, token, password string, dev *webauthntest.Device) string {
	t.Helper()
	opts, err := auth.EnrolPasskeyStart(ctx, token, password, "")
	if err != nil {
		t.Fatalf("enrol start: %v", err)
	}
	att, err := dev.Enrol(opts)
	if err != nil {
		t.Fatalf("device enrol: %v", err)
	}
	res, err := auth.EnrolPasskeyFinish(ctx, token, att)
	if err != nil {
		t.Fatalf("enrol finish: %v", err)
	}
	return res.SessionToken
}

// discoverableLogin runs a full passkey login with the device.
func discoverableLogin(t *testing.T, auth *service.Auth, ctx context.Context, dev *webauthntest.Device) (service.LoginResult, error) {
	t.Helper()
	opts, err := auth.PasskeyLoginStart(ctx)
	if err != nil {
		t.Fatalf("login start: %v", err)
	}
	assertion, err := dev.Assert(opts)
	if err != nil {
		t.Fatalf("device assert: %v", err)
	}
	return auth.PasskeyLoginFinish(ctx, assertion)
}

func TestWebAuthnRoundtripSQLite(t *testing.T)   { runWebAuthnRoundtrip(t, seededDB(t, openSQLite)) }
func TestWebAuthnRoundtripPostgres(t *testing.T) { runWebAuthnRoundtrip(t, seededDB(t, openPostgres)) }

// runWebAuthnRoundtrip: enrol a passkey (proof = the pre-existing password),
// then log in with one gesture. The session carries method local-passkey and a
// single webauthn factor class, and passes an MFA-mandatory operation the
// password-only session is refused — the "UV is inherent 2FA" rule made real.
func runWebAuthnRoundtrip(t *testing.T, db *store.DB) {
	auth, _, token := bootstrapWebAuthnAdmin(t, db)
	ctx := t.Context()
	orgs := &service.Orgs{DB: db}

	dev := webauthntest.New(waRPID, waOrigin)
	passwordSession := enrolPasskey(t, auth, ctx, token, waPassword, dev)

	login, err := discoverableLogin(t, auth, ctx, dev)
	if err != nil {
		t.Fatalf("passkey login: %v", err)
	}
	if login.Assurance.Method != service.MethodLocalPasskey {
		t.Errorf("passkey login method = %q, want %q", login.Assurance.Method, service.MethodLocalPasskey)
	}
	if len(login.Assurance.Factors) != 1 || login.Assurance.Factors[0] != "webauthn" {
		t.Errorf("passkey login factors = %v, want [webauthn]", login.Assurance.Factors)
	}
	if login.Artifact != service.ArtifactBrowser {
		t.Errorf("passkey login artifact = %q, want browser", login.Artifact)
	}
	if login.CSRFToken == "" {
		t.Error("a browser session must carry a CSRF token")
	}
	// The minted session's ceremony_id is the RELOADED login ceremony row,
	// consumed by its fresh id (A3): it resolves to a consumed login ceremony
	// stamped with the credential that authored it.
	if got := queryInt(t, db, "SELECT COUNT(*) FROM sessions s JOIN webauthn_ceremonies c ON c.id = s.ceremony_id WHERE s.id = '"+login.SessionID+"' AND c.purpose = 'login' AND c.consumed_at IS NOT NULL AND c.credential_id IS NOT NULL"); got != 1 {
		t.Errorf("minted session must trace to its consumed login ceremony (fresh id), got %d", got)
	}

	// The passkey session passes an MFA-mandatory operation (org create is
	// instance-config); the password-only session is refused for inadequate
	// assurance.
	if _, err := orgs.Create(ctx, service.Bearer(login.SessionToken), "passkey-org", true, []byte(`{}`)); err != nil {
		t.Fatalf("a webauthn session must pass an MFA-mandatory op: %v", err)
	}
	if _, err := orgs.Create(ctx, service.Bearer(passwordSession), "pw-org", true, []byte(`{}`)); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("a password-only session must be refused an MFA-mandatory op, got %v", err)
	}
}

func TestWebAuthnUVRefusedSQLite(t *testing.T)   { runWebAuthnUVRefused(t, seededDB(t, openSQLite)) }
func TestWebAuthnUVRefusedPostgres(t *testing.T) { runWebAuthnUVRefused(t, seededDB(t, openPostgres)) }

// runWebAuthnUVRefused: an assertion whose UV bit is not set is refused. UV is
// required on every ceremony and re-asserted server-side.
func runWebAuthnUVRefused(t *testing.T, db *store.DB) {
	auth, _, token := bootstrapWebAuthnAdmin(t, db)
	ctx := t.Context()
	dev := webauthntest.New(waRPID, waOrigin)
	enrolPasskey(t, auth, ctx, token, waPassword, dev)

	dev.SetUserVerified(false)
	if _, err := discoverableLogin(t, auth, ctx, dev); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("a UV-not-set assertion must be refused, got %v", err)
	}
}

func TestWebAuthnCloneSQLite(t *testing.T)   { runWebAuthnClone(t, seededDB(t, openSQLite)) }
func TestWebAuthnClonePostgres(t *testing.T) { runWebAuthnClone(t, seededDB(t, openPostgres)) }

// runWebAuthnClone: a sign-count regression on a non-backup credential disables
// it, sweeps every session it minted and audits passkey_cloned, before refusing
// (B9).
func runWebAuthnClone(t *testing.T, db *store.DB) {
	auth, accountID, token := bootstrapWebAuthnAdmin(t, db)
	ctx := t.Context()
	dev := webauthntest.New(waRPID, waOrigin) // non-backup by default
	enrolPasskey(t, auth, ctx, token, waPassword, dev)

	// A first login advances the stored counter to 5.
	dev.SetCounter(5)
	if _, err := discoverableLogin(t, auth, ctx, dev); err != nil {
		t.Fatalf("first passkey login: %v", err)
	}
	if got := queryInt(t, db, "SELECT sign_count FROM webauthn_credentials WHERE account_id = '"+accountID+"'"); got != 5 {
		t.Fatalf("stored sign_count = %d, want 5", got)
	}

	// A second login presenting a non-advancing counter is a clone.
	dev.SetCounter(3)
	if _, err := discoverableLogin(t, auth, ctx, dev); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("a sign-count regression must be refused, got %v", err)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM webauthn_credentials WHERE account_id = '"+accountID+"' AND disabled_at IS NOT NULL"); got != 1 {
		t.Errorf("cloned credential disabled count = %d, want 1", got)
	}
	// Every session the cloned credential minted (traced session -> ceremony ->
	// credential_id) is swept; other sessions die by generation advance.
	if got := queryInt(t, db, "SELECT COUNT(*) FROM sessions WHERE ceremony_id IN (SELECT id FROM webauthn_ceremonies WHERE credential_id IN (SELECT id FROM webauthn_credentials WHERE account_id = '"+accountID+"'))"); got != 0 {
		t.Errorf("clone sweep left %d passkey-login session(s), want 0", got)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'auth.passkey_cloned'"); got < 1 {
		t.Error("a clone must emit auth.passkey_cloned")
	}
	// A subsequent login against the disabled credential stays refused.
	dev.SetCounter(9)
	if _, err := discoverableLogin(t, auth, ctx, dev); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("a disabled credential must stay refused, got %v", err)
	}
}

func TestWebAuthnSyncedNotFlaggedSQLite(t *testing.T) {
	runWebAuthnSyncedNotFlagged(t, seededDB(t, openSQLite))
}
func TestWebAuthnSyncedNotFlaggedPostgres(t *testing.T) {
	runWebAuthnSyncedNotFlagged(t, seededDB(t, openPostgres))
}

// runWebAuthnSyncedNotFlagged: a backup-eligible (synced) credential whose
// counter stays 0 across logins is NOT falsely flagged as cloned (B9 skip).
func runWebAuthnSyncedNotFlagged(t *testing.T, db *store.DB) {
	auth, _, token := bootstrapWebAuthnAdmin(t, db)
	ctx := t.Context()
	dev := webauthntest.New(waRPID, waOrigin)
	dev.SetBackupEligible(true)
	enrolPasskey(t, auth, ctx, token, waPassword, dev)

	// Both logins present counter 0 (a synced passkey keeps no counter).
	for i := 0; i < 2; i++ {
		if _, err := discoverableLogin(t, auth, ctx, dev); err != nil {
			t.Fatalf("synced-passkey login %d refused: %v", i, err)
		}
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM webauthn_credentials WHERE disabled_at IS NOT NULL"); got != 0 {
		t.Errorf("a synced passkey was falsely disabled (%d)", got)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'auth.passkey_cloned'"); got != 0 {
		t.Errorf("a synced passkey was falsely flagged cloned (%d events)", got)
	}
}

func TestWebAuthnPasskeyOnlySQLite(t *testing.T)   { runWebAuthnPasskeyOnly(t, openSQLite) }
func TestWebAuthnPasskeyOnlyPostgres(t *testing.T) { runWebAuthnPasskeyOnly(t, openPostgres) }

// runWebAuthnPasskeyOnly exercises the passkey-only post-state invariant (B4/B13)
// in both of its failing directions, through the removal structural pre-check
// (which refuses an impossible removal before any proof is required):
//
//   - the discoverable-count arm: a passwordless account with two discoverable
//     passkeys cannot lose the second-to-last one;
//   - the recovery-batch arm: a passwordless account with no current recovery
//     batch cannot drop below the floor even with enough authenticators.
//
// The "drop the password" direction shares the identical predicate, enforced in
// every credential-mutation tx; this vertical has no password-removal endpoint
// to exercise it (noted in the handoff).
func runWebAuthnPasskeyOnly(t *testing.T, open func(*testing.T) *store.DB) {
	// Direction 1 — count arm. Two discoverable passkeys + recovery, then drop
	// the password directly (no endpoint drops it): removing either passkey is
	// refused structurally.
	t.Run("second_to_last_discoverable_refused", func(t *testing.T) {
		db := seededDB(t, open)
		auth, accountID, token := bootstrapWebAuthnAdmin(t, db)
		ctx := t.Context()
		d1, d2 := webauthntest.New(waRPID, waOrigin), webauthntest.New(waRPID, waOrigin)
		token = enrolPasskey(t, auth, ctx, token, waPassword, d1)
		token = enrolPasskey(t, auth, ctx, token, waPassword, d2)
		_, reissue, err := auth.GenerateRecoveryCodes(ctx, token, waPassword)
		if err != nil {
			t.Fatalf("generate recovery codes: %v", err)
		}
		token = reissue.SessionToken
		// Reach the passwordless state the ADR describes; no network path drops a
		// password, so the fixture does it directly to test the invariant.
		execRaw(t, db, "DELETE FROM password_credentials WHERE account_id = '"+accountID+"'")
		targetID := queryString(t, db, "SELECT id FROM webauthn_credentials WHERE account_id = '"+accountID+"' ORDER BY created_at LIMIT 1")
		if _, err := auth.RemovePasskey(ctx, token, targetID, "", ""); !errors.Is(err, service.ErrPasskeyOnlyViolation) {
			t.Fatalf("removing the second-to-last discoverable passkey must be refused, got %v", err)
		}
	})

	// Direction 2 — recovery arm. Three discoverable passkeys but no current
	// recovery batch: removing one (leaving two) is still refused because the
	// passwordless account holds no recovery batch.
	t.Run("no_recovery_batch_refused", func(t *testing.T) {
		db := seededDB(t, open)
		auth, accountID, token := bootstrapWebAuthnAdmin(t, db)
		ctx := t.Context()
		for range 3 {
			token = enrolPasskey(t, auth, ctx, token, waPassword, webauthntest.New(waRPID, waOrigin))
		}
		execRaw(t, db, "DELETE FROM password_credentials WHERE account_id = '"+accountID+"'")
		// No recovery batch was ever generated.
		targetID := queryString(t, db, "SELECT id FROM webauthn_credentials WHERE account_id = '"+accountID+"' ORDER BY created_at LIMIT 1")
		if _, err := auth.RemovePasskey(ctx, token, targetID, "", ""); !errors.Is(err, service.ErrPasskeyOnlyViolation) {
			t.Fatalf("removing a passkey from a passwordless account with no recovery batch must be refused, got %v", err)
		}
	})
}

func TestWebAuthnEnrolProofSQLite(t *testing.T) { runWebAuthnEnrolProof(t, seededDB(t, openSQLite)) }
func TestWebAuthnEnrolProofPostgres(t *testing.T) {
	runWebAuthnEnrolProof(t, seededDB(t, openPostgres))
}

// runWebAuthnEnrolProof: a new passkey cannot authorize its own enrolment — the
// proof is the pre-existing credential (the password), verified before any
// ceremony. A wrong password is refused, and the removal that follows a
// successful enrol proves with the password, never the passkey.
func runWebAuthnEnrolProof(t *testing.T, db *store.DB) {
	auth, _, token := bootstrapWebAuthnAdmin(t, db)
	ctx := t.Context()

	// Enrolment demands the pre-existing password up front; a wrong one refuses
	// before any credential is created.
	if _, err := auth.EnrolPasskeyStart(ctx, token, "not the password", ""); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("enrol start with a wrong password must refuse, got %v", err)
	}

	// A correct proof enrols; the account still holds the password, so removing
	// the passkey later is proven by it (the passkey never proves its own removal).
	dev := webauthntest.New(waRPID, waOrigin)
	token = enrolPasskey(t, auth, ctx, token, waPassword, dev)
	credID := queryString(t, db, "SELECT id FROM webauthn_credentials LIMIT 1")
	if _, err := auth.RemovePasskey(ctx, token, credID, waPassword, ""); err != nil {
		t.Fatalf("removing a passkey with the password proof must succeed: %v", err)
	}
}

func TestWebAuthnStepUpReauthSQLite(t *testing.T) {
	runWebAuthnStepUpReauth(t, seededDB(t, openSQLite))
}
func TestWebAuthnStepUpReauthPostgres(t *testing.T) {
	runWebAuthnStepUpReauth(t, seededDB(t, openPostgres))
}

// runWebAuthnStepUpReauth: a passkey elevates a password session in place
// (step-up appends the webauthn class, rotating the token and preserving the
// original authentication), and a passkey reauth opens a window over an
// enumerated unit — single-decision at the default 0 effective window (B11).
func runWebAuthnStepUpReauth(t *testing.T, db *store.DB) {
	auth, accountID, token := bootstrapWebAuthnAdmin(t, db)
	ctx := t.Context()
	dev := webauthntest.New(waRPID, waOrigin)
	token = enrolPasskey(t, auth, ctx, token, waPassword, dev)

	// The reissued session is password-only; step it up with the passkey.
	sopts, err := auth.StepUpPasskeyStart(ctx, token)
	if err != nil {
		t.Fatalf("step-up start: %v", err)
	}
	sresp, err := dev.Assert(sopts)
	if err != nil {
		t.Fatalf("device assert (step-up): %v", err)
	}
	stepped, err := auth.StepUpPasskeyFinish(ctx, token, sresp)
	if err != nil {
		t.Fatalf("step-up finish: %v", err)
	}
	if !contains(stepped.Assurance.Factors, "password") || !contains(stepped.Assurance.Factors, "webauthn") {
		t.Errorf("stepped-up factors = %v, want password + webauthn", stepped.Assurance.Factors)
	}
	if stepped.SessionToken == "" || stepped.SessionToken == token {
		t.Error("step-up must rotate the session token")
	}
	token = stepped.SessionToken

	// Reauth over an enumerated unit opens a single-decision window (default
	// effective window is 0, so only WebAuthn can gate it).
	ropts, err := auth.ReauthPasskeyStart(ctx, token, "env_prod", []string{"key_b", "key_a"})
	if err != nil {
		t.Fatalf("reauth start: %v", err)
	}
	rresp, err := dev.Assert(ropts)
	if err != nil {
		t.Fatalf("device assert (reauth): %v", err)
	}
	reauth, err := auth.ReauthPasskeyFinish(ctx, token, rresp)
	if err != nil {
		t.Fatalf("reauth finish: %v", err)
	}
	if !reauth.SingleDecision {
		t.Error("a 0-window reauth must open a single-decision window")
	}
	if reauth.SessionToken == "" {
		t.Error("reauth must rotate and return the session token")
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM reauth_windows w JOIN sessions s ON s.id = w.session_id JOIN accounts a ON a.principal_id = s.principal_id WHERE a.id = '"+accountID+"' AND w.factor_class = 'webauthn' AND w.single_decision = 1 AND w.environment_id = 'env_prod'"); got != 1 {
		t.Errorf("webauthn single-decision reauth window count = %d, want 1", got)
	}
	// The window's ceremony carries the enumerated unit as canonical JSON (sorted
	// key ids), which #7's consumption at disclosure will read to match the unit
	// a reveal names. Pinning it here fixes the sort and the row linkage.
	binding := queryString(t, db, "SELECT c.operation_binding FROM webauthn_ceremonies c JOIN reauth_windows w ON w.ceremony_id = c.id WHERE w.environment_id = 'env_prod'")
	if binding != `{"environment_id":"env_prod","key_ids":["key_a","key_b"]}` {
		t.Errorf("reauth operation_binding = %q, want canonical sorted JSON", binding)
	}
}

func TestWebAuthnReauthBindingMismatchSQLite(t *testing.T) {
	runWebAuthnReauthBindingMismatch(t, seededDB(t, openSQLite))
}
func TestWebAuthnReauthBindingMismatchPostgres(t *testing.T) {
	runWebAuthnReauthBindingMismatch(t, seededDB(t, openPostgres))
}

// runWebAuthnReauthBindingMismatch is the reauth-binding regression (A3): a
// reauth ceremony whose operation_binding no longer names its own environment (a
// tampered or inconsistent row) is refused before any window opens — the finish
// revalidates that the enumerated unit binds the ceremony's environment,
// fail-closed, in the same validCeremony check the write tx re-runs against the
// reloaded row.
func runWebAuthnReauthBindingMismatch(t *testing.T, db *store.DB) {
	auth, _, token := bootstrapWebAuthnAdmin(t, db)
	ctx := t.Context()
	dev := webauthntest.New(waRPID, waOrigin)
	token = enrolPasskey(t, auth, ctx, token, waPassword, dev)

	ropts, err := auth.ReauthPasskeyStart(ctx, token, "env_prod", []string{"key_a"})
	if err != nil {
		t.Fatalf("reauth start: %v", err)
	}
	// Tamper the pending ceremony so its operation_binding names a DIFFERENT
	// environment than its environment_id column.
	execRaw(t, db, `UPDATE webauthn_ceremonies SET operation_binding = '{"environment_id":"env_other","key_ids":["key_a"]}' WHERE purpose = 'reauth' AND consumed_at IS NULL`)
	rresp, err := dev.Assert(ropts)
	if err != nil {
		t.Fatalf("device assert (reauth): %v", err)
	}
	if _, err := auth.ReauthPasskeyFinish(ctx, token, rresp); !errors.Is(err, service.ErrNoWebAuthnCeremony) {
		t.Fatalf("a reauth ceremony whose binding does not name its environment must refuse, got %v", err)
	}
	// No window was opened.
	if got := queryInt(t, db, "SELECT COUNT(*) FROM reauth_windows WHERE factor_class = 'webauthn'"); got != 0 {
		t.Errorf("a refused reauth must open no window, got %d", got)
	}
}

func TestWebAuthnDeleteAccountScopedSQLite(t *testing.T) {
	runWebAuthnDeleteAccountScoped(t, seededDB(t, openSQLite))
}
func TestWebAuthnDeleteAccountScopedPostgres(t *testing.T) {
	runWebAuthnDeleteAccountScoped(t, seededDB(t, openPostgres))
}

// runWebAuthnDeleteAccountScoped is the IDOR regression (B1): the credential
// DELETE carries an account_id predicate, so a delete naming a DIFFERENT owner
// matches zero rows and leaves the credential intact — even with the correct
// surrogate id — so an IDOR cannot appear even if a service-layer ownership
// check regresses. The true owner still deletes its own credential.
func runWebAuthnDeleteAccountScoped(t *testing.T, db *store.DB) {
	auth, accountID, token := bootstrapWebAuthnAdmin(t, db)
	ctx := t.Context()
	enrolPasskey(t, auth, ctx, token, waPassword, webauthntest.New(waRPID, waOrigin))
	credID := queryString(t, db, "SELECT id FROM webauthn_credentials WHERE account_id = '"+accountID+"' LIMIT 1")

	del := func(owner string) bool {
		t.Helper()
		var deleted bool
		if err := tx.Write(ctx, db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
			var e error
			deleted, e = az.DeleteWebAuthnCredential(ctx, credID, owner)
			return e
		}); err != nil {
			t.Fatalf("delete tx: %v", err)
		}
		return deleted
	}

	// A non-owning account id removes nothing and the row survives.
	if del("acc_not-the-owner") {
		t.Error("a cross-account DELETE reported a row removed")
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM webauthn_credentials WHERE id = '"+credID+"'"); got != 1 {
		t.Fatalf("the credential was deleted by a non-owning account id (count=%d)", got)
	}
	// The true owner deletes it.
	if !del(accountID) {
		t.Error("the owning account could not delete its own credential")
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM webauthn_credentials WHERE id = '"+credID+"'"); got != 0 {
		t.Errorf("the owner's DELETE left the row (count=%d)", got)
	}
}

func TestWebAuthnLoginNoAccountThrottleSQLite(t *testing.T) {
	runWebAuthnLoginNoAccountThrottle(t, seededDB(t, openSQLite))
}
func TestWebAuthnLoginNoAccountThrottlePostgres(t *testing.T) {
	runWebAuthnLoginNoAccountThrottle(t, seededDB(t, openPostgres))
}

// runWebAuthnLoginNoAccountThrottle is the login-DoS regression (A2): a bad
// discoverable-login assertion that RESOLVES a victim account (the assertion
// carries the victim's real credential id and user handle) but fails
// verification must NOT charge that account's per-account backoff — otherwise
// anyone who can present a victim's handle/credential id holds the victim in
// AccountDelay. The pre-auth login path is bounded by the per-IP + global
// admission budget only; per-account backoff lives on the authenticated paths.
// So after six bad assertions naming the victim, a genuine login still succeeds.
func runWebAuthnLoginNoAccountThrottle(t *testing.T, db *store.DB) {
	auth, _, token := bootstrapWebAuthnAdmin(t, db)
	ctx := t.Context()
	dev := webauthntest.New(waRPID, waOrigin)
	enrolPasskey(t, auth, ctx, token, waPassword, dev)

	// Six UV-not-set assertions: each resolves the victim account in the lookup
	// (real credential id + matching handle) but fails server-side UV.
	dev.SetUserVerified(false)
	for i := range 6 {
		if _, err := discoverableLogin(t, auth, ctx, dev); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Fatalf("bad assertion %d must refuse unauthenticated, got %v", i, err)
		}
	}
	// The victim is untouched: a genuine assertion still logs in (no per-account
	// backoff was charged by the unauthenticated login path).
	dev.SetUserVerified(true)
	if _, err := discoverableLogin(t, auth, ctx, dev); err != nil {
		t.Fatalf("bad login assertions naming a victim must not throttle the victim, got %v", err)
	}
}

func TestWebAuthnLoginHandleMismatchSQLite(t *testing.T) {
	runWebAuthnLoginHandleMismatch(t, seededDB(t, openSQLite))
}
func TestWebAuthnLoginHandleMismatchPostgres(t *testing.T) {
	runWebAuthnLoginHandleMismatch(t, seededDB(t, openPostgres))
}

// runWebAuthnLoginHandleMismatch: the lookup resolves the account from the
// assertion's credential id, and the assertion's user handle must match that
// credential's account handle. A handle that does not match the resolved
// credential's account is refused (the account is chosen by the credential,
// never by the client-supplied handle).
func runWebAuthnLoginHandleMismatch(t *testing.T, db *store.DB) {
	auth, accountID, token := bootstrapWebAuthnAdmin(t, db)
	ctx := t.Context()
	dev := webauthntest.New(waRPID, waOrigin)
	enrolPasskey(t, auth, ctx, token, waPassword, dev)

	// Clear the stored handle so the assertion's (unchanged) handle no longer
	// matches the credential's account handle; the login must refuse. NULL scans
	// to a nil handle in both dialects, so bytes.Equal(nil, presented) is false.
	execRaw(t, db, "UPDATE accounts SET webauthn_user_handle = NULL WHERE id = '"+accountID+"'")
	if _, err := discoverableLogin(t, auth, ctx, dev); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("a user handle not matching the resolved credential's account must refuse, got %v", err)
	}
}

func TestWebAuthnStepUpThrottleSQLite(t *testing.T) {
	runWebAuthnStepUpThrottle(t, seededDB(t, openSQLite))
}
func TestWebAuthnStepUpThrottlePostgres(t *testing.T) {
	runWebAuthnStepUpThrottle(t, seededDB(t, openPostgres))
}

// runWebAuthnStepUpThrottle proves step-up no longer bypasses admission (A2):
// the account is known up front, so a bad step-up assertion advances the
// per-account backoff and, once armed, the next step-up finish is refused before
// verification. Reauth shares the identical finishAssertionElevation gate.
func runWebAuthnStepUpThrottle(t *testing.T, db *store.DB) {
	auth, _, token := bootstrapWebAuthnAdmin(t, db)
	ctx := t.Context()
	dev := webauthntest.New(waRPID, waOrigin)
	token = enrolPasskey(t, auth, ctx, token, waPassword, dev)

	stepUp := func() error {
		opts, err := auth.StepUpPasskeyStart(ctx, token)
		if err != nil {
			return err
		}
		resp, err := dev.Assert(opts)
		if err != nil {
			t.Fatalf("device assert (step-up): %v", err)
		}
		_, err = auth.StepUpPasskeyFinish(ctx, token, resp)
		return err
	}

	dev.SetUserVerified(false)
	for i := range 6 {
		if err := stepUp(); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Fatalf("bad step-up %d must refuse unauthenticated, got %v", i, err)
		}
	}
	dev.SetUserVerified(true)
	if err := stepUp(); !errors.Is(err, admission.ErrOverloaded) {
		t.Fatalf("after repeated bad step-up assertions the finish must throttle, got %v", err)
	}
}

func TestWebAuthnCeremonyExpirySQLite(t *testing.T) {
	runWebAuthnCeremonyExpiry(t, seededDB(t, openSQLite))
}
func TestWebAuthnCeremonyExpiryPostgres(t *testing.T) {
	runWebAuthnCeremonyExpiry(t, seededDB(t, openPostgres))
}

// runWebAuthnCeremonyExpiry is the ceremony-lifetime regression (A3): a login
// ceremony aged past its lifetime is refused — the finish re-validates expiry
// against the current clock (both before verification and again inside the write
// tx), so a challenge accepted just before expiry cannot complete after it.
func runWebAuthnCeremonyExpiry(t *testing.T, db *store.DB) {
	auth, _, token := bootstrapWebAuthnAdmin(t, db)
	ctx := t.Context()
	// A controllable server clock, installed after bootstrap so the ceremony's
	// life is measured against it.
	clk := time.Now().UTC()
	auth.Now = func() time.Time { return clk }
	dev := webauthntest.New(waRPID, waOrigin)
	enrolPasskey(t, auth, ctx, token, waPassword, dev)

	opts, err := auth.PasskeyLoginStart(ctx)
	if err != nil {
		t.Fatalf("login start: %v", err)
	}
	assertion, err := dev.Assert(opts)
	if err != nil {
		t.Fatalf("device assert: %v", err)
	}
	// Age the clock past the ceremony lifetime, then finish.
	clk = clk.Add(service.WebAuthnCeremonyLifetime + time.Minute)
	if _, err := auth.PasskeyLoginFinish(ctx, assertion); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("a ceremony used after expiry must be refused, got %v", err)
	}
}

func TestRecoveryLastCodePasswordlessSQLite(t *testing.T) {
	runRecoveryLastCodePasswordless(t, seededDB(t, openSQLite))
}
func TestRecoveryLastCodePasswordlessPostgres(t *testing.T) {
	runRecoveryLastCodePasswordless(t, seededDB(t, openPostgres))
}

// runRecoveryLastCodePasswordless is the recovery-floor regression (A1):
// consuming the FINAL recovery code on a passwordless (passkey-only) account is
// refused fail-closed — it would strand the account with no password and no
// recovery batch. The refusal is non-destructive: the batch is not re-sealed, so
// the reserve code is not burned (its row_version is unchanged).
func runRecoveryLastCodePasswordless(t *testing.T, db *store.DB) {
	auth, accountID, token := bootstrapWebAuthnAdmin(t, db)
	ctx := t.Context()
	// A legitimate passkey-only account: two discoverable passkeys and a batch.
	token = enrolPasskey(t, auth, ctx, token, waPassword, webauthntest.New(waRPID, waOrigin))
	token = enrolPasskey(t, auth, ctx, token, waPassword, webauthntest.New(waRPID, waOrigin))
	codes, _, err := auth.GenerateRecoveryCodes(ctx, token, waPassword)
	if err != nil {
		t.Fatalf("generate recovery codes: %v", err)
	}

	// Consume every code but the last while the account still holds a password,
	// so those consumptions are unconstrained by the floor.
	for i := range len(codes) - 1 {
		if _, err := auth.ConsumeRecoveryCode(ctx, waAdmin, codes[i]); err != nil {
			t.Fatalf("consuming code %d: %v", i, err)
		}
	}
	// Become passwordless — no endpoint drops a password, so the fixture does it
	// directly to reach the passkey-only state.
	execRaw(t, db, "DELETE FROM password_credentials WHERE account_id = '"+accountID+"'")
	rvBefore := queryInt(t, db, "SELECT row_version FROM recovery_codes WHERE account_id = '"+accountID+"'")

	// The final code on a passwordless account is refused, fail-closed.
	if _, err := auth.ConsumeRecoveryCode(ctx, waAdmin, codes[len(codes)-1]); !errors.Is(err, service.ErrPasskeyOnlyViolation) {
		t.Fatalf("consuming the last recovery code on a passwordless account must be refused, got %v", err)
	}
	// Non-destructive: the batch was rolled back, not re-sealed — the code survives.
	if rvAfter := queryInt(t, db, "SELECT row_version FROM recovery_codes WHERE account_id = '"+accountID+"'"); rvAfter != rvBefore {
		t.Errorf("the refused consume mutated the batch (row_version %d -> %d): the reserve code was burned", rvBefore, rvAfter)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// runWebAuthnLifecycle drives passkey_added, passkey_cloned and passkey_removed
// once, so the audit_e2e emitter check finds each event reached a trail. It logs
// in fresh (the preceding lifecycles rotated the account's sessions) and
// configures the relying party if the shared service has none.
func runWebAuthnLifecycle(t *testing.T, auth *service.Auth, ctx context.Context, username, password string) {
	t.Helper()
	auth.ExternalOrigin = waOrigin
	if err := auth.ConfigureWebAuthnRP(); err != nil {
		t.Fatal(err)
	}
	login, err := auth.LocalLogin(ctx, username, password, service.ArtifactCLI)
	if err != nil {
		t.Fatalf("lifecycle login: %v", err)
	}
	token := login.SessionToken

	a := webauthntest.New(waRPID, waOrigin)
	b := webauthntest.New(waRPID, waOrigin)
	token = enrolPasskey(t, auth, ctx, token, password, a) // passkey_added
	_ = enrolPasskey(t, auth, ctx, token, password, b)     // passkey_added

	a.SetCounter(5)
	if _, err := discoverableLogin(t, auth, ctx, a); err != nil {
		t.Fatalf("lifecycle login: %v", err)
	}
	a.SetCounter(3)
	if _, err := discoverableLogin(t, auth, ctx, a); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("lifecycle clone must refuse, got %v", err) // passkey_cloned; kills sessions
	}
	// The clone advanced the generation, so re-login for a fresh session, then
	// remove the surviving passkey with the password proof.
	relog, err := auth.LocalLogin(ctx, username, password, service.ArtifactCLI)
	if err != nil {
		t.Fatalf("lifecycle re-login: %v", err)
	}
	keys, err := auth.ListPasskeys(ctx, relog.SessionToken)
	if err != nil {
		t.Fatalf("lifecycle list: %v", err)
	}
	var surviving string
	for _, k := range keys {
		if !k.Disabled {
			surviving = k.ID
			break
		}
	}
	if surviving == "" {
		t.Fatal("lifecycle: no surviving passkey to remove")
	}
	if _, err := auth.RemovePasskey(ctx, relog.SessionToken, surviving, password, ""); err != nil {
		t.Fatalf("lifecycle remove: %v", err) // passkey_removed
	}
}
