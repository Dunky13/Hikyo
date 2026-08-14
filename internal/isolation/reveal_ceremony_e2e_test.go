package isolation

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
	"github.com/Hikyo-Org/hikyo/internal/webauthntest"
	"github.com/pquerna/otp/totp"
)

// The reveal CEREMONY, end to end on both engines (#58, permission-model ADR
// § The reveal guard, mvp-boundary A5).
//
// #50 gave the value surface its capability half — `read ∧ reveal` and one
// audit event per disclosed key. These fixtures cover the half this ticket
// adds, and each exists because the ADR names it:
//
//   - a disclosure with no live window is refused, BEFORE any ciphertext is
//     opened and before any disclosure event is written;
//   - the window gates the PROMPT, never the check — a second disclosure
//     inside a live window needs no new ceremony;
//   - an effective window of 0, which every protected environment is capped
//     at, has no TOTP path: a passkey ceremony is the only way through, it
//     authorizes exactly ONE decision over exactly the enumerated keys, and it
//     is spent by that decision;
//   - one audit event per disclosed key, never a single "revealed N secrets";
//   - a machine identity never reauthenticates.
//
// They run against a REAL session rather than LocalPrincipal, because the
// whole mechanism hangs off the acting session's window rows: a fixture that
// authorized as a bare principal would exercise the local-authority exemption
// instead of the gate.

const (
	ceremonyPassword = "correct horse battery staple ceremony"
	ceremonyOrigin   = "https://hikyo.example"
	ceremonyRPID     = "hikyo.example"
	// Two secrets, because the enumerated unit is a SET and a one-element set
	// cannot tell a binding match from a binding mismatch.
	ceremonySecretA = "CEREMONY_SECRET_A"
	ceremonySecretB = "CEREMONY_SECRET_B"
)

// ceremonyFixture bootstraps an administrator with a passkey, seeds two
// `secret` keys with values in the dev environment, and returns the acting
// service, a live session token, the value surface bound to the SAME Auth, and
// the passkey device.
//
// The Values service takes this Auth deliberately: the window a ceremony opens
// and the window a disclosure consumes must come from one configuration, and a
// fixture that wired two would pass while the product could not.
func ceremonyFixture(t *testing.T, db *store.DB, username string) (
	*service.Auth, string, *service.Values, *webauthntest.Device,
) {
	t.Helper()
	ctx := t.Context()
	auth := authService(t, db)
	auth.ExternalOrigin = ceremonyOrigin
	if err := auth.ConfigureWebAuthnRP(); err != nil {
		t.Fatalf("configuring the webauthn relying party: %v", err)
	}
	boot, err := auth.BootstrapAdmin(ctx, username, "Ceremony Admin", "terminal")
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.EstablishCredential(ctx, boot.Authority, ceremonyPassword); err != nil {
		t.Fatal(err)
	}
	login, err := auth.LocalLogin(ctx, username, ceremonyPassword, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	dev := webauthntest.New(ceremonyRPID, ceremonyOrigin)
	token := enrolPasskey(t, auth, ctx, login.SessionToken, ceremonyPassword, dev)
	// `reveal` is MFA-mandatory, and that check sits at authorize() ahead of
	// the ceremony gate. A password-only session is refused there — correctly,
	// and for a different reason than the one these fixtures are about — so the
	// session is stepped up before any of them looks at a window.
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
	token = stepped.SessionToken

	// Bootstrap seeds `operator` at INSTANCE scope and deliberately no
	// disclosure (the ADR forbids the first administrator holding secret
	// access over every org that will ever exist). The value authority this
	// fixture is about therefore has to be granted explicitly, at org scope,
	// exactly as the first administrator would grant it to themselves.
	for _, cap := range []string{"read", "edit", "publish", "reveal", "project-settings"} {
		id := "g_cer_" + username + "_" + cap
		execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
			`VALUES ('`+id+`', '`+string(boot.PrincipalID)+`', '`+cap+`', 'org_a', NULL, NULL, `+ts+`)`)
		execRaw(t, db, `INSERT INTO grant_origins (id, grant_id, kind, subject, created_at) `+
			`VALUES ('gor_`+id+`', '`+id+`', 'manual', '`+string(boot.PrincipalID)+`', `+ts+`)`)
	}

	values := &service.Values{DB: db, Keyring: probeKeyring(t, db), Auth: auth}
	// The keys are seeded through raw SQL and the VALUES through the service,
	// for the same reason seedValues does: a value is a sealed envelope bound
	// to its own row, so only the service can produce one anything can open.
	// The writer is the custodian (LocalPrincipal), never the session under
	// test — seeding must not consume the window the assertions are about.
	for _, name := range []string{ceremonySecretA, ceremonySecretB} {
		execRaw(t, db, `INSERT INTO keys (id, org_id, project_id, name, folder_path, classification, `+
			`description, deprecated, deprecation_note, declaration, required_mode, forbidden_mode, `+
			`group_id, created_at) VALUES ('key_`+name+`', 'org_a', 'prj_a1', '`+name+`', '', 'secret', `+
			`'', FALSE, '', '{"rule":{"type":"string"}}', 'none', 'none', NULL, `+ts+`)`)
		publishValue(t, values, service.LocalPrincipal(custodian),
			scopeEnv(orgA, prjA1, envA1), name, "plaintext-"+name)
	}
	return auth, token, values, dev
}

// publishValue stages a value and then publishes it, which is what "seed a
// value that can be read" means since #51: `Set` only writes a pending change
// owned by its caller, and nothing delivers — nor reveals, copies or exports —
// until a publish materializes the environment's next revision.
//
// The Revisions service is built from the Values service's OWN datastore and
// keyring rather than from the package keyring cache, because a drill fixture
// mints its keyring under a root of its own and a second root is refused.
func publishValue(t *testing.T, values *service.Values, actor service.Actor,
	scope domain.Scope, keyName, value string) {
	t.Helper()
	ctx := t.Context()
	staged, err := values.Set(ctx, actor, scope, keyName, value)
	if err != nil {
		t.Fatalf("stage %s: %v", keyName, err)
	}
	revisions := &service.Revisions{DB: values.DB, Keyring: values.Keyring}
	if _, err := revisions.Publish(ctx, actor, scope, []string{staged.VersionID}); err != nil {
		t.Fatalf("publish %s: %v", keyName, err)
	}
}

// passkeyCeremony runs a full purpose-bound reauth over an enumerated unit and
// returns the rotated session token. This IS the ceremony modal's server half:
// start binds the challenge to (environment, sorted key ids), finish opens the
// window.
func passkeyCeremony(t *testing.T, auth *service.Auth, ctx context.Context, token string,
	purpose service.ReauthPurpose, envID string, keyIDs []string,
	dev *webauthntest.Device) service.ReauthResult {
	t.Helper()
	opts, err := auth.ReauthPasskeyStart(ctx, token, purpose, envID, keyIDs)
	if err != nil {
		t.Fatalf("reauth start: %v", err)
	}
	resp, err := dev.Assert(opts)
	if err != nil {
		t.Fatalf("device assert: %v", err)
	}
	res, err := auth.ReauthPasskeyFinish(ctx, token, resp)
	if err != nil {
		t.Fatalf("reauth finish: %v", err)
	}
	return res
}

func disclosureRows(t *testing.T, db *store.DB) int64 {
	t.Helper()
	return queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'disclosure.value_revealed'")
}

func TestTOTPOpensARevealWindowSQLite(t *testing.T) {
	runTOTPOpensARevealWindow(t, seededDB(t, openSQLite))
}
func TestTOTPOpensARevealWindowPostgres(t *testing.T) {
	runTOTPOpensARevealWindow(t, seededDB(t, openPostgres))
}

// runTOTPOpensARevealWindow is the possession-factor SUCCESS path.
//
// Every other fixture here drives the ceremony with a passkey, and every TOTP
// assertion in the suite is a REFUSAL — so a TOTP path that opened a window
// nothing could spend would ship green. This one presents a real code on a
// non-protected environment, then discloses through the window it opened, then
// discloses again without a second ceremony: the sliding half of the guard,
// end to end, on the factor the ceremony modal offers whenever the window is
// not capped at 0.
func runTOTPOpensARevealWindow(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, token, values, _ := ceremonyFixture(t, db, "ceremony-totp")
	auth.ReauthWindow = 5 * time.Minute
	auth.ReauthHardCap = time.Hour
	scope := scopeEnv(orgA, prjA1, envA1)

	// An injected clock, because every TOTP code is single-use per
	// (account, step): enrolment consumes one step and the reauth needs a
	// LATER one, which a real clock would make this fixture wait 30 seconds
	// for.
	base := time.Now().UTC()
	clk := base
	auth.Now = func() time.Time { return clk }

	uri, err := auth.EnrolTOTPStart(ctx, token, ceremonyPassword)
	if err != nil {
		t.Fatalf("totp enrol start: %v", err)
	}
	clk = base.Add(30 * time.Second)
	// Confirmation reissues the session carrying only the PASSWORD class, so
	// the acting token moves with it.
	confirmed, err := auth.EnrolTOTPConfirm(ctx, token, ceremonyCode(t, uri, clk))
	if err != nil {
		t.Fatalf("totp enrol confirm: %v", err)
	}
	token = confirmed.SessionToken

	// Enrolment is an account-security mutation: it advanced the generation,
	// deleted every session including the passkey-stepped-up one the fixture
	// established, and reissued this one carrying the password class alone.
	// `reveal` is MFA-mandatory at the chokepoint, so the factor just enrolled
	// has to be PRESENTED before any of this reaches the reveal guard.
	clk = base.Add(60 * time.Second)
	stepped, err := auth.StepUpTOTP(ctx, token, ceremonyCode(t, uri, clk))
	if err != nil {
		t.Fatalf("totp step-up: %v", err)
	}
	token = stepped.SessionToken

	// A code opens a SLIDING window — never a single decision, because TOTP
	// cannot bind a challenge to the enumerated unit.
	clk = base.Add(90 * time.Second)
	res, err := auth.ReauthTOTP(ctx, token, string(envA1), ceremonyCode(t, uri, clk))
	if err != nil {
		t.Fatalf("totp reauth: %v", err)
	}
	if res.SingleDecision {
		t.Error("a TOTP window is never single-decision")
	}
	token = res.SessionToken

	before := disclosureRows(t, db)
	if _, err := values.Get(ctx, service.Bearer(token), scope, ceremonySecretA, true); err != nil {
		t.Fatalf("reveal through a TOTP-opened window: %v", err)
	}
	// The window gates the PROMPT: the second disclosure needs no new code.
	if _, err := values.Get(ctx, service.Bearer(token), scope, ceremonySecretB, true); err != nil {
		t.Fatalf("second reveal inside the TOTP window: %v", err)
	}
	if got := disclosureRows(t, db) - before; got != 2 {
		t.Fatalf("two disclosures wrote %d rows, want one per key (2)", got)
	}
}

// ceremonyCode computes a code for the enrolment URI at an instant. The server
// consumes each step once, so callers pass DISTINCT instants a step apart.
func ceremonyCode(t *testing.T, otpauthURI string, at time.Time) string {
	t.Helper()
	u, err := url.Parse(otpauthURI)
	if err != nil {
		t.Fatalf("otpauth uri %q: %v", otpauthURI, err)
	}
	code, err := totp.GenerateCode(u.Query().Get("secret"), at)
	if err != nil {
		t.Fatalf("computing a TOTP code: %v", err)
	}
	return code
}

func TestRevealNeedsACeremonySQLite(t *testing.T) {
	runRevealNeedsACeremony(t, seededDB(t, openSQLite))
}
func TestRevealNeedsACeremonyPostgres(t *testing.T) {
	runRevealNeedsACeremony(t, seededDB(t, openPostgres))
}

// runRevealNeedsACeremony: the sliding half. A disclosure with no window is
// refused and writes nothing; a passkey ceremony opens one; inside it a second
// disclosure proceeds with no further prompt — the window gating the prompt,
// not the check.
func runRevealNeedsACeremony(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, token, values, dev := ceremonyFixture(t, db, "ceremony-sliding")
	auth.ReauthWindow = 5 * time.Minute
	auth.ReauthHardCap = time.Hour
	scope := scopeEnv(orgA, prjA1, envA1)

	before := disclosureRows(t, db)
	if _, err := values.List(ctx, service.Bearer(token), scope, true); !errors.Is(err, service.ErrNoReauthWindow) {
		t.Fatalf("reveal with no window = %v, want ErrNoReauthWindow", err)
	}
	// The refusal lands before the first ciphertext is opened, so the trail
	// records nothing. A gate that refused AFTER opening would leave a
	// disclosure event for material that never reached anyone.
	if got := disclosureRows(t, db); got != before {
		t.Fatalf("a refused disclosure wrote %d audit rows, want 0", got-before)
	}

	// A non-revealing read is NOT gated: write-presence and `config` ride
	// `read`, and prompting for them would train people to click through the
	// ceremony that matters.
	if _, err := values.List(ctx, service.Bearer(token), scope, false); err != nil {
		t.Fatalf("a masked read must not need a ceremony: %v", err)
	}

	res := passkeyCeremony(t, auth, ctx, token, service.PurposeReveal, string(envA1), nil, dev)
	if res.SingleDecision {
		t.Error("a non-zero effective window must open a SLIDING window, not a single decision")
	}
	token = res.SessionToken

	cells, err := values.List(ctx, service.Bearer(token), scope, true)
	if err != nil {
		t.Fatalf("reveal inside a live window: %v", err)
	}
	var revealed int
	for _, c := range cells {
		if c.Classification == "secret" && c.Revealed {
			revealed++
		}
	}
	if revealed != 2 {
		t.Fatalf("revealed %d secrets, want 2", revealed)
	}
	// One event PER KEY. "revealed 2 secrets" as a single row is exactly what
	// the audit ADR forbids, and the count is what makes that checkable.
	if got := disclosureRows(t, db) - before; got != 2 {
		t.Fatalf("bulk reveal wrote %d disclosure rows, want one per key (2)", got)
	}

	// THE WINDOW ACTUALLY SLIDES, and the proof has to outlive the ORIGINAL
	// expiry or a fixed window passes it.
	//
	// The ceremony opened a five-minute window at T0, so it originally lapsed
	// at T0+5m. A disclosure at T0+4m is inside that window and pushes the
	// expiry to T0+9m. A third disclosure at T0+7m is therefore PAST what the
	// ceremony alone bought and succeeds only because the second one slid it —
	// which is what sliding means, and what a fixed window would fail.
	opened := time.Now().UTC()
	at := func(d time.Duration) func() time.Time {
		return func() time.Time { return opened.Add(d) }
	}
	auth.Now = at(4 * time.Minute)
	if _, err := values.Get(ctx, service.Bearer(token), scope, ceremonySecretA, true); err != nil {
		t.Fatalf("disclosure inside the original window: %v", err)
	}
	auth.Now = at(7 * time.Minute)
	if _, err := values.Get(ctx, service.Bearer(token), scope, ceremonySecretB, true); err != nil {
		t.Fatalf("disclosure past the ORIGINAL expiry, inside the slid window: %v", err)
	}
	if got := disclosureRows(t, db) - before; got != 4 {
		t.Fatalf("after four disclosures the trail holds %d rows, want 4", got)
	}

	// And the hard cap still bites: slide or no slide, a window cannot outlive
	// it, so a disclosure beyond it is refused.
	auth.Now = at(2 * time.Hour)
	if _, err := values.Get(ctx, service.Bearer(token), scope, ceremonySecretA, true); !errors.Is(err, service.ErrReauthWindowExpired) {
		t.Fatalf("disclosure past the hard cap = %v, want ErrReauthWindowExpired", err)
	}
}

func TestZeroWindowForcesAPasskeyPerDisclosureSQLite(t *testing.T) {
	runZeroWindowForcesAPasskeyPerDisclosure(t, seededDB(t, openSQLite))
}
func TestZeroWindowForcesAPasskeyPerDisclosurePostgres(t *testing.T) {
	runZeroWindowForcesAPasskeyPerDisclosure(t, seededDB(t, openPostgres))
}

// runZeroWindowForcesAPasskeyPerDisclosure is mvp-boundary A5's [E2E] line:
// at an effective window of 0 a passkey ceremony authorizes exactly one
// decision over exactly the enumerated keys, is spent by it, and TOTP has no
// path at all.
func runZeroWindowForcesAPasskeyPerDisclosure(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, token, values, dev := ceremonyFixture(t, db, "ceremony-zero")
	auth.ReauthWindow = 0
	auth.ReauthHardCap = time.Hour
	scope := scopeEnv(orgA, prjA1, envA1)
	keyA, keyB := "key_"+ceremonySecretA, "key_"+ceremonySecretB

	// TOTP is refused BEFORE any code is presented, by the environment's state
	// rather than by the caller's: at a 0 window there is no TOTP path, which
	// is why the ceremony modal must not offer the option. The sentinel is
	// asserted EXACTLY — "not unauthenticated" would also pass on success,
	// which is the one outcome this must never see.
	if _, err := auth.ReauthTOTP(ctx, token, string(envA1), "000000"); !errors.Is(err, service.ErrReauthWindowClosed) {
		t.Fatalf("a 0-window TOTP reauth = %v, want ErrReauthWindowClosed", err)
	}

	// A ceremony bound to key A alone authorizes key A alone.
	res := passkeyCeremony(t, auth, ctx, token, service.PurposeReveal, string(envA1), []string{keyA}, dev)
	if !res.SingleDecision {
		t.Fatal("a 0-window ceremony must open a SINGLE-DECISION window")
	}
	token = res.SessionToken

	// The whole-environment reveal enumerates {A, B}, which is not the unit the
	// assertion signed. Refused by the binding, not by the capability.
	if _, err := values.List(ctx, service.Bearer(token), scope, true); !errors.Is(err, service.ErrReauthUnitMismatch) {
		t.Fatalf("reveal of a wider unit = %v, want ErrReauthUnitMismatch", err)
	}

	before := disclosureRows(t, db)
	if _, err := values.Get(ctx, service.Bearer(token), scope, ceremonySecretA, true); err != nil {
		t.Fatalf("reveal of the enumerated key: %v", err)
	}
	if got := disclosureRows(t, db) - before; got != 1 {
		t.Fatalf("one disclosure wrote %d rows, want 1", got)
	}

	// Spent. "Per disclosure" is only true if the second one refuses.
	if _, err := values.Get(ctx, service.Bearer(token), scope, ceremonySecretA, true); !errors.Is(err, service.ErrReauthWindowSpent) {
		t.Fatalf("second disclosure on a spent single-decision window = %v, want ErrReauthWindowSpent", err)
	}

	// A fresh ceremony over key B authorizes key B, and only it.
	res = passkeyCeremony(t, auth, ctx, token, service.PurposeReveal, string(envA1), []string{keyB}, dev)
	token = res.SessionToken
	if _, err := values.Get(ctx, service.Bearer(token), scope, ceremonySecretA, true); !errors.Is(err, service.ErrReauthUnitMismatch) {
		t.Fatalf("key A under key B's ceremony = %v, want ErrReauthUnitMismatch", err)
	}
	if _, err := values.Get(ctx, service.Bearer(token), scope, ceremonySecretB, true); err != nil {
		t.Fatalf("reveal of key B under key B's ceremony: %v", err)
	}
}

func TestProtectedEnvironmentCapsTheWindowAtZeroSQLite(t *testing.T) {
	runProtectedEnvironmentCapsTheWindow(t, seededDB(t, openSQLite))
}
func TestProtectedEnvironmentCapsTheWindowAtZeroPostgres(t *testing.T) {
	runProtectedEnvironmentCapsTheWindow(t, seededDB(t, openPostgres))
}

// runProtectedEnvironmentCapsTheWindow: the protected flag is not a second
// mechanism, it is the same knob capped at 0. With a generous instance default
// in force, a protected environment still refuses TOTP and still takes a
// single-decision ceremony — and the guard's own read surface says so, which is
// what lets the browser decide whether to offer the option.
func runProtectedEnvironmentCapsTheWindow(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, token, values, dev := ceremonyFixture(t, db, "ceremony-protected")
	auth.ReauthWindow = 5 * time.Minute
	auth.ReauthHardCap = time.Hour
	scope := scopeEnv(orgA, prjA1, envA1)
	reveal := &service.Reveal{DB: db, Auth: auth}

	// Unprotected: the instance default applies and TOTP is on the table.
	state, err := reveal.Window(ctx, service.Bearer(token), scope)
	if err != nil {
		t.Fatalf("reveal window: %v", err)
	}
	if state.EffectiveWindowSeconds != 300 || !state.TOTPOffered || state.Live || state.Protected {
		t.Fatalf("unprotected window state = %+v, want 300s, totp offered, nothing live", state)
	}

	settings := &service.ProjectSettings{DB: db, Auth: auth}
	if _, err := settings.SetEnvironment(ctx, service.Bearer(token), scope,
		service.EnvironmentSettings{Protected: true}); err != nil {
		t.Fatalf("marking the environment protected: %v", err)
	}

	state, err = reveal.Window(ctx, service.Bearer(token), scope)
	if err != nil {
		t.Fatalf("reveal window (protected): %v", err)
	}
	if !state.Protected || state.EffectiveWindowSeconds != 0 || state.TOTPOffered {
		t.Fatalf("protected window state = %+v, want capped at 0 with no TOTP option", state)
	}

	// And the cap binds the disclosure path, not merely the report: a passkey
	// ceremony here opens a single-decision window even though the instance
	// default is five minutes.
	res := passkeyCeremony(t, auth, ctx, token, service.PurposeReveal, string(envA1),
		[]string{"key_" + ceremonySecretA}, dev)
	if !res.SingleDecision {
		t.Fatal("a protected environment must open a single-decision window whatever the instance default")
	}
	token = res.SessionToken

	state, err = reveal.Window(ctx, service.Bearer(token), scope)
	if err != nil {
		t.Fatalf("reveal window (after ceremony): %v", err)
	}
	if !state.Live || !state.SingleDecision {
		t.Fatalf("window state after a protected ceremony = %+v, want live and single-decision", state)
	}
	if _, err := values.Get(ctx, service.Bearer(token), scope, ceremonySecretA, true); err != nil {
		t.Fatalf("reveal under a protected ceremony: %v", err)
	}
}

func TestCopySourceTakesTheCeremonySQLite(t *testing.T) {
	runCopySourceTakesTheCeremony(t, seededDB(t, openSQLite))
}
func TestCopySourceTakesTheCeremonyPostgres(t *testing.T) {
	runCopySourceTakesTheCeremony(t, seededDB(t, openPostgres))
}

// runCopySourceTakesTheCeremony: copy is a disclosure by proxy — the material
// leaves toward a destination the actor chose, whether or not their eyes saw
// it — so the copy formula's `reveal(source)` conjunct carries the same
// enumerated-key ceremony a cell reveal does. This is the server half of the
// prototype's copy-without-display.
func runCopySourceTakesTheCeremony(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, token, values, dev := ceremonyFixture(t, db, "ceremony-copy")
	auth.ReauthWindow = 5 * time.Minute
	auth.ReauthHardCap = time.Hour
	req := service.CopyRequest{
		SourceEnvironmentID:       string(envA1),
		KeyNames:                  []string{ceremonySecretA},
		DestinationEnvironmentIDs: []string{string(envProd)},
	}
	project := scopeProject(orgA, prjA1)

	before := disclosureRows(t, db)
	if _, err := values.Copy(ctx, service.Bearer(token), project, req); !errors.Is(err, service.ErrNoReauthWindow) {
		t.Fatalf("copy with no source window = %v, want ErrNoReauthWindow", err)
	}
	if got := disclosureRows(t, db); got != before {
		t.Fatalf("a refused copy wrote %d disclosure rows, want 0", got-before)
	}

	token = passkeyCeremony(t, auth, ctx, token, service.PurposeCopy, string(envA1), nil, dev).SessionToken
	if _, err := values.Copy(ctx, service.Bearer(token), project, req); err != nil {
		t.Fatalf("copy inside a live source window: %v", err)
	}

	// A PROTECTED DESTINATION takes its own ceremony, and a live SOURCE window
	// does not stand in for it. This is the hole the surface would otherwise
	// have: reveal something in dev, then publish into production, and the
	// protected environment's "a passkey per decision" would never be asked
	// for — a source window is not authority over a destination.
	settings := &service.ProjectSettings{DB: db, Auth: auth}
	prodScope := scopeEnv(orgA, prjA1, envProd)
	if _, err := settings.SetEnvironment(ctx, service.Bearer(token), prodScope,
		service.EnvironmentSettings{Protected: true}); err != nil {
		t.Fatalf("marking the destination protected: %v", err)
	}
	req.KeyNames = []string{ceremonySecretB}
	req.ConfirmProtected = true
	// The source window is still live here — that is the whole point.
	if _, err := values.Copy(ctx, service.Bearer(token), project, req); !errors.Is(err, service.ErrNoReauthWindow) {
		t.Fatalf("copy into a protected destination under a source-only window = %v, want ErrNoReauthWindow", err)
	}

	// With the destination's own single-decision ceremony, it goes through —
	// bound to exactly the keys the decision named.
	token = passkeyCeremony(t, auth, ctx, token, service.PurposePublish, string(envProd),
		[]string{"key_" + ceremonySecretB}, dev).SessionToken
	if _, err := values.Copy(ctx, service.Bearer(token), project, req); err != nil {
		t.Fatalf("copy into a protected destination after its ceremony: %v", err)
	}
}

func TestAMachineNeverReauthenticatesSQLite(t *testing.T) {
	runAMachineNeverReauthenticates(t, seededDB(t, openSQLite))
}
func TestAMachineNeverReauthenticatesPostgres(t *testing.T) {
	runAMachineNeverReauthenticates(t, seededDB(t, openPostgres))
}

// runAMachineNeverReauthenticates: "the token IS the credential and there is
// no second factor to re-present". A machine identity holding `read ∧ reveal`
// discloses with no window at all — and still writes one event per key, which
// is the property the exemption must not cost.
//
// It presents a REAL minted credential as a bearer artifact, not a
// LocalPrincipal. That distinction is the whole test: LocalPrincipal is the
// local-host-authority path, which is exempt for a different reason (it has no
// session because it is not on the network at all), so a fixture using it
// would prove the exemption for a caller class this assertion is not about.
func runAMachineNeverReauthenticates(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, _, values, _ := ceremonyFixture(t, db, "ceremony-machine")
	auth.ReauthWindow = 0
	scope := scopeEnv(orgA, prjA1, envA1)

	// A service account, and a credential that actually authenticates.
	identityFixtures(t, db)
	identities := &service.Identities{DB: db, Auth: auth}
	// usr_idrev, not usr_ident: minting a credential whose post-state reaches
	// plaintext carries `reveal` for every environment it reaches, and only
	// this fixture principal holds it.
	admin := service.LocalPrincipal("usr_idrev")
	sa, err := identities.CreateServiceAccount(ctx, admin,
		scopeProject(orgA, prjA1), "ceremony-reader", domain.ClassWorkload)
	if err != nil {
		t.Fatalf("create service account: %v", err)
	}

	// MINT FIRST, GRANT SECOND. Minting a credential whose post-state reaches
	// plaintext carries `reveal` for every environment it reaches plus a
	// reauthentication — a gate this fixture is not about. An account with no
	// grants reaches nothing, so the conjunct is vacuous; the capabilities it
	// then receives are an ordinary audited grant, and the credential minted
	// before them authenticates exactly the same.
	minted, err := identities.MintCredential(ctx, admin, scopeProject(orgA, prjA1), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatalf("mint credential: %v", err)
	}

	// The disclosure capability the ADR's explicit per-project operator opt-in
	// supplies, plus the `read` every delivery needs.
	for _, cap := range []string{"read", "reveal"} {
		id := "g_sa_" + cap
		execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
			`VALUES ('`+id+`', '`+string(sa.Principal)+`', '`+cap+`', 'org_a', 'prj_a1', 'env_a1', `+ts+`)`)
		execRaw(t, db, `INSERT INTO grant_origins (id, grant_id, kind, subject, created_at) `+
			`VALUES ('gor_`+id+`', '`+id+`', 'manual', '`+string(sa.Principal)+`', `+ts+`)`)
	}
	before := disclosureRows(t, db)
	cells, err := values.List(ctx, service.Bearer(minted.Value), scope, true)
	if err != nil {
		t.Fatalf("machine reveal on a presented credential: %v", err)
	}
	var revealed int
	for _, c := range cells {
		if c.Classification == "secret" && c.Revealed {
			revealed++
		}
	}
	if revealed != 2 {
		t.Fatalf("machine revealed %d secrets, want 2", revealed)
	}
	if got := disclosureRows(t, db) - before; got != 2 {
		t.Fatalf("machine reveal wrote %d disclosure rows, want one per key (2)", got)
	}
	// And no window was minted for it: a machine has no session to hang one on.
	if got := queryInt(t, db, "SELECT COUNT(*) FROM reauth_windows"); got != 0 {
		t.Fatalf("a machine disclosure opened %d reauthentication windows, want 0", got)
	}
}

func TestProtectedDestinationRefusesAConfirmationFlagSQLite(t *testing.T) {
	runProtectedDestinationRefusesAConfirmationFlag(t, seededDB(t, openSQLite))
}
func TestProtectedDestinationRefusesAConfirmationFlagPostgres(t *testing.T) {
	runProtectedDestinationRefusesAConfirmationFlag(t, seededDB(t, openPostgres))
}

// runProtectedDestinationRefusesAConfirmationFlag (review R1 finding 1): a
// HUMAN cannot satisfy a protected destination with a caller-supplied boolean,
// whatever the copy carries.
//
// The hole was that the ceremony hung on the SECRET leg, so a config-only copy
// into a protected environment went through on `confirm_protected: true` alone
// — a value the UI supplies, which means the UI could delete the guard by
// sending a constant. The decision is now one per destination, over every key
// the copy names, and the flag is the machine plan field it always was.
func runProtectedDestinationRefusesAConfirmationFlag(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, token, values, dev := ceremonyFixture(t, db, "ceremony-configonly")
	auth.ReauthWindow = 5 * time.Minute
	auth.ReauthHardCap = time.Hour
	project := scopeProject(orgA, prjA1)
	prodScope := scopeEnv(orgA, prjA1, envProd)

	// A `config` key with a value in the source, and a protected destination.
	execRaw(t, db, `INSERT INTO keys (id, org_id, project_id, name, folder_path, classification, `+
		`description, deprecated, deprecation_note, declaration, required_mode, forbidden_mode, `+
		`group_id, created_at) VALUES ('key_CEREMONY_CONFIG', 'org_a', 'prj_a1', 'CEREMONY_CONFIG', '', `+
		`'config', '', FALSE, '', '{"rule":{"type":"string"}}', 'none', 'none', NULL, `+ts+`)`)
	publishValue(t, values, service.LocalPrincipal(custodian),
		scopeEnv(orgA, prjA1, envA1), "CEREMONY_CONFIG", "debug")
	settings := &service.ProjectSettings{DB: db, Auth: auth}
	if _, err := settings.SetEnvironment(ctx, service.Bearer(token), prodScope,
		service.EnvironmentSettings{Protected: true}); err != nil {
		t.Fatalf("marking the destination protected: %v", err)
	}

	req := service.CopyRequest{
		SourceEnvironmentID:       string(envA1),
		KeyNames:                  []string{"CEREMONY_CONFIG"},
		DestinationEnvironmentIDs: []string{string(envProd)},
		// The flag a human's client controls. It must not be enough.
		ConfirmProtected: true,
	}
	if _, err := values.Copy(ctx, service.Bearer(token), project, req); !errors.Is(err, service.ErrNoReauthWindow) {
		t.Fatalf("config-only copy into a protected destination on the flag alone = %v, want ErrNoReauthWindow", err)
	}

	// With the destination's own ceremony — enumerated over the CONFIG key,
	// because that is what the decision carries — it goes through.
	token = passkeyCeremony(t, auth, ctx, token, service.PurposePublish, string(envProd),
		[]string{"key_CEREMONY_CONFIG"}, dev).SessionToken
	if _, err := values.Copy(ctx, service.Bearer(token), project, req); err != nil {
		t.Fatalf("config-only copy after the destination ceremony: %v", err)
	}
}

func TestACeremonyIsBoundToItsPurposeSQLite(t *testing.T) {
	runACeremonyIsBoundToItsPurpose(t, seededDB(t, openSQLite))
}
func TestACeremonyIsBoundToItsPurposePostgres(t *testing.T) {
	runACeremonyIsBoundToItsPurpose(t, seededDB(t, openPostgres))
}

// runACeremonyIsBoundToItsPurpose (review R1 finding 3): "purpose-bound" has to
// mean the SIGNATURE covers the purpose, not that a modal displayed one.
//
// An assertion the human gave to "reveal · production" must not be spendable on
// taking that same key out of production, which is a different decision over
// the same unit and one they were never shown.
func runACeremonyIsBoundToItsPurpose(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, token, values, dev := ceremonyFixture(t, db, "ceremony-purpose")
	auth.ReauthWindow = 0
	auth.ReauthHardCap = time.Hour
	scope := scopeEnv(orgA, prjA1, envA1)
	keyA := "key_" + ceremonySecretA

	// A REVEAL ceremony over exactly this key.
	token = passkeyCeremony(t, auth, ctx, token, service.PurposeReveal, string(envA1),
		[]string{keyA}, dev).SessionToken

	// Spending it on a COPY of the same key out of the same environment is
	// refused by the binding, not by the capability.
	copyReq := service.CopyRequest{
		SourceEnvironmentID:       string(envA1),
		KeyNames:                  []string{ceremonySecretA},
		DestinationEnvironmentIDs: []string{string(envProd)},
	}
	before := disclosureRows(t, db)
	if _, err := values.Copy(ctx, service.Bearer(token), scopeProject(orgA, prjA1), copyReq); !errors.Is(err, service.ErrReauthUnitMismatch) {
		t.Fatalf("a reveal ceremony spent on a copy = %v, want ErrReauthUnitMismatch", err)
	}
	if got := disclosureRows(t, db); got != before {
		t.Fatalf("a purpose-mismatched copy wrote %d disclosure rows, want 0", got-before)
	}

	// The same window still authorizes what it was given for.
	if _, err := values.Get(ctx, service.Bearer(token), scope, ceremonySecretA, true); err != nil {
		t.Fatalf("reveal under its own ceremony: %v", err)
	}
}

func TestTheTOTPRouteIsNotAnEnvironmentOracleSQLite(t *testing.T) {
	runTheTOTPRouteIsNotAnEnvironmentOracle(t, seededDB(t, openSQLite))
}
func TestTheTOTPRouteIsNotAnEnvironmentOraclePostgres(t *testing.T) {
	runTheTOTPRouteIsNotAnEnvironmentOracle(t, seededDB(t, openPostgres))
}

// runTheTOTPRouteIsNotAnEnvironmentOracle (review R1 finding 4): the route
// resolves and authorizes the environment before it will discuss that
// environment's reauthentication policy at all.
//
// Otherwise it is an oracle: the window check runs before any code is
// verified, so a signed-in principal could tell a protected environment from a
// nonexistent one by presenting nonsense and reading the refusal.
func runTheTOTPRouteIsNotAnEnvironmentOracle(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, token, _, _ := ceremonyFixture(t, db, "ceremony-oracle")
	auth.ReauthWindow = 5 * time.Minute

	// env_b1 belongs to org B: a real environment this principal cannot reach.
	// A nonexistent id is the control, and the two must be indistinguishable.
	_, unreachable := auth.ReauthTOTP(ctx, token, "env_b1", "000000")
	if unreachable == nil {
		t.Fatal("a TOTP reauth against another org's environment must be refused")
	}
	_, missing := auth.ReauthTOTP(ctx, token, "env_does_not_exist", "000000")
	if missing == nil {
		t.Fatal("a TOTP reauth against a nonexistent environment must be refused")
	}
	assertUniformNotFound(t, unreachable, missing)

	// And neither leaks the policy the caller cannot see: an environment they
	// CAN reach is the only one that ever answers with the window's state.
	if _, err := auth.ReauthTOTP(ctx, token, string(envA1), "000000"); errors.Is(err, domain.ErrNotFound) {
		t.Fatal("a reachable environment must not answer the nonexistent shape")
	}
}

func TestConcurrentCeremoniesSupersedeSQLite(t *testing.T) {
	runConcurrentCeremoniesSupersede(t, seededDB(t, openSQLite))
}
func TestConcurrentCeremoniesSupersedePostgres(t *testing.T) {
	runConcurrentCeremoniesSupersede(t, seededDB(t, openPostgres))
}

// runConcurrentCeremoniesSupersede (review R1 finding 6): two tabs finishing a
// ceremony at the same moment must both SUPERSEDE, never collide.
//
// A delete-then-insert cannot promise that on postgres: both deletes can miss
// the other transaction's not-yet-visible row, and the loser's insert then hits
// the unique constraint — turning a legitimate passkey-per-disclosure ceremony
// into an intermittent failure. The upsert makes the loser update.
func runConcurrentCeremoniesSupersede(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, token, _, dev := ceremonyFixture(t, db, "ceremony-concurrent")
	auth.ReauthWindow = 0
	auth.ReauthHardCap = time.Hour
	keyA := "key_" + ceremonySecretA

	res := passkeyCeremony(t, auth, ctx, token, service.PurposeReveal, string(envA1),
		[]string{keyA}, dev)
	session := res.SessionID

	// TWO WINDOW OPENS AT ONCE, on the same (session, environment) pair, in
	// separate transactions released together by a barrier. This is two tabs
	// finishing a ceremony at the same moment — the shape a protected
	// environment produces by design, because every disclosure there needs its
	// own ceremony.
	//
	// A delete-then-insert cannot promise it: on postgres both deletes can miss
	// the other transaction's not-yet-visible row and the loser's insert then
	// hits the unique constraint, so a legitimate supersede fails
	// intermittently. The upsert makes the loser update. (On sqlite the store
	// serialises writers, so this leg proves the statement is correct rather
	// than that it arbitrates; postgres is where the arbitration happens.)
	now := time.Now().UTC()
	open := func(id string) error {
		return tx.Write(ctx, db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
			epoch, err := az.CredentialEpoch(ctx)
			if err != nil {
				return err
			}
			return az.OpenReauthWindow(ctx, authz.NewReauthWindow{
				ID: id, SessionID: session, EnvironmentID: string(envA1),
				CeremonyID: id, FactorClass: "webauthn", SingleDecision: true,
				AuthenticatedAt: now, WindowExpiresAt: now.Add(time.Minute),
				HardExpiresAt: now.Add(time.Hour), CredentialEpoch: epoch, CreatedAt: now,
			})
		})
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, id := range []string{"raw_concurrent_a", "raw_concurrent_b"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			errs <- open(id)
		}(id)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a concurrent ceremony failed to supersede: %v", err)
		}
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM reauth_windows WHERE environment_id = 'env_a1'"); got != 1 {
		t.Fatalf("after two concurrent ceremonies the pair holds %d windows, want exactly 1", got)
	}
	// And the survivor is one of them, unspent: the loser UPDATED the row
	// rather than leaving a spent one behind.
	if got := queryInt(t, db, "SELECT COUNT(*) FROM reauth_windows WHERE environment_id = 'env_a1' AND consumed_at IS NULL"); got != 1 {
		t.Fatalf("the surviving window is not fresh: %d unspent rows, want 1", got)
	}
}

func TestAWindowExpiringDuringACopyIsNotSpentSQLite(t *testing.T) {
	runAWindowExpiringDuringACopyIsNotSpent(t, seededDB(t, openSQLite))
}
func TestAWindowExpiringDuringACopyIsNotSpentPostgres(t *testing.T) {
	runAWindowExpiringDuringACopyIsNotSpent(t, seededDB(t, openPostgres))
}

// runAWindowExpiringDuringACopyIsNotSpent (review R1 finding 2): consumption
// reads the clock AT consumption, never an instant the caller captured earlier.
//
// A copy resolves its keys, takes the destination project lock and runs a
// preflight before anything is opened. An instant captured before that lock can
// be arbitrarily old by the time it is used — so a window that lapsed while the
// transaction waited would still be spent against it. Driving the whole copy
// through an injected clock that has already passed the hard cap is the cheapest
// way to prove the gate consults it: a gate holding a captured wall-clock
// instant would not notice at all.
func runAWindowExpiringDuringACopyIsNotSpent(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, token, values, dev := ceremonyFixture(t, db, "ceremony-expiry")
	auth.ReauthWindow = 5 * time.Minute
	auth.ReauthHardCap = time.Hour
	project := scopeProject(orgA, prjA1)
	prodScope := scopeEnv(orgA, prjA1, envProd)

	// A protected destination, so the copy consumes TWO windows: the
	// destination's in the preflight and the source's when material is opened.
	// Two consumptions are what make "when is the clock read" observable.
	settings := &service.ProjectSettings{DB: db, Auth: auth}
	if _, err := settings.SetEnvironment(ctx, service.Bearer(token), prodScope,
		service.EnvironmentSettings{Protected: true}); err != nil {
		t.Fatalf("marking the destination protected: %v", err)
	}
	token = passkeyCeremony(t, auth, ctx, token, service.PurposeCopy, string(envA1), nil, dev).SessionToken
	token = passkeyCeremony(t, auth, ctx, token, service.PurposePublish, string(envProd),
		[]string{"key_" + ceremonySecretA}, dev).SessionToken

	// A clock that lapses WHILE THE COPY IS IN FLIGHT: valid on its first read
	// and expired on every one after. A gate that reads the clock at each
	// consumption sees the second read and refuses; one that captured an
	// instant when the copy began would reuse the first, never notice, and
	// decrypt against a window that is gone. That is the difference this
	// fixture exists to detect, and a fixture that simply advanced the clock
	// before calling Copy would not detect it.
	opened := time.Now().UTC()
	var reads int
	auth.Now = func() time.Time {
		reads++
		if reads <= 1 {
			return opened
		}
		return opened.Add(2 * time.Hour)
	}

	req := service.CopyRequest{
		SourceEnvironmentID:       string(envA1),
		KeyNames:                  []string{ceremonySecretA},
		DestinationEnvironmentIDs: []string{string(envProd)},
		ConfirmProtected:          true,
	}
	before := disclosureRows(t, db)
	if _, err := values.Copy(ctx, service.Bearer(token), project, req); !errors.Is(err, service.ErrReauthWindowExpired) {
		t.Fatalf("copy whose window lapsed mid-flight = %v, want ErrReauthWindowExpired", err)
	}
	if reads < 2 {
		t.Fatalf("the copy read the clock %d time(s): consumption must read it per window, not once", reads)
	}
	if got := disclosureRows(t, db); got != before {
		t.Fatalf("a copy refused on an expired window wrote %d disclosure rows, want 0", got-before)
	}
}

func TestThePasskeyRouteIsNotAnEnvironmentOracleSQLite(t *testing.T) {
	runThePasskeyRouteIsNotAnEnvironmentOracle(t, seededDB(t, openSQLite))
}
func TestThePasskeyRouteIsNotAnEnvironmentOraclePostgres(t *testing.T) {
	runThePasskeyRouteIsNotAnEnvironmentOracle(t, seededDB(t, openPostgres))
}

// runThePasskeyRouteIsNotAnEnvironmentOracle (review R2): the passkey reauth
// route carries the same obligation the TOTP one does.
//
// A reauth ceremony NAMES an environment and `finish` derives the window's
// shape from that environment's policy — so a route that started a ceremony
// for any id a caller supplied would let an authenticated principal tell an
// environment they cannot reach from one that does not exist, and a protected
// one from an open one, by reading the refusals. Resolving the chain and
// requiring `read(E)` first collapses them into the uniform outcome.
func runThePasskeyRouteIsNotAnEnvironmentOracle(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, token, _, _ := ceremonyFixture(t, db, "ceremony-pk-oracle")
	auth.ReauthWindow = 5 * time.Minute

	// env_b1 is org B's: real, reachable by someone, not by this principal.
	// env_does_not_exist is the control, and the two must be indistinguishable.
	_, unreachable := auth.ReauthPasskeyStart(ctx, token, service.PurposeReveal, "env_b1", nil)
	if unreachable == nil {
		t.Fatal("a passkey reauth against another org's environment must be refused")
	}
	_, missing := auth.ReauthPasskeyStart(ctx, token, service.PurposeReveal, "env_does_not_exist", nil)
	if missing == nil {
		t.Fatal("a passkey reauth against a nonexistent environment must be refused")
	}
	assertUniformNotFound(t, unreachable, missing)

	// A reachable environment is the only one that gets past the gate, and it
	// answers with a ceremony rather than the nonexistent shape.
	if _, err := auth.ReauthPasskeyStart(ctx, token, service.PurposeReveal, string(envA1), nil); err != nil {
		t.Fatalf("a reachable environment must open a ceremony: %v", err)
	}
	// And nothing was written for the refused ones: a ceremony row for an
	// environment the caller cannot reach is the oracle in durable form.
	if got := queryInt(t, db, "SELECT COUNT(*) FROM webauthn_ceremonies WHERE environment_id IN ('env_b1', 'env_does_not_exist')"); got != 0 {
		t.Fatalf("refused reauth starts wrote %d ceremony rows, want 0", got)
	}
}
