package isolation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/remotefetch"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/authn"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// The workspace session's ASSURANCE RECORD and the STEP-UP ELEVATION PATH
// (#71, multi-instance ADR § The handoff and the workspace session).
//
// These are the two halves of criterion 3's "reveals under B's ceremony" that
// the earlier sessions left open, and they are tested together because they are
// one fact seen twice: what the human demonstrated in the popup on B's origin
// has to reach the session B issued, both at establishment (migration 00020)
// and at every later elevation.
//
// Everything below drives the REAL service against a REAL datastore. Nothing
// asserts against a fixture's idea of a handoff: the transactions are opened,
// approved and redeemed through the same three calls the transport makes.

const stepUpOrigin = "https://shell.example"

// seedSessionFactors seeds one live session carrying an exact assurance record.
// The record is the subject of these tests, so it is an argument rather than a
// constant: "what the ceremony demonstrated" is precisely what must travel.
func seedSessionFactors(t *testing.T, db *store.DB, p domain.PrincipalID, factors string) string {
	t.Helper()
	value, verifier, err := crypto.NewArtifact(crypto.ArtifactCLISession)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := crypto.RandomBytes(8)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	err = tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		return az.MintSession(ctx, authn.NewSession{
			ID: "ses_" + base64.RawURLEncoding.EncodeToString(raw), PrincipalID: p,
			Verifier: verifier, Artifact: "cli", SessionGeneration: 1, CredentialEpoch: 1,
			AuthMethod: "local-password", Factors: factors,
			AuthenticatedAt: now, CreatedAt: now,
			IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(24 * time.Hour),
			SourceIP: "127.0.0.1", UserAgent: "test",
		})
	})
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return value
}

// pkcePair is one RFC 7636 S256 verifier and its challenge.
func pkcePair(seed string) (verifier, challenge string) {
	verifierSeed := sha256.Sum256([]byte(seed))
	verifier = base64.RawURLEncoding.EncodeToString(verifierSeed[:])
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// stepUpWorkspace builds the serving side with a REAL reauthentication seam.
// The window bound is set here rather than left at zero because a zero
// effective window fails closed by design — a test against the default would
// pass for the wrong reason.
func stepUpWorkspace(t *testing.T, db *store.DB) *service.Workspace {
	t.Helper()
	auth := authService(t, db)
	auth.ReauthWindow = 15 * time.Minute
	return &service.Workspace{DB: db, Version: "test", Reauth: auth}
}

// establishWorkspace runs the full establishment arc and returns the session it
// issued together with the approving session's bearer.
func establishWorkspace(t *testing.T, ws *service.Workspace, approver string) service.WorkspaceSession {
	t.Helper()
	ctx := t.Context()
	verifier, challenge := pkcePair("establish")
	started, err := ws.StartHandoff(ctx, service.HandoffRequest{
		Origin: stepUpOrigin, RedirectURI: stepUpOrigin + "/workspace/callback",
		PKCEChallenge: challenge, Purpose: service.HandoffEstablishment,
	})
	if err != nil {
		t.Fatalf("start establishment: %v", err)
	}
	code, _, err := ws.ApproveHandoff(ctx, service.Bearer(approver), started.State)
	if err != nil {
		t.Fatalf("approve establishment: %v", err)
	}
	out, err := ws.RedeemHandoff(ctx, code, verifier, stepUpOrigin)
	if err != nil {
		t.Fatalf("redeem establishment: %v", err)
	}
	return out
}

// ceremony is what the approving human does INSIDE the popup between the
// transaction opening and the approval. A step-up approval now demands one, so
// every arc below has to say which it performed.
type ceremony func(t *testing.T, approvingSessionID string)

// noCeremony is the approver who simply happens to be logged in. It is the
// exact shortcut the step-up gate exists to refuse.
func noCeremony(*testing.T, string) {}

// freshCeremony writes the reauthentication window a real factor verification
// leaves behind, through OpenReauthWindow -- the SAME writer ReauthTOTP,
// ReauthPasskeyFinish and OIDC reauth each call the instant their ceremony
// verifies. What it seeds is therefore a real ceremony record and not a
// test-only shape; TestStepUpDemandsARealFactorVerification drives the actual
// TOTP ceremony end to end so this helper cannot drift away from one.
func freshCeremony(db *store.DB, envID, class string) ceremony {
	return func(t *testing.T, sessionID string) {
		t.Helper()
		now := time.Now().UTC()
		id, err := crypto.RandomBytes(8)
		if err != nil {
			t.Fatal(err)
		}
		err = tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
			epoch, err := az.CredentialEpoch(ctx)
			if err != nil {
				return err
			}
			return az.OpenReauthWindow(ctx, authz.NewReauthWindow{
				ID: "raw_" + base64.RawURLEncoding.EncodeToString(id), SessionID: sessionID,
				EnvironmentID: envID, CeremonyID: "cer_test", FactorClass: class,
				AuthenticatedAt: now, WindowExpiresAt: now.Add(15 * time.Minute),
				HardExpiresAt: now.Add(time.Hour), CredentialEpoch: epoch, CreatedAt: now,
			})
		})
		if err != nil {
			t.Fatalf("seed the approving ceremony: %v", err)
		}
	}
}

// stepUp opens, approves and redeems one step-up transaction over env_prod,
// running `did` as the approving human's in-popup ceremony first.
func stepUp(
	t *testing.T, ws *service.Workspace, approver, sessionID, envID string, did ceremony,
) (service.WorkspaceSession, error) {
	t.Helper()
	return stepUpFor(t, ws, approver, sessionID, envID, string(authz.OpValueReveal), "DATABASE_URL", did)
}

// stepUpFor is stepUp with the consent's exact operation and key set spelled
// out, so a test can prove the binding is the thing being enforced.
func stepUpFor(
	t *testing.T, ws *service.Workspace, approver, sessionID, envID, operation, keySet string, did ceremony,
) (service.WorkspaceSession, error) {
	t.Helper()
	ctx := t.Context()
	verifier, challenge := pkcePair("stepup-" + sessionID + envID + operation + keySet)
	started, err := ws.StartHandoff(ctx, service.HandoffRequest{
		Origin: stepUpOrigin, RedirectURI: stepUpOrigin + "/workspace/callback",
		PKCEChallenge: challenge, Purpose: service.HandoffStepUp,
		SessionID: sessionID, Operation: operation, EnvID: envID,
		KeySet: keySet,
	})
	if err != nil {
		return service.WorkspaceSession{}, err
	}
	did(t, sessionIDOf(t, ws.DB, approver))
	code, _, err := ws.ApproveHandoff(ctx, service.Bearer(approver), started.State)
	if err != nil {
		return service.WorkspaceSession{}, err
	}
	return ws.RedeemHandoff(ctx, code, verifier, stepUpOrigin)
}

// sessionFactors reads a session row's stored assurance record. Read from the
// DATABASE and not from the service's return value on purpose: the claim under
// test is that the record was persisted onto the session, not that a struct
// carried it out of one function.
func sessionFactors(t *testing.T, db *store.DB, sessionID string) string {
	t.Helper()
	return queryString(t, db, `SELECT factors FROM sessions WHERE id = '`+sessionID+`'`)
}

func runWorkspaceAssuranceAndStepUp(t *testing.T, db *store.DB) {
	ctx := t.Context()
	ws := stepUpWorkspace(t, db)
	admin := service.LocalPrincipal(root)

	if _, err := ws.AddOrigin(ctx, admin, stepUpOrigin); err != nil {
		t.Fatalf("allowlist the viewing origin: %v", err)
	}

	// --- the assurance record travels (migration 00020) ---------------------
	//
	// The approving session demonstrated two factors. Before 00020 the
	// workspace session was minted with an empty record whatever the human had
	// just done, which made it permanently single-factor and silently unable to
	// reach any MFA-mandatory operation.
	approver := seedSessionFactors(t, db, root, `["password","totp"]`)
	established := establishWorkspace(t, ws, approver)
	if got := sessionFactors(t, db, established.SessionID); got != `["password","totp"]` {
		t.Fatalf("the workspace session's assurance record is %q, want the approving ceremony's "+
			"[\"password\",\"totp\"] — the ADR requires the session model's assurance record, "+
			"not an empty one", got)
	}
	if established.Elevated {
		t.Error("an establishment is not an elevation")
	}

	// --- the elevation ------------------------------------------------------

	fresh := freshCeremony(db, string(envProd), "totp")
	elevated, err := stepUp(t, ws, approver, established.SessionID, string(envProd), fresh)
	if err != nil {
		t.Fatalf("step-up elevation: %v", err)
	}
	if !elevated.Elevated {
		t.Error("a redeemed step-up must report itself as an elevation")
	}
	if elevated.SessionID != established.SessionID {
		t.Fatalf("the elevation minted a SECOND session (%s, was %s) — a step-up elevates the "+
			"session it bound and mints nothing", elevated.SessionID, established.SessionID)
	}
	if elevated.Value == established.Value {
		t.Error("the elevated session's bearer was not rotated: a bearer stolen before the " +
			"elevation would become an elevated bearer after it")
	}
	if elevated.EnvironmentID != string(envProd) || elevated.WindowExpiresAt.IsZero() {
		t.Errorf("the elevation reported no window (env %q, expires %v)",
			elevated.EnvironmentID, elevated.WindowExpiresAt)
	}

	// The window is real: it exists over exactly (session, environment), which
	// is what the disclosure gate reads.
	assertReauthWindow(t, db, established.SessionID, string(envProd))

	// The rotation bit, proven at the chokepoint rather than by comparing
	// strings: the old value is dead and the new one resolves.
	shell := browserCtx(ctx, stepUpOrigin)
	if _, err := ws.ListSessions(shell, service.Bearer(established.Value)); err == nil {
		t.Error("the pre-elevation bearer still authenticates — the rotation did not bite")
	}
	if _, err := ws.ListSessions(shell, service.Bearer(elevated.Value)); err != nil {
		t.Errorf("the elevated bearer does not authenticate: %v", err)
	}

	// A SECOND elevation over the same environment must re-arm the window
	// rather than collide with it. The table makes (session, environment)
	// unique, and a plain insert answered a fault here.
	again, err := stepUp(t, ws, approver, established.SessionID, string(envProd), fresh)
	if err != nil {
		t.Fatalf("a second elevation over the same environment must re-arm the window: %v", err)
	}
	if again.SessionID != established.SessionID {
		t.Error("the second elevation moved the session")
	}

	// --- the refusals -------------------------------------------------------

	// A step-up naming ANOTHER principal's session. StartHandoff is
	// pre-authentication, so anyone may open a transaction naming any session
	// id; the binding is enforced at redemption by resolving the id within the
	// APPROVER's own sessions. Without that, a stolen workspace bearer could be
	// elevated using the thief's own factors.
	other := seedSessionFactors(t, db, alice, `["password","totp"]`)
	if _, err := stepUp(t, ws, other, established.SessionID, string(envProd), fresh); !errors.Is(err, service.ErrHandoffInvalid) {
		t.Fatalf("a step-up approved by a different principal must be refused, got %v", err)
	}

	// A popup the human walked through with a password alone demonstrates
	// nothing the workspace session did not already have.
	// A password-only approver WITH a real possession-factor ceremony is
	// multi-factor by the time the elevation runs -- the ceremony IS the second
	// factor, and joining it onto the record is what makes that true rather
	// than merely arguable. The same approver WITHOUT one is refused below.
	weak := seedSessionFactors(t, db, root, `["password"]`)
	weakWS := establishWorkspace(t, ws, weak)
	if _, err := stepUp(t, ws, weak, weakWS.SessionID, string(envProd), fresh); err != nil {
		t.Fatalf("a password login plus a live TOTP ceremony must elevate: %v", err)
	}
	// An approver with NO recorded factors at all is still refused after a
	// ceremony: one factor class is not two, whatever produced it.
	bare := seedSessionFactors(t, db, root, `[]`)
	bareWS := establishWorkspace(t, ws, bare)
	if _, err := stepUp(t, ws, bare, bareWS.SessionID, string(envProd), fresh); !errors.Is(err, service.ErrHandoffInvalid) {
		t.Fatalf("a single-factor approval must not elevate, got %v", err)
	}

	// THE FRESH-CEREMONY GATE. The approving session's assurance record says
	// two factors, exactly as it does on the arc that succeeded above -- the
	// only difference is that this human performed no factor verification in
	// the popup. Being logged in is not stepping up.
	if _, err := stepUp(t, ws, approver, established.SessionID, string(envProd), noCeremony); !errors.Is(err, service.ErrHandoffInvalid) {
		t.Fatalf("a step-up approved with no fresh ceremony must be refused, got %v", err)
	}

	// A ceremony over ANOTHER environment is not consent for this one.
	if _, err := stepUp(t, ws, approver, established.SessionID, string(envProd),
		freshCeremony(db, "env_staging", "totp")); !errors.Is(err, service.ErrHandoffInvalid) {
		t.Fatalf("a ceremony over another environment must not license this elevation, got %v", err)
	}

	// An elevation with no environment has no window to open, and says so at
	// the transaction rather than succeeding into something nothing can consume.
	if _, err := stepUp(t, ws, approver, established.SessionID, "", fresh); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("a step-up naming no environment must be refused, got %v", err)
	}

	// A step-up bound to an ORDINARY session, not a workspace one: elevating
	// the human's own same-origin session through a cross-origin popup would
	// put the viewing origin in that path.
	ordinaryID := sessionIDOf(t, db, approver)
	if _, err := stepUp(t, ws, approver, ordinaryID, string(envProd), fresh); !errors.Is(err, service.ErrHandoffInvalid) {
		t.Fatalf("a step-up bound to a CLI session must be refused, got %v", err)
	}

	// And the kill switch still reaches an elevated session: de-allowlisting
	// the origin kills it whatever assurance it accumulated.
	killed, err := ws.RemoveOrigin(ctx, admin, stepUpOrigin)
	if err != nil {
		t.Fatalf("remove origin: %v", err)
	}
	if killed == 0 {
		t.Error("de-allowlisting killed no workspace session")
	}
	if _, err := ws.ListSessions(shell, service.Bearer(elevated.Value)); err == nil {
		t.Error("an elevated workspace session survived its origin's removal")
	}
}

// assertReauthWindow fails unless exactly one live window exists over the pair.
func assertReauthWindow(t *testing.T, db *store.DB, sessionID, envID string) {
	t.Helper()
	got := queryString(t, db,
		`SELECT count(*) FROM reauth_windows WHERE session_id = '`+sessionID+
			`' AND environment_id = '`+envID+`' AND consumed_at IS NULL`)
	if got != "1" {
		t.Fatalf("the elevation left %s reauthentication windows over (%s, %s), want exactly 1",
			got, sessionID, envID)
	}
}

func TestWorkspaceAssuranceAndStepUpSQLite(t *testing.T) {
	runWorkspaceAssuranceAndStepUp(t, seededDB(t, openSQLite))
}

func TestWorkspaceAssuranceAndStepUpPostgres(t *testing.T) {
	runWorkspaceAssuranceAndStepUp(t, seededDB(t, openPostgres))
}

// The bounds this path opens its window under are the human-auth service's own,
// never a second copy: an environment whose window was lowered must be honoured
// by an elevation exactly as it is by a TOTP or WebAuthn ceremony.
func TestElevationHonoursTheEnvironmentsOwnWindow(t *testing.T) {
	db := seededDB(t, openSQLite)
	ctx := t.Context()
	ws := stepUpWorkspace(t, db)
	admin := service.LocalPrincipal(root)
	if _, err := ws.AddOrigin(ctx, admin, stepUpOrigin); err != nil {
		t.Fatal(err)
	}
	approver := seedSessionFactors(t, db, root, `["webauthn"]`)
	established := establishWorkspace(t, ws, approver)

	// Zero is the fail-closed state: at a 0 effective window the only valid
	// ceremony is a single-decision WebAuthn one, and a handoff transaction is
	// not a WebAuthn ceremony.
	execRaw(t, db, `UPDATE environments SET reauth_window_seconds = 0 WHERE id = 'env_prod'`)
	fresh := freshCeremony(db, string(envProd), "webauthn")
	if _, err := stepUp(t, ws, approver, established.SessionID, string(envProd), fresh); !errors.Is(err, service.ErrHandoffInvalid) {
		t.Fatalf("an elevation at a zero effective window must fail closed, got %v", err)
	}

	execRaw(t, db, `UPDATE environments SET reauth_window_seconds = 60 WHERE id = 'env_prod'`)
	out, err := stepUp(t, ws, approver, established.SessionID, string(envProd), fresh)
	if err != nil {
		t.Fatalf("elevation at a 60s window: %v", err)
	}
	if lifetime := time.Until(out.WindowExpiresAt); lifetime > 2*time.Minute {
		t.Errorf("the window lives %v, want the environment's own 60s — the elevation is using "+
			"its own bound rather than the one seam", lifetime)
	}
	// And it is a sliding window, not a single-decision one: nothing here can
	// be resolved back to a WebAuthn ceremony for byte-exact unit matching.
	if single := queryString(t, db,
		`SELECT single_decision FROM reauth_windows WHERE session_id = '`+established.SessionID+
			`' AND environment_id = 'env_prod'`); single != "0" && single != "false" {
		t.Errorf("the elevation opened a single-decision window (%s)", single)
	}
	_ = remotefetch.HandoffExpiry
}

// A step-up consent names ONE operation over ONE key set, and the window it
// opens must authorize that pair and nothing else. Before this the bindings
// were stored on the transaction row and read by nobody: consent to reveal
// DATABASE_URL opened an environment-wide sliding window that any later
// disclosure over that environment could spend.
func runStepUpBindingIsConsumed(t *testing.T, db *store.DB) {
	ctx := t.Context()
	ws := stepUpWorkspace(t, db)
	if _, err := ws.AddOrigin(ctx, service.LocalPrincipal(root), stepUpOrigin); err != nil {
		t.Fatal(err)
	}
	approver := seedSessionFactors(t, db, root, `["password","totp"]`)
	established := establishWorkspace(t, ws, approver)
	fresh := freshCeremony(db, string(envProd), "totp")

	elevated, err := stepUpFor(t, ws, approver, established.SessionID, string(envProd),
		string(authz.OpValueReveal), "DATABASE_URL", fresh)
	if err != nil {
		t.Fatalf("step-up: %v", err)
	}
	now := time.Now().UTC()
	auth := ws.Reauth

	// The consented pair is authorized.
	if err := consumeWindowFor(t, auth, db, elevated.SessionID, string(envProd),
		string(authz.OpValueReveal), []string{"DATABASE_URL"}, now); err != nil {
		t.Fatalf("the consented operation and key set must be authorized: %v", err)
	}

	// Everything else is a replay of that consent against something the human
	// never saw, and is refused.
	for _, c := range []struct {
		name      string
		operation string
		keys      []string
	}{
		{"another key set", string(authz.OpValueReveal), []string{"API_KEY"}},
		{"a superset of the consented keys", string(authz.OpValueReveal), []string{"API_KEY", "DATABASE_URL"}},
		{"another operation", string(authz.OpValueCopySource), []string{"DATABASE_URL"}},
		{"no operation named at all", "", nil},
	} {
		err := consumeWindowFor(t, auth, db, elevated.SessionID, string(envProd), c.operation, c.keys, now)
		if !errors.Is(err, service.ErrReauthUnitMismatch) {
			t.Errorf("%s: consumed the step-up window (%v), want ErrReauthUnitMismatch — "+
				"a consent for one operation and key set must not authorize another", c.name, err)
		}
	}

	// Key ORDER is not part of the consent: the binding is a set.
	if err := consumeWindowFor(t, auth, db, elevated.SessionID, string(envProd),
		string(authz.OpValueReveal), []string{"DATABASE_URL"}, now); err != nil {
		t.Fatalf("the consented pair stopped being authorized after the refusals: %v", err)
	}
	second, err := stepUpFor(t, ws, approver, established.SessionID, string(envProd),
		string(authz.OpValueReveal), "B_KEY\nA_KEY", fresh)
	if err != nil {
		t.Fatalf("second step-up: %v", err)
	}
	if err := consumeWindowFor(t, auth, db, second.SessionID, string(envProd),
		string(authz.OpValueReveal), []string{"A_KEY", "B_KEY"}, now); err != nil {
		t.Fatalf("the key set is a SET, so a different order is the same consent: %v", err)
	}
}

func TestStepUpBindingIsConsumedSQLite(t *testing.T) {
	runStepUpBindingIsConsumed(t, seededDB(t, openSQLite))
}

func TestStepUpBindingIsConsumedPostgres(t *testing.T) {
	runStepUpBindingIsConsumed(t, seededDB(t, openPostgres))
}

// The approve page reads the step-up's operation, environment and key set back
// from the SERVER-bound transaction by state, rather than trusting them from its
// URL. This proves the read answers the bound policy, refuses without a session,
// and refuses an unknown state — the three properties the approve page rests on.
func runShowHandoffReturnsBoundPolicy(t *testing.T, db *store.DB) {
	ctx := t.Context()
	ws := stepUpWorkspace(t, db)
	if _, err := ws.AddOrigin(ctx, service.LocalPrincipal(root), stepUpOrigin); err != nil {
		t.Fatal(err)
	}
	approver := seedSessionFactors(t, db, root, `["password","totp"]`)
	established := establishWorkspace(t, ws, approver)

	_, challenge := pkcePair("show-handoff")
	started, err := ws.StartHandoff(ctx, service.HandoffRequest{
		Origin: stepUpOrigin, RedirectURI: stepUpOrigin + "/workspace/callback",
		PKCEChallenge: challenge, Purpose: service.HandoffStepUp,
		SessionID: established.SessionID, Operation: string(authz.OpValueReveal),
		EnvID: string(envProd), KeySet: "key_one\nkey_two",
	})
	if err != nil {
		t.Fatalf("start step-up handoff: %v", err)
	}

	view, err := ws.ShowHandoff(ctx, service.Bearer(approver), started.State)
	if err != nil {
		t.Fatalf("show handoff: %v", err)
	}
	if view.Purpose != service.HandoffStepUp {
		t.Errorf("purpose = %q, want step-up", view.Purpose)
	}
	if view.Operation != string(authz.OpValueReveal) {
		t.Errorf("operation = %q, want %q", view.Operation, authz.OpValueReveal)
	}
	if view.EnvID != string(envProd) {
		t.Errorf("environment = %q, want %q", view.EnvID, envProd)
	}
	// The whole key set comes back, split — the reason the endpoint exists is to
	// carry a set a URL could not.
	if got := append([]string(nil), view.KeySet...); len(got) != 2 ||
		!slices.Contains(got, "key_one") || !slices.Contains(got, "key_two") {
		t.Errorf("key set = %v, want both key_one and key_two", view.KeySet)
	}

	// No session, no read — the numbers here are the ceremony's, not the world's.
	if _, err := ws.ShowHandoff(ctx, service.Bearer(""), started.State); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Errorf("show handoff without a session: err = %v, want ErrUnauthenticated", err)
	}

	// A DIFFERENT human, authenticated but not the transaction's owner, is
	// refused as if the state did not exist — one human (or tenant) must not read
	// another's bound environment and key set from a leaked state.
	other := seedSessionFactors(t, db, custodian, `["password","totp"]`)
	if _, err := ws.ShowHandoff(ctx, service.Bearer(other), started.State); !errors.Is(err, service.ErrHandoffInvalid) {
		t.Errorf("show handoff by a non-owner: err = %v, want ErrHandoffInvalid", err)
	}

	// A malformed or unknown state is a uniform invalid-handoff refusal (a 404 at
	// the transport), never a partial answer.
	if _, err := ws.ShowHandoff(ctx, service.Bearer(approver), "not-a-state"); !errors.Is(err, service.ErrHandoffInvalid) {
		t.Errorf("show handoff with a bogus state: err = %v, want ErrHandoffInvalid", err)
	}

	// An establishment transaction has no bound session to anchor ownership on
	// and is not readable here — the approve page never asks for one.
	establishment, err := ws.StartHandoff(ctx, service.HandoffRequest{
		Origin: stepUpOrigin, RedirectURI: stepUpOrigin + "/workspace/callback",
		PKCEChallenge: challenge, Purpose: service.HandoffEstablishment,
	})
	if err != nil {
		t.Fatalf("start establishment handoff: %v", err)
	}
	if _, err := ws.ShowHandoff(ctx, service.Bearer(approver), establishment.State); !errors.Is(err, service.ErrHandoffInvalid) {
		t.Errorf("show handoff for an establishment: err = %v, want ErrHandoffInvalid", err)
	}
}

func TestShowHandoffReturnsBoundPolicySQLite(t *testing.T) {
	runShowHandoffReturnsBoundPolicy(t, seededDB(t, openSQLite))
}

func TestShowHandoffReturnsBoundPolicyPostgres(t *testing.T) {
	runShowHandoffReturnsBoundPolicy(t, seededDB(t, openPostgres))
}

// A workspace step-up for the reveal operation must be spendable by the real
// value reveal path. The binding test above calls ConsumeReauthWindow directly;
// this arc keeps the ceremony seam itself from silently presenting no operation.
func runStepUpRevealIsSpentByValuePath(t *testing.T, db *store.DB) {
	ctx := t.Context()
	ws := stepUpWorkspace(t, db)
	if _, err := ws.AddOrigin(ctx, service.LocalPrincipal(root), stepUpOrigin); err != nil {
		t.Fatal(err)
	}
	approver := seedSessionFactors(t, db, custodian, `["password","totp"]`)
	established := establishWorkspace(t, ws, approver)

	const (
		keyID   = "key_workspace_reveal"
		keyName = "WORKSPACE_REVEAL"
	)
	execRaw(t, db, `INSERT INTO keys (id, org_id, project_id, name, folder_path, classification, `+
		`description, deprecated, deprecation_note, declaration, required_mode, forbidden_mode, `+
		`group_id, created_at) VALUES ('`+keyID+`', 'org_a', 'prj_a1', '`+keyName+`', '', 'secret', `+
		`'', FALSE, '', '{"rule":{"type":"string"}}', 'none', 'none', NULL, `+ts+`)`)
	values := &service.Values{DB: db, Keyring: probeKeyring(t, db), Auth: ws.Reauth}
	valueScope := scopeEnv(orgA, prjA1, envA1)
	staged, err := values.Set(ctx, service.LocalPrincipal(custodian),
		valueScope, keyName, "workspace-secret", nil)
	if err != nil {
		t.Fatalf("seed workspace reveal value: %v", err)
	}
	if _, err := revisionSvc(t, db).Publish(ctx, service.LocalPrincipal(custodian),
		valueScope, []string{staged.VersionID}); err != nil {
		t.Fatalf("publish workspace reveal value: %v", err)
	}

	fresh := freshCeremony(db, string(envA1), "totp")
	elevated, err := stepUpFor(t, ws, approver, established.SessionID, string(envA1),
		string(authz.OpValueReveal), keyID, fresh)
	if err != nil {
		t.Fatalf("step-up for value reveal: %v", err)
	}
	shell := browserCtx(ctx, stepUpOrigin)
	cell, err := values.Get(shell, service.Bearer(elevated.Value),
		scopeEnv(orgA, prjA1, envA1), keyName, true)
	if err != nil {
		t.Fatalf("the real reveal path did not spend its matching workspace consent: %v", err)
	}
	if !cell.Revealed {
		t.Fatal("the real reveal path returned the secret without marking it revealed")
	}

	wrong, err := stepUpFor(t, ws, approver, established.SessionID, string(envA1),
		string(authz.OpValueCopySource), keyID, fresh)
	if err != nil {
		t.Fatalf("step-up for a different operation: %v", err)
	}
	if _, err := values.Get(shell, service.Bearer(wrong.Value),
		scopeEnv(orgA, prjA1, envA1), keyName, true); !errors.Is(err, service.ErrReauthUnitMismatch) {
		t.Fatalf("a different operation's consent reached the real reveal path (%v), want ErrReauthUnitMismatch", err)
	}
}

func TestStepUpRevealIsSpentByValuePathSQLite(t *testing.T) {
	runStepUpRevealIsSpentByValuePath(t, seededDB(t, openSQLite))
}

func TestStepUpRevealIsSpentByValuePathPostgres(t *testing.T) {
	runStepUpRevealIsSpentByValuePath(t, seededDB(t, openPostgres))
}

// The fresh-ceremony gate, driven through a REAL factor verification rather
// than a seeded window: the approving human enrols a TOTP authenticator, and
// the elevation is refused until they present a code and allowed once they do.
// This is the test that keeps freshCeremony honest — if OpenReauthWindow ever
// stopped being what a ceremony writes, this would fail and that would not.
func TestStepUpDemandsARealFactorVerification(t *testing.T) {
	db := seededDB(t, openSQLite)
	ctx := t.Context()
	auth, _, password := bootstrapFactorAdmin(t, db)
	base := time.Now().UTC()
	clk := base
	auth.Now = func() time.Time { return clk }
	t.Cleanup(func() { auth.Now = nil })
	auth.ReauthWindow = 15 * time.Minute
	auth.ReauthHardCap = time.Hour
	ws := &service.Workspace{DB: db, Version: "test", Reauth: auth, Now: func() time.Time { return clk }}

	if _, err := ws.AddOrigin(ctx, service.LocalPrincipal(root), stepUpOrigin); err != nil {
		t.Fatal(err)
	}
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
	approver := confirmed.SessionToken

	// The establishment inherits the login ceremony's record, which is correct:
	// establishing a workspace session IS the login the human just performed.
	established := establishWorkspace(t, ws, approver)
	if got := sessionFactors(t, db, established.SessionID); got != `["password"]` {
		t.Fatalf("the workspace session's assurance record is %q, want the login "+
			"ceremony's [\"password\"]", got)
	}

	verifier, challenge := pkcePair("real-totp-stepup")
	started, err := ws.StartHandoff(ctx, service.HandoffRequest{
		Origin: stepUpOrigin, RedirectURI: stepUpOrigin + "/workspace/callback",
		PKCEChallenge: challenge, Purpose: service.HandoffStepUp,
		SessionID: established.SessionID, Operation: string(authz.OpValueReveal),
		EnvID: string(envProd), KeySet: "DATABASE_URL",
	})
	if err != nil {
		t.Fatalf("start step-up: %v", err)
	}

	// Logged in with MFA, and refused: no factor was verified for THIS consent.
	if _, _, err := ws.ApproveHandoff(ctx, service.Bearer(approver), started.State); !errors.Is(err, service.ErrHandoffInvalid) {
		t.Fatalf("an MFA session with no fresh ceremony approved a step-up (%v) — being "+
			"logged in is not stepping up", err)
	}

	// Now the ceremony: a real TOTP code, verified by the real reauth path,
	// which rotates the approving session's bearer as every reauth does.
	clk = base.Add(90 * time.Second)
	res, err := auth.ReauthTOTP(ctx, approver, string(envProd), totpCode(t, uri, clk))
	if err != nil {
		t.Fatalf("TOTP reauth: %v", err)
	}
	code, _, err := ws.ApproveHandoff(ctx, service.Bearer(res.SessionToken), started.State)
	if err != nil {
		t.Fatalf("approve after a real ceremony: %v", err)
	}
	elevated, err := ws.RedeemHandoff(ctx, code, verifier, stepUpOrigin)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if !elevated.Elevated || elevated.SessionID != established.SessionID {
		t.Fatalf("redemption did not elevate the bound session: %+v", elevated)
	}
	// The elevated session RECORDS the factor it just demonstrated. A
	// reauthentication leaves the session's own record alone, so without the
	// join at approval a password login plus a live TOTP ceremony would read as
	// single-factor and the elevation would refuse itself.
	if got := sessionFactors(t, db, elevated.SessionID); got != `["password","totp"]` {
		t.Errorf("the elevated session's assurance record is %q, want "+
			"[\"password\",\"totp\"] — the ceremony's factor must join it", got)
	}
	if class := queryString(t, db,
		`SELECT factor_class FROM reauth_windows WHERE session_id = '`+elevated.SessionID+
			`' AND environment_id = 'env_prod'`); class != "totp" {
		t.Errorf("the elevation's window records factor class %q, want the ceremony's totp", class)
	}
}
