package isolation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
)

// The browser session artifact end to end on a real datastore (#56).
//
// The transport's half — which channel the token leaves on, and when the
// synchronizer token is demanded — is asserted in internal/server against
// stubs. What needs a real datastore is the other half: that a browser login
// mints a `br` artifact with its own clocks and a stored CSRF verifier, and
// that `VerifyBrowserCSRF` actually consults that verifier rather than
// believing whatever the caller presented.

func TestBrowserLoginMintsACSRFBoundSessionSQLite(t *testing.T) {
	runBrowserSessionFlow(t, seededDB(t, openSQLite))
}

func TestBrowserLoginMintsACSRFBoundSessionPostgres(t *testing.T) {
	runBrowserSessionFlow(t, seededDB(t, openPostgres))
}

func runBrowserSessionFlow(t *testing.T, db *store.DB) {
	auth, _, password := bootstrapFactorAdmin(t, db)
	ctx := t.Context()

	login, err := auth.LocalLogin(ctx, "factor-admin", password, service.ArtifactBrowser)
	if err != nil {
		t.Fatalf("browser login: %v", err)
	}
	if login.Artifact != service.ArtifactBrowser {
		t.Fatalf("artifact = %q, want browser", login.Artifact)
	}
	// The grammar is load-bearing: the cookie leg accepts only `br` and the
	// header leg only `cli` (#54 A10), and both are checked before any row is
	// read.
	if err := crypto.ParseArtifact(login.SessionToken, crypto.ArtifactBrowserSession); err != nil {
		t.Fatalf("session token is not a browser artifact: %v", err)
	}
	if login.CSRFToken == "" {
		t.Fatal("a browser login minted no synchronizer token")
	}
	if err := crypto.ParseArtifact(login.CSRFToken, crypto.ArtifactCSRF); err != nil {
		t.Fatalf("synchronizer token is not a csrf artifact: %v", err)
	}
	// Distinct clocks, not the CLI's: a cookie session that inherited the CLI's
	// 30-day idle window would quietly be the long-lived artifact the two types
	// exist to keep apart.
	if want := login.CreatedAt.Add(service.BrowserSessionIdle); !login.IdleExpires.Equal(want) {
		t.Fatalf("idle expiry = %s, want the browser window %s", login.IdleExpires, want)
	}
	if want := login.CreatedAt.Add(service.BrowserSessionAbsolute); !login.AbsExpires.Equal(want) {
		t.Fatalf("absolute expiry = %s, want the browser window %s", login.AbsExpires, want)
	}

	if err := auth.VerifyBrowserCSRF(ctx, login.SessionToken, login.CSRFToken); err != nil {
		t.Fatalf("the minted synchronizer token was refused: %v", err)
	}

	// A well-formed token that this session never minted is refused. This is
	// what the stored verifier buys over comparing the header to the cookie:
	// an attacker who can plant a self-consistent pair still cannot pass.
	//
	// The refusal is ErrCSRFMismatch, NOT ErrUnauthenticated, and the
	// difference is load-bearing: the transport treats "no live session" as
	// "no cookie leg" and lets the request through, so a mismatch that
	// answered ErrUnauthenticated would silently disable the gate.
	other, _, err := crypto.NewArtifact(crypto.ArtifactCSRF)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.VerifyBrowserCSRF(ctx, login.SessionToken, other); !errors.Is(err, service.ErrCSRFMismatch) {
		t.Fatalf("a foreign synchronizer token answered %v, want a CSRF mismatch", err)
	}
	if err := auth.VerifyBrowserCSRF(ctx, login.SessionToken, ""); !errors.Is(err, service.ErrCSRFMismatch) {
		t.Fatalf("an absent synchronizer token answered %v, want a CSRF mismatch", err)
	}

	// A CLI session has no CSRF verifier, so it can satisfy no CSRF contract —
	// including one reached by planting a `cli` token in the browser cookie.
	cli, err := auth.LocalLogin(ctx, "factor-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatalf("cli login: %v", err)
	}
	if cli.CSRFToken != "" {
		t.Fatal("a CLI login minted a synchronizer token it has no channel for")
	}
	if err := auth.VerifyBrowserCSRF(ctx, cli.SessionToken, login.CSRFToken); !errors.Is(err, service.ErrCSRFMismatch) {
		t.Fatalf("a CLI session satisfied a CSRF contract: %v", err)
	}

	// Logout revokes. A revoked session answers ErrUnauthenticated — "there is
	// no cookie leg here" — which is what lets the browser that still holds
	// the dead cookie reach the login page again instead of being refused by
	// the CSRF gate on its own re-login POST.
	if err := auth.Logout(ctx, login.SessionToken); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if err := auth.VerifyBrowserCSRF(ctx, login.SessionToken, login.CSRFToken); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("a revoked session answered %v, want unauthenticated", err)
	}
}

// An artifact the contract does not describe is refused before any credential
// work happens — never silently downgraded to CLI, which would hand a browser
// its session token in a script-readable body.
func TestUnknownLoginArtifactIsRefusedBeforeVerification(t *testing.T) {
	auth, _, password := bootstrapFactorAdmin(t, seededDB(t, openSQLite))
	_, err := auth.LocalLogin(t.Context(), "factor-admin", password, "kiosk")
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("err = %v, want invalid", err)
	}
}

// Every account-security mutation reissues or rotates the acting session. Each
// one must preserve the ACTING artifact: a browser that enrolled a factor and
// got a `cli` session back would be logged out (its cookie points at a dead
// verifier) and handed a long-lived credential the transport can only deliver
// in a script-readable body.
//
// The transport half is asserted in internal/server; what needs a datastore is
// that the SERVICE mints the right grammar, the right clocks and a live CSRF
// verifier on each of these paths.
func TestAccountSecurityMutationsPreserveTheBrowserArtifactSQLite(t *testing.T) {
	runBrowserMutationFlow(t, seededDB(t, openSQLite))
}

func TestAccountSecurityMutationsPreserveTheBrowserArtifactPostgres(t *testing.T) {
	runBrowserMutationFlow(t, seededDB(t, openPostgres))
}

// browserSessionCheck returns the assertion every reissued browser session
// must satisfy: the artifact, the token grammar, a synchronizer token the
// server will actually accept, and the browser clocks rather than the CLI's.
// One definition, so the TOTP legs and the federation legs cannot drift into
// asserting different things about the same obligation.
func browserSessionCheck(
	t *testing.T, auth *service.Auth, ctx context.Context,
) func(string, service.LoginResult) {
	t.Helper()
	return func(what string, r service.LoginResult) {
		t.Helper()
		if r.Artifact != service.ArtifactBrowser {
			t.Fatalf("%s: artifact = %q, want browser", what, r.Artifact)
		}
		if err := crypto.ParseArtifact(r.SessionToken, crypto.ArtifactBrowserSession); err != nil {
			t.Fatalf("%s: token is not a browser artifact: %v", what, err)
		}
		if err := auth.VerifyBrowserCSRF(ctx, r.SessionToken, r.CSRFToken); err != nil {
			t.Fatalf("%s: the reissued session has no usable synchronizer token: %v", what, err)
		}
		if want := r.CreatedAt.Add(service.BrowserSessionIdle); !r.IdleExpires.Equal(want) {
			t.Fatalf("%s: idle expiry = %s, want the browser window %s", what, r.IdleExpires, want)
		}
	}
}

func runBrowserMutationFlow(t *testing.T, db *store.DB) {
	auth, _, password := bootstrapFactorAdmin(t, db)
	ctx := t.Context()

	// A clock the test advances, so each TOTP step is a fresh unspent one.
	base := time.Now().UTC()
	clk := base
	auth.Now = func() time.Time { return clk }

	browserSession := browserSessionCheck(t, auth, ctx)

	login, err := auth.LocalLogin(ctx, "factor-admin", password, service.ArtifactBrowser)
	if err != nil {
		t.Fatalf("browser login: %v", err)
	}

	// Recovery-code regeneration reissues.
	_, regenerated, err := auth.GenerateRecoveryCodes(ctx, login.SessionToken, password)
	if err != nil {
		t.Fatalf("regenerate recovery codes: %v", err)
	}
	browserSession("recovery regeneration", regenerated)

	// TOTP enrolment confirm reissues.
	uri, err := auth.EnrolTOTPStart(ctx, regenerated.SessionToken, password)
	if err != nil {
		t.Fatalf("enrol start: %v", err)
	}
	clk = base.Add(30 * time.Second)
	confirmed, err := auth.EnrolTOTPConfirm(ctx, regenerated.SessionToken, totpCode(t, uri, clk))
	if err != nil {
		t.Fatalf("enrol confirm: %v", err)
	}
	browserSession("totp enrolment", confirmed)

	// Step-up ROTATES in place: the session id and the CSRF verifier are
	// untouched, so the token grammar is the only thing that has to follow the
	// acting artifact — and the synchronizer token the client already holds
	// must still work afterwards.
	clk = base.Add(60 * time.Second)
	stepped, err := auth.StepUpTOTP(ctx, confirmed.SessionToken, totpCode(t, uri, clk))
	if err != nil {
		t.Fatalf("step-up: %v", err)
	}
	if stepped.Artifact != service.ArtifactBrowser {
		t.Fatalf("step-up artifact = %q, want browser", stepped.Artifact)
	}
	if err := crypto.ParseArtifact(stepped.SessionToken, crypto.ArtifactBrowserSession); err != nil {
		t.Fatalf("step-up token is not a browser artifact: %v", err)
	}
	if err := auth.VerifyBrowserCSRF(ctx, stepped.SessionToken, confirmed.CSRFToken); err != nil {
		t.Fatalf("step-up invalidated the synchronizer token the client still holds: %v", err)
	}

	// Factor removal reissues.
	removed, err := auth.RemoveTOTP(ctx, stepped.SessionToken, password)
	if err != nil {
		t.Fatalf("remove totp: %v", err)
	}
	browserSession("totp removal", removed)
}

// The federation half of the same claim (#56 R2-1): identity LINK and UNLINK
// both reissue the acting session, and both hard-coded the CLI artifact before
// this ticket. The existing OIDC lifecycle tests drive them with a CLI session,
// so a regression there would be invisible — these drive the same two
// operations from a browser session and assert the artifact survives.
func TestBrowserFederationPreservesTheArtifactSQLite(t *testing.T) {
	runBrowserFederationFlow(t, seededDB(t, openSQLite))
}

func TestBrowserFederationPreservesTheArtifactPostgres(t *testing.T) {
	runBrowserFederationFlow(t, seededDB(t, openPostgres))
}

func runBrowserFederationFlow(t *testing.T, db *store.DB) {
	auth, boot, password := bootstrapFactorAdmin(t, db)
	ctx := t.Context()
	configureProvider(t, auth, ctx, boot.PrincipalID, "browser-idp", service.ProviderInput{
		DisplayName: "Browser IdP", ClientID: "client", ClientSecret: "secret",
		Scopes: "openid", Enabled: true,
	})

	browserSession := browserSessionCheck(t, auth, ctx)

	login, err := auth.LocalLogin(ctx, "factor-admin", password, service.ArtifactBrowser)
	if err != nil {
		t.Fatalf("browser login: %v", err)
	}

	// Link: `completeLink` reissues the acting session out of the proof
	// ceremony. A browser that linked an identity and got a `cli` session back
	// would be logged out by its own success.
	start, err := auth.OIDCStart(ctx, "browser-idp", "link", "", login.SessionToken, password)
	if err != nil {
		t.Fatalf("oidc link start: %v", err)
	}
	code, state := driveIdP(t, start.AuthURL+"&sub=browser-subject")
	linked, err := auth.OIDCCallback(ctx, "browser-idp", code, state, "", "", "", login.SessionToken)
	if err != nil {
		t.Fatalf("oidc link callback: %v", err)
	}
	browserSession("identity link", linked.Login)

	// Unlink reissues too, from the session the link just handed back.
	ids, err := auth.ListIdentities(ctx, linked.Login.SessionToken)
	if err != nil || len(ids) != 1 {
		t.Fatalf("list identities: %v (n=%d)", err, len(ids))
	}
	unlinked, err := auth.UnlinkIdentity(ctx, linked.Login.SessionToken, ids[0].ID, password)
	if err != nil {
		t.Fatalf("unlink: %v", err)
	}
	browserSession("identity unlink", unlinked)
}
