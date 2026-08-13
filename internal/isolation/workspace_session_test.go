package isolation

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/tx"
)

// The workspace session's admission split (#71, multi-instance ADR § The
// handoff and the workspace session).
//
// A workspace session is a session row in every locked mechanical respect, and
// it resolves through the ordinary session machinery. What is NOT ordinary is
// which entry points admit it:
//
//	AuthenticateCaller  -> admits it (the data plane; the workspace is just
//	                       another client of the remote's ordinary /api/v1)
//	Authenticate        -> refuses it (the account-security surface: logout,
//	                       factor enrolment, passkeys, identity linking,
//	                       step-up)
//
// That split is a security property, not a tidiness one. A workspace bearer
// lives in ANOTHER ORIGIN'S JAVASCRIPT and the ADR states plainly that it is
// extractable. If it could reach the account-security surface, an XSS on the
// viewing origin would be able to enrol a factor or remove a passkey on the
// remote — turning a bounded, revocable, short-lived credential into permanent
// account takeover. The blast radius the ADR accepts is "the compromised
// human's grants per remote"; this is what keeps it there.
//
// The test seeds a REAL workspace session row, because "Authenticate refuses
// it" is only meaningful when the row exists. Against a missing row, refusal
// and non-existence are indistinguishable and the assertion would pass against
// a broken split.
func TestWorkspaceSessionIsAdmittedOnlyByAuthenticateCaller(t *testing.T) {
	db := seededDB(t, openSQLite)

	value, verifier, err := crypto.NewArtifact(crypto.ArtifactWorkspaceSession)
	if err != nil {
		t.Fatalf("mint workspace artifact: %v", err)
	}

	const origin = workspaceTestOrigin
	now := time.Now().UTC()
	seedWorkspaceSession(t, db, alice, verifier, origin, now)

	// The data plane resolves it, as a workspace artifact.
	id := authenticateCaller(t, db, value)
	if id.Principal != alice {
		t.Fatalf("AuthenticateCaller did not resolve a live workspace session (principal %q)", id.Principal)
	}
	if id.Artifact != "workspace" {
		// NOTE the value: session rows carry the DATABASE's artifact string,
		// not the bearer grammar's two-letter type. Anything keyed on
		// crypto.ArtifactWorkspaceSession ("ws") will not match this.
		t.Errorf("artifact = %q, want %q", id.Artifact, "workspace")
	}
	if len(id.CSRFVerifier) != 0 {
		t.Error("a workspace session carries a CSRF verifier; the bearer rides an Authorization " +
			"header, nothing is ambient, and there is no synchronizer token to demand")
	}

	// The account-security surface refuses the very same value.
	err = tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		_, authErr := az.Authenticate(ctx, value, time.Now().UTC())
		if !errors.Is(authErr, domain.ErrUnauthenticated) {
			t.Errorf("Authenticate accepted a workspace bearer (err = %v). The account-security "+
				"surface must refuse it by construction: an XSS on the viewing origin would "+
				"otherwise reach the human's factors on the remote", authErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	// And a CLI session still resolves through both, so the refusal above is
	// the artifact split firing rather than the whole surface being closed.
	cli := sessionWithWindows(t, db, bob)
	err = tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		if _, authErr := az.Authenticate(ctx, cli, time.Now().UTC()); authErr != nil {
			t.Errorf("Authenticate refused an ordinary CLI session: %v", authErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("authenticate cli: %v", err)
	}
}

// Removing an origin from the allowlist must kill every session bound to it,
// atomically — the ADR's "de-allowlisting is a real kill switch, not a headers
// change". The revocation statement is not written yet, so this asserts the
// SCHEMA half that makes it a one-statement operation: the binding column
// exists, is populated, and is indexed for exactly this sweep.
func TestWorkspaceSessionsAreBoundToTheirRequestingOrigin(t *testing.T) {
	db := seededDB(t, openSQLite)

	value, verifier, err := crypto.NewArtifact(crypto.ArtifactWorkspaceSession)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	const origin = workspaceTestOrigin
	seedWorkspaceSession(t, db, alice, verifier, origin, time.Now().UTC())

	if authenticateCaller(t, db, value).Principal == "" {
		t.Fatal("the workspace session did not authenticate before the sweep")
	}

	// The kill switch, as one statement over one indexed column. When the
	// service layer lands this moves behind an allowlist-removal method; the
	// property asserted here is that the schema makes it atomic.
	execRaw(t, db, `DELETE FROM sessions WHERE requesting_origin = '`+origin+`'`)

	if id := authenticateCaller(t, db, value); id.Principal != "" {
		t.Fatal("a workspace session survived removal of the origin it is bound to")
	}
}

// seedWorkspaceSession writes a workspace session row directly. It is raw SQL
// because authz.NewSession has no origin/handoff fields yet — those arrive with
// the issuance path — and the point here is the RESOLUTION behaviour, which
// reads the row whatever wrote it.
func seedWorkspaceSession(t *testing.T, db *store.DB, p domain.PrincipalID, verifier []byte, origin string, now time.Time) {
	t.Helper()

	var generation, epoch int64
	err := tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		var err error
		if generation, err = az.PrincipalGeneration(ctx, p); err != nil {
			return err
		}
		epoch, err = az.CredentialEpoch(ctx)
		return err
	})
	if err != nil {
		t.Fatalf("read generation/epoch: %v", err)
	}

	stamp := "'" + now.Format("2006-01-02T15:04:05.000000Z") + "'"
	future := "'" + now.Add(time.Hour).Format("2006-01-02T15:04:05.000000Z") + "'"

	execRaw(t, db, `INSERT INTO sessions (
		id, principal_id, verifier, artifact, session_generation, credential_epoch,
		auth_method, factors, authenticated_at, ceremony_id, created_at, last_seen_at,
		idle_expires_at, absolute_expires_at, source_ip, user_agent,
		requesting_origin, handoff_id
	) VALUES (
		'ses_ws_`+string(p)+`', '`+string(p)+`', X'`+hex.EncodeToString(verifier)+`', 'workspace',
		`+strconv.FormatInt(generation, 10)+`, `+strconv.FormatInt(epoch, 10)+`,
		'local', '["password","totp"]', `+stamp+`, NULL, `+stamp+`, `+stamp+`,
		`+future+`, `+future+`, '127.0.0.1', 'test',
		'`+origin+`', 'hof_test'
	)`)
}

// authenticateCaller resolves through the data-plane entry point.
func authenticateCaller(t *testing.T, db *store.DB, presented string) authz.Identity {
	t.Helper()
	return authenticateCallerFrom(t, db, presented, workspaceTestOrigin)
}

// workspaceTestOrigin is the origin every seeded workspace session in this file
// is bound to.
const workspaceTestOrigin = "https://hikyo.went.io"

// browserCtx simulates the ONLY request shape a workspace bearer legitimately
// arrives on: a cross-origin call from the shell it was issued to, carrying
// that shell's Origin header. In-process test callers have no wire metadata at
// all, and the authentication leg reads absence as mismatch — correctly, since
// a workspace bearer presented without an Origin is a bearer presented from
// somewhere that is not a browser at the consented origin.
func browserCtx(ctx context.Context, origin string) context.Context {
	return audit.WithContext(ctx, audit.Context{Origin: audit.OriginAPI, RequestOrigin: origin})
}

// authenticateCallerFrom resolves a bearer as if presented from `origin`.
func authenticateCallerFrom(t *testing.T, db *store.DB, presented, origin string) authz.Identity {
	t.Helper()
	var out authz.Identity
	err := tx.Write(browserCtx(t.Context(), origin), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		id, err := az.AuthenticateCaller(ctx, presented, time.Now().UTC())
		if errors.Is(err, domain.ErrUnauthenticated) {
			return nil
		}
		if err != nil {
			return err
		}
		out = id
		return nil
	})
	if err != nil {
		t.Fatalf("authenticateCaller: %v", err)
	}
	return out
}

// THE ORIGIN BINDING IS AN AUTHENTICATION PREDICATE, not just a revocation key.
//
// A workspace bearer is issued to exactly one origin. Before this it could be
// lifted out of allowlisted shell A and replayed from allowlisted shell B — the
// allowlist was the only gate, and an allowlist admits every consented origin
// rather than the one this session belongs to. Two allowlisted origins is the
// homelab's normal case (a laptop shell and a phone shell), so this is not a
// hypothetical arrangement.
func TestWorkspaceSessionRefusesAForeignOrigin(t *testing.T) {
	db := seededDB(t, openSQLite)
	value, verifier, err := crypto.NewArtifact(crypto.ArtifactWorkspaceSession)
	if err != nil {
		t.Fatal(err)
	}
	seedWorkspaceSession(t, db, alice, verifier, workspaceTestOrigin, time.Now().UTC())

	if id := authenticateCallerFrom(t, db, value, workspaceTestOrigin); id.Principal != alice {
		t.Fatalf("the bearer did not authenticate from its OWN origin (principal %q)", id.Principal)
	}
	for _, from := range []struct{ name, origin string }{
		{"another allowlisted shell", "https://other.went.io"},
		{"no Origin header at all", ""},
		{"a prefix of its own origin", "https://hikyo.went"},
	} {
		if id := authenticateCallerFrom(t, db, value, from.origin); id.Principal != "" {
			t.Errorf("%s: a workspace bearer bound to %s authenticated from %q — the binding "+
				"is stored but not enforced", from.name, workspaceTestOrigin, from.origin)
		}
	}

	// A CLI session has no bound origin and is untouched by the predicate: it
	// authenticates with an Origin header, without one, and with a foreign one.
	cli := sessionWithWindows(t, db, bob)
	for _, origin := range []string{"", workspaceTestOrigin, "https://elsewhere.example"} {
		if id := authenticateCallerFrom(t, db, cli, origin); id.Principal != bob {
			t.Errorf("a CLI session was refused for Origin %q — the origin predicate must "+
				"look at workspace rows only", origin)
		}
	}
}

// THE SELF-SCOPED SURFACE IS CONFINED TOO (acceptance criterion 4, at the
// endpoint rather than at the operation).
//
// `GET /api/v1/me/sessions` and its DELETE call no operation — deliberately, so
// incident response never depends on an authority an attacker may have just
// removed — which means the artifact-eligibility chokepoint never sees them.
// They were therefore the one door an instance-connection credential could
// walk through, and a workspace bearer could use to enumerate and end the
// human's CLI and browser sessions, IP addresses and user agents included.
func TestSelfSessionSurfaceConfinesForeignArtifacts(t *testing.T) {
	db := seededDB(t, openSQLite)
	ctx := t.Context()
	ws := stepUpWorkspace(t, db)
	if _, err := ws.AddOrigin(ctx, service.LocalPrincipal(root), stepUpOrigin); err != nil {
		t.Fatal(err)
	}

	// An instance-connection credential authenticates for its ONE operation and
	// must reach nothing here at all.
	conn := mintInstanceConnection(t, db, "selfsurface")
	if _, err := ws.ListSessions(ctx, service.Bearer(conn)); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Errorf("an instance-connection credential reached the session listing (%v) — "+
			"an operation-less endpoint is exactly where the eligibility table cannot "+
			"confine it, so the admitting set has to", err)
	}
	if err := ws.RevokeSession(ctx, service.Bearer(conn), "ses_anything"); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Errorf("an instance-connection credential reached the session revoke (%v)", err)
	}

	// The SAME door on /me/orgs, which is the other operation-less self-scoped
	// projection and predates #71. It calls no operation either, so the
	// eligibility chokepoint is equally blind to it, and an instance-connection
	// credential presented there used to authenticate and receive a successful
	// listing — the same endpoint-level criterion-4 failure, one route over.
	orgs := &service.Orgs{DB: db}
	if _, err := orgs.ListMine(ctx, service.Bearer(conn)); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Errorf("an instance-connection credential enumerated a principal's organisations (%v)", err)
	}

	// A workspace bearer sees ITS OWN ROW and nothing else. The human's CLI
	// sessions are on the same account and must stay invisible to a credential
	// living in another origin's JavaScript.
	approver := seedSessionFactors(t, db, root, `["password","totp"]`)
	established := establishWorkspace(t, ws, approver)
	shell := browserCtx(ctx, stepUpOrigin)

	all, err := ws.ListSessions(ctx, service.Bearer(approver))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 2 {
		t.Fatalf("the account holds %d sessions; the narrowing below would prove nothing", len(all))
	}
	mine, err := ws.ListSessions(shell, service.Bearer(established.Value))
	if err != nil {
		t.Fatalf("the workspace bearer cannot read its own row: %v — the shell's liveness "+
			"poll is this endpoint, and both kill switches become visible through it", err)
	}
	if len(mine) != 1 || mine[0].ID != established.SessionID {
		t.Fatalf("a workspace bearer listed %d sessions (%+v), want exactly its own", len(mine), mine)
	}

	// And it cannot end anybody else's.
	otherID := sessionIDOf(t, db, approver)
	if err := ws.RevokeSession(shell, service.Bearer(established.Value), otherID); err == nil {
		t.Error("a workspace bearer revoked the human's CLI session — an XSS on the viewing " +
			"origin would be able to log the human out of their own terminal")
	}
	// A workspace bearer keeps /me/orgs, deliberately: it is a session of this
	// instance holding exactly this human's own grants, and the projection
	// reports nothing outside the ADR's stated blast radius for it.
	if _, err := orgs.ListMine(shell, service.Bearer(established.Value)); err != nil {
		t.Errorf("a workspace bearer was refused its own organisation list: %v — the shell "+
			"needs it to render, and it reports only grants the human already holds", err)
	}

	// Self-termination stays available: it is the shell's own disconnect.
	if err := ws.RevokeSession(shell, service.Bearer(established.Value), established.SessionID); err != nil {
		t.Errorf("a workspace bearer cannot end its own session: %v", err)
	}
}
