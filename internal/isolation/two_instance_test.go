package isolation

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dunky13/hikyo/api"
	"github.com/Dunky13/hikyo/internal/remotefetch"
	"github.com/Dunky13/hikyo/internal/server"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/migrate"
)

// The two-instance harness (#71, M6's recast of acceptance criterion 6).
//
// TWO INSTANCES, two datastores, two HTTP surfaces — A views, B serves. What
// this proves that the single-process lifecycle test cannot:
//
//  1. A's directory reaches B over a REAL pinned TLS connection to B's REAL
//     router, so the served listing and the fetched listing are the same
//     contract rather than two hand-written shapes that happen to agree.
//  2. THE VIEWING SERVER ORIGINATES NO CONNECTION DURING WORKSPACE USE. That is
//     the criterion, and it is asserted with the counting dialer every outbound
//     connection in the process goes through — so "it did not move" is a
//     measurement, not a claim.
//
// The workspace calls in this test are made by an HTTP client that is NOT A's
// server. That is the architecture, expressed as a test: the browser talks to
// the remote directly, and A's server contributes the shell, the directory and
// the deep link and nothing else. If someone later routes a workspace call
// through A, the dial counter moves and this fails.

// instanceUnderTest is one running hikyo: its datastore, its services and its
// TLS surface with the SPKI pin a peer would store.
type instanceUnderTest struct {
	db        *store.DB
	remotes   *service.Remotes
	workspace *service.Workspace
	server    *httptest.Server
	pin       string
}

func newInstance(t *testing.T, name string) *instanceUnderTest {
	t.Helper()
	// A distinct file per instance: t.TempDir() is per-test, so two instances
	// sharing the default name would share a datastore and prove nothing.
	cfg := store.Config{Engine: store.EngineSQLite, Path: filepath.Join(t.TempDir(), name+".db")}
	if err := migrate.Run(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	auth := authService(t, db)
	client, err := remotefetch.New(remotefetch.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	inst := &instanceUnderTest{
		db:        db,
		remotes:   &service.Remotes{DB: db, Keyring: auth.Keyring, Fetch: client},
		workspace: &service.Workspace{DB: db, Version: "test"},
	}
	// The REAL router, with the real middleware chain: CORS, the security
	// headers, the artifact extraction and the strict handler. A hand-rolled
	// mux here would test the service layer twice and the transport never.
	handler := server.New(
		&service.System{DB: db, Store: cfg},
		&server.API{
			// Auth is wired because the middleware chain slides the session
			// idle clock on every request; a nil one panics before any handler
			// runs, and the symptom is an EOF at the TLS layer that looks
			// nothing like a missing dependency.
			Auth:    auth,
			Remotes: inst.remotes, Workspace: inst.workspace, Version: "test",
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		nil,
	)
	inst.server = httptest.NewTLSServer(handler)
	t.Cleanup(inst.server.Close)
	inst.pin = remotefetch.SPKIFingerprint(inst.server.Certificate())
	return inst
}

// browser is the workspace tier's actor: an HTTP client that is not either
// server. It ignores WebPKI for the test's self-signed certificate, which is
// exactly the trust model the ADR states for this tier — the browser's own
// WebPKI, never the connection pin, and a test CA is the local equivalent.
func (i *instanceUnderTest) browser() *http.Client { return i.server.Client() }

func (i *instanceUnderTest) post(t *testing.T, path, bearer, origin string, body any, out any) int {
	t.Helper()
	var payload *strings.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		payload = strings.NewReader(string(raw))
	} else {
		payload = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, i.server.URL+path, payload)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := i.browser().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
	return resp.StatusCode
}

func TestTwoInstancesDirectoryAndWorkspace(t *testing.T) {
	a := newInstance(t, "viewing")
	b := newInstance(t, "serving")

	adminA := service.LocalPrincipal(root)
	adminB := service.LocalPrincipal(root)
	grantInstanceDirectory(t, a.db)
	grantInstanceDirectory(t, b.db)

	ctx := t.Context()

	// B mints a directory credential and consents to A's UI origin.
	minted, err := b.workspace.MintConnection(ctx, adminB, "instance-a", service.MintRequest{})
	if err != nil {
		t.Fatalf("B mints a connection: %v", err)
	}
	originA := a.server.URL
	if _, err := b.workspace.AddOrigin(ctx, adminB, originA); err != nil {
		t.Fatalf("B allowlists A's origin: %v", err)
	}

	// A adds B. This is the ONE place A's server is supposed to originate a
	// connection, and the verifying fetch goes through B's real router.
	added, err := a.remotes.AddRemote(ctx, adminA, "b", b.server.URL, b.pin, minted.Value)
	if err != nil {
		t.Fatalf("A adds B: %v", err)
	}
	if added.Identity == "" {
		t.Fatal("the verifying fetch returned no instance identity")
	}
	if added.OrgCount == 0 {
		t.Fatal("B's listing carried no organisations; the fixtures should have seeded some")
	}

	// Criterion 1's self-connection leg: pointing an entry at A's OWN url is
	// refused BY INSTANCE IDENTITY at the authenticated fetch, not guessed
	// from the URL.
	selfCred, err := a.workspace.MintConnection(ctx, adminA, "self", service.MintRequest{})
	if err != nil {
		t.Fatalf("A mints a credential for the self-connection probe: %v", err)
	}
	if _, err := a.remotes.AddRemote(ctx, adminA, "myself", a.server.URL, a.pin, selfCred.Value); err == nil {
		t.Fatal("A accepted itself as a remote; self-connection must be refused at the authenticated fetch")
	}

	// ------------------------------------------------------------------
	// Criterion 6's harness half.
	// ------------------------------------------------------------------
	//
	// From here on, every call is the BROWSER talking to B directly. A's
	// server must originate nothing, and the counting dialer is what says so.
	before := remotefetch.Dials()

	verifier := "two-instance-pkce-verifier-value-long-enough"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	var started struct {
		Handoff string `json:"handoff"`
		State   string `json:"state"`
	}
	code := a.server.URL + "/workspace/callback"
	if status := b.post(t, api.PathPrefix+"/auth/workspace/start", "", originA, map[string]any{
		"origin": originA, "redirect_uri": code,
		"pkce_challenge": challenge, "purpose": "establishment",
	}, &started); status != http.StatusCreated {
		t.Fatalf("start handoff: status %d", status)
	}

	// Approval is the human, in the popup, on B's own origin.
	humanB := seedCLISession(t, b.db, root)
	var approved struct {
		Code        string `json:"code"`
		RedirectURI string `json:"redirect_uri"`
	}
	if status := b.post(t, api.PathPrefix+"/auth/workspace/approve", humanB, originA, map[string]any{
		"state": started.State,
	}, &approved); status != http.StatusOK {
		t.Fatalf("approve handoff: status %d", status)
	}

	var ws struct {
		Value   string `json:"value"`
		Session string `json:"session"`
	}
	if status := b.post(t, api.PathPrefix+"/auth/workspace/redeem", "", originA, map[string]any{
		"code": approved.Code, "pkce_verifier": verifier, "origin": originA,
	}, &ws); status != http.StatusCreated {
		t.Fatalf("redeem handoff: status %d", status)
	}
	if ws.Value == "" {
		t.Fatal("redemption disclosed no workspace bearer")
	}

	// THE ASSERTION. Everything since `before` was browser→B. A's server ran
	// no fetch round, so the process originated no new connection through the
	// one dialer that can originate one.
	if after := remotefetch.Dials(); after != before {
		t.Errorf("the server originated %d connection(s) during workspace use; "+
			"the workspace tier is the BROWSER talking to the remote directly, and a "+
			"server-side hop here is the proxy design the ADR rejected", after-before)
	}

	// ------------------------------------------------------------------
	// Criterion 3's kill switch, across two instances.
	// ------------------------------------------------------------------
	killed, err := b.workspace.RemoveOrigin(ctx, adminB, originA)
	if err != nil {
		t.Fatalf("B de-allowlists A: %v", err)
	}
	if killed != 1 {
		t.Errorf("de-allowlisting killed %d workspace sessions, want 1 — removal must be a real kill switch", killed)
	}
	// And a NEW handoff refuses at the transaction, not merely at CORS.
	if status := b.post(t, api.PathPrefix+"/auth/workspace/start", "", originA, map[string]any{
		"origin": originA, "redirect_uri": code,
		"pkce_challenge": challenge, "purpose": "establishment",
	}, nil); status != http.StatusForbidden {
		t.Errorf("a handoff from a de-allowlisted origin returned %d, want 403", status)
	}

	// ------------------------------------------------------------------
	// Criterion 1's revocation leg: B revokes, A shows credential-rejected.
	// ------------------------------------------------------------------
	if err := b.workspace.RevokeConnection(ctx, adminB, minted.Connection.ID); err != nil {
		t.Fatalf("B revokes the credential: %v", err)
	}
	view, err := a.remotes.ShowRemote(ctx, adminA, "b")
	if err != nil {
		t.Fatalf("A views B after revocation: %v", err)
	}
	if view.State != string(remotefetch.OutcomeCredentialRejected) {
		t.Errorf("A shows state %q after B revoked, want credential-rejected — the operator's fix differs from unreachable", view.State)
	}
	if !view.Stale {
		t.Error("A must mark the listing stale rather than serve it as current")
	}
	if view.OrgCount == 0 {
		t.Error("A discarded the last-known listing; \"unreachable, last known state shown\" depends on keeping it")
	}
}

// TestZeroRemotesOriginateZeroConnections is the air-gap statement as a
// measurement. It is the other half of the dial instrumentation: the criterion
// asks that a workspace flow adds nothing, and the ADR asks that an instance
// with no remotes adds nothing at all.
func TestZeroRemotesOriginateZeroConnections(t *testing.T) {
	a := newInstance(t, "airgapped")
	grantInstanceDirectory(t, a.db)

	before := remotefetch.Dials()
	views, err := a.remotes.ListRemotes(t.Context(), service.LocalPrincipal(root))
	if err != nil {
		t.Fatalf("list an empty directory: %v", err)
	}
	if len(views) != 0 {
		t.Fatalf("an unconfigured instance listed %d remotes", len(views))
	}
	if after := remotefetch.Dials(); after != before {
		t.Errorf("an instance with zero configured remotes originated %d connection(s)", after-before)
	}
}

func grantInstanceDirectory(t *testing.T, db *store.DB) {
	t.Helper()
	seedInstanceFixtures(t, db)
	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
		`VALUES ('g_ti_dir', 'usr_root', 'instance-directory', NULL, NULL, NULL, `+ts+`)`)
	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
		`VALUES ('g_ti_cfg', 'usr_root', 'instance-config', NULL, NULL, NULL, `+ts+`)`)
}

// seedInstanceFixtures gives an instance the minimum a directory listing needs
// to be non-empty: the root principal and one org with one project.
func seedInstanceFixtures(t *testing.T, db *store.DB) {
	t.Helper()
	execRaw(t, db, `INSERT INTO principals (id, kind, created_at, session_generation) VALUES ('usr_root', 'human', `+ts+`, 1)`)
	execRaw(t, db, `INSERT INTO orgs (id, name, active, metadata, created_at) VALUES ('org_ti', 'acme', 1, '{}', `+ts+`)`)
	execRaw(t, db, `INSERT INTO projects (id, org_id, name, created_at) VALUES ('prj_ti', 'org_ti', 'api', `+ts+`)`)
}
