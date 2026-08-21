package isolation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/remotefetch"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/authn"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// The multi-instance service surface, end to end (#71).
//
// This is the seam test for both tiers, and it is what makes the thirteen
// registered `remote.*` audit types real rather than declared: every one of
// them is emitted here by the code that owns it, against a real database, with
// a real pinned TLS peer standing in for the serving instance.
//
// The fake peer is a real `httptest.NewTLSServer` and the pin is that server's
// OWN SPKI fingerprint, so the pin verification the ADR calls normative
// actually runs — a stubbed client would have proven the plumbing and nothing
// about the trust model.

// fakeRemote is a serving instance: a TLS server answering the directory path
// with a listing, whose SPKI fingerprint is the pin the viewing side stores.
type fakeRemote struct {
	server   *httptest.Server
	pin      string
	identity string
	// reject flips the peer to answering 401, which is the credential-rejected
	// state — distinct from unreachable, because the operator's fix differs.
	reject bool
}

func newFakeRemote(t *testing.T, identity string) *fakeRemote {
	t.Helper()
	f := &fakeRemote{identity: identity}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.reject {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/instance/directory" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		listing := remotefetch.Listing{
			Identity: f.identity, Version: "test",
			Orgs: []remotefetch.OrgEntry{{Name: "acme", Projects: []string{"api", "web"}}},
		}
		// Derived, never hand-written: the ingest check refuses a listing whose
		// counts disagree with its names, and a fixture that hard-coded them
		// would eventually disagree with its own fixture.
		listing.OrgCount, listing.ProjectCount = len(listing.Orgs), listing.CountProjects()
		_ = json.NewEncoder(w).Encode(listing)
	}))
	t.Cleanup(f.server.Close)
	f.pin = remotefetch.SPKIFingerprint(f.server.Certificate())
	return f
}

func remoteSvcs(t *testing.T, db *store.DB) (*service.Remotes, *service.Workspace) {
	t.Helper()
	auth := authService(t, db)
	client, err := remotefetch.New(remotefetch.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return &service.Remotes{DB: db, Keyring: auth.Keyring, Fetch: client},
		&service.Workspace{DB: db, Version: "test"}
}

// runRemoteLifecycle drives every #71 service verb once, so the audit
// completeness check downstream reads trails a real emitter filled.
func runRemoteLifecycle(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := t.Context()
	remotes, workspace := remoteSvcs(t, db)
	admin := service.LocalPrincipal(root)

	// `root` holds instance-config from the shared fixtures; instance-directory
	// is this ticket's own atom and has to be granted like any other.
	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
		`VALUES ('g_rmt_dir', 'usr_root', 'instance-directory', NULL, NULL, NULL, `+ts+`)`)

	// --- serving side -------------------------------------------------------

	minted, err := workspace.MintConnection(ctx, admin, "peer-b", service.MintRequest{})
	if err != nil {
		t.Fatalf("remote.credential_minted: %v", err)
	}
	if minted.Value == "" {
		t.Fatal("the mint disclosed no value — the one disclosure that exists must happen")
	}
	if _, err := workspace.ListConnections(ctx, admin); err != nil {
		t.Fatalf("remote.credentials_listed: %v", err)
	}
	if _, err := workspace.ShowConnection(ctx, admin, minted.Connection.ID); err != nil {
		t.Fatalf("remote-credential.show: %v", err)
	}

	// The directory this instance serves, presented by the credential it just
	// minted — through the REAL chokepoint, so the confinement is exercised
	// rather than assumed.
	listing, err := workspace.Serve(ctx, service.Bearer(minted.Value))
	if err != nil {
		t.Fatalf("remote.directory_served: %v", err)
	}
	if listing.Identity == "" {
		t.Fatal("the served listing carries no instance identity — self-connection refusal depends on it")
	}

	// ACTOR CORRECTNESS, not merely "the event exists". The registry declares
	// who this event names, and the sweep that checks every type is emitted
	// cannot tell an event attributed to the connection from one attributed to
	// nobody. The serve above ran under the connection credential, so the row
	// must carry that principal and say which class it is.
	assertServedActor(t, db, string(minted.Connection.Principal), "instance-connection")

	// The SAME operation reached by a NON-CONNECTION holder. It is a legitimate
	// emitter — the ADR grants the directory hop to humans who work across
	// instances — and it must attribute to that principal, with no connection
	// id and a class that is visibly not `instance-connection`. Here the holder
	// is local host authority, which is the shape the harness has; the point
	// asserted is that the event does NOT claim to be a connection's fetch.
	if _, err := workspace.Serve(ctx, admin); err != nil {
		t.Fatalf("a directory-holding caller must reach the listing: %v", err)
	}
	assertServedActor(t, db, string(root), "local-authority")

	if _, err := workspace.AddOrigin(ctx, admin, "https://shell.example"); err != nil {
		t.Fatalf("remote.origin_allowlist_changed (added): %v", err)
	}
	if _, err := workspace.ListOrigins(ctx, admin); err != nil {
		t.Fatalf("remote.origin_allowlist_read: %v", err)
	}

	verifierSeed := sha256.Sum256([]byte("remote lifecycle PKCE verifier"))
	verifier := base64.RawURLEncoding.EncodeToString(verifierSeed[:])
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// A handoff refused at the transaction, which is the failure event's
	// `start` stage. The origin is not allowlisted, and the refusal must still
	// be audited even though the transaction rolls back — that is why the
	// event rides the durable settlement path.
	if _, err := workspace.StartHandoff(ctx, service.HandoffRequest{
		Origin: "https://hostile.example", RedirectURI: "https://hostile.example/cb",
		PKCEChallenge: challenge, Purpose: authn.HandoffEstablishment,
	}); !errors.Is(err, service.ErrOriginNotAllowed) {
		t.Fatalf("a non-allowlisted origin must be refused at the transaction, got %v", err)
	}

	// The full establishment arc against the allowlisted origin.
	started, err := workspace.StartHandoff(ctx, service.HandoffRequest{
		Origin: "https://shell.example", RedirectURI: "https://shell.example/workspace/callback",
		PKCEChallenge: challenge, Purpose: authn.HandoffEstablishment,
	})
	if err != nil {
		t.Fatalf("start handoff: %v", err)
	}
	// Approval runs as a HUMAN SESSION on this instance's own origin. A seeded
	// session is the point: against a missing row, "refused" and "does not
	// exist" are indistinguishable, and the test would pass against a broken
	// approval path.
	humanBearer := seedCLISession(t, db, root)
	code, redirect, err := workspace.ApproveHandoff(ctx, service.Bearer(humanBearer), started.State)
	if err != nil {
		t.Fatalf("approve handoff: %v", err)
	}
	if redirect != "https://shell.example/workspace/callback" {
		t.Fatalf("the code must be delivered to the pre-registered callback, got %q", redirect)
	}
	ws, err := workspace.RedeemHandoff(ctx, code, verifier, "https://shell.example")
	if err != nil {
		t.Fatalf("remote.workspace_session_issued: %v", err)
	}

	// A step-up transaction, and the approve page reading its bound policy back:
	// remote.workspace_handoff_read. Only START + READ here — the elevation
	// itself needs the reauthentication seam this lifecycle deliberately leaves
	// unwired; the read does not, and it is the audited act under test.
	stepUp, err := workspace.StartHandoff(ctx, service.HandoffRequest{
		Origin: "https://shell.example", RedirectURI: "https://shell.example/workspace/callback",
		PKCEChallenge: challenge, Purpose: authn.HandoffStepUp,
		SessionID: ws.SessionID, Operation: string(authz.OpValueReveal),
		EnvID: "env_lifecycle", KeySet: "key_x",
	})
	if err != nil {
		t.Fatalf("start step-up handoff: %v", err)
	}
	if _, err := workspace.ShowHandoff(ctx, service.Bearer(humanBearer), stepUp.State); err != nil {
		t.Fatalf("remote.workspace_handoff_read: %v", err)
	}
	// Ownership: a DIFFERENT human, with a valid session but not the one the
	// transaction bound, is refused as if the state did not exist — the leak the
	// endpoint's session check exists to close.
	otherBearer := seedCLISession(t, db, custodian)
	if _, err := workspace.ShowHandoff(ctx, service.Bearer(otherBearer), stepUp.State); !errors.Is(err, service.ErrHandoffInvalid) {
		t.Fatalf("a step-up transaction read by a non-owner must be refused, got %v", err)
	}

	// Single use: the same code again is refused, and the refusal is audited
	// as a redeem-stage failure.
	if _, err := workspace.RedeemHandoff(ctx, code, verifier, "https://shell.example"); !errors.Is(err, service.ErrHandoffInvalid) {
		t.Fatalf("a consumed code must be refused, got %v", err)
	}
	// AND IT NAMES WHO. The transaction was approved, so the principal who
	// approved it is known at the moment of refusal; constructing every handoff
	// failure as anonymous discarded the one fact an operator investigating a
	// run of refusals would act on. The uniform ErrHandoffInvalid the CALLER
	// sees is unchanged — the cause and the actor live on the trail only.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_instance_events `+
		`WHERE type = 'remote.handoff_failed' AND actor_id = '`+string(root)+
		`' AND payload LIKE '%"stage":"redeem"%'`); n == 0 {
		t.Error("the second redemption's refusal was audited with no actor, though the " +
			"transaction it refused had already been approved by a known principal. " +
			"handoffFailure used to construct every event anonymously, which threw away " +
			"the one fact an operator investigating a run of refusals would act on")
	}
	// And a PRE-AUTHENTICATION refusal stays anonymous, because there genuinely
	// is nobody to name: the start-stage refusal above (a non-allowlisted
	// origin probing) happened before anyone authenticated.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM audit_instance_events `+
		`WHERE type = 'remote.handoff_failed' AND actor_id IS NULL `+
		`AND payload LIKE '%"stage":"start"%'`); n == 0 {
		t.Error("the start-stage refusal did not record as anonymous — absence is a " +
			"structural fact here, and inventing an actor for it would be worse than none")
	}

	// The workspace session appears in the caller's own list AS ITS OWN
	// ARTIFACT TYPE — criterion 5's first half.
	sessions, err := workspace.ListSessions(ctx, service.Bearer(humanBearer))
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	sawWorkspace := false
	for _, s := range sessions {
		if s.ID == ws.SessionID {
			sawWorkspace = true
			if s.Artifact != "workspace" {
				t.Errorf("the workspace session lists as artifact %q, want \"workspace\"", s.Artifact)
			}
			if s.RequestingOrigin != "https://shell.example" {
				t.Errorf("the listed session carries origin %q", s.RequestingOrigin)
			}
		}
	}
	if !sawWorkspace {
		t.Error("the workspace session is absent from the active-session listing — criterion 5 depends on it")
	}

	// Explicit revocation — criterion 5's second half.
	if err := workspace.RevokeSession(ctx, service.Bearer(humanBearer), ws.SessionID); err != nil {
		t.Fatalf("remote.workspace_session_revoked: %v", err)
	}
	// And the ordinary-session revoke, which lands as a logout rather than a
	// #71 type: same verb, different event, because the trail already has that
	// fact's vocabulary.
	other := seedCLISession(t, db, root)
	otherID := sessionIDOf(t, db, other)
	if err := workspace.RevokeSession(ctx, service.Bearer(humanBearer), otherID); err != nil {
		t.Fatalf("revoke an ordinary session: %v", err)
	}

	// --- viewing side -------------------------------------------------------

	peer := newFakeRemote(t, "ins_peer_b")
	added, err := remotes.AddRemote(ctx, admin, "peer-b", peer.server.URL, peer.pin, minted.Value)
	if err != nil {
		t.Fatalf("remote.added: %v", err)
	}
	if added.Identity != "ins_peer_b" {
		t.Fatalf("the verifying fetch did not record the peer identity, got %q", added.Identity)
	}
	if _, err := remotes.ListRemotes(ctx, admin); err != nil {
		t.Fatalf("remote.directory_viewed: %v", err)
	}
	if _, err := remotes.ShowRemote(ctx, admin, "peer-b"); err != nil {
		t.Fatalf("remote.show: %v", err)
	}

	// Credential rejected is its OWN loud state, distinct from unreachable.
	// The coalescing window would otherwise serve the previous round, so the
	// gate is reset by asking for the single entry after the peer flips.
	peer.reject = true
	resetFetchGate(t, remotes)
	after, err := remotes.ShowRemote(ctx, admin, "peer-b")
	if err != nil {
		t.Fatalf("remote.fetch_failed: %v", err)
	}
	if after.State != string(remotefetch.OutcomeCredentialRejected) {
		t.Errorf("a 401 from the peer is state %q, want credential-rejected — the operator's fix differs", after.State)
	}
	if !after.Stale {
		t.Error("a failed fetch must mark the snapshot stale rather than serve it as current")
	}
	peer.reject = false

	renamed, err := remotes.RenameRemote(ctx, admin, "peer-b", "peer-b-renamed")
	if err != nil {
		t.Fatalf("remote.renamed: %v", err)
	}
	if renamed.State != after.State || !renamed.LastAttemptAt.Equal(store.CanonTime(after.LastAttemptAt)) ||
		renamed.Identity != after.Identity || renamed.OrgCount != after.OrgCount || !renamed.Stale {
		t.Errorf("rename discarded the last-known snapshot: before=%+v after=%+v", after, renamed)
	}
	for _, invalidName := range []string{" leading", "trailing ", "line\nbreak", string([]byte{0xff})} {
		if _, err := remotes.RenameRemote(ctx, admin, "peer-b-renamed", invalidName); err == nil {
			t.Errorf("remote rename accepted invalid name %q", invalidName)
		}
	}
	if err := remotes.RemoveRemote(ctx, admin, "peer-b-renamed"); err != nil {
		t.Fatalf("remote.removed: %v", err)
	}

	// The kill switch, last: removing the origin must also revoke sessions.
	if _, err := workspace.RemoveOrigin(ctx, admin, "https://shell.example"); err != nil {
		t.Fatalf("remote.origin_allowlist_changed (removed): %v", err)
	}
	if err := workspace.RevokeConnection(ctx, admin, minted.Connection.ID); err != nil {
		t.Fatalf("remote.credential_revoked: %v", err)
	}
}

// resetFetchGate clears the coalescing window so a test can observe two
// distinct rounds. Production has no such door: the window exists precisely so
// concurrent viewers share one fetch.
func resetFetchGate(t *testing.T, r *service.Remotes) {
	t.Helper()
	// A fresh service value has a fresh gate, and nothing else about Remotes
	// is stateful — reassigning is smaller than exporting a reset.
	*r = service.Remotes{DB: r.DB, Keyring: r.Keyring, Fetch: r.Fetch, Now: r.Now}
}

// seedCLISession mints a real CLI session row for `p` and returns the bearer.
// A REAL row is the point: a fabricated value would make "refused" and "does
// not exist" indistinguishable at every assertion that depends on it.
func seedCLISession(t *testing.T, db *store.DB, p domain.PrincipalID) string {
	t.Helper()
	value, verifier, err := crypto.NewArtifact(crypto.ArtifactCLISession)
	if err != nil {
		t.Fatal(err)
	}
	id, err := crypto.RandomBytes(8)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	err = tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		return az.MintSession(ctx, authn.NewSession{
			ID: "ses_" + base64.RawURLEncoding.EncodeToString(id), PrincipalID: p,
			Verifier: verifier, Artifact: "cli", SessionGeneration: 1, CredentialEpoch: 1,
			AuthMethod: "local-password", Factors: `["password"]`,
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

func sessionIDOf(t *testing.T, db *store.DB, bearer string) string {
	t.Helper()
	var id string
	err := tx.Read(t.Context(), db, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		who, err := az.AuthenticateCaller(ctx, bearer, time.Now().UTC())
		if err != nil {
			return err
		}
		id = who.SessionID
		return nil
	})
	if err != nil {
		t.Fatalf("resolve session id: %v", err)
	}
	return id
}

// runScopedCoalescing pins the exact sequence a scope-blind coalescing cache
// gets wrong: `remote show A` runs a ONE-ENTRY round, and a `remote list`
// arriving inside CoalesceWindow shares it. Every entry absent from that round
// would then settle as `unreachable` — a persisted fetch-failure snapshot and a
// `remote.fetch_failed` event for a remote nobody ever contacted.
//
// A shared round may only be reused by a request the round actually covers.
// There is no outcome in the closed enum for "we did not look", so a fabricated
// one is the only alternative, and fabricating an operator-visible failure is
// worse than spending a connection.
func runScopedCoalescing(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := t.Context()
	remotes, _ := remoteSvcs(t, db)
	admin := service.LocalPrincipal(root)

	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
		`VALUES ('g_rmt_dir', 'usr_root', 'instance-directory', NULL, NULL, NULL, `+ts+`)`)

	peerA := newFakeRemote(t, "ins_peer_a")
	peerB := newFakeRemote(t, "ins_peer_b")
	if _, err := remotes.AddRemote(ctx, admin, "peer-a", peerA.server.URL, peerA.pin, "hik_ic_a"); err != nil {
		t.Fatalf("add peer-a: %v", err)
	}
	if _, err := remotes.AddRemote(ctx, admin, "peer-b", peerB.server.URL, peerB.pin, "hik_ic_b"); err != nil {
		t.Fatalf("add peer-b: %v", err)
	}

	// The one-entry round.
	if _, err := remotes.ShowRemote(ctx, admin, "peer-a"); err != nil {
		t.Fatalf("show peer-a: %v", err)
	}
	// Inside CoalesceWindow, deliberately: the gate is NOT reset here, because
	// the window is precisely the condition under test.
	views, err := remotes.ListRemotes(ctx, admin)
	if err != nil {
		t.Fatalf("list within the coalescing window: %v", err)
	}
	seen := false
	for _, v := range views {
		if v.Name != "peer-b" {
			continue
		}
		seen = true
		if v.State != string(remotefetch.OutcomeOK) {
			t.Errorf("peer-b settled as %q after a round that never fetched it — that outcome is fabricated", v.State)
		}
		if v.Stale {
			t.Error("peer-b is marked stale by a round it was not part of")
		}
		if v.Identity != "ins_peer_b" {
			t.Errorf("peer-b carries identity %q, want ins_peer_b — the list did not really fetch it", v.Identity)
		}
	}
	if !seen {
		t.Fatal("peer-b is missing from the directory listing")
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'remote.fetch_failed'"); n != 0 {
		t.Errorf("%d remote.fetch_failed events for remotes that were never fetched — no fabricated outcomes, ever", n)
	}
}

// runCorruptSnapshot pins the fail-loud rule for a stored snapshot that does
// not parse. This instance wrote those bytes itself, from a listing it had
// already bounded and sorted, so a snapshot that will not parse is an INVARIANT
// BREAK. Rendered as an empty org list it would read as "that instance has
// nothing on it" — a plausible answer that is simply false, and the one failure
// mode a directory must never produce.
func runCorruptSnapshot(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := t.Context()
	remotes, _ := remoteSvcs(t, db)
	admin := service.LocalPrincipal(root)

	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
		`VALUES ('g_rmt_dir', 'usr_root', 'instance-directory', NULL, NULL, NULL, `+ts+`)`)

	peer := newFakeRemote(t, "ins_peer_b")
	if _, err := remotes.AddRemote(ctx, admin, "peer-b", peer.server.URL, peer.pin, "hik_ic_b"); err != nil {
		t.Fatalf("add peer-b: %v", err)
	}
	execRaw(t, db, `UPDATE remote_snapshots SET listing = 'not json at all'`)

	// The peer is flipped to refusing and the gate reset FIRST: a successful
	// fetch would overwrite the corrupt row on the way through and the test
	// would prove nothing.
	peer.reject = true
	resetFetchGate(t, remotes)
	if _, err := remotes.ShowRemote(ctx, admin, "peer-b"); err == nil {
		t.Fatal("a corrupt stored snapshot rendered as a directory instead of failing loud")
	}
}

func TestRemoteCorruptSnapshotFailsLoudSQLite(t *testing.T) {
	runCorruptSnapshot(t, seededDB(t, openSQLite))
}

func TestRemoteCorruptSnapshotFailsLoudPostgres(t *testing.T) {
	runCorruptSnapshot(t, seededDB(t, openPostgres))
}

func TestRemoteCoalescingIsScopedSQLite(t *testing.T) {
	runScopedCoalescing(t, seededDB(t, openSQLite))
}

func TestRemoteCoalescingIsScopedPostgres(t *testing.T) {
	runScopedCoalescing(t, seededDB(t, openPostgres))
}

func TestRemoteLifecycleSQLite(t *testing.T) {
	db := seededDB(t, openSQLite)
	runRemoteLifecycle(t, db)
	assertRemoteEventsEmitted(t, db)
}

func TestRemoteLifecyclePostgres(t *testing.T) {
	db := seededDB(t, openPostgres)
	runRemoteLifecycle(t, db)
	assertRemoteEventsEmitted(t, db)
}

// assertRemoteEventsEmitted is the per-engine half of the closure invariant.
// The audit suite's own sweep runs on sqlite only; this one runs on both, so a
// type that only an engine-specific path emits cannot go missing on postgres.
func assertRemoteEventsEmitted(t *testing.T, db *store.DB) {
	t.Helper()
	for _, typ := range audit.Types() {
		if len(typ) < 7 || typ[:7] != "remote." {
			continue
		}
		spec, _ := audit.Spec(typ)
		if !spec.Trails[audit.TrailInstance] {
			continue
		}
		got := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = '"+string(typ)+"'")
		if got == 0 {
			t.Errorf("registered event type %s was never emitted by the #71 lifecycle", typ)
		}
	}
}

// assertServedActor fails unless a remote.directory_served row exists for the
// given actor and principal class. Both are asserted because either alone is a
// way for the attribution to be wrong while looking right: the class without
// the actor names a kind and nobody, the actor without the class leaves an
// operator unable to tell a foreign installation's fetch from a person's.
func assertServedActor(t *testing.T, db *store.DB, actor, class string) {
	t.Helper()
	where := "actor_id = '" + actor + "'"
	if actor == "" {
		where = "actor_id IS NULL"
	}
	got := queryInt(t, db, `SELECT COUNT(*) FROM audit_instance_events WHERE type = 'remote.directory_served' AND `+
		where+` AND payload LIKE '%"principal_class":"`+class+`"%'`)
	if got == 0 {
		t.Errorf("no remote.directory_served row attributed to actor %q with principal_class %q — "+
			"the registry declares who this event names, and an unattributed access event is "+
			"the one an operator cannot act on", actor, class)
	}
}
