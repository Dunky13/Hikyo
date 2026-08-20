package isolation

// The audit-model ADR's end-to-end acceptance criteria (mvp-boundary A4),
// on both engines: denial durability (including under an induced commit
// failure), the export INTENT/OUTCOME pair, and the page-boundary
// revocation stop.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/admission"
	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// authService builds a real Auth against the harness database: a live
// keyring (verifiers are envelope-encrypted, so there is nothing to fake) and
// a real admission limiter. The Argon2id cost is dialled to the floor because
// the floor is what production runs and the flow exercises it a handful of
// times.
func authService(t *testing.T, db *store.DB) *service.Auth {
	return authServiceWithKeyring(t, db)
}

// authServiceWithKeyring is authService plus access to the keyring it loaded.
// The keyring hierarchy is minted ONCE per datastore under one root, so a
// later loader with a fresh root is refused (correctly) — anything in this
// suite that needs to seal must therefore share this one.
func authServiceWithKeyring(t *testing.T, db *store.DB) *service.Auth {
	t.Helper()
	kr := probeKeyring(t, db)
	limiter, err := admission.New(admission.Config{ArgonMemoryKiB: crypto.PasswordFloor.MemoryKiB})
	if err != nil {
		t.Fatal(err)
	}
	return &service.Auth{DB: db, Keyring: kr, KDF: crypto.PasswordFloor, Admission: limiter}
}

func queryString(t *testing.T, db *store.DB, q string) string {
	t.Helper()
	var s string
	var err error
	if db.Engine() == store.EnginePostgres {
		err = db.PG().QueryRow(t.Context(), q).Scan(&s)
	} else {
		err = db.SQLiteRead().QueryRowContext(t.Context(), q).Scan(&s)
	}
	if err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return s
}

// hookWriter triggers a side effect on its first write — the mid-export
// revocation lever.
type hookWriter struct {
	buf     bytes.Buffer
	onFirst func()
	fired   bool
}

func (w *hookWriter) Write(p []byte) (int, error) {
	if !w.fired {
		w.fired = true
		if w.onFirst != nil {
			w.onFirst()
		}
	}
	return w.buf.Write(p)
}

// failingWriter fails every write — the sink-disconnect lever.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("sink gone")
}

func runAuditSuite(t *testing.T, db *store.DB) {
	audits := &service.Audits{DB: db}
	envs := &service.Environments{DB: db, Keyring: probeKeyring(t, db)}
	projects := &service.Projects{DB: db}
	orgsSvc := &service.Orgs{DB: db}

	countTenant := func(where string) int64 {
		return queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE "+where)
	}
	countInstance := func(where string) int64 {
		return queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE "+where)
	}

	t.Run("denial_resolvable_durable_before_response", func(t *testing.T) {
		before := countTenant("type = 'grant.denied'")
		_, err := envs.Get(tctx(t), service.LocalPrincipal(bob), domain.Scope{Org: orgA, Project: prjA1, Env: envA1})
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("cross-org probe outcome = %v, want uniform not-found", err)
		}
		// The service call has returned; the denial event must already be
		// durable (flush commits before tx.Read returns), in the TENANT
		// trail with the truthful resolved chain — org A's auditors see
		// org A being probed.
		after := countTenant("type = 'grant.denied' AND org_id = 'org_a' AND actor_id = 'usr_bob' AND actor_class = 'human' AND outcome = 'denied'")
		if after != before+1 {
			t.Fatalf("resolvable denial events for bob in org A: %d, want %d", after, before+1)
		}
		if n := countTenant("type = 'grant.denied' AND actor_id = 'usr_bob' AND payload LIKE '%resolvable%' AND payload LIKE '%environment.read%'"); n == 0 {
			t.Error("denial payload does not carry operation + resolution shape")
		}
		if n := countTenant("payload LIKE '%grants_missing%' OR payload LIKE '%missing_grants%'"); n != 0 {
			t.Error("denial payload enumerates missing grants — authorization oracle")
		}
	})

	t.Run("denial_unresolvable_instance_trail", func(t *testing.T) {
		before := countInstance("type = 'grant.denied'")
		_, err := envs.Get(tctx(t), service.LocalPrincipal(bob), domain.Scope{Org: "org_zz", Project: "prj_zz", Env: "env_zz"})
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("unresolvable probe outcome = %v, want uniform not-found", err)
		}
		after := countInstance("type = 'grant.denied' AND actor_id = 'usr_bob' AND payload LIKE '%unresolvable%' AND payload LIKE '%org_zz%'")
		if after != before+1 {
			t.Fatalf("unresolvable denial not recorded on the instance trail with caller-asserted claims (%d -> %d)", before, after)
		}
		// No chain is recorded: the addressed identifiers stay claims.
		if n := countTenant("org_id = 'org_zz'"); n != 0 {
			t.Error("unresolvable denial materialized a tenant chain")
		}
	})

	t.Run("instance_denial", func(t *testing.T) {
		_, err := audits.InstanceQuery(tctx(t), nobody, store.AuditFilter{Limit: 10})
		if !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatalf("instance query without audit-read = %v, want unauthorized", err)
		}
		if n := countInstance("type = 'grant.denied' AND actor_id = 'usr_nobody' AND payload LIKE '%audit.instance-query%'"); n != 1 {
			t.Fatalf("instance-operation denial events = %d, want 1", n)
		}
	})

	t.Run("domain_event_committed_in_transaction", func(t *testing.T) {
		proj, err := projects.Create(tctx(t), service.LocalPrincipal(alice), orgA, "audited-project")
		if err != nil {
			t.Fatal(err)
		}
		if n := countTenant("type = 'settings.project_created' AND org_id = 'org_a' AND actor_id = 'usr_alice' AND object_id = '" + proj.ID + "'"); n != 1 {
			t.Fatalf("project-created events = %d, want 1", n)
		}
	})

	t.Run("query_is_audited_unconditionally", func(t *testing.T) {
		page, err := audits.Query(tctx(t), alice, domain.Scope{Org: orgA}, store.AuditFilter{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			t.Fatal("org A trail is empty — prior subtests wrote events")
		}
		if n := countTenant("type = 'audit.query' AND actor_id = 'usr_alice' AND payload LIKE '%row_count%'"); n != 1 {
			t.Fatalf("audit.query events = %d, want 1 (one per query, normalized filters + row count)", n)
		}
		// The reader capability is its own: org-admin-shaped capabilities do
		// not imply it.
		if _, err := audits.Query(tctx(t), reader, domain.Scope{Org: orgA}, store.AuditFilter{Limit: 10}); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("reader without audit-read = %v, want uniform not-found", err)
		}
	})

	t.Run("instance_query_grant_evaluated", func(t *testing.T) {
		page, err := audits.InstanceQuery(tctx(t), root, store.AuditFilter{Limit: 100})
		if err != nil {
			t.Fatalf("root with instance audit-read: %v", err)
		}
		// Asserting the ROWS, not just the absence of an error: an instance
		// page that silently returns nothing (a mis-bound paging parameter)
		// would otherwise pass every other assertion here.
		if len(page) == 0 {
			t.Fatal("instance trail page is empty — prior subtests wrote instance events")
		}
		if n := countInstance("type = 'audit.query' AND actor_id = 'usr_root'"); n != 1 {
			t.Fatalf("instance audit.query events = %d, want 1", n)
		}
	})

	t.Run("export_intent_outcome_pairing", func(t *testing.T) {
		var buf bytes.Buffer
		if err := audits.Export(tctx(t), alice, domain.Scope{Org: orgA}, store.AuditFilter{}, 2, &buf); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) == 0 {
			t.Fatal("export streamed nothing")
		}
		for _, line := range lines {
			var parsed map[string]any
			if err := json.Unmarshal([]byte(line), &parsed); err != nil {
				t.Fatalf("export line is not JSONL: %v", err)
			}
			if _, ok := parsed["payload"]; !ok {
				t.Fatal("export line lacks the payload")
			}
		}
		startedID := queryString(t, db,
			"SELECT id FROM audit_tenant_events WHERE type = 'audit.export_started' AND outcome = 'intent' ORDER BY seq DESC LIMIT 1")
		completed := countTenant(fmt.Sprintf(
			"type = 'audit.export_completed' AND outcome = 'success' AND correlation_id = '%s' AND payload LIKE '%%\"rows_streamed\":%d%%'",
			startedID, len(lines)))
		if completed != 1 {
			t.Fatalf("completed events correlated to %s with rows_streamed=%d: %d, want 1", startedID, len(lines), completed)
		}
	})

	t.Run("export_sink_disconnect_terminal_outcome", func(t *testing.T) {
		err := audits.Export(tctx(t), alice, domain.Scope{Org: orgA}, store.AuditFilter{}, 2, failingWriter{})
		if err == nil {
			t.Fatal("export into a dead sink succeeded")
		}
		if n := countTenant("type = 'audit.export_completed' AND outcome = 'disconnected'"); n != 1 {
			t.Fatalf("disconnected terminal events = %d, want 1", n)
		}
	})

	t.Run("export_revocation_stops_at_page_boundary", func(t *testing.T) {
		startedBefore := countTenant("type = 'audit.export_started'")
		w := &hookWriter{onFirst: func() {
			// Revoke alice's audit-read after the first committed page has
			// started streaming; the next page's fresh transaction-bound
			// proof must fail.
			// Origins hold the row (RESTRICT FK, #55), so the origin goes first.
			execRaw(t, db, "DELETE FROM grant_origins WHERE grant_id = 'g_al_ar'")
			execRaw(t, db, "DELETE FROM grants WHERE id = 'g_al_ar'")
		}}
		err := audits.Export(tctx(t), alice, domain.Scope{Org: orgA}, store.AuditFilter{}, 1, w)
		if !errors.Is(err, service.ErrExportUnpaired) {
			t.Fatalf("mid-export revocation outcome = %v, want ErrExportUnpaired", err)
		}
		if w.buf.Len() == 0 {
			t.Fatal("stream stopped before the first page — revocation must stop at the NEXT page boundary")
		}
		if got := int(countTenant("type = 'audit.export_started'")) - int(startedBefore); got != 1 {
			t.Fatalf("started events during revoked export = %d, want 1", got)
		}
		startedID := queryString(t, db,
			"SELECT id FROM audit_tenant_events WHERE type = 'audit.export_started' ORDER BY seq DESC LIMIT 1")
		if n := countTenant("type = 'audit.export_completed' AND correlation_id = '" + startedID + "'"); n != 0 {
			t.Fatal("revoked export has a completed event — the unpaired started record is the visible reconciliation case")
		}
		// The revoked page authorization itself is a recorded denial.
		if n := countTenant("type = 'grant.denied' AND actor_id = 'usr_alice' AND payload LIKE '%audit.export-org%'"); n != 1 {
			t.Fatalf("revocation denial events = %d, want 1", n)
		}
		// Restore the grant for any later subtest.
		execRaw(t, db, "INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_al_ar', 'usr_alice', 'audit-read', 'org_a', NULL, NULL, "+ts+")")
	})

	t.Run("no_token_material_in_trails", func(t *testing.T) {
		// The dump-grep half of CI invariant 4, extended to both audit
		// tables: plant a grammar-valid bearer token in every
		// attacker-influencable field a denial records (user agent, claimed
		// identifiers), then grep the trails — the marker must be there and
		// the token must not.
		tokens := []string{
			"hik_1_wl_" + strings.Repeat("Ab3", 15),
			"hik_1_wl_" + strings.Repeat("Cd4", 15),
		}
		for _, token := range tokens {
			wired := audit.WithContext(tctx(t), audit.Context{
				UserAgent: "probe/1.0 " + token,
				SourceIP:  "203.0.113.7",
				Origin:    audit.OriginAPI,
			})
			if _, err := envs.Get(wired, service.LocalPrincipal(bob), domain.Scope{Org: orgA, Project: prjA1, Env: envA1}); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("resolvable probe = %v", err)
			}
			if _, err := envs.Get(wired, service.LocalPrincipal(bob), domain.Scope{Org: domain.OrgID("org_" + token), Project: "prj_x", Env: "env_x"}); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("unresolvable probe = %v", err)
			}
		}
		for _, table := range []string{"audit_tenant_events", "audit_instance_events"} {
			for _, col := range []string{"user_agent", "payload", "source_ip", "object_id", "correlation_id"} {
				for _, token := range tokens {
					if n := queryInt(t, db, "SELECT COUNT(*) FROM "+table+" WHERE "+col+" LIKE '%"+token+"%'"); n != 0 {
						t.Errorf("%s.%s holds raw token material (%d rows)", table, col, n)
					}
				}
			}
			if n := queryInt(t, db, "SELECT COUNT(*) FROM "+table+" WHERE user_agent LIKE '%"+audit.RedactionMarker+"%'"); n == 0 {
				t.Errorf("%s: no redaction marker found — the filter did not run", table)
			}
		}
		if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE payload LIKE '%"+audit.RedactionMarker+"%'"); n == 0 {
			t.Error("claimed identifiers were not token-filtered")
		}
	})

	t.Run("human_authentication_flow", func(t *testing.T) {
		// The A1 slice end to end on a real datastore: bootstrap the first
		// administrator, refuse a bad authority, establish the credential,
		// fail a login, succeed, and log out. It lives inside the audit suite
		// because every step of it is an audit obligation the human-auth ADR
		// names, and the emitter check below is what proves the obligations
		// are met by code rather than by declaration.
		auth := authService(t, db)
		ctx := tctx(t)

		boot, err := auth.BootstrapAdmin(ctx, "e2e-admin", "E2E Admin", "terminal")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := auth.BootstrapAdmin(ctx, "second", "Second", "terminal"); !errors.Is(err, service.ErrInstanceAlreadyBootstrapped) {
			t.Fatalf("a second first-administrator was minted: %v", err)
		}

		// A well-formed but unknown authority is refused uniformly.
		bogus, _, err := crypto.NewArtifact(crypto.ArtifactBootstrap)
		if err != nil {
			t.Fatal(err)
		}
		if err := auth.EstablishCredential(ctx, bogus, "a-long-enough-password"); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Fatalf("unknown authority: err = %v, want ErrUnauthenticated", err)
		}
		// A short password is the one loud refusal on this path.
		if err := auth.EstablishCredential(ctx, boot.Authority, "short"); !errors.Is(err, service.ErrWeakPassword) {
			t.Fatalf("short password accepted: %v", err)
		}

		const password = "correct horse battery staple"
		if err := auth.EstablishCredential(ctx, boot.Authority, password); err != nil {
			t.Fatal(err)
		}
		// Single-use: the same authority cannot establish a second credential.
		if err := auth.EstablishCredential(ctx, boot.Authority, password); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Fatalf("an authority was consumed twice: %v", err)
		}

		// Wrong password and unknown account answer identically.
		for _, bad := range []struct{ user, pass string }{
			{"e2e-admin", "wrong password entirely"},
			{"no-such-account", password},
		} {
			if _, err := auth.LocalLogin(ctx, bad.user, bad.pass, service.ArtifactCLI); !errors.Is(err, domain.ErrUnauthenticated) {
				t.Fatalf("login(%q): err = %v, want ErrUnauthenticated", bad.user, err)
			}
		}

		session, err := auth.LocalLogin(ctx, "e2e-admin", password, service.ArtifactCLI)
		if err != nil {
			t.Fatal(err)
		}
		if session.Assurance.Method != service.MethodLocalPassword {
			t.Errorf("assurance method %q", session.Assurance.Method)
		}
		id, err := auth.Identity(ctx, session.SessionToken)
		if err != nil {
			t.Fatalf("the freshly minted session does not resolve: %v", err)
		}
		if id.Principal != boot.PrincipalID {
			t.Errorf("session resolves to %q, want %q", id.Principal, boot.PrincipalID)
		}

		// The administrator can now perform the first audited mutating
		// operation — the demo criterion, exercised through the real grants
		// the admin template wrote.
		if _, err := orgsSvc.Create(ctx, service.LocalPrincipal(id.Principal), "bootstrapped-org", true, []byte(`{}`)); err != nil {
			t.Fatalf("the bootstrapped administrator cannot administer: %v", err)
		}

		if err := auth.Logout(ctx, session.SessionToken); err != nil {
			t.Fatal(err)
		}
		if _, err := auth.Identity(ctx, session.SessionToken); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Fatalf("a revoked session still resolves: %v", err)
		}

		// The full factor lifecycle, so every factor audit event is emitted by
		// code before the emitter check below reads the trail: recovery
		// generate/consume, TOTP enrol/confirm, step-up, remove.
		runFactorLifecycle(t, auth, ctx, "e2e-admin", password)

		// The full OIDC lifecycle, so every OIDC audit event is emitted by code
		// before the emitter check: provider config + read, link, federated
		// login, JIT provisioning, a refusal, and unlink.
		runOIDCLifecycle(t, auth, ctx, boot.PrincipalID, "e2e-admin", password)

		// The full WebAuthn lifecycle, so passkey_added, passkey_cloned and
		// passkey_removed are emitted before the emitter check.
		runWebAuthnLifecycle(t, auth, ctx, "e2e-admin", password)

		// The SAML lifecycle emits every registered SAML audit family through
		// real provider configuration, failed login/reauth, refresh, and removal.
		runSAMLAuditLifecycle(t, auth, boot.PrincipalID, password)

		// Crossing the per-account backoff threshold is its own event.
		for range 6 {
			_, _ = auth.LocalLogin(ctx, "e2e-admin", "still wrong", service.ArtifactCLI)
		}

		// Credential reset (#54): break-glass on the host reaches any target,
		// including this instance-capability admin, emitting the reset issuance
		// and the authority mint. Runs after the flows above because it advances
		// the admin's generation and revokes its sessions.
		if _, err := auth.BreakGlassResetCredential(ctx, string(boot.PrincipalID), "terminal"); err != nil {
			t.Fatalf("break-glass reset: %v", err)
		}
		// Lowering an effective window emits auth.effective_window_lowered. The #54
		// B6 library takes the caller's transaction (#55's project-settings knob is
		// the arriving caller); exercised directly here as it has no operation row.
		if err := tx.Write(ctx, db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
			_, _, e := auth.LowerEffectiveWindow(ctx, az, "env_e2e_window", time.Minute, time.Now())
			return e
		}); err != nil {
			t.Fatalf("lower effective window: %v", err)
		}
	})

	t.Run("every_registered_type_is_actually_emitted", func(t *testing.T) {
		// The registry-closure invariant is static: it proves declarations
		// agree, not that an emitter exists. This runs last over the trails
		// the preceding subtests filled and asserts every registered type
		// really reached a table — an operation that drops its insert while
		// keeping its `events:` declaration fails here.
		if _, err := orgsSvc.List(tctx(t), service.LocalPrincipal(root)); err != nil {
			t.Fatal(err)
		}
		if err := envs.UpdateNote(tctx(t), service.LocalPrincipal(alice), domain.Scope{Org: orgA, Project: prjA1, Env: envA1}, "noted"); err != nil {
			t.Fatal(err)
		}
		if _, err := envs.Create(tctx(t), service.LocalPrincipal(alice), domain.Scope{Org: orgA, Project: prjA1}, "audited-env"); err != nil {
			t.Fatal(err)
		}
		retentionNow := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
		retention := &service.Retention{DB: db, Now: func() time.Time { return retentionNow }}
		if _, err := retention.SetOrg(tctx(t), service.LocalPrincipal(orgAdmin), orgA, service.RetentionPolicy{
			MaxAge: 60 * 24 * time.Hour, LastRevisions: 5,
		}); err != nil {
			t.Fatalf("emit org retention event: %v", err)
		}
		projectRetention := service.RetentionPolicy{MaxAge: 30 * 24 * time.Hour, LastRevisions: 3}
		if _, err := retention.SetProject(tctx(t), service.LocalPrincipal(orgAdmin), scopeProject(orgA, prjA1), &projectRetention); err != nil {
			t.Fatalf("emit project retention event: %v", err)
		}
		seedRetentionCorpus(t, db)
		if _, err := retention.Sweep(tctx(t)); err != nil {
			t.Fatalf("emit retention GC events: %v", err)
		}
		if _, err := retention.GetHealth(tctx(t), service.LocalPrincipal(root)); err != nil {
			t.Fatalf("emit retention health-read event: %v", err)
		}
		org, err := orgsSvc.Create(tctx(t), service.LocalPrincipal(root), "audited-org", true, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		// The rest of the hierarchy lifecycle (#48), so every settings.* type
		// has a real emitter behind it before the check below reads the trails.
		runHierarchyLifecycle(t, db, domain.OrgID(org.ID))
		// The permission surface (#55): every grant.* and settings.* type gets
		// a real emitter before the trails are read.
		runGrantLifecycle(t, db)
		// The machine-identity surface (#61): every identity.* type gets a
		// real emitter before the trails are read.
		runIdentityLifecycle(t, db)
		// OIDC federation and the delivery surface (#62): the same obligation, one
		// ticket later.
		runFederationLifecycle(t, db)
		// SCIM provisioning (#73): every `scim.*` type gets a real emitter —
		// binding, credential, user, group, mapping, attention and the lockout
		// pair — before the trails are read.
		runSCIMLifecycle(t, db)
		// Definitions Git flow (#70): plan/apply, stale/deletion/additive
		// refusals, and the source-mode setting all traverse the real service.
		runDefinitionsAuditLifecycle(t, db)
		// Deployment adapters (#65): configuration, conflict adoption, outbox
		// converge/abort and teardown all traverse their real service/runtime
		// boundaries before the registry-emitter closure check.
		runAdapterAuditLifecycle(t, db)
		// The multi-instance surface (#71): both tiers, against a real pinned
		// TLS peer, so every remote.* type has a real emitter behind it too.
		// Before the backup lifecycle, because that one advances the restore
		// epoch and this one authenticates real artifacts against the current.
		runRemoteLifecycle(t, db)
		// The operator lifecycle (#76): every backup.* and restore.* type gets
		// a real emitter. It runs LAST of the lifecycles because it advances
		// the restore epoch and then reconciles the principals it made inert,
		// one call per principal, leaving the fixture authorizing again.
		runBackupLifecycle(t, db)
		for _, typ := range audit.Types() {
			spec, _ := audit.Spec(typ)
			seen := int64(0)
			if spec.Trails[audit.TrailTenant] {
				seen += queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE type = '"+string(typ)+"'")
			}
			if spec.Trails[audit.TrailInstance] {
				seen += queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = '"+string(typ)+"'")
			}
			if seen == 0 {
				t.Errorf("registered event type %s was never emitted — declaration without an emitter", typ)
			}
		}
	})

	t.Run("reveal_gate_attempts_survive_the_rollback", func(t *testing.T) {
		// "Every attempt is audited" is a claim about the outcomes that ROLL
		// BACK: a refused gate and a gate that passed before a later failure
		// both leave nothing behind if the record is an in-transaction insert.
		// Both therefore ride the settlement path, which is the one writer that
		// survives a rollback — and the key rides in the ENVELOPE's object,
		// because grant.denied's payload is a closed schema shared by every
		// operation and must not grow a key field.
		keys := &service.Keys{DB: db, Keyring: probeKeyring(t, db)}
		scope := domain.Scope{Org: orgA, Project: prjA1}
		// alice holds definitions-edit in org A and NOT reveal, which is the
		// legal, supported grant shape the gate exists for.
		secret, err := keys.Create(tctx(t), service.LocalPrincipal(alice), scope, service.KeySpec{
			Name: "GATED_PROBE", Classification: string(schema.Secret),
			Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}},
			Presence:    schema.DefaultPresenceRules(),
		})
		if err != nil {
			t.Fatal(err)
		}
		tighten := func(pattern string) service.KeyDeclarationUpdate {
			return service.KeyDeclarationUpdate{
				Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString, Pattern: pattern}},
				Presence:    schema.DefaultPresenceRules(),
			}
		}
		gateRows := func(outcome string) int64 {
			return queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events"+
				" WHERE type = 'settings.key_reveal_gate_attempt' AND outcome = '"+outcome+"'"+
				" AND object_id = '"+secret.ID+"'")
		}

		// 1. Refused. The transaction rolls back; the attempt and the denial
		// both survive, both naming the key.
		if _, err := keys.UpdateDeclaration(tctx(t), service.LocalPrincipal(alice), scope, secret.ID, tighten("A.*")); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("a reveal-less rule change on a secret key answered %v", err)
		}
		if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'grant.denied' AND object_id = '"+secret.ID+"'"); n != 1 {
			t.Fatalf("the gate denial carries the key id %d times, want exactly 1", n)
		}
		if n := gateRows("denied"); n != 1 {
			t.Fatalf("a refused gate attempt was recorded %d times, want exactly 1", n)
		}

		// 2. Passed, then the operation fails on something later. The mutation
		// rolls back; the attempt must not.
		revealer := domain.PrincipalID("usr_gate_revealer")
		execRaw(t, db, `INSERT INTO principals (id, kind, created_at) VALUES ('usr_gate_revealer', 'human', `+ts+`)`)
		for i, capability := range []string{"definitions-edit", "read", "reveal"} {
			execRaw(t, db, fmt.Sprintf(
				`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
				 VALUES ('grt_gate_%d', 'usr_gate_revealer', '%s', '%s', NULL, NULL, %s)`,
				i, capability, orgA, ts))
		}
		// RE2 has no lookahead, so the declaration cannot compile — and it is
		// examined only AFTER the gate, which is the ordering this exercises.
		_, err = keys.UpdateDeclaration(tctx(t), service.LocalPrincipal(revealer), scope, secret.ID, tighten(`(?=x)y`))
		if !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("an uncompilable declaration from a reveal holder answered %v", err)
		}
		if n := gateRows("success"); n != 1 {
			t.Fatalf("a passed gate whose operation later failed was recorded %d times, want exactly 1", n)
		}
		// The mutation really did roll back: the declaration is untouched.
		after, err := keys.Get(tctx(t), service.LocalPrincipal(revealer), scope, secret.ID)
		if err != nil {
			t.Fatal(err)
		}
		if after.Declaration.Rule.Pattern != "" {
			t.Fatalf("the failed update committed a pattern: %q", after.Declaration.Rule.Pattern)
		}
		if err := keys.Delete(tctx(t), service.LocalPrincipal(alice), scope, secret.ID); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("denial_durability_under_induced_commit_failure", func(t *testing.T) {
		// Break the denial writer's target table, then probe: the response
		// MUST NOT be the uniform denial — a denial answer without its
		// durable record is what fail-closed forbids.
		execRaw(t, db, "ALTER TABLE audit_tenant_events RENAME TO audit_tenant_events_broken")
		defer execRaw(t, db, "ALTER TABLE audit_tenant_events_broken RENAME TO audit_tenant_events")
		_, err := envs.Get(tctx(t), service.LocalPrincipal(bob), domain.Scope{Org: orgA, Project: prjA1, Env: envA1})
		if err == nil {
			t.Fatal("denied probe answered success under audit-write failure")
		}
		if errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("denied probe answered the uniform denial with no durable record: %v", err)
		}
		if !strings.Contains(err.Error(), "denial audit record not durable") {
			t.Fatalf("induced commit failure surfaced as %v, want the loud refusal", err)
		}
	})
}

func TestAuditCoreSQLite(t *testing.T) {
	runAuditSuite(t, seededDB(t, openSQLite))
}

func TestAuditCorePostgres(t *testing.T) {
	runAuditSuite(t, seededDB(t, openPostgres))
}

// TestPostgresAuditExportCommitOrder is #84's regression: sequence allocation
// order is not commit order. The lower-seq row stays uncommitted while the
// higher-seq row crosses the first export page, then commits. A gap-free
// export must still emit both rows.
func TestPostgresAuditExportCommitOrder(t *testing.T) {
	db := seededDB(t, openPostgres)
	audits := &service.Audits{DB: db}

	insert := `INSERT INTO audit_tenant_events (
		id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
		actor_id, actor_class, scope_class, org_id, outcome, origin, payload
	) VALUES ($1, 'settings.project_created', 1, clock_timestamp(), FALSE, clock_timestamp(),
		'usr_alice', 'human', 'org', 'org_a', 'success', 'cli', '{}')
	RETURNING seq`

	lowTx, err := db.PG().Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lowTx.Rollback(context.Background()) })

	var lowSeq int64
	if err := lowTx.QueryRow(t.Context(), insert, "evt_gap_low").Scan(&lowSeq); err != nil {
		t.Fatal(err)
	}
	var highSeq int64
	if err := db.PG().QueryRow(t.Context(), insert, "evt_gap_high").Scan(&highSeq); err != nil {
		t.Fatal(err)
	}
	if lowSeq >= highSeq {
		t.Fatalf("fixture seq order = low %d, high %d", lowSeq, highSeq)
	}

	firstPage := make(chan struct{})
	w := &hookWriter{onFirst: func() { close(firstPage) }}
	exportDone := make(chan error, 1)
	go func() {
		// A one-row page forces the full-page path before the exporter reaches
		// its short-page barrier and rereads the later lower-seq commit.
		exportDone <- audits.Export(t.Context(), alice, domain.Scope{Org: orgA}, store.AuditFilter{}, 1, w)
	}()

	select {
	case <-firstPage:
	case err := <-exportDone:
		t.Fatalf("export ended before first page crossed the higher seq: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("export did not emit its first page")
	}

	deadline := time.After(5 * time.Second)
	for queryInt(t, db, `SELECT COUNT(*) FROM pg_locks
		WHERE locktype = 'advisory' AND classid = 1464159830 AND objid = 85 AND NOT granted`) == 0 {
		select {
		case err := <-exportDone:
			t.Fatalf("export ended before waiting for the in-flight lower seq: %v", err)
		case <-deadline:
			t.Fatal("export did not wait at the in-flight audit barrier")
		case <-time.After(10 * time.Millisecond):
		}
	}

	if err := lowTx.Commit(t.Context()); err != nil {
		t.Fatalf("commit lower-seq event after first page: %v", err)
	}
	select {
	case err := <-exportDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("export did not finish after the in-flight event committed")
	}

	// The export carries the whole org trail, which the fixture also seeds
	// into (#50's value fixture writes one value.set). This regression is
	// about the ORDER of the two concurrent commits, so it asserts on exactly
	// those two rows rather than on the trail's length — a fixture row
	// elsewhere in the org is not a gap.
	var gap []exportLineForTest
	for _, line := range strings.Split(strings.TrimSpace(w.buf.String()), "\n") {
		var parsed exportLineForTest
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed.ID == "evt_gap_low" || parsed.ID == "evt_gap_high" {
			gap = append(gap, parsed)
		}
	}
	if len(gap) != 2 {
		t.Fatalf("exported %d of the 2 concurrent commits:\n%s", len(gap), w.buf.String())
	}
	first, second := gap[0], gap[1]
	if first.ID != "evt_gap_high" || first.Seq != highSeq {
		t.Fatalf("first page = %+v, want committed higher seq %d", first, highSeq)
	}
	if second.ID != "evt_gap_low" || second.Seq != lowSeq {
		t.Fatalf("second page = %+v, want later commit with lower seq %d", second, lowSeq)
	}
	interactive, err := audits.Query(t.Context(), alice, domain.Scope{Org: orgA}, store.AuditFilter{
		Limit:          10,
		Order:          store.AuditPageByCommit,
		AfterCommitSeq: store.AuditCommitSeq(1 << 62),
	})
	if err != nil {
		t.Fatal(err)
	}
	var seqs []int64
	for _, ev := range interactive {
		if ev.ID == "evt_gap_low" || ev.ID == "evt_gap_high" {
			seqs = append(seqs, ev.Seq)
		}
	}
	if len(seqs) != 2 || seqs[0] != lowSeq || seqs[1] != highSeq {
		t.Fatalf("interactive query honored export-only cursor/order: %+v", interactive)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE commit_seq IS NULL"); n != 0 {
		t.Fatalf("committed tenant audit rows without commit order = %d", n)
	}
	_, err = db.PG().Exec(t.Context(), `INSERT INTO audit_tenant_events (
		id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
		actor_id, actor_class, scope_class, org_id, outcome, origin, payload, commit_seq
	) VALUES ('evt_gap_forged', 'settings.project_created', 1, clock_timestamp(), FALSE, clock_timestamp(),
		'usr_alice', 'human', 'org', 'org_a', 'success', 'cli', '{}', 999999)`)
	if err == nil || !strings.Contains(err.Error(), "commit_seq is database-owned") {
		t.Fatalf("caller-supplied commit order refusal = %v", err)
	}
}

// TestPostgresAuditExportCutoffRegistration closes the other side of #84's
// termination race. A writer paused before the production writer gate must be
// timestamped after the cutoff when it resumes; otherwise the completed export
// has silently omitted an event that its own cutoff says was eligible.
func TestPostgresAuditExportCutoffRegistration(t *testing.T) {
	db := seededDB(t, openPostgres)
	audits := &service.Audits{DB: db}

	execRaw(t, db, `CREATE FUNCTION audit_test_pause_before_gate() RETURNS TRIGGER
		LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.id = 'evt_cutoff_race' THEN
				PERFORM pg_advisory_xact_lock_shared(1464159830, 86);
			END IF;
			RETURN NEW;
		END;
		$$`)
	execRaw(t, db, `CREATE TRIGGER audit_000_test_pause_before_gate
		BEFORE INSERT ON audit_tenant_events
		FOR EACH ROW EXECUTE FUNCTION audit_test_pause_before_gate()`)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := db.PG().Exec(ctx, "DROP TRIGGER IF EXISTS audit_000_test_pause_before_gate ON audit_tenant_events"); err != nil {
			t.Errorf("drop cutoff-race test trigger: %v", err)
		}
		if _, err := db.PG().Exec(ctx, "DROP FUNCTION IF EXISTS audit_test_pause_before_gate()"); err != nil {
			t.Errorf("drop cutoff-race test function: %v", err)
		}
	})

	blocker, err := db.PG().Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blocker.Rollback(context.Background()) })
	if _, err := blocker.Exec(t.Context(), "SELECT pg_advisory_xact_lock(1464159830, 86)"); err != nil {
		t.Fatal(err)
	}

	insertDone := make(chan error, 1)
	go func() {
		_, err := db.PG().Exec(t.Context(), `INSERT INTO audit_tenant_events (
			id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
			actor_id, actor_class, scope_class, org_id, outcome, origin, payload
		) VALUES ('evt_cutoff_race', 'settings.project_created', 1,
			clock_timestamp(), FALSE, clock_timestamp(), 'usr_alice', 'human',
			'org', 'org_a', 'success', 'cli', '{}')`)
		insertDone <- err
	}()

	deadline := time.After(5 * time.Second)
	for queryInt(t, db, `SELECT COUNT(*) FROM pg_locks
		WHERE locktype = 'advisory' AND classid = 1464159830 AND objid = 86 AND NOT granted`) == 0 {
		select {
		case err := <-insertDone:
			t.Fatalf("writer passed the pre-gate pause unexpectedly: %v", err)
		case <-deadline:
			t.Fatal("writer did not pause before the production export gate")
		case <-time.After(10 * time.Millisecond):
		}
	}

	var cutoff time.Time
	if err := db.PG().QueryRow(t.Context(), "SELECT clock_timestamp()").Scan(&cutoff); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := audits.Export(t.Context(), alice, domain.Scope{Org: orgA}, store.AuditFilter{To: cutoff}, 2, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "evt_cutoff_race") {
		t.Fatal("uncommitted cutoff-race event appeared in export")
	}

	if err := blocker.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-insertDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not finish after the pre-gate pause was released")
	}

	var recordedAt time.Time
	if err := db.PG().QueryRow(t.Context(),
		"SELECT recorded_at FROM audit_tenant_events WHERE id = 'evt_cutoff_race'").Scan(&recordedAt); err != nil {
		t.Fatal(err)
	}
	if !recordedAt.After(cutoff) {
		t.Fatalf("writer recorded_at = %s, want after export cutoff %s", recordedAt, cutoff)
	}
}

type exportLineForTest struct {
	Seq int64  `json:"seq"`
	ID  string `json:"id"`
}

// TestPostgresDurabilityBootRefusal is the A4 CI leg the unit test cannot
// reach for real: a database whose synchronous_commit is off must refuse to
// boot. (The fsync leg needs a server restart and is unit-tested through
// the querier seam in internal/store.)
func TestPostgresDurabilityBootRefusal(t *testing.T) {
	dsn := os.Getenv("HIKYO_TEST_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI run without HIKYO_TEST_POSTGRES_DSN: the postgres durability leg must not silently skip in CI")
		}
		t.Skip("HIKYO_TEST_POSTGRES_DSN not set")
	}
	derived := derivedDatabase(t, dsn, "_durability")
	u, err := url.Parse(derived)
	if err != nil {
		t.Fatal(err)
	}
	name := strings.TrimPrefix(u.Path, "/")

	admin, err := store.Open(t.Context(), store.Config{Engine: store.EnginePostgres, DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.PG().Exec(t.Context(), "ALTER DATABASE "+pq(name)+" SET synchronous_commit = off"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.PG().Exec(t.Context(), "ALTER DATABASE "+pq(name)+" RESET synchronous_commit"); err != nil {
			t.Errorf("reset synchronous_commit: %v", err)
		}
	}()

	db, err := store.Open(t.Context(), store.Config{Engine: store.EnginePostgres, DSN: derived})
	if err == nil {
		db.Close()
		t.Fatal("boot accepted a database with synchronous_commit = off")
	}
	if !strings.Contains(err.Error(), "refusing to boot") {
		t.Fatalf("refusal does not name itself: %v", err)
	}
}

// runHierarchyLifecycle exercises every hierarchy mutation once, so each
// registered settings.* event type has an emitter behind it rather than only a
// declaration. It runs against a fresh org the instance operator just created,
// with tenant grants seeded for it — the same shape production uses, through
// authorize() with no test-only mint.
func runHierarchyLifecycle(t *testing.T, db *store.DB, org domain.OrgID) {
	t.Helper()
	ctx := tctx(t)
	projects := &service.Projects{DB: db}
	envs := &service.Environments{DB: db, Keyring: probeKeyring(t, db)}
	folders := &service.Folders{DB: db}
	orgs := &service.Orgs{DB: db}

	const who = domain.PrincipalID("usr_hierarchy_audit")
	stmts := []string{
		`INSERT INTO principals (id, kind, created_at) VALUES ('usr_hierarchy_audit', 'human', ` + ts + `)`,
	}
	// `reveal` joins the set for the key catalogue (#49): the two reveal gates
	// — a value-dependent rule change on a `secret` key, and declassification —
	// are the only path to settings.key_reveal_gate_passed, so a fixture without
	// it could not prove that type has an emitter.
	// `edit` and `publish` join for the flat value model (#50): a value write
	// is `edit ∧ publish` on the environment it delivers into, and copy adds
	// `reveal ∧ publish` on the destination — without all four, value.set,
	// value.cleared and the two disclosure.* types would have no emitter.
	for i, capability := range []string{"manage-projects", "definitions-edit", "read", "reveal", "edit", "publish", "pin", "reveal-history"} {
		stmts = append(stmts, fmt.Sprintf(
			`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
			 VALUES ('grt_ha_%d', 'usr_hierarchy_audit', '%s', '%s', NULL, NULL, %s)`,
			i, capability, org, ts))
	}
	for _, stmt := range stmts {
		execRaw(t, db, stmt)
	}
	actor := service.LocalPrincipal(who)

	proj, err := projects.Create(ctx, actor, org, "audited-project")
	if err != nil {
		t.Fatal(err)
	}
	scope := domain.Scope{Org: org, Project: domain.ProjectID(proj.ID)}
	env, err := envs.Create(ctx, actor, scope, "audited-environment")
	if err != nil {
		t.Fatal(err)
	}
	envScope := scope
	envScope.Env = domain.EnvID(env.ID)
	if _, err := envs.Rename(ctx, actor, envScope, "audited-environment-renamed"); err != nil {
		t.Fatal(err)
	}
	if _, err := envs.Reorder(ctx, actor, scope, []string{env.ID}); err != nil {
		t.Fatal(err)
	}
	if err := envs.Delete(ctx, actor, envScope); err != nil {
		t.Fatal(err)
	}
	folder, err := folders.Create(ctx, actor, scope, "audited-folder")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := folders.Rename(ctx, actor, scope, folder.ID, "audited-folder-renamed"); err != nil {
		t.Fatal(err)
	}
	if err := folders.Delete(ctx, actor, scope, folder.ID); err != nil {
		t.Fatal(err)
	}
	runValueLifecycle(t, db, actor, who, scope)
	runCatalogueLifecycle(t, db, actor, scope)
	if _, err := projects.Rename(ctx, actor, scope, "audited-project-renamed"); err != nil {
		t.Fatal(err)
	}
	if err := projects.Delete(ctx, actor, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := orgs.Rename(ctx, service.LocalPrincipal(root), org, "audited-org-renamed"); err != nil {
		t.Fatal(err)
	}
	// The org still holds this fixture's grants, so it cannot be deleted here.
	// A throwaway org with nothing pointing at it supplies settings.org_deleted.
	throwaway, err := orgs.Create(ctx, service.LocalPrincipal(root), "audited-org-throwaway", true, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := orgs.Delete(ctx, service.LocalPrincipal(root), domain.OrgID(throwaway.ID)); err != nil {
		t.Fatal(err)
	}
}

// runValueLifecycle drives every value-model act (#50) so each value.* and
// disclosure.value_* type has a real emitter behind it: a supplied write, a
// revealed read, a copy into a second environment, and a clear. It cleans up
// after itself — the keys and both environments go — because the catalogue
// lifecycle that follows ends with an empty project, and a key holding values
// refuses to be deleted at all.
func runValueLifecycle(t *testing.T, db *store.DB, actor service.Actor, who domain.PrincipalID, scope domain.Scope) {
	t.Helper()
	ctx := tctx(t)
	kr := probeKeyring(t, db)
	keys := &service.Keys{DB: db, Keyring: probeKeyring(t, db)}
	envs := &service.Environments{DB: db, Keyring: kr}
	values := &service.Values{DB: db, Keyring: kr}

	source, err := envs.Create(ctx, actor, scope, "audited-values-source")
	if err != nil {
		t.Fatal(err)
	}
	dest, err := envs.Create(ctx, actor, scope, "audited-values-dest")
	if err != nil {
		t.Fatal(err)
	}
	sourceScope := scope
	sourceScope.Env = domain.EnvID(source.ID)
	destScope := scope
	destScope.Env = domain.EnvID(dest.ID)

	key, err := keys.Create(ctx, actor, scope, service.KeySpec{
		Name: "AUDITED_VALUE", Classification: string(schema.Secret),
		Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}},
		Presence:    schema.DefaultPresenceRules(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// STAGE then PUBLISH (#51): `values set` writes the caller's own working
	// state and delivers nothing, so the two events are separate types and both
	// need a real emitter behind them here — value.staged for the draft,
	// revision.published for the materialization it commits.
	revisions := &service.Revisions{DB: db, Keyring: kr}
	staged, err := values.Set(ctx, actor, sourceScope, key.Name, "audited-material")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revisions.Publish(ctx, actor, sourceScope, []string{staged.VersionID}); err != nil {
		t.Fatal(err)
	}
	// Rollback and pin lifecycle (#52): restore stages ordinary drafts; pin
	// create, renew, reassign and release each carry their own durable event.
	if _, err := revisions.Restore(ctx, actor, sourceScope, 1, ""); err != nil {
		t.Fatal(err)
	}
	const workload = domain.PrincipalID("mch_audit_pin")
	execRaw(t, db, `INSERT INTO principals (id, kind, class, created_at) VALUES ('mch_audit_pin', 'machine', 'workload', `+ts+`)`)
	execRaw(t, db, fmt.Sprintf(`INSERT INTO service_accounts
		(id, principal_id, org_id, project_id, name, kind, created_at, created_by)
		VALUES ('sa_audit_pin', 'mch_audit_pin', '%s', '%s', 'audit-pin', 'workload', %s, '%s')`,
		scope.Org, scope.Project, ts, who))
	execRaw(t, db, fmt.Sprintf(`INSERT INTO grants
		(id, principal_id, capability, org_id, project_id, env_id, created_at)
		VALUES ('grt_audit_pin_read', 'mch_audit_pin', 'read', '%s', '%s', NULL, %s)`,
		scope.Org, scope.Project, ts))
	pins := &service.Pins{DB: db, Keyring: kr}
	latest := queryInt(t, db, fmt.Sprintf("SELECT MAX(revision) FROM snapshots WHERE environment_id = '%s'", source.ID))
	if _, err := pins.Set(ctx, actor, sourceScope, service.SetPinRequest{
		WorkloadPrincipalID: workload, Revision: latest,
		ExpiresAt: time.Now().UTC().Add(service.MaxPinLifetime + time.Hour),
	}); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("pin expiry refusal = %v, want invalid", err)
	}
	if _, err := pins.Set(ctx, actor, sourceScope, service.SetPinRequest{WorkloadPrincipalID: workload, Revision: latest}); err != nil {
		t.Fatal(err)
	}
	if _, err := pins.Set(ctx, actor, sourceScope, service.SetPinRequest{WorkloadPrincipalID: workload, Revision: latest}); err != nil {
		t.Fatal(err)
	}
	if _, err := pins.Set(ctx, actor, sourceScope, service.SetPinRequest{WorkloadPrincipalID: workload, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if err := pins.Release(ctx, actor, sourceScope, workload); err != nil {
		t.Fatal(err)
	}
	execRaw(t, db, "DELETE FROM pin_generations WHERE principal_id = 'mch_audit_pin'")
	execRaw(t, db, "DELETE FROM grants WHERE principal_id = 'mch_audit_pin'")
	execRaw(t, db, "DELETE FROM service_accounts WHERE principal_id = 'mch_audit_pin'")
	execRaw(t, db, "DELETE FROM principals WHERE id = 'mch_audit_pin'")
	// A revealing read: one disclosure event for the one `secret` key.
	if _, err := values.Get(ctx, actor, sourceScope, key.Name, true); err != nil {
		t.Fatal(err)
	}
	if _, err := values.Copy(ctx, actor, scope, service.CopyRequest{
		SourceEnvironmentID:       source.ID,
		KeyNames:                  []string{key.Name},
		DestinationEnvironmentIDs: []string{dest.ID},
	}); err != nil {
		t.Fatal(err)
	}
	for _, env := range []domain.Scope{sourceScope, destScope} {
		cleared, err := values.Unset(ctx, actor, env, key.Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := revisions.Publish(ctx, actor, env, []string{cleared.VersionID}); err != nil {
			t.Fatal(err)
		}
	}
	// `rotate-token-key` is the last registered type with no other emitter. It
	// is instance-scoped, so it runs as the operator principal rather than the
	// tenant actor this helper otherwise uses.
	if _, err := revisions.RotateTokenKey(ctx, service.LocalPrincipal(root)); err != nil {
		t.Fatal(err)
	}
	// `rotate-scanning-key` (#74) is the same shape: instance-scoped, the only
	// emitter of crypto.scanning_key_rotated.
	if _, err := revisions.RotateScanningKey(ctx, service.LocalPrincipal(root)); err != nil {
		t.Fatal(err)
	}
	// A `values import` run (#68), so value.imported has a real emitter. It
	// carries the manifest precondition, which is the shape that matters to the
	// trail: `manifest_bound` is the fact an investigator reads first.
	presence, err := values.Occurrences(ctx, actor, sourceScope, nil)
	if err != nil {
		t.Fatal(err)
	}
	pre := service.ImportPrecondition{
		DefinitionsRevision: presence.DefinitionsRevision,
		Environments:        []string{source.ID},
	}
	for _, k := range presence.Keys {
		pre.Occurrences = append(pre.Occurrences, service.ImportOccurrenceRef{
			Key: k.Name, Environment: source.ID, Token: k.Token,
		})
	}
	if _, err := values.Import(ctx, actor, sourceScope, service.ImportRequest{
		Entries:      []service.ImportEntry{{Key: key.Name, Value: "imported-material"}},
		Precondition: &pre,
	}); err != nil {
		t.Fatal(err)
	}
	cleared, err := values.Unset(ctx, actor, sourceScope, key.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revisions.Publish(ctx, actor, sourceScope, []string{cleared.VersionID}); err != nil {
		t.Fatal(err)
	}
	if err := keys.Delete(ctx, actor, scope, key.ID); err != nil {
		t.Fatal(err)
	}
	for _, env := range []domain.Scope{sourceScope, destScope} {
		if err := envs.Delete(ctx, actor, env); err != nil {
			t.Fatal(err)
		}
	}
}

// runCatalogueLifecycle drives every key-catalogue mutation (#49) so each
// settings.key_* type has a real emitter behind it before the emitter check
// reads the trails. It ends with an EMPTY catalogue, because the project
// delete that follows refuses while any key or group is still declared.
func runCatalogueLifecycle(t *testing.T, db *store.DB, actor service.Actor, scope domain.Scope) {
	t.Helper()
	ctx := tctx(t)
	keys := &service.Keys{DB: db, Keyring: probeKeyring(t, db)}
	groups := &service.KeyGroups{DB: db, Keyring: probeKeyring(t, db)}

	secret, err := keys.Create(ctx, actor, scope, service.KeySpec{
		Name:           "AUDITED_SECRET",
		Classification: string(schema.Secret),
		FolderPath:     "audited",
		Declaration:    schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}},
		Presence:       schema.DefaultPresenceRules(),
	})
	if err != nil {
		t.Fatal(err)
	}
	config, err := keys.Create(ctx, actor, scope, service.KeySpec{
		Name:           "AUDITED_CONFIG",
		Classification: string(schema.Config),
		Declaration:    schema.Declaration{Rule: &schema.Rule{Type: schema.TypeBoolean}},
		Presence:       schema.DefaultPresenceRules(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Rename(ctx, actor, scope, secret.ID, "AUDITED_SECRET_RENAMED"); err != nil {
		t.Fatal(err)
	}
	folder, description, note, deprecated := "audited/moved", "documented", "superseded", true
	if _, err := keys.UpdateMetadata(ctx, actor, scope, secret.ID, service.KeyMetadataUpdate{
		FolderPath: &folder, Description: &description,
		Deprecated: &deprecated, DeprecationNote: &note,
	}); err != nil {
		t.Fatal(err)
	}
	// A tightened rule on a SECRET key: the reveal gate fires here, which is
	// the only emitter of settings.key_reveal_gate_passed's rule-change form.
	minLength := 8
	if _, err := keys.UpdateDeclaration(ctx, actor, scope, secret.ID, service.KeyDeclarationUpdate{
		Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString, MinLength: &minLength}},
		Presence:    schema.DefaultPresenceRules(),
	}); err != nil {
		t.Fatal(err)
	}
	group, err := groups.Create(ctx, actor, scope, "audited-group")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.SetGroup(ctx, actor, scope, secret.ID, group.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := groups.Rename(ctx, actor, scope, group.ID, "audited-group-renamed"); err != nil {
		t.Fatal(err)
	}
	if err := groups.Delete(ctx, actor, scope, group.ID); err != nil {
		t.Fatal(err)
	}
	// Declassification: the second reveal gate, plus the reclassification
	// record itself.
	if _, err := keys.Reclassify(ctx, actor, scope, secret.ID, string(schema.Config)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{secret.ID, config.ID} {
		if err := keys.Delete(ctx, actor, scope, id); err != nil {
			t.Fatal(err)
		}
	}
}
