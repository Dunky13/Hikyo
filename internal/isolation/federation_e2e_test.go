package isolation

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/admission"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/delivery"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/oidcfed"
	"github.com/Hikyo-Org/hikyo/internal/oidctest"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// OIDC federation and the conditional fetch cursor (#62, machine-identities ADR
// § Federation, § JWKS, § Restore, § Authentication authorization and the fetch
// path; mvp-boundary M1's federation portion).
//
// Every fixture here runs against a REAL wire flow: a live test issuer over
// httptest serving discovery and JWKS, RS256-signed tokens carrying each
// platform's actual claim vocabulary, and a real datastore on both engines. The
// acceptance criteria are named on the tests that discharge them.

// clock is a mutable instant every seam under test reads, so the staleness bound
// and the restore predicate are exercised by moving time rather than by
// sleeping. Shared because the whole point of some fixtures is that the cache's
// clock and the validator's clock agree.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock { return &clock{now: time.Now().UTC().Truncate(time.Second)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fedRig is one federation fixture: an issuer, the services under test, and the
// clock they share.
type fedRig struct {
	db    *store.DB
	clk   *clock
	idp   *oidctest.IdP
	fed   *service.Federation
	del   *service.Delivery
	ident *service.Identities
	cache *oidcfed.Cache
}

// newFedRig wires the whole surface against a seeded database.
//
// The admission limiter is REAL rather than nil: the unknown-`kid` refresh limit
// is the ADR's named outbound-fetch amplifier defence, and a fixture that passed
// nil would exercise the unlimited path and prove nothing about the limited one.
func newFedRig(t *testing.T, db *store.DB) *fedRig {
	t.Helper()
	identityFixtures(t, db)
	seedDeliveryCatalogue(t, db)
	return fedRigOn(t, db)
}

// fedRigOn wires the surface WITHOUT seeding, for a caller whose database is
// already seeded — the audit suite's emitter walk, which has run the identity
// lifecycle first and would otherwise insert the same fixture principals twice.
func fedRigOn(t *testing.T, db *store.DB) *fedRig {
	t.Helper()
	idp, err := oidctest.NewTLS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)

	clk := newClock()
	limiter, err := admission.New(admission.Config{
		ArgonMemoryKiB: crypto.PasswordFloor.MemoryKiB, Now: clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	cache := &oidcfed.Cache{Limiter: limiter, Nowf: clk.Now, HTTP: idp.Client()}
	fed := &service.Federation{
		DB: db, Auth: authWithWindow(db), Cache: cache, Now: clk.Now,
	}
	return &fedRig{
		db: db, clk: clk, idp: idp, fed: fed, cache: cache,
		ident: identitySvc(db),
		del: &service.Delivery{
			DB: db, Keyring: authService(t, db).Keyring, Federation: fed, Now: clk.Now,
		},
	}
}

// seedDeliveryCatalogue gives the fetch surface something to deliver: two keys,
// one `config` and one `secret`, with a presence rule that differs per
// environment. It writes rows directly because declaring keys through the
// catalogue API would need `definitions-edit` fixtures this file is not about.
func seedDeliveryCatalogue(t *testing.T, db *store.DB) {
	t.Helper()
	for _, stmt := range []string{
		`INSERT INTO keys (id, org_id, project_id, name, folder_path, classification, description, deprecated, deprecation_note, declaration, required_mode, forbidden_mode, group_id, created_at)
		 VALUES ('key_fed_url', 'org_a', 'prj_a1', 'DATABASE_URL', '', 'config', '', FALSE, '', '{"rule":{"type":"string"}}', 'none', 'none', NULL, ` + ts + `)`,
		`INSERT INTO keys (id, org_id, project_id, name, folder_path, classification, description, deprecated, deprecation_note, declaration, required_mode, forbidden_mode, group_id, created_at)
		 VALUES ('key_fed_pw', 'org_a', 'prj_a1', 'DATABASE_PASSWORD', '', 'secret', '', FALSE, '', '{"rule":{"type":"string"}}', 'none', 'none', NULL, ` + ts + `)`,
	} {
		execRaw(t, db, stmt)
	}
	// #51: DELIVERY READS ONLY COMMITTED SNAPSHOTS, or fails closed. Seeding
	// the catalogue is therefore no longer enough to make a fetch answer — the
	// environments must be MATERIALIZED, and an environment is materialized by
	// publishing into it.
	//
	// Both keys get real values, which is also what makes the change-token
	// assertions meaningful for the first time: the manifest is
	// `(key, classification, value)` triples, so a token that did not move with
	// a value would be a token no consumer could use.
	//
	// NEITHER KEY CARRIES A PRESENCE RULE, and that is deliberate under #51.
	// A `required_in` rule is a standing obligation on every LATER
	// materialization of that environment — and this fixture's project is
	// shared with the audit suite, which creates environments and keys of its
	// own afterwards. A `mode: all` requirement here would veto those,
	// coupling two unrelated suites through the schema. The presence veto has
	// its own scenarios; this fixture only needs values that deliver.
	// `definitions-edit` rides along because a semantic schema change is now
	// part of what the delivery tests exercise: reclassification and presence
	// edits are the two ways a snapshot moves without a value moving.
	for i, capability := range []string{"edit", "publish", "definitions-edit"} {
		execRaw(t, db, fmt.Sprintf(
			`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
			 VALUES ('g_del_%d', '%s', '%s', 'org_a', 'prj_a1', NULL, %s)`,
			i, identAdmin, capability, ts))
	}
	// Both env_a1 keys land in ONE publish, which is also the ordinary shape:
	// a publish names a set of version ids and materializes once.
	publishDeliveryValues(t, db, envA1, map[string]string{
		"DATABASE_URL": "postgres://dev", "DATABASE_PASSWORD": "dev-secret",
	})
	publishDeliveryValues(t, db, envProd, map[string]string{"DATABASE_URL": "postgres://prod"})
}

// publishDeliveryValues stages a batch of values and publishes exactly those
// versions, as the fixture administrator. It is the two-step every delivering
// write is made of under #51: `edit` stages, `publish` commits, and nothing
// delivers in between.
func publishDeliveryValues(t *testing.T, db *store.DB, env domain.EnvID, values map[string]string) {
	t.Helper()
	actor := service.LocalPrincipal(identAdmin)
	scope := scopeEnv(orgA, prjA1, env)
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	versions := make([]string, 0, len(names))
	for _, name := range names {
		staged, err := valueSvc(t, db).Set(t.Context(), actor, scope, name, values[name])
		if err != nil {
			t.Fatalf("stage %s in %s: %v", name, env, err)
		}
		versions = append(versions, staged.VersionID)
	}
	revisions := revisionSvc(t, db)
	_, err := revisions.PublishPlanned(t.Context(), actor, scope, service.PublishRequest{VersionIDs: versions})
	if errors.Is(err, service.ErrProtectedDestination) {
		_, err = revisions.PublishPlanned(t.Context(), actor, scope, service.PublishRequest{
			VersionIDs: versions, ConfirmedProtectedEnvironments: []string{string(scope.Env)},
		})
	}
	if err != nil {
		t.Fatalf("publish %v in %s: %v", names, env, err)
	}
}

// revisionSvc is the publish pipeline with a live keyring: a snapshot is
// sealed material, so there is nothing to fake here either.
func revisionSvc(t *testing.T, db *store.DB) *service.Revisions {
	t.Helper()
	return &service.Revisions{DB: db, Keyring: probeKeyring(t, db)}
}

// grantMachineRead gives a service account `read` at one environment through the
// REAL grant API, so the fetch it enables passes the same widening gate a
// production grant does. `read` is on the workload allowlist at environment
// depth, which is exactly the shape #55 requires of a workload grant.
func grantMachineRead(t *testing.T, db *store.DB, p domain.PrincipalID, env domain.EnvID) {
	t.Helper()
	if _, err := grantSvcWithAuth(db).Create(t.Context(), service.LocalPrincipal(identAdmin),
		service.GrantSpec{Target: p, Capability: domain.CapRead, Scope: envScope(env)}); err != nil {
		t.Fatalf("grant read(%s) to %s: %v", env, p, err)
	}
}

// configureIssuer registers the fixture issuer under `instance-config`.
func (r *fedRig) configureIssuer(t *testing.T, typ domain.IssuerType, refused []string) service.IssuerView {
	t.Helper()
	iss, err := r.fed.CreateIssuer(t.Context(), service.LocalPrincipal(root), service.IssuerRequest{
		Issuer: r.idp.Issuer(), Type: typ, Mode: domain.JWKSDiscovery,
		RefusedAudiences: refused,
	})
	if err != nil {
		t.Fatalf("configure issuer: %v", err)
	}
	return iss
}

// bindShape creates a service account and binds the shape's subject and pinned
// claims to it, then grants it `read` on env_a1.
func (r *fedRig) bindShape(t *testing.T, name string, s oidctest.Shape, audience string) (service.ServiceAccountView, service.BindingView) {
	t.Helper()
	sa, err := r.ident.CreateServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), name, domain.ClassWorkload)
	if err != nil {
		t.Fatalf("create service account: %v", err)
	}
	binding, err := r.fed.CreateBinding(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.BindingRequest{
			Issuer: r.idp.Issuer(), Subject: s.Subject, Audience: audience,
			RequiredClaims: pinsOf(t, s),
		})
	if err != nil {
		t.Fatalf("create binding: %v", err)
	}
	grantMachineRead(t, r.db, sa.Principal, envA1)
	return sa, binding
}

// pinsOf converts a fixture shape's pinned map into the discriminated pins the
// API takes. It preserves the string/number distinction, which is the whole
// reason the wire shape is discriminated: a GitHub `repository_id` is the number
// 4242 and must never be satisfied by the string "4242".
func pinsOf(t *testing.T, s oidctest.Shape) []service.ClaimPin {
	t.Helper()
	out := make([]service.ClaimPin, 0, len(s.Pinned))
	for claim, value := range s.Pinned {
		pin := service.ClaimPin{Claim: claim}
		switch v := value.(type) {
		case string:
			sv := v
			pin.String = &sv
		case int64:
			nv := v
			pin.Number = &nv
		case bool:
			bv := v
			pin.Boolean = &bv
		default:
			t.Fatalf("fixture pins %q as %T, which the wire shape cannot carry", claim, value)
		}
		out = append(out, pin)
	}
	return out
}

// hikyoAudience is the audience a workload asks its platform for. It is
// deliberately NOT any platform's default: the whole audience rule is that the
// default must be refused.
const hikyoAudience = "hikyo://instance"

func TestFederationAgainstEachIssuerTypeSQLite(t *testing.T) {
	runFederationPerIssuerType(t, seededDB(t, openSQLite))
}

func TestFederationAgainstEachIssuerTypePostgres(t *testing.T) {
	runFederationPerIssuerType(t, seededDB(t, openPostgres))
}

// runFederationPerIssuerType is mvp-boundary M1's "[E2E] federation against a
// real issuer fixture per type": Kubernetes projected ServiceAccount tokens,
// Forgejo Actions and GitHub Actions, each with its own subject grammar, its own
// claim vocabulary and its own default audience.
//
// Each type runs the same three assertions, because they are the ones that
// generalise: a correctly bound token authenticates and delivers; the same
// identity asking for the platform's DEFAULT audience does not; and an
// unbound subject does not.
func runFederationPerIssuerType(t *testing.T, db *store.DB) {
	cases := []struct {
		name  string
		typ   domain.IssuerType
		shape oidctest.Shape
	}{
		{"kubernetes", domain.IssuerKubernetes,
			oidctest.KubernetesShape("prod", "deployer", "uid-9f2c", "https://kubernetes.default.svc")},
		{"forgejo", domain.IssuerForgejo,
			oidctest.ForgejoShape("https://git.example.test", "acme/service", "refs/heads/main", "push")},
		{"github-actions", domain.IssuerGitHubActions,
			oidctest.GitHubActionsShape("acme/service", 4242, 77, "refs/heads/main", "push")},
	}

	// One rig per case: its own database and its own issuer. Sharing one would
	// mean re-registering a single issuer under three platform types, and the
	// per-platform rules — the CI `event_name` pin, the default-audience list —
	// are properties OF the type, so a shared issuer would test one of them three
	// times rather than three of them once. The outer `db` is the caller's engine
	// selection, which each case re-seeds.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			caseDB := db
			if tc.name != cases[0].name {
				caseDB = seededDB(t, engineOpener(db))
			}
			r := newFedRig(t, caseDB)
			r.configureIssuer(t, tc.typ, []string{tc.shape.DefaultAudience})
			r.bindShape(t, "wl-"+tc.name, tc.shape, hikyoAudience)

			bound, err := r.idp.MintShape(tc.shape, hikyoAudience, r.clk.Now(), 10*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			res, err := r.del.Fetch(t.Context(), bound, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{})
			if err != nil {
				t.Fatalf("federated fetch: %v", err)
			}
			if res.Current {
				t.Fatal("a cursor-less federated fetch answered `current`")
			}
			// The bound identity holds `read` and no disclosure capability, so
			// the value rule applies per classification: the config value
			// crosses, the secret is presence-only. A federated principal has
			// identical authority to a bearer sibling, so this is the same rule
			// the bearer tests exercise, reached over a real token.
			presence := map[string]delivery.Presence{}
			values := map[string]*string{}
			for _, k := range res.Keys {
				presence[k.Name] = k.Presence
				values[k.Name] = k.Value
			}
			// Every delivered key is `set`: it is in the payload because the
			// snapshot RESOLVED it. The declared presence rule is no longer
			// what a fetch reports — the delivered key set is exactly the keys
			// that resolve, under the schema revision the snapshot pinned.
			for _, name := range []string{"DATABASE_PASSWORD", "DATABASE_URL"} {
				if presence[name] != delivery.PresenceSet {
					t.Errorf("presence for %s = %q, want set (the snapshot delivers it)", name, presence[name])
				}
			}
			if v := values["DATABASE_URL"]; v == nil {
				t.Error("the config value did not cross under read")
			}
			if values["DATABASE_PASSWORD"] != nil {
				t.Error("the secret value crossed without reveal — it must be presence-only")
			}

			// THE DEFAULT AUDIENCE IS REFUSED. Same identity, same signature,
			// same pinned claims — only the audience differs, and it is the one
			// the platform hands out when nobody asks.
			defaulted, err := r.idp.MintShape(tc.shape, tc.shape.DefaultAudience, r.clk.Now(), 10*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.del.Fetch(t.Context(), defaulted, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
				t.Fatalf("default-audience token = %v, want the uniform refusal", err)
			}

			// A token carrying BOTH audiences is refused too. A Kubernetes token
			// minted for the API server that happens to list Hikyo as well is
			// still a token the API server could have been handed.
			both, err := r.idp.MintShape(tc.shape,
				[]string{hikyoAudience, tc.shape.DefaultAudience}, r.clk.Now(), 10*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.del.Fetch(t.Context(), both, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
				t.Fatalf("multi-audience token = %v, want the uniform refusal", err)
			}

			// AN UNBOUND SUBJECT IS NOT A LOGIN. Byte-exact means byte-exact: a
			// subject differing by one character resolves nothing, and there is
			// no pattern, prefix or namespace rule that could rescue it.
			unbound := tc.shape
			unbound.Subject += "x"
			unbound.Claims = cloneClaims(tc.shape.Claims)
			unbound.Claims["sub"] = unbound.Subject
			stranger, err := r.idp.MintShape(unbound, hikyoAudience, r.clk.Now(), 10*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.del.Fetch(t.Context(), stranger, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
				t.Fatalf("unbound subject = %v, want the uniform refusal", err)
			}
		})
	}
}

func cloneClaims(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// engineOpener returns the opener matching an already-open database, so a
// subtest can take a fresh one on the SAME engine the caller selected. Without
// it, the per-issuer-type loop would have to be written twice.
func engineOpener(db *store.DB) func(*testing.T) *store.DB {
	if db.Engine() == store.EnginePostgres {
		return openPostgres
	}
	return openSQLite
}

func TestFederationRefusesPullRequestEventsSQLite(t *testing.T) {
	runPullRequestRefusal(t, seededDB(t, openSQLite))
}

func TestFederationRefusesPullRequestEventsPostgres(t *testing.T) {
	runPullRequestRefusal(t, seededDB(t, openPostgres))
}

// runPullRequestRefusal is mvp-boundary M1's "`pull_request` /
// `pull_request_target` refusal unless separately bound".
//
// The dangerous one is `pull_request_target`, and the fixture is built to show
// exactly why: it carries the ORDINARY ref-form subject, the default branch's
// subject, the one a production binding names. So a token minted for it against
// a production `push` binding matches the subject perfectly and is refused only
// by the pinned `event_name`.
func runPullRequestRefusal(t *testing.T, db *store.DB) {
	r := newFedRig(t, db)
	const instance = "https://git.example.test"
	production := oidctest.ForgejoShape(instance, "acme/service", "refs/heads/main", "push")
	r.configureIssuer(t, domain.IssuerForgejo, []string{production.DefaultAudience})
	r.bindShape(t, "ci-production", production, hikyoAudience)

	// A CI binding that pins no `event_name` is refused AT CREATION. That is the
	// first of the rule's two enforcement points, and the more important one: it
	// makes the unsafe binding unrepresentable rather than merely ineffective.
	saNoEvent, err := r.ident.CreateServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), "ci-no-event", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	repo := "acme/service"
	if _, err := r.fed.CreateBinding(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), saNoEvent.ID, service.BindingRequest{
			Issuer: r.idp.Issuer(), Subject: production.Subject, Audience: hikyoAudience,
			RequiredClaims: []service.ClaimPin{{Claim: "repository", String: &repo}},
		}); !errors.Is(err, service.ErrBindingEventName) {
		t.Fatalf("CI binding without event_name = %v, want ErrBindingEventName", err)
	}

	// `pull_request_target` against the production binding. The subject IS the
	// production subject — the fixture asserts that rather than assuming it, so
	// the refusal cannot be a subject mismatch wearing an event rule's clothes.
	prTarget := oidctest.ForgejoShape(instance, "acme/service", "refs/heads/main", "pull_request_target")
	if prTarget.Subject != production.Subject {
		t.Fatalf("fixture broken: pull_request_target subject %q should equal the production subject %q",
			prTarget.Subject, production.Subject)
	}
	token, err := r.idp.MintShape(prTarget, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), token, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("pull_request_target against a push binding = %v, want the uniform refusal", err)
	}

	// `pull_request` carries the OTHER subject form, so it is refused twice over.
	// Both refusals are the same uniform answer, which is the point.
	pr := oidctest.ForgejoShape(instance, "acme/service", "refs/heads/main", "pull_request")
	prToken, err := r.idp.MintShape(pr, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), prToken, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("pull_request against a push binding = %v, want the uniform refusal", err)
	}

	// UNLESS SEPARATELY BOUND. A binding that deliberately pins
	// `event_name: pull_request_target` admits exactly that event — the ADR
	// permits it as an explicit, deliberate act, and the implementation must not
	// turn a deliberate binding into a blanket ban.
	saPR, err := r.ident.CreateServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), "ci-pr-target", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	// A distinct subject, because the production binding already holds the
	// ref-form one and the live-row unique index admits one binding per
	// `(issuer, subject)`. That constraint is itself the ADR's rule: one external
	// identity, one service account.
	deliberate := oidctest.ForgejoShape(instance, "acme/preview", "refs/heads/main", "pull_request_target")
	if _, err := r.fed.CreateBinding(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), saPR.ID, service.BindingRequest{
			Issuer: r.idp.Issuer(), Subject: deliberate.Subject, Audience: hikyoAudience,
			RequiredClaims: pinsOf(t, deliberate),
		}); err != nil {
		t.Fatalf("deliberate pull_request_target binding: %v", err)
	}
	grantMachineRead(t, db, saPR.Principal, envA1)
	prtToken, err := r.idp.MintShape(deliberate, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), prtToken, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("deliberately bound pull_request_target = %v, want acceptance", err)
	}
}

func TestFederationJWKSStalenessBoundSQLite(t *testing.T) {
	runJWKSStalenessBound(t, seededDB(t, openSQLite))
}

func TestFederationJWKSStalenessBoundPostgres(t *testing.T) {
	runJWKSStalenessBound(t, seededDB(t, openPostgres))
}

// runJWKSStalenessBound is mvp-boundary M1's "JWKS staleness bound under induced
// issuer outage".
//
// Three phases, and all three matter. Inside the refresh interval the cache is
// simply used. Past it, with the issuer DOWN, validation continues from cache —
// the ADR rejects failing closed the moment a refresh fails, because the failure
// this must survive is an API-server blip and refusing would stop every workload
// fetch cluster-wide. Past the staleness bound it FAILS CLOSED, loudly.
func runJWKSStalenessBound(t *testing.T, db *store.DB) {
	r := newFedRig(t, db)
	shape := oidctest.KubernetesShape("prod", "deployer", "uid-1", "https://kubernetes.default.svc")
	r.configureIssuer(t, domain.IssuerKubernetes, []string{shape.DefaultAudience})
	r.bindShape(t, "wl-staleness", shape, hikyoAudience)

	mint := func() string {
		t.Helper()
		token, err := r.idp.MintShape(shape, hikyoAudience, r.clk.Now(), 30*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}

	// Phase 1: warm the cache while the issuer is up.
	if _, err := r.del.Fetch(t.Context(), mint(), scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("warm fetch: %v", err)
	}
	warmFetches := r.idp.Fetches()
	if warmFetches == 0 {
		t.Fatal("no JWKS fetch happened: the fixture is not exercising the cache")
	}

	// Phase 2: induce the outage, move past the refresh interval, and assert
	// validation CONTINUES from cache. Stale-but-valid beats not-starting.
	r.idp.SetOffline(true)
	r.clk.advance(oidcfed.RefreshInterval + time.Minute)
	if _, err := r.del.Fetch(t.Context(), mint(), scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("fetch inside the staleness bound during an outage = %v, want serve-from-cache", err)
	}
	// The tolerated failure is RECORDED, not swallowed: the ADR requires an
	// event for a JWKS refresh failure, and "we are serving keys nobody could
	// confirm" is exactly the operator-visible fact.
	if n := queryInt(t, db,
		"SELECT COUNT(*) FROM audit_instance_events WHERE type = 'identity.jwks_refresh_failed'"); n == 0 {
		t.Error("a tolerated refresh failure emitted no identity.jwks_refresh_failed event")
	}

	// Phase 3: past the bound, FAIL CLOSED. The refusal is the uniform one on
	// the wire; the trail is where the cause lives.
	r.clk.advance(oidcfed.StalenessBound)
	if _, err := r.del.Fetch(t.Context(), mint(), scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("fetch past the staleness bound = %v, want the uniform refusal", err)
	}
	breaches := queryInt(t, db,
		"SELECT COUNT(*) FROM audit_instance_events WHERE type = 'identity.jwks_refresh_failed' AND payload LIKE '%\"staleness_breached\":true%'")
	if breaches == 0 {
		t.Error("the staleness-bound breach emitted no event recording it as a breach")
	}
	if refusals := queryInt(t, db,
		"SELECT COUNT(*) FROM audit_instance_events WHERE type = 'identity.federation_refused' AND payload LIKE '%keys-stale%'"); refusals == 0 {
		t.Error("the staleness-bound refusal was not recorded by cause")
	}

	// Phase 4: the issuer comes back and the fleet recovers WITHOUT operator
	// action. A bound that needed a restart to clear would be an outage with
	// extra steps.
	//
	// The clock advances past RefreshBackoff first, and that is the mechanism
	// rather than a test convenience: after a failed fetch the cache suppresses
	// the next attempt for one window, so recovery is bounded by the backoff — one
	// retry per issuer per window, never one per request.
	r.idp.SetOffline(false)
	r.clk.advance(oidcfed.RefreshBackoff + time.Second)
	if _, err := r.del.Fetch(t.Context(), mint(), scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("fetch after the issuer recovered = %v, want acceptance", err)
	}
}

func TestFederationUnknownKIDRefreshIsRateLimitedSQLite(t *testing.T) {
	runUnknownKIDRateLimit(t, seededDB(t, openSQLite))
}

// runUnknownKIDRateLimit exercises the ADR's outbound-fetch amplifier defence:
// an unknown `kid` triggers a refresh, and that trigger is rate-limited because
// it sits on a pre-authentication path where fabricated `kid` values would
// otherwise become one outbound request each, aimed at the issuer.
//
// sqlite only: the property under test is entirely in the JWKS cache and the
// admission limiter, neither of which touches the datastore, so a second engine
// leg would re-run the same assertions against the same in-memory objects.
func runUnknownKIDRateLimit(t *testing.T, db *store.DB) {
	r := newFedRig(t, db)
	shape := oidctest.KubernetesShape("prod", "deployer", "uid-1", "https://kubernetes.default.svc")
	r.configureIssuer(t, domain.IssuerKubernetes, []string{shape.DefaultAudience})
	r.bindShape(t, "wl-kid", shape, hikyoAudience)

	// Warm the cache with the current key.
	first, err := r.idp.MintShape(shape, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), first, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("warm fetch: %v", err)
	}

	// A genuine rotation: the issuer mints a new key and publishes both. The
	// unknown `kid` triggers exactly the refresh the mechanism exists for, and
	// the token verifies without any operator action.
	if err := r.idp.Rotate(); err != nil {
		t.Fatal(err)
	}
	rotated, err := r.idp.MintShape(shape, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), rotated, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("fetch after issuer key rotation = %v, want the unknown-kid refresh to recover it", err)
	}

	// Now the amplifier. Every rotation past the allowance presents a `kid` the
	// cache does not know, and the limiter must stop turning those into outbound
	// fetches. The assertion is on the FETCH COUNT rather than on the refusal,
	// because the refusal is not the property — the bounded outbound work is.
	before := r.idp.Fetches()
	for range admission.IssuerRefreshPerMinute * 3 {
		if err := r.idp.Rotate(); err != nil {
			t.Fatal(err)
		}
		token, err := r.idp.MintShape(shape, hikyoAudience, r.clk.Now(), 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		// The outcome is deliberately not asserted: some of these succeed (the
		// refresh went out) and some fail (it was throttled), and which is which
		// depends on where in the window the loop is. Both are correct.
		_, _ = r.del.Fetch(t.Context(), token, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{})
	}
	if spent := r.idp.Fetches() - before; spent > admission.IssuerRefreshPerMinute {
		t.Errorf("%d outbound JWKS fetches for %d unknown kids: the per-issuer allowance of %d did not bind",
			spent, admission.IssuerRefreshPerMinute*3, admission.IssuerRefreshPerMinute)
	}
	// And the throttling is recorded, because an operator debugging a fleet that
	// stopped authenticating needs to know the limiter is why.
	if n := queryInt(t, db,
		"SELECT COUNT(*) FROM audit_instance_events WHERE type = 'identity.jwks_refresh_failed' AND payload LIKE '%\"refresh_throttled\":true%'"); n == 0 {
		t.Error("a throttled unknown-kid refresh emitted no event recording the throttle")
	}
}

func TestFederationStaticJWKSSQLite(t *testing.T) {
	db := seededDB(t, openSQLite)
	r := newFedRig(t, db)
	shape := oidctest.KubernetesShape("prod", "airgapped", "uid-air", "https://kubernetes.default.svc")

	document, err := r.idp.JWKSDocument()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.fed.CreateIssuer(t.Context(), service.LocalPrincipal(root), service.IssuerRequest{
		Issuer: r.idp.Issuer(), Type: domain.IssuerKubernetes, Mode: domain.JWKSStatic,
		StaticJWKS: document, RefusedAudiences: []string{shape.DefaultAudience},
	}); err != nil {
		t.Fatalf("configure static issuer: %v", err)
	}
	r.bindShape(t, "wl-static", shape, hikyoAudience)

	// The issuer is DOWN for the whole fixture. A static JWKS is configuration,
	// not machinery: it is never fetched, so air-gapped operation works and the
	// staleness bound has nothing to be stale about.
	r.idp.SetOffline(true)
	token, err := r.idp.MintShape(shape, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), token, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("static-JWKS fetch with the issuer unreachable = %v, want acceptance", err)
	}
	if r.idp.Fetches() != 0 {
		t.Errorf("static mode performed %d outbound JWKS fetches, want none", r.idp.Fetches())
	}

	// And the documented failure mode is loud rather than silent: the issuer
	// rotates, the configuration does not, and the next token is refused.
	if err := r.idp.Rotate(); err != nil {
		t.Fatal(err)
	}
	rotated, err := r.idp.MintShape(shape, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), rotated, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("static JWKS after an unrecorded rotation = %v, want the uniform refusal", err)
	}
}

func TestFederationRestorePredicateSQLite(t *testing.T) {
	runRestorePredicate(t, seededDB(t, openSQLite))
}

func TestFederationRestorePredicatePostgres(t *testing.T) {
	runRestorePredicate(t, seededDB(t, openPostgres))
}

// runRestorePredicate is the ADR's § Restore `iat` rule: a token presented
// against a RE-ACTIVATED binding must have been issued after re-activation, by a
// margin that swallows clock skew.
//
// The margin is the whole point, not padding. Validation accepts an `iat` within
// the skew in both directions, so an issuer whose clock leads Hikyo by the
// accepted skew mints tokens with an `iat` in Hikyo's future — and an attacker
// capturing one immediately before the restore holds an artifact that satisfies a
// naive `iat > reactivated_at` test while being, in fact, a pre-restore
// credential. The fixture mints exactly that artifact.
//
// And the predicate is PERMANENT. The last phase moves the clock far past every
// window in the system and re-presents the captured token, because a time-boxed
// quarantine that simply expires is not equivalent and must not be substituted.
func runRestorePredicate(t *testing.T, db *store.DB) {
	r := newFedRig(t, db)
	shape := oidctest.KubernetesShape("prod", "restored", "uid-r", "https://kubernetes.default.svc")
	r.configureIssuer(t, domain.IssuerKubernetes, []string{shape.DefaultAudience})
	sa, binding := r.bindShape(t, "wl-restore", shape, hikyoAudience)

	// The captured pre-restore artifact: an `iat` in Hikyo's FUTURE, inside the
	// accepted skew, exactly what an issuer whose clock leads produces.
	captured, err := r.idp.MintShape(shape, hikyoAudience,
		r.clk.Now().Add(oidcfed.MaxClockSkew-time.Second), 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// It authenticates BEFORE the restore. If it did not, the fixture would be
	// proving nothing about the predicate.
	if _, err := r.del.Fetch(t.Context(), captured, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("pre-restore fetch with a skewed iat = %v, want acceptance", err)
	}

	// The restore's re-validation of this binding.
	at, err := r.fed.Reactivate(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, binding.CredentialID)
	if err != nil {
		t.Fatalf("reactivate binding: %v", err)
	}
	if at.IsZero() {
		t.Fatal("reactivation recorded no instant")
	}

	// The captured token is now dead, even though its `iat` is strictly AFTER the
	// re-activation instant. That inequality is the fixture's whole premise —
	// asserted, not assumed — because it is what makes the refusal a property of
	// the MARGIN rather than of ordinary ordering: a naive `iat > reactivated_at`
	// test would admit this token.
	capturedIAT := at.Add(oidcfed.MaxClockSkew - time.Second)
	if !capturedIAT.After(at) {
		t.Fatalf("fixture broken: the captured iat %s must be after the re-activation instant %s", capturedIAT, at)
	}
	if _, err := r.del.Fetch(t.Context(), captured, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("captured pre-restore token after re-activation = %v, want the uniform refusal", err)
	}
	// The refusal IS recorded, and under the in-transaction leg's single cause
	// rather than a restore-specific one.
	//
	// That collapse is deliberate and worth stating: the resolution surface hands
	// the predicate a DECOY binding on a miss, so an unbound identity runs the
	// same claim comparisons a bound one does — which is what keeps the unbound
	// case from being the cheap case, and which also means the predicate's verdict
	// on a miss is the decoy's verdict, not this binding's. Reporting it as a
	// cause would therefore sometimes report the decoy. One cause for the whole
	// in-transaction leg is the honest answer; the pre-transaction causes
	// (unknown issuer, stale keys, signature, token age) are reported
	// individually because nothing decoy-shaped is involved in producing them.
	if n := queryInt(t, db,
		"SELECT COUNT(*) FROM audit_instance_events WHERE type = 'identity.federation_refused' AND payload LIKE '%unbound%'"); n == 0 {
		t.Error("the restore-predicate refusal was not recorded at all")
	}

	// A token minted strictly after the floor authenticates, so the predicate is
	// a floor rather than a wall.
	r.clk.advance(oidcfed.MaxClockSkew + time.Minute)
	fresh, err := r.idp.MintShape(shape, hikyoAudience, r.clk.Now(), 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), fresh, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("post-reactivation token = %v, want acceptance", err)
	}

	// PERMANENT, not a quarantine window — and this phase is built to be
	// FALSIFIABLE, which the first version was not: it presented a 24-hour-span
	// token more than an hour old, so MaxTokenSpan and MaxTokenAge rejected it
	// before the predicate ran and deleting the predicate outright would have left
	// the phase green.
	//
	// Both tokens below sit INSIDE both caps, are presented at the same instant,
	// and differ in exactly one thing: whether `iat` is above or below
	// `reactivated_at + MaxClockSkew`. The pair is the delete-and-it-fails
	// property — remove the predicate and the first one is accepted too.
	//
	// The instant is far past any plausible quarantine window's expiry: the clock
	// has advanced well beyond the two-minute margin, and MaxTokenAge bounds how
	// much further a live token can be carried at all.
	floor := at.Add(oidcfed.MaxClockSkew)
	r.clk.advance(40 * time.Minute)
	presentedAt := r.clk.Now()
	if age := presentedAt.Sub(floor); age <= oidcfed.MaxClockSkew || age >= oidcfed.MaxTokenAge {
		t.Fatalf("fixture broken: presenting %s after the floor must be well past the margin and inside MaxTokenAge", age)
	}

	// BELOW the floor by a second: a captured pre-restore artifact, valid in every
	// other respect.
	belowFloor, err := r.idp.MintShape(shape, hikyoAudience, floor.Add(-time.Second), 90*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// ABOVE the floor by a second, minted at the same moment, same span.
	aboveFloor, err := r.idp.MintShape(shape, hikyoAudience, floor.Add(time.Second), 90*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), aboveFloor, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("control token one second ABOVE the floor = %v, want acceptance — without this the refusal below proves nothing", err)
	}
	if _, err := r.del.Fetch(t.Context(), belowFloor, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("token one second BELOW the floor = %v, want a PERMANENT refusal", err)
	}
}

// TestFederationRequiresImmutableIdentifiersSQLite is the ADR's "where an issuer
// exposes immutable numeric identifiers for the repository and its owner, the
// binding pins those rather than the names" — read as the MUST it is and enforced
// at creation, per issuer type.
//
// The hole it closes: a binding pinning only `event_name=push` was accepted, so
// renaming `acme/prod` and letting someone else claim the path produced the same
// subject and inherited the Hikyo principal.
func TestFederationRequiresImmutableIdentifiersSQLite(t *testing.T) {
	db := seededDB(t, openSQLite)
	r := newFedRig(t, db)
	github := oidctest.GitHubActionsShape("acme/service", 4242, 77, "refs/heads/main", "push")
	r.configureIssuer(t, domain.IssuerGitHubActions, []string{github.DefaultAudience})

	sa, err := r.ident.CreateServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), "wl-ids", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	push := "push"
	repo := "acme/service"
	repoID := int64(4242)

	// event_name alone: refused. This is the exact binding the review found
	// acceptable.
	if _, err := r.fed.CreateBinding(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.BindingRequest{
			Issuer: r.idp.Issuer(), Subject: github.Subject, Audience: hikyoAudience,
			RequiredClaims: []service.ClaimPin{{Claim: "event_name", String: &push}},
		}); !errors.Is(err, service.ErrBindingImmutableID) {
		t.Fatalf("github binding pinning only event_name = %v, want ErrBindingImmutableID", err)
	}
	// Names instead of ids: still refused. Pinning `repository` is what a rename
	// defeats, which is the whole point of the rule.
	if _, err := r.fed.CreateBinding(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.BindingRequest{
			Issuer: r.idp.Issuer(), Subject: github.Subject, Audience: hikyoAudience,
			RequiredClaims: []service.ClaimPin{
				{Claim: "repository", String: &repo}, {Claim: "event_name", String: &push},
			},
		}); !errors.Is(err, service.ErrBindingImmutableID) {
		t.Fatalf("github binding pinning names instead of ids = %v, want ErrBindingImmutableID", err)
	}
	// One of the two ids: refused. The ADR names the repository AND its owner.
	if _, err := r.fed.CreateBinding(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.BindingRequest{
			Issuer: r.idp.Issuer(), Subject: github.Subject, Audience: hikyoAudience,
			RequiredClaims: []service.ClaimPin{
				{Claim: "repository_id", Number: &repoID}, {Claim: "event_name", String: &push},
			},
		}); !errors.Is(err, service.ErrBindingImmutableID) {
		t.Fatalf("github binding pinning only repository_id = %v, want ErrBindingImmutableID", err)
	}
	// Both ids plus event_name: accepted, and it authenticates.
	if _, err := r.fed.CreateBinding(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.BindingRequest{
			Issuer: r.idp.Issuer(), Subject: github.Subject, Audience: hikyoAudience,
			RequiredClaims: pinsOf(t, github),
		}); err != nil {
		t.Fatalf("github binding pinning both ids = %v, want acceptance", err)
	}
	grantMachineRead(t, db, sa.Principal, envA1)
	token, err := r.idp.MintShape(github, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), token, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("id-pinned binding = %v, want acceptance", err)
	}
}

// TestFederationPinsNestedKubernetesUIDSQLite is the other half of the same rule,
// and the reason nested claim paths exist at all.
//
// A real projected ServiceAccount token nests everything under the single literal
// claim `kubernetes.io`, so the immutable UID lives at
// `/kubernetes.io/serviceaccount/uid` and NOWHERE else. Without JSON-Pointer pins
// the ADR's requirement is unsatisfiable against a real token and the only
// writable bindings are the name-based ones it forbids.
func TestFederationPinsNestedKubernetesUIDSQLite(t *testing.T) {
	db := seededDB(t, openSQLite)
	r := newFedRig(t, db)
	shape := oidctest.KubernetesShape("prod", "deployer", "9f2c-uid", "https://kubernetes.default.svc")
	r.configureIssuer(t, domain.IssuerKubernetes, []string{shape.DefaultAudience})

	// The fixture must mint the REAL shape, or this test proves nothing about
	// real tokens. Asserted rather than assumed: the platform claims live under
	// one nested `kubernetes.io` object, and there is no flattened alias.
	if _, flattened := shape.Claims["kubernetes.io/serviceaccount/uid"]; flattened {
		t.Fatal("fixture regressed to inventing a flattened uid claim Kubernetes never emits")
	}
	nested, ok := shape.Claims["kubernetes.io"].(map[string]any)
	if !ok {
		t.Fatal("fixture does not nest the platform claims under `kubernetes.io`")
	}
	sub, ok := nested["serviceaccount"].(map[string]any)
	if !ok || sub["uid"] != "9f2c-uid" {
		t.Fatalf("fixture's nested serviceaccount is %v, want a uid", nested["serviceaccount"])
	}

	sa, _ := r.bindShape(t, "wl-nested", shape, hikyoAudience)
	token, err := r.idp.MintShape(shape, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), token, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("uid-pinned kubernetes binding = %v, want acceptance", err)
	}

	// A RECREATED ServiceAccount: same namespace, same name, same subject —
	// different uid. It must not inherit the binding. This is the attack the uid
	// pin exists for, and the name-based binding would have admitted it.
	recreated := oidctest.KubernetesShape("prod", "deployer", "different-uid", "https://kubernetes.default.svc")
	if recreated.Subject != shape.Subject {
		t.Fatalf("fixture broken: a recreated ServiceAccount must keep the subject %q", shape.Subject)
	}
	reborn, err := r.idp.MintShape(recreated, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), reborn, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("recreated ServiceAccount with a new uid = %v, want the uniform refusal", err)
	}

	// A binding that pins no uid is refused at creation, so the safe binding is
	// the only writable one.
	other, err := r.ident.CreateServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), "wl-nameonly", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	namespace := "prod"
	if _, err := r.fed.CreateBinding(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), other.ID, service.BindingRequest{
			Issuer: r.idp.Issuer(), Subject: "system:serviceaccount:prod:other", Audience: hikyoAudience,
			RequiredClaims: []service.ClaimPin{{Claim: "/kubernetes.io/namespace", String: &namespace}},
		}); !errors.Is(err, service.ErrBindingImmutableID) {
		t.Fatalf("kubernetes binding without the uid = %v, want ErrBindingImmutableID", err)
	}
	_ = sa
}

// TestFederationRefusesPlaintextJWKSSQLite is C1: an HTTPS discovery document
// must not be able to point key material at a plaintext endpoint.
//
// The consequence if it could: an on-path attacker replaces the JWKS, this
// instance caches the attacker's key, and tokens forged with any bound
// `iss`/`sub`/audience/claims authenticate. Both halves are covered — the scheme
// check on the document-supplied `jwks_uri`, and the redirect policy, because a
// scheme check alone is defeated by an HTTPS url that 302s to `http://`.
func TestFederationRefusesPlaintextJWKSSQLite(t *testing.T) {
	db := seededDB(t, openSQLite)
	r := newFedRig(t, db)
	shape := oidctest.KubernetesShape("prod", "plain", "uid-p", "https://kubernetes.default.svc")
	r.configureIssuer(t, domain.IssuerKubernetes, []string{shape.DefaultAudience})
	r.bindShape(t, "wl-plaintext", shape, hikyoAudience)

	plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		document, err := r.idp.JWKSDocument()
		if err != nil {
			http.Error(w, "sign", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(document))
	}))
	t.Cleanup(plaintext.Close)

	mint := func() string {
		t.Helper()
		token, err := r.idp.MintShape(shape, hikyoAudience, r.clk.Now(), 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}

	// (a) The discovery document names an `http://` jwks_uri. The keys it serves
	// are the RIGHT keys, so nothing but the scheme check can refuse this — which
	// is the point: a fixture serving wrong keys would pass for the wrong reason.
	r.idp.JWKSURIOverride = plaintext.URL
	if _, err := r.del.Fetch(t.Context(), mint(), scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("plaintext jwks_uri serving the correct keys = %v, want the uniform refusal", err)
	}

	// (b) An HTTPS jwks_uri that REDIRECTS to the plaintext one. The initial url
	// passes a scheme check; only the redirect policy catches it.
	r.clk.advance(oidcfed.RefreshBackoff + time.Second)
	r.idp.JWKSURIOverride = r.idp.Server.URL + "/jwks-redirect"
	r.idp.RedirectJWKSTo = plaintext.URL
	if _, err := r.del.Fetch(t.Context(), mint(), scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("https jwks_uri redirecting to plaintext = %v, want the uniform refusal", err)
	}

	// (c) Control: with the override cleared the same keys over HTTPS are
	// accepted, so (a) and (b) refused the TRANSPORT and not the key set.
	r.clk.advance(oidcfed.RefreshBackoff + time.Second)
	r.idp.JWKSURIOverride, r.idp.RedirectJWKSTo = "", ""
	if _, err := r.del.Fetch(t.Context(), mint(), scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("the same keys over https = %v, want acceptance", err)
	}
}

// TestFederationOutageDoesNotSerializeIssuersSQLite is C3: the stale-but-valid
// path must not become an unauthenticated cross-issuer denial of service.
//
// Three properties, all of which the first cut failed. Concurrent requests
// against a dead issuer must not each start their own fetch (backoff);
// a dead issuer must not block validation for a HEALTHY one (per-issuer locking,
// not one process-wide mutex held across the network call); and the outbound
// fetch count must stay bounded however many requests arrive.
func TestFederationOutageDoesNotSerializeIssuersSQLite(t *testing.T) {
	db := seededDB(t, openSQLite)
	r := newFedRig(t, db)

	dead := oidctest.KubernetesShape("prod", "dead", "uid-d", "https://kubernetes.default.svc")
	r.configureIssuer(t, domain.IssuerKubernetes, []string{dead.DefaultAudience})
	r.bindShape(t, "wl-dead", dead, hikyoAudience)

	// A SECOND, independent issuer with its own fixture server and its own
	// binding. It is the control: whatever the dead one does, this must keep
	// authenticating.
	healthyIdP, err := oidctest.NewTLS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(healthyIdP.Close)
	// One cache, one client. The client must trust BOTH fixture CAs, which is
	// what a real instance federating with two platforms looks like.
	r.cache.HTTP = multiCAClient(r.idp, healthyIdP)
	healthy := oidctest.ForgejoShape("https://git.example.test", "acme/healthy", "refs/heads/main", "push")
	if _, err := r.fed.CreateIssuer(t.Context(), service.LocalPrincipal(root), service.IssuerRequest{
		Issuer: healthyIdP.Issuer(), Type: domain.IssuerForgejo, Mode: domain.JWKSDiscovery,
		RefusedAudiences: []string{healthy.DefaultAudience},
	}); err != nil {
		t.Fatalf("configure the healthy issuer: %v", err)
	}
	healthySA, err := r.ident.CreateServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), "wl-healthy", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.fed.CreateBinding(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), healthySA.ID, service.BindingRequest{
			Issuer: healthyIdP.Issuer(), Subject: healthy.Subject, Audience: hikyoAudience,
			RequiredClaims: pinsOf(t, healthy),
		}); err != nil {
		t.Fatalf("bind the healthy issuer: %v", err)
	}
	grantMachineRead(t, db, healthySA.Principal, envA1)

	// Warm both caches while both issuers are up.
	for _, tok := range []struct {
		shape oidctest.Shape
		idp   *oidctest.IdP
	}{{dead, r.idp}, {healthy, healthyIdP}} {
		token, err := tok.idp.MintShape(tok.shape, hikyoAudience, r.clk.Now(), 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.del.Fetch(t.Context(), token, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
			t.Fatalf("warm fetch for %s: %v", tok.idp.Issuer(), err)
		}
	}

	// Kill one issuer and age both key sets past the refresh interval.
	r.idp.SetOffline(true)
	r.clk.advance(oidcfed.RefreshInterval + time.Minute)
	before := r.idp.Attempts()

	// TWENTY CONCURRENT requests against the dead issuer. Every one must be
	// served from cache (inside the staleness bound), and between them they must
	// perform at most ONE outbound attempt.
	const concurrent = 20
	var wg sync.WaitGroup
	errs := make([]error, concurrent)
	for i := range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := r.idp.MintShape(dead, hikyoAudience, r.clk.Now(), 10*time.Minute)
			if err != nil {
				errs[i] = err
				return
			}
			_, errs[i] = r.del.Fetch(t.Context(), token, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{})
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent request %d during the outage = %v, want serve-from-cache", i, err)
		}
	}
	// THE BOUND, asserted directly. Attempts() counts requests that REACHED the
	// fixture, including the ones it answered 503 — so this is the outbound work
	// twenty concurrent requests actually performed, not a proxy for it.
	//
	// One attempt is the whole allowance: the first request finds the issuer down
	// and records the failure, and RefreshBackoff suppresses every other request
	// in the window without touching the network. `<= 1` rather than `== 1`
	// because a request that arrives before the first one has recorded its failure
	// may legitimately also try; what must never happen is twenty.
	if attempts := r.idp.Attempts() - before; attempts > 1 {
		t.Errorf("%d concurrent requests produced %d outbound attempts against the dead issuer, want at most 1",
			concurrent, attempts)
	}

	// THE CONTROL: the healthy issuer still authenticates. Under one process-wide
	// mutex held across the fetch, this is where the first cut failed.
	healthyToken, err := healthyIdP.MintShape(healthy, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), healthyToken, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("healthy issuer during the other one's outage = %v, want acceptance", err)
	}

	// And the outbound attempts against the dead issuer were BOUNDED: bring it
	// back without advancing the clock and the suppressed window still holds, so
	// the request serves stale rather than fetching.
	r.idp.SetOffline(false)
	recovered := r.idp.Attempts()
	token, err := r.idp.MintShape(dead, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), token, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("fetch inside the backoff window = %v, want serve-from-cache", err)
	}
	if attempts := r.idp.Attempts() - recovered; attempts != 0 {
		t.Errorf("a request inside the backoff window performed %d outbound attempts, want none", attempts)
	}
}

// multiCAClient is an HTTP client trusting both fixture CAs, which is what one
// instance federating with two platforms needs.
func multiCAClient(idps ...*oidctest.IdP) *http.Client {
	pool := x509.NewCertPool()
	for _, idp := range idps {
		pool.AddCert(idp.Server.Certificate())
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

// TestFederationIssuerPolicyCannotGoStaleSQLite is C4: the network half of
// federated authentication runs outside any transaction, so the policy it
// validated under must be re-checked inside the authorizing one.
//
// Without it, an administrator who adds a refused audience while a slow
// verification is in flight has that request complete under the superseded
// policy — after the update committed.
func TestFederationIssuerPolicyCannotGoStaleSQLite(t *testing.T) {
	db := seededDB(t, openSQLite)
	r := newFedRig(t, db)
	shape := oidctest.KubernetesShape("prod", "racer", "uid-r", "https://kubernetes.default.svc")
	iss := r.configureIssuer(t, domain.IssuerKubernetes, []string{shape.DefaultAudience})
	r.bindShape(t, "wl-race", shape, hikyoAudience)

	token, err := r.idp.MintShape(shape, hikyoAudience, r.clk.Now(), 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Baseline: it authenticates.
	if _, err := r.del.Fetch(t.Context(), token, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("baseline fetch: %v", err)
	}

	// THE RACE, made deterministic. `OnValidated` runs after the pre-transaction
	// validation and before the authorizing transaction opens — exactly the window
	// an administrator's update can land in. It narrows the policy by refusing the
	// audience this token carries.
	r.fed.OnValidated = func() {
		if _, err := r.fed.UpdateIssuer(t.Context(), service.LocalPrincipal(root), iss.ID,
			domain.JWKSDiscovery, "", []string{shape.DefaultAudience, hikyoAudience}); err != nil {
			t.Errorf("mid-flight issuer update: %v", err)
		}
		r.fed.OnValidated = nil
	}
	if _, err := r.del.Fetch(t.Context(), token, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("fetch whose issuer policy moved mid-flight = %v, want the uniform refusal", err)
	}

	// And the new policy is what applies from now on: the same token, presented
	// fresh, is refused because its audience is now a refused one. The mid-flight
	// refusal was not a one-off retry hint.
	if _, err := r.del.Fetch(t.Context(), token, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("fetch under the narrowed policy = %v, want the uniform refusal", err)
	}
}

func TestFederationBindingImmutabilitySQLite(t *testing.T) {
	runBindingImmutability(t, seededDB(t, openSQLite))
}

func TestFederationBindingImmutabilityPostgres(t *testing.T) {
	runBindingImmutability(t, seededDB(t, openPostgres))
}

// runBindingImmutability rides both engines because its subject IS storage
// behaviour: the live-row partial unique index, and the cross-engine fold of a
// duplicate onto one refusal (postgres 23505 versus sqlite's constraint code).
func runBindingImmutability(t *testing.T, db *store.DB) {
	r := newFedRig(t, db)
	shape := oidctest.GitHubActionsShape("acme/service", 4242, 77, "refs/heads/main", "push")
	r.configureIssuer(t, domain.IssuerGitHubActions, []string{shape.DefaultAudience})
	sa, first := r.bindShape(t, "wl-immutable", shape, hikyoAudience)

	// A second binding for the SAME `(issuer, subject)` is refused: one external
	// identity, one service account.
	saOther, err := r.ident.CreateServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), "wl-duplicate", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.fed.CreateBinding(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), saOther.ID, service.BindingRequest{
			Issuer: r.idp.Issuer(), Subject: shape.Subject, Audience: hikyoAudience,
			RequiredClaims: pinsOf(t, shape),
		}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate live binding = %v, want a conflict", err)
	}

	// A REPLACEMENT re-pins the same identity with a stricter claim set, in one
	// transaction: the predecessor dies and the successor takes the pair. That
	// the pair is reusable is the whole reason the unique index is
	// liveness-aware.
	stricter := oidctest.GitHubActionsShape("acme/service", 4242, 77, "refs/heads/main", "push")
	env := "production"
	pins := append(pinsOf(t, stricter), service.ClaimPin{Claim: "environment", String: &env})
	stricter.Claims["environment"] = env
	replacement, err := r.fed.CreateBinding(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.BindingRequest{
			Issuer: r.idp.Issuer(), Subject: shape.Subject, Audience: hikyoAudience,
			RequiredClaims: pins, Replaces: first.CredentialID,
		})
	if err != nil {
		t.Fatalf("replacement mint: %v", err)
	}
	if replacement.ReplacedID != first.CredentialID {
		t.Fatalf("replacement recorded %q as replaced, want %q", replacement.ReplacedID, first.CredentialID)
	}

	// A token satisfying only the OLD, looser pin set no longer authenticates:
	// the replacement is a real narrowing, not a bookkeeping entry.
	loose, err := r.idp.MintShape(shape, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), loose, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("token matching only the replaced binding = %v, want the uniform refusal", err)
	}
	tight, err := r.idp.MintShape(stricter, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), tight, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err != nil {
		t.Fatalf("token matching the replacement = %v, want acceptance", err)
	}

	// The predecessor's death is recorded with its own cause, at the same
	// cardinality an ordinary revoke has.
	if n := queryInt(t, db,
		"SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.credential_revoked' AND payload LIKE '%replaced%'"); n == 0 {
		t.Error("the replaced binding's revocation was not recorded with cause `replaced`")
	}
}

func TestFederationClaimTypeIsNotFoldedSQLite(t *testing.T) {
	db := seededDB(t, openSQLite)
	r := newFedRig(t, db)
	shape := oidctest.GitHubActionsShape("acme/service", 4242, 77, "refs/heads/main", "push")
	r.configureIssuer(t, domain.IssuerGitHubActions, []string{shape.DefaultAudience})

	sa, err := r.ident.CreateServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), "wl-typed", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	// The binding pins `repository_id` as the STRING "4242" while the issuer
	// emits the NUMBER 4242. A validator that folded one onto the other would
	// accept this; the ADR's byte-exact rule says it must not, because a binding
	// written one way must not be satisfiable by a token the other.
	//
	// The other two required pins are correct, so the refusal below isolates the
	// type: a binding missing a required pin is refused at CREATION, which is a
	// different rule tested elsewhere.
	stringID := "4242"
	ownerID := int64(77)
	pushEvent := "push"
	if _, err := r.fed.CreateBinding(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.BindingRequest{
			Issuer: r.idp.Issuer(), Subject: shape.Subject, Audience: hikyoAudience,
			RequiredClaims: []service.ClaimPin{
				{Claim: "repository_id", String: &stringID},
				{Claim: "repository_owner_id", Number: &ownerID},
				{Claim: "event_name", String: &pushEvent},
			},
		}); err != nil {
		t.Fatalf("create binding: %v", err)
	}
	grantMachineRead(t, db, sa.Principal, envA1)

	token, err := r.idp.MintShape(shape, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), token, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf(`numeric repository_id against a string pin = %v, want the uniform refusal`, err)
	}
}

func TestFederationTokenCapsSQLite(t *testing.T) {
	db := seededDB(t, openSQLite)
	r := newFedRig(t, db)
	shape := oidctest.KubernetesShape("prod", "capped", "uid-c", "https://kubernetes.default.svc")
	r.configureIssuer(t, domain.IssuerKubernetes, []string{shape.DefaultAudience})
	r.bindShape(t, "wl-caps", shape, hikyoAudience)

	// Hikyo's OWN caps, independent of what the issuer chose. A configured issuer
	// that mints long-lived tokens must not thereby mint long-lived Hikyo access.
	overSpan, err := r.idp.MintShape(shape, hikyoAudience, r.clk.Now(), oidcfed.MaxTokenSpan+time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), overSpan, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("token declaring a span beyond the cap = %v, want the uniform refusal", err)
	}

	tooOld, err := r.idp.MintShape(shape, hikyoAudience,
		r.clk.Now().Add(-(oidcfed.MaxTokenAge + time.Minute)), oidcfed.MaxTokenSpan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), tooOld, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("token older than the age cap = %v, want the uniform refusal", err)
	}
	if n := queryInt(t, db,
		"SELECT COUNT(*) FROM audit_instance_events WHERE type = 'identity.federation_refused' AND payload LIKE '%token-age%'"); n == 0 {
		t.Error("the age-cap refusals were not recorded by cause")
	}

	// An issuer this instance does not configure is refused, and the refusal is
	// the same uniform one.
	other, err := oidctest.NewTLS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	foreign, err := other.MintShape(shape, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.del.Fetch(t.Context(), foreign, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("unconfigured issuer = %v, want the uniform refusal", err)
	}
	if n := queryInt(t, db,
		"SELECT COUNT(*) FROM audit_instance_events WHERE type = 'identity.federation_refused' AND payload LIKE '%unknown-issuer%'"); n == 0 {
		t.Error("the unknown-issuer refusal was not recorded by cause")
	}
}

func TestFederationTokenAgeCannotExpireMidFlightSQLite(t *testing.T) {
	runFederationTokenAgeCannotExpireMidFlight(t, seededDB(t, openSQLite))
}

func TestFederationTokenAgeCannotExpireMidFlightPostgres(t *testing.T) {
	runFederationTokenAgeCannotExpireMidFlight(t, seededDB(t, openPostgres))
}

// runFederationTokenAgeCannotExpireMidFlight proves the authoritative,
// in-transaction binding check revalidates Hikyo's own age cap. Signature-time
// validation happens before OnValidated; advancing the clock there models a
// slow delivery preflight without sleeping.
func runFederationTokenAgeCannotExpireMidFlight(t *testing.T, db *store.DB) {
	r := newFedRig(t, db)
	shape := oidctest.KubernetesShape("prod", "age-racer", "uid-age-racer", "https://kubernetes.default.svc")
	r.configureIssuer(t, domain.IssuerKubernetes, []string{shape.DefaultAudience})
	r.bindShape(t, "wl-age-race", shape, hikyoAudience)

	token, err := r.idp.MintShape(shape, hikyoAudience, r.clk.Now(), oidcfed.MaxTokenSpan)
	if err != nil {
		t.Fatal(err)
	}
	validated := false
	r.fed.OnValidated = func() {
		validated = true
		r.clk.advance(oidcfed.MaxTokenAge + time.Second)
		r.fed.OnValidated = nil
	}
	if _, err := r.del.Fetch(t.Context(), token, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("token crossing the age cap during validation = %v, want the uniform refusal", err)
	}
	if !validated {
		t.Fatal("OnValidated was not called; mid-flight timing was not tested")
	}
	if n := queryInt(t, db,
		"SELECT COUNT(*) FROM audit_instance_events WHERE type = 'identity.federation_refused' AND payload LIKE '%token-age%'"); n != 1 {
		t.Fatalf("mid-flight age-cap refusal audit count = %d, want 1 token-age event", n)
	}
	if n := queryInt(t, db,
		"SELECT COUNT(*) FROM audit_instance_events WHERE type = 'identity.federation_refused' AND payload LIKE '%unbound%'"); n != 0 {
		t.Fatalf("mid-flight age-cap refusal was misclassified as unbound %d time(s)", n)
	}
}

func TestFederationIssuerDeleteGuardSQLite(t *testing.T) {
	runIssuerDeleteGuard(t, seededDB(t, openSQLite))
}

func TestFederationIssuerDeleteGuardPostgres(t *testing.T) {
	runIssuerDeleteGuard(t, seededDB(t, openPostgres))
}

// runIssuerDeleteGuard rides both engines because the guard it tests is half
// application logic and half foreign key: the census refuses first, and the FK
// from machine_credentials to federation_issuers is what would refuse anyway.
// Only a real postgres run exercises the second half.
func runIssuerDeleteGuard(t *testing.T, db *store.DB) {
	r := newFedRig(t, db)
	shape := oidctest.KubernetesShape("prod", "guard", "uid-g", "https://kubernetes.default.svc")
	iss := r.configureIssuer(t, domain.IssuerKubernetes, []string{shape.DefaultAudience})
	sa, binding := r.bindShape(t, "wl-guard", shape, hikyoAudience)

	if err := r.fed.DeleteIssuer(t.Context(), service.LocalPrincipal(root), iss.ID); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("delete issuer with a live binding = %v, want a conflict", err)
	}
	// Revoking is NOT enough, and that is the guard's second half: a revoked
	// binding is still a row naming this issuer, and erasing the issuer would
	// erase what that binding trusted. The historical record outlives the
	// credential.
	if err := r.ident.RevokeCredential(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, binding.CredentialID); err != nil {
		t.Fatalf("revoke binding: %v", err)
	}
	if err := r.fed.DeleteIssuer(t.Context(), service.LocalPrincipal(root), iss.ID); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("delete issuer with a revoked binding still naming it = %v, want a conflict", err)
	}
	// The revocation recorded WHICH KIND died, which is the forensic fact a
	// bearer revoke and a binding revoke differ by.
	if n := queryInt(t, db,
		"SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.credential_revoked' AND payload LIKE '%oidc-federation%'"); n == 0 {
		t.Error("a revoked binding did not record its credential kind")
	}

	// Deleting the SERVICE ACCOUNT removes its credential rows in one
	// transaction, which is the operator act that genuinely retires the binding —
	// and only then is the issuer deletable.
	if err := r.ident.DeleteServiceAccount(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID); err != nil {
		t.Fatalf("delete service account: %v", err)
	}
	if err := r.fed.DeleteIssuer(t.Context(), service.LocalPrincipal(root), iss.ID); err != nil {
		t.Fatalf("delete issuer after its bindings are gone = %v, want success", err)
	}
}

// runFederationLifecycle drives every #62 event type through a real emitter, so
// the audit suite's "declaration without an emitter" check has something behind
// each registration. It is the federation half of runIdentityLifecycle, and the
// identity lifecycle calls it.
func runFederationLifecycle(t *testing.T, db *store.DB) {
	t.Helper()
	// The identity lifecycle ran first and seeded the fixture principals, so this
	// takes the un-seeding rig and adds only the catalogue rows the delivery
	// surface needs.
	seedDeliveryCatalogue(t, db)
	r := fedRigOn(t, db)
	shape := oidctest.ForgejoShape("https://git.example.test", "acme/audited", "refs/heads/main", "push")

	iss := r.configureIssuer(t, domain.IssuerForgejo, []string{shape.DefaultAudience})
	if _, err := r.fed.ListIssuers(t.Context(), service.LocalPrincipal(root)); err != nil {
		t.Fatalf("identity.federation_issuer_read: %v", err)
	}
	if _, err := r.fed.UpdateIssuer(t.Context(), service.LocalPrincipal(root), iss.ID,
		domain.JWKSDiscovery, "", []string{shape.DefaultAudience, "https://other.test"}); err != nil {
		t.Fatalf("identity.federation_issuer_changed (updated): %v", err)
	}
	sa, binding := r.bindShape(t, "audited-binding", shape, hikyoAudience)
	if _, err := r.fed.Reactivate(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, binding.CredentialID); err != nil {
		t.Fatalf("identity.binding_reactivated: %v", err)
	}

	// The delivery access record, both dispositions. A human session drives it
	// because the point here is the EVENT, not the artifact class — and a
	// federated token would additionally have to clear the restore predicate the
	// line above just armed.
	res, err := r.del.Fetch(t.Context(), "", scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{})
	if err == nil {
		t.Fatal("an empty artifact fetched successfully; the surface is not authenticating")
	}
	human := service.LocalPrincipal(identAdmin)
	res, err = r.del.FetchAs(t.Context(), human, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{})
	if err != nil {
		t.Fatalf("identity.delivery_fetched (full): %v", err)
	}
	if _, err := r.del.FetchAs(t.Context(), human, scopeEnv(orgA, prjA1, envA1), res.Cursor, service.FetchOptions{}); err != nil {
		t.Fatalf("identity.delivery_fetched (current): %v", err)
	}

	// A federated refusal and a JWKS event, so both wire-declared types have an
	// emitter too.
	if _, err := r.del.Fetch(t.Context(), "not.a.token", scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err == nil {
		t.Fatal("a malformed token fetched successfully")
	}
	r.idp.SetOffline(true)
	r.clk.advance(oidcfed.RefreshInterval + time.Minute)
	token, err := r.idp.MintShape(shape, hikyoAudience, r.clk.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Refused by the restore predicate, and on the way there it records the
	// tolerated refresh failure.
	if _, err := r.del.Fetch(t.Context(), token, scopeEnv(orgA, prjA1, envA1), "", service.FetchOptions{}); err == nil {
		t.Fatal("a token predating re-activation fetched successfully")
	}
	r.idp.SetOffline(false)
}

func TestFederationBindingIsListedWithItsIdentitySQLite(t *testing.T) {
	runBindingListedWithIdentity(t, seededDB(t, openSQLite))
}

func TestFederationBindingIsListedWithItsIdentityPostgres(t *testing.T) {
	runBindingListedWithIdentity(t, seededDB(t, openPostgres))
}

// runBindingListedWithIdentity pins what the credential LISTING carries for a
// binding row.
//
// A binding is a credential row and is listed through the credential route
// rather than a second pair of routes, which is what makes this the only place
// an operator can read back the `(issuer, subject)` pair a binding matches. The
// wire schema has always said so — an `oidc-federation` row "carries the binding
// members instead" of a prefix hint — and the transport dropped every one of
// them until #67, so a federation surface could show that a binding existed and
// not which external identity it admitted.
//
// The issuer is asserted as the byte-exact STRING rather than the configuration
// id: nothing folds case, resolves the URL or strips a trailing slash anywhere
// on this path, and the id is not what the external authority presents.
func runBindingListedWithIdentity(t *testing.T, db *store.DB) {
	r := newFedRig(t, db)
	const instance = "https://git.example.test"
	shape := oidctest.ForgejoShape(instance, "acme/service", "refs/heads/main", "push")
	r.configureIssuer(t, domain.IssuerForgejo, []string{shape.DefaultAudience})
	sa, binding := r.bindShape(t, "listed-binding", shape, hikyoAudience)

	// A bearer credential on the SAME account, so the discriminator is exercised
	// in both directions by one listing.
	if _, err := r.ident.MintCredential(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.MintRequest{}); err != nil {
		t.Fatalf("mint bearer credential: %v", err)
	}

	rows, err := r.ident.ListCredentials(t.Context(), service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("listed %d credentials, want the binding and the bearer", len(rows))
	}

	var listed, bearer *service.CredentialView
	for i := range rows {
		switch rows[i].Kind {
		case domain.CredentialOIDCFederation:
			listed = &rows[i]
		case domain.CredentialHikyoToken:
			bearer = &rows[i]
		}
	}
	if listed == nil || bearer == nil {
		t.Fatal("the listing did not carry one row of each kind")
	}

	if listed.ID != binding.CredentialID {
		t.Fatalf("listed binding id %q, want %q", listed.ID, binding.CredentialID)
	}
	if listed.Issuer != r.idp.Issuer() {
		t.Fatalf("listed issuer %q, want the byte-exact %q", listed.Issuer, r.idp.Issuer())
	}
	if listed.Subject != shape.Subject {
		t.Fatalf("listed subject %q, want %q", listed.Subject, shape.Subject)
	}
	if listed.Audience != hikyoAudience {
		t.Fatalf("listed audience %q, want %q", listed.Audience, hikyoAudience)
	}
	// The pins travel too, and the discriminated scalar is not folded on the way
	// out: `event_name` is the whole CI rule, and an operator auditing a binding
	// has to be able to see which event it admits.
	pinned := map[string]bool{}
	for _, pin := range listed.RequiredClaims {
		pinned[pin.Claim] = true
	}
	if !pinned[oidcfed.EventNameClaim] {
		t.Fatalf("listed pins %v, want the event_name pin among them", pinned)
	}
	if listed.PrefixHint != "" {
		t.Fatalf("a binding has no minted value to hint at, got %q", listed.PrefixHint)
	}

	// And the other direction: a bearer row carries no binding members at all,
	// so nothing on the read surface can read one into a credential that has none.
	if bearer.Issuer != "" || bearer.Subject != "" || bearer.Audience != "" ||
		len(bearer.RequiredClaims) != 0 || !bearer.ReactivatedAt.IsZero() {
		t.Fatalf("a bearer credential carried binding members: %+v", *bearer)
	}
	if bearer.PrefixHint == "" {
		t.Fatal("a bearer credential must carry its prefix hint")
	}
}

// TestFederationIssuerGrammarRefusesNonIssuerURLs pins the issuer identifier
// grammar at creation: an https URL with a host and NOTHING that is not part
// of an identity namespace. The load-bearing case is userinfo — an issuer
// stored as `https://user:secret@host` would be listed byte-exact by the
// credential route to project-level `manage-identities` (#67), turning an
// instance-config mistake into plaintext exposure on a project surface. The
// refusal has to happen here, before a row exists, because byte-exact
// matching forbids sanitising it later.
func TestFederationIssuerGrammarRefusesNonIssuerURLs(t *testing.T) {
	r := newFedRig(t, seededDB(t, openSQLite))
	for _, tc := range []struct {
		name   string
		issuer string
	}{
		{"userinfo", "https://user:secret@issuer.example.test"},
		{"userinfo without password", "https://user@issuer.example.test"},
		{"query", "https://issuer.example.test/path?x=1"},
		{"fragment", "https://issuer.example.test#frag"},
		{"http", "http://issuer.example.test"},
		{"no host", "https:///path"},
		{"opaque", "https:issuer.example.test"},
		{"empty", ""},
	} {
		if _, err := r.fed.CreateIssuer(t.Context(), service.LocalPrincipal(root), service.IssuerRequest{
			Issuer: tc.issuer, Type: domain.IssuerForgejo, Mode: domain.JWKSDiscovery,
			RefusedAudiences: []string{"https://forgejo.example.test"},
		}); !errors.Is(err, service.ErrIssuerValue) {
			t.Errorf("%s: CreateIssuer(%q) = %v, want the issuer-grammar refusal", tc.name, tc.issuer, err)
		}
	}

	// And the well-formed shapes stay admitted: a port and a path are both
	// part of real issuer identifiers (kind clusters, tenant paths).
	if _, err := r.fed.CreateIssuer(t.Context(), service.LocalPrincipal(root), service.IssuerRequest{
		Issuer: "https://issuer.example.test:6443/tenant", Type: domain.IssuerForgejo,
		Mode: domain.JWKSDiscovery, RefusedAudiences: []string{"https://forgejo.example.test"},
	}); err != nil {
		t.Fatalf("a host:port/path issuer must stay admitted, got %v", err)
	}
}
