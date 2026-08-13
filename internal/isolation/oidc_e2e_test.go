package isolation

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/oidctest"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
)

// The OIDC A1 fixture families (#54, human-auth ADR - The OIDC transaction),
// dual-engine, driven against a real test IdP (internal/oidctest) so the wire
// flow is exercised end to end: mix-up in both directions, byte-exact
// (issuer, subject) linking, the purpose walls, the transaction binding, and
// the reauth refusals.

func strptr(s string) *string { return &s }

// driveIdP follows the authorization request to the test IdP and returns the
// code and state the IdP redirected back with, WITHOUT following the redirect
// to the (non-serving) callback URL. Extra query params (e.g. sub) let a
// fixture control the minted subject.
func driveIdP(t *testing.T, authURL string) (code, state string) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("driving the IdP authorize: %v", err)
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parsing the IdP redirect %q: %v", loc, err)
	}
	return u.Query().Get("code"), u.Query().Get("state")
}

// configureProvider installs a provider under local host authority (MFA-exempt),
// returning the Providers service and the IdP.
func configureProvider(t *testing.T, auth *service.Auth, ctx context.Context, admin domain.PrincipalID, slug string, in service.ProviderInput) (*service.Providers, *oidctest.IdP) {
	t.Helper()
	idp, err := oidctest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)
	if auth.ExternalOrigin == "" {
		auth.ExternalOrigin = "https://hikyo.test"
	}
	if err := idp.RegisterRedirectURI(strings.TrimRight(auth.ExternalOrigin, "/") + "/api/v1/auth/oidc/" + slug + "/callback"); err != nil {
		t.Fatal(err)
	}
	providers := &service.Providers{DB: auth.DB, Keyring: auth.Keyring, ExternalOrigin: auth.ExternalOrigin}
	in.Issuer = idp.Issuer()
	if _, err := providers.Put(ctx, service.LocalPrincipal(admin), slug, in); err != nil {
		t.Fatalf("configuring provider %q: %v", slug, err)
	}
	return providers, idp
}

// runOIDCLifecycle drives every OIDC audit event once into the shared audit_e2e
// datastore, so the emitter-closure subtest finds each reached a trail.
func runOIDCLifecycle(t *testing.T, auth *service.Auth, ctx context.Context, admin domain.PrincipalID, username, password string) {
	t.Helper()
	providers, idp := configureProvider(t, auth, ctx, admin, "lifecycle-idp", service.ProviderInput{
		DisplayName: "Lifecycle IdP", ClientID: "client", ClientSecret: "secret", Scopes: "openid",
		JITPolicy: strptr(`{"claim":"sub","values":["jit-user"]}`), Enabled: true,
	})
	// provider_read (get + list).
	if _, err := providers.Get(ctx, service.LocalPrincipal(admin), "lifecycle-idp"); err != nil {
		t.Fatalf("provider get: %v", err)
	}
	if _, err := providers.List(ctx, service.LocalPrincipal(admin)); err != nil {
		t.Fatalf("provider list: %v", err)
	}

	// Link an identity to the admin account (identity_linked + session_created).
	login, err := auth.LocalLogin(ctx, username, password, service.ArtifactCLI)
	if err != nil {
		t.Fatalf("local login: %v", err)
	}
	start, err := auth.OIDCStart(ctx, "lifecycle-idp", "link", "", login.SessionToken, password)
	if err != nil {
		t.Fatalf("oidc link start: %v", err)
	}
	code, state := driveIdP(t, start.AuthURL+"&sub=lifecycle-subject")
	if _, err := auth.OIDCCallback(ctx, "lifecycle-idp", code, state, "", "", "", login.SessionToken); err != nil {
		t.Fatalf("oidc link callback: %v", err)
	}

	// OIDC login as that identity (oidc_login + session_created).
	oidcLogin(t, auth, ctx, "lifecycle-idp", "lifecycle-subject")
	// JIT provisioning (jit_provisioned + oidc_login + session_created).
	oidcLogin(t, auth, ctx, "lifecycle-idp", "jit-user")

	// A refusal (oidc_refused): a malformed state matches no transaction.
	if _, err := auth.OIDCCallback(ctx, "lifecycle-idp", "code", "not-a-state", "", "", "", ""); !isUnauth(err) {
		t.Fatalf("malformed state should refuse: %v", err)
	}

	// Unlink (identity_unlinked + session_created).
	relogin, err := auth.LocalLogin(ctx, username, password, service.ArtifactCLI)
	if err != nil {
		t.Fatalf("re-login for unlink: %v", err)
	}
	ids, err := auth.ListIdentities(ctx, relogin.SessionToken)
	if err != nil || len(ids) == 0 {
		t.Fatalf("list identities: %v (n=%d)", err, len(ids))
	}
	if _, err := auth.UnlinkIdentity(ctx, relogin.SessionToken, ids[0].ID, password); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	_ = idp
}

// oidcLogin drives an anonymous OIDC login for the given subject and returns
// the resulting session.
func oidcLogin(t *testing.T, auth *service.Auth, ctx context.Context, slug, subject string) service.LoginResult {
	t.Helper()
	start, err := auth.OIDCStart(ctx, slug, "login", "", "", "")
	if err != nil {
		t.Fatalf("oidc login start: %v", err)
	}
	code, state := driveIdP(t, start.AuthURL+"&sub="+subject)
	res, err := auth.OIDCCallback(ctx, slug, code, state, "", "", start.BindingCookie, "")
	if err != nil {
		t.Fatalf("oidc login callback: %v", err)
	}
	return res.Login
}

func isUnauth(err error) bool {
	return err == domain.ErrUnauthenticated || (err != nil && err.Error() == domain.ErrUnauthenticated.Error())
}

// --- A1 fixtures ---

// oidcAdmin bootstraps an admin, establishes a password, and returns the acting
// service, principal and password.
func oidcAdmin(t *testing.T, db *store.DB) (*service.Auth, domain.PrincipalID, string) {
	t.Helper()
	auth := authService(t, db)
	auth.ExternalOrigin = "https://hikyo.test"
	boot, err := auth.BootstrapAdmin(t.Context(), "oidc-admin", "OIDC Admin", "terminal")
	if err != nil {
		t.Fatal(err)
	}
	const password = "correct horse battery staple oidc"
	if err := auth.EstablishCredential(t.Context(), boot.Authority, password); err != nil {
		t.Fatal(err)
	}
	acc, err := auth.LocalLogin(t.Context(), "oidc-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	return auth, acc.Principal, password
}

func runOIDCMixup(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, _ := oidcAdmin(t, db)
	_, idpA := configureProvider(t, auth, ctx, admin, "prov-a", service.ProviderInput{
		DisplayName: "A", ClientID: "ca", ClientSecret: "sa", Scopes: "openid", Enabled: true,
	})
	_, idpB := configureProvider(t, auth, ctx, admin, "prov-b", service.ProviderInput{
		DisplayName: "B", ClientID: "cb", ClientSecret: "sb", Scopes: "openid", Enabled: true,
	})

	// Begin a transaction at A; obtain a code from A's authorize.
	startA, err := auth.OIDCStart(ctx, "prov-a", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	codeA, stateA := driveIdP(t, startA.AuthURL+"&sub=user")

	// Deliver A's response to B's callback path: the transaction is pinned to A,
	// so an exchange (were the slug check removed) would hit A's token endpoint,
	// never B's. Assert A's counter is untouched: the refusal precedes exchange.
	hitsA := idpA.TokenEndpointHits
	if _, err := auth.OIDCCallback(ctx, "prov-b", codeA, stateA, "", "", startA.BindingCookie, ""); !isUnauth(err) {
		t.Fatalf("mix-up A->B should refuse: %v", err)
	}
	if idpA.TokenEndpointHits != hitsA {
		t.Fatalf("mix-up A->B hit the recorded provider's token endpoint: refusal must precede exchange")
	}

	// The other direction: begin at B, deliver to A's callback. The tx is pinned
	// to B, so assert B's counter is untouched.
	startB, err := auth.OIDCStart(ctx, "prov-b", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	codeB, stateB := driveIdP(t, startB.AuthURL+"&sub=user")
	hitsB := idpB.TokenEndpointHits
	if _, err := auth.OIDCCallback(ctx, "prov-a", codeB, stateB, "", "", startB.BindingCookie, ""); !isUnauth(err) {
		t.Fatalf("mix-up B->A should refuse: %v", err)
	}
	if idpB.TokenEndpointHits != hitsB {
		t.Fatalf("mix-up B->A hit the recorded provider's token endpoint: refusal must precede exchange")
	}
}

func TestOIDCMixupSQLite(t *testing.T)   { runOIDCMixup(t, seededDB(t, openSQLite)) }
func TestOIDCMixupPostgres(t *testing.T) { runOIDCMixup(t, seededDB(t, openPostgres)) }

// runOIDCByteExactSubject: two subjects differing only in case are two distinct
// identities, both loginable, never merged.
func runOIDCByteExactSubject(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, password := oidcAdmin(t, db)
	configureProvider(t, auth, ctx, admin, "idp", service.ProviderInput{
		DisplayName: "IdP", ClientID: "c", ClientSecret: "s", Scopes: "openid",
		JITPolicy: strptr(`{"claim":"sub","values":["alice","Alice"]}`), Enabled: true,
	})
	// JIT-provision two accounts for case-variant subjects.
	lower := oidcLogin(t, auth, ctx, "idp", "alice")
	upper := oidcLogin(t, auth, ctx, "idp", "Alice")
	if lower.AccountID == upper.AccountID {
		t.Fatalf("case-variant subjects merged into one account: %s", lower.AccountID)
	}
	// Both remain independently loginable.
	again := oidcLogin(t, auth, ctx, "idp", "alice")
	if again.AccountID != lower.AccountID {
		t.Fatalf("subject 'alice' resolved to a different account on re-login")
	}
	_ = password
}

func TestOIDCByteExactSubjectSQLite(t *testing.T) {
	runOIDCByteExactSubject(t, seededDB(t, openSQLite))
}
func TestOIDCByteExactSubjectPostgres(t *testing.T) {
	runOIDCByteExactSubject(t, seededDB(t, openPostgres))
}

func oidcRefusedCount(t *testing.T, db *store.DB, cause string) int64 {
	t.Helper()
	return queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'auth.oidc_refused' AND payload LIKE '%"+cause+"%'")
}

// runOIDCBinding: the transaction binding (A2) refuses a callback that cannot
// present the binding the start recorded, and the refusal is audited by cause.
// The purpose wall is STRUCTURAL and needs no separate probe: the callback
// dispatches on the transaction's own purpose (a state resolves only its own
// transaction), so a response obtained for one purpose can never reach another
// purpose's branch.
func runOIDCBinding(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, password := oidcAdmin(t, db)
	configureProvider(t, auth, ctx, admin, "idp", service.ProviderInput{
		DisplayName: "IdP", ClientID: "c", ClientSecret: "s", Scopes: "openid",
		JITPolicy: strptr(`{"claim":"sub","values":["user"]}`), Enabled: true,
	})

	// Anonymous login is browser-cookie-bound (A2): a callback with the absent ob
	// cookie is refused, audited cause=binding.
	start, err := auth.OIDCStart(ctx, "idp", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	code, state := driveIdP(t, start.AuthURL+"&sub=user")
	before := oidcRefusedCount(t, db, "binding")
	if _, err := auth.OIDCCallback(ctx, "idp", code, state, "", "", "", ""); !isUnauth(err) {
		t.Fatalf("login callback with no binding cookie should refuse: %v", err)
	}
	if oidcRefusedCount(t, db, "binding") != before+1 {
		t.Fatalf("the binding refusal was not audited cause=binding")
	}

	// The correct binding cookie completes the same flow (positive control) - a
	// fresh transaction, since the first was consumed.
	start2, err := auth.OIDCStart(ctx, "idp", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	code2, state2 := driveIdP(t, start2.AuthURL+"&sub=user")
	if _, err := auth.OIDCCallback(ctx, "idp", code2, state2, "", "", start2.BindingCookie, ""); err != nil {
		t.Fatalf("login with the correct binding cookie should succeed: %v", err)
	}

	// A link transaction is session-bound: a callback with no session fails the
	// binding, audited cause=binding.
	login, err := auth.LocalLogin(ctx, "oidc-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	lstart, err := auth.OIDCStart(ctx, "idp", "link", "", login.SessionToken, password)
	if err != nil {
		t.Fatal(err)
	}
	lcode, lstate := driveIdP(t, lstart.AuthURL+"&sub=user")
	before = oidcRefusedCount(t, db, "binding")
	if _, err := auth.OIDCCallback(ctx, "idp", lcode, lstate, "", "", "", ""); !isUnauth(err) {
		t.Fatalf("link callback with no session should refuse (binding): %v", err)
	}
	if oidcRefusedCount(t, db, "binding") != before+1 {
		t.Fatalf("the session-binding refusal was not audited cause=binding")
	}
	_ = admin
}

func TestOIDCBindingSQLite(t *testing.T)   { runOIDCBinding(t, seededDB(t, openSQLite)) }
func TestOIDCBindingPostgres(t *testing.T) { runOIDCBinding(t, seededDB(t, openPostgres)) }

// runOIDCReauthRefusals: OIDC reauth refuses when the environment is missing,
// when the provider has no assurance policy (A5), and when the returned token
// carries no auth_time (A7). Each cause is audited.
func runOIDCReauthRefusals(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, password := oidcAdmin(t, db)
	_, strict := configureProvider(t, auth, ctx, admin, "strict", service.ProviderInput{
		DisplayName: "Strict", ClientID: "c", ClientSecret: "s", Scopes: "openid",
		AssurancePolicy: strptr(`{"amr_sets":[["mfa"]]}`), Enabled: true,
	})
	// Link an identity on the strict provider.
	login, err := auth.LocalLogin(ctx, "oidc-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	ls, err := auth.OIDCStart(ctx, "strict", "link", "", login.SessionToken, password)
	if err != nil {
		t.Fatal(err)
	}
	lc, lst := driveIdP(t, ls.AuthURL+"&sub=reauth-user")
	if _, err := auth.OIDCCallback(ctx, "strict", lc, lst, "", "", "", login.SessionToken); err != nil {
		t.Fatalf("link: %v", err)
	}

	// reauth with no environment is refused loudly (would violate the tx CHECK).
	relogin, err := auth.LocalLogin(ctx, "oidc-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.OIDCStart(ctx, "strict", "reauth", "", relogin.SessionToken, ""); err != service.ErrReauthNoEnvironment {
		t.Fatalf("reauth with no environment: want ErrReauthNoEnvironment, got %v", err)
	}

	// reauth whose token carries amr=mfa but NO auth_time is refused (A7),
	// audited cause=no-auth-time. (The IdP asserts amr but leaves auth_time zero.)
	strict.AMR = []string{"mfa"}
	rs, err := auth.OIDCStart(ctx, "strict", "reauth", "env_prod", relogin.SessionToken, "")
	if err != nil {
		t.Fatalf("reauth start: %v", err)
	}
	rc, rst := driveIdP(t, rs.AuthURL+"&sub=reauth-user")
	before := oidcRefusedCount(t, db, "no-auth-time")
	if _, err := auth.OIDCCallback(ctx, "strict", rc, rst, "", "", "", relogin.SessionToken); !isUnauth(err) {
		t.Fatalf("reauth with no auth_time should refuse: %v", err)
	}
	if oidcRefusedCount(t, db, "no-auth-time") != before+1 {
		t.Fatalf("the auth_time refusal was not audited cause=no-auth-time")
	}

	// A provider with NO assurance policy refuses reauth by name at start (A5).
	configureProvider(t, auth, ctx, admin, "loose", service.ProviderInput{
		DisplayName: "Loose", ClientID: "c", ClientSecret: "s", Scopes: "openid", Enabled: true,
	})
	if _, err := auth.OIDCStart(ctx, "loose", "reauth", "env_prod", relogin.SessionToken, ""); err != service.ErrReauthNoPolicy {
		t.Fatalf("policy-less reauth: want ErrReauthNoPolicy, got %v", err)
	}
}

func TestOIDCReauthRefusalsSQLite(t *testing.T) {
	runOIDCReauthRefusals(t, seededDB(t, openSQLite))
}
func TestOIDCReauthRefusalsPostgres(t *testing.T) {
	runOIDCReauthRefusals(t, seededDB(t, openPostgres))
}

// runOIDCIssuerImmutable: a provider's issuer cannot change on update (A3).
func runOIDCIssuerImmutable(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, _ := oidcAdmin(t, db)
	_, idp := configureProvider(t, auth, ctx, admin, "idp", service.ProviderInput{
		DisplayName: "IdP", ClientID: "c", ClientSecret: "s", Scopes: "openid", Enabled: true,
	})
	providers := &service.Providers{DB: auth.DB, Keyring: auth.Keyring, ExternalOrigin: auth.ExternalOrigin}
	// A different issuer on update is refused by name.
	other, err := oidctest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	_, err = providers.Put(ctx, service.LocalPrincipal(admin), "idp", service.ProviderInput{
		DisplayName: "IdP2", Issuer: other.Issuer(), ClientID: "c", ClientSecret: "s", Scopes: "openid", Enabled: true,
	})
	if err != service.ErrIssuerImmutable {
		t.Fatalf("issuer change should be refused as immutable, got %v", err)
	}
	// The same issuer updates fine (display name change).
	if _, err := providers.Put(ctx, service.LocalPrincipal(admin), "idp", service.ProviderInput{
		DisplayName: "Renamed", Issuer: idp.Issuer(), ClientID: "c2", ClientSecret: "s2", Scopes: "openid", Enabled: true,
	}); err != nil {
		t.Fatalf("same-issuer update should succeed: %v", err)
	}
}

func TestOIDCIssuerImmutableSQLite(t *testing.T) {
	runOIDCIssuerImmutable(t, seededDB(t, openSQLite))
}
func TestOIDCIssuerImmutablePostgres(t *testing.T) {
	runOIDCIssuerImmutable(t, seededDB(t, openPostgres))
}

// runOIDCProviderChangeSweeps: reconfiguring a provider deletes sessions
// authenticated through it (A4).
func runOIDCProviderChangeSweeps(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, _ := oidcAdmin(t, db)
	providers, idp := configureProvider(t, auth, ctx, admin, "idp", service.ProviderInput{
		DisplayName: "IdP", ClientID: "c", ClientSecret: "s", Scopes: "openid",
		JITPolicy: strptr(`{"claim":"sub","values":["user"]}`), Enabled: true,
	})
	session := oidcLogin(t, auth, ctx, "idp", "user")
	if _, err := auth.Identity(ctx, session.SessionToken); err != nil {
		t.Fatalf("federated session should be live before the change: %v", err)
	}
	// Reconfigure (assurance policy change): the federated session is swept.
	if _, err := providers.Put(ctx, service.LocalPrincipal(admin), "idp", service.ProviderInput{
		DisplayName: "IdP", Issuer: idp.Issuer(), ClientID: "c", ClientSecret: "s", Scopes: "openid",
		AssurancePolicy: strptr(`{"amr_sets":[["mfa"]]}`), Enabled: true,
	}); err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	if _, err := auth.Identity(ctx, session.SessionToken); !isUnauth(err) {
		t.Fatalf("federated session survived a provider change: %v", err)
	}
}

func TestOIDCProviderChangeSweepsSQLite(t *testing.T) {
	runOIDCProviderChangeSweeps(t, seededDB(t, openSQLite))
}
func TestOIDCProviderChangeSweepsPostgres(t *testing.T) {
	runOIDCProviderChangeSweeps(t, seededDB(t, openPostgres))
}

// --- reauth assurance fixtures (#54 cross-model review R1) ---
//
// The reauth path must be at least as strict as completeLogin: a reveal reauth
// window is opened only for evidence that carries a recognized possession
// factor, is live (current credential epoch), is recorded against the currently
// enabled provider, and is not weaker than the session it re-authorizes.

// linkOn links an external identity for the given subject on the given provider
// slug, using the admin's password as the account-security proof.
func linkOn(t *testing.T, auth *service.Auth, ctx context.Context, slug, subject, password string) {
	t.Helper()
	login, err := auth.LocalLogin(ctx, "oidc-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatalf("login for link: %v", err)
	}
	ls, err := auth.OIDCStart(ctx, slug, "link", "", login.SessionToken, password)
	if err != nil {
		t.Fatalf("link start: %v", err)
	}
	lc, lst := driveIdP(t, ls.AuthURL+"&sub="+subject)
	if _, err := auth.OIDCCallback(ctx, slug, lc, lst, "", "", "", login.SessionToken); err != nil {
		t.Fatalf("link callback: %v", err)
	}
}

// reauthOn drives a reauth callback for the given subject on the given provider
// slug with the given acting session, returning the callback error.
func reauthOn(t *testing.T, auth *service.Auth, ctx context.Context, slug, subject, session string) error {
	t.Helper()
	rs, err := auth.OIDCStart(ctx, slug, "reauth", "env_prod", session, "")
	if err != nil {
		t.Fatalf("reauth start: %v", err)
	}
	rc, rst := driveIdP(t, rs.AuthURL+"&sub="+subject)
	_, err = auth.OIDCCallback(ctx, slug, rc, rst, "", "", "", session)
	return err
}

// runOIDCReauthPossession: a token that satisfies the assurance policy but
// carries no recognized possession amr (only "pwd") is refused (A5/B5), whether
// the policy keyed on an amr set or on acr. Policy satisfaction alone must never
// imply possession.
func runOIDCReauthPossession(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, password := oidcAdmin(t, db)
	auth.ReauthWindow = time.Minute

	// (a) amr_sets [["pwd"]] satisfied by amr=["pwd"] — possession absent.
	_, amrIdP := configureProvider(t, auth, ctx, admin, "pwd-amr", service.ProviderInput{
		DisplayName: "pwd-amr", ClientID: "c", ClientSecret: "s", Scopes: "openid",
		AssurancePolicy: strptr(`{"amr_sets":[["pwd"]]}`), Enabled: true,
	})
	linkOn(t, auth, ctx, "pwd-amr", "pwd-user", password)
	amrIdP.AuthTime = time.Now()
	amrIdP.AMR = []string{"pwd"}
	relogin, err := auth.LocalLogin(ctx, "oidc-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	before := oidcRefusedCount(t, db, "no-possession")
	if err := reauthOn(t, auth, ctx, "pwd-amr", "pwd-user", relogin.SessionToken); !isUnauth(err) {
		t.Fatalf("pwd-only amr reauth should refuse: %v", err)
	}
	if oidcRefusedCount(t, db, "no-possession") != before+1 {
		t.Fatalf("pwd-only amr refusal was not audited cause=no-possession")
	}

	// (b) acr-satisfied policy with amr=["pwd"] — the case evaluateAssurance
	// alone can never catch, since acr matches with no amr at all.
	_, acrIdP := configureProvider(t, auth, ctx, admin, "acr-only", service.ProviderInput{
		DisplayName: "acr-only", ClientID: "c", ClientSecret: "s", Scopes: "openid",
		AssurancePolicy: strptr(`{"acr_values":["urn:strong"]}`), Enabled: true,
	})
	linkOn(t, auth, ctx, "acr-only", "acr-user", password)
	acrIdP.AuthTime = time.Now()
	acrIdP.ACR = "urn:strong"
	acrIdP.AMR = []string{"pwd"}
	relogin2, err := auth.LocalLogin(ctx, "oidc-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	before = oidcRefusedCount(t, db, "no-possession")
	if err := reauthOn(t, auth, ctx, "acr-only", "acr-user", relogin2.SessionToken); !isUnauth(err) {
		t.Fatalf("acr-satisfied pwd-amr reauth should refuse: %v", err)
	}
	if oidcRefusedCount(t, db, "no-possession") != before+1 {
		t.Fatalf("acr-satisfied refusal was not audited cause=no-possession")
	}

	// (c) amr_sets [["mfa"]] satisfied by amr=["mfa"] (rA-1). RFC 8176 "mfa"
	// asserts multiple factors were used but proves no possession factor, so
	// the policy is satisfied yet the reveal window is refused. A ["hwk"] or
	// ["otp"] token on the same policy passes (the downgrade fixture's positive
	// control exercises the ["hwk"] pass).
	_, mfaIdP := configureProvider(t, auth, ctx, admin, "mfa-only", service.ProviderInput{
		DisplayName: "mfa-only", ClientID: "c", ClientSecret: "s", Scopes: "openid",
		AssurancePolicy: strptr(`{"amr_sets":[["mfa"]]}`), Enabled: true,
	})
	linkOn(t, auth, ctx, "mfa-only", "mfa-user", password)
	mfaIdP.AuthTime = time.Now()
	mfaIdP.AMR = []string{"mfa"}
	relogin3, err := auth.LocalLogin(ctx, "oidc-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	before = oidcRefusedCount(t, db, "no-possession")
	if err := reauthOn(t, auth, ctx, "mfa-only", "mfa-user", relogin3.SessionToken); !isUnauth(err) {
		t.Fatalf("mfa-only amr reauth should refuse (mfa is not possession): %v", err)
	}
	if oidcRefusedCount(t, db, "no-possession") != before+1 {
		t.Fatalf("mfa-only refusal was not audited cause=no-possession")
	}
}

func TestOIDCReauthPossessionSQLite(t *testing.T) {
	runOIDCReauthPossession(t, seededDB(t, openSQLite))
}
func TestOIDCReauthPossessionPostgres(t *testing.T) {
	runOIDCReauthPossession(t, seededDB(t, openPostgres))
}

// runOIDCReauthEpochInert: an epoch-inert (restored) identity is terminally
// refused, never opens a window (B2), matching completeLogin.
func runOIDCReauthEpochInert(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, password := oidcAdmin(t, db)
	auth.ReauthWindow = time.Minute
	_, idp := configureProvider(t, auth, ctx, admin, "strict", service.ProviderInput{
		DisplayName: "strict", ClientID: "c", ClientSecret: "s", Scopes: "openid",
		AssurancePolicy: strptr(`{"amr_sets":[["mfa"]]}`), Enabled: true,
	})
	linkOn(t, auth, ctx, "strict", "epoch-user", password)
	// Restore the identity to an earlier epoch WITHOUT bumping the instance
	// epoch (which would trip the Phase-A epoch check first); this exercises the
	// reauth-branch epoch check directly.
	execRaw(t, db, "UPDATE external_identities SET credential_epoch = credential_epoch - 1 WHERE subject = 'epoch-user'")
	idp.AuthTime = time.Now()
	idp.AMR = []string{"mfa"}
	relogin, err := auth.LocalLogin(ctx, "oidc-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	before := oidcRefusedCount(t, db, "epoch")
	if err := reauthOn(t, auth, ctx, "strict", "epoch-user", relogin.SessionToken); !isUnauth(err) {
		t.Fatalf("epoch-inert reauth should refuse: %v", err)
	}
	if oidcRefusedCount(t, db, "epoch") != before+1 {
		t.Fatalf("epoch-inert refusal was not audited cause=epoch")
	}
}

func TestOIDCReauthEpochInertSQLite(t *testing.T) {
	runOIDCReauthEpochInert(t, seededDB(t, openSQLite))
}
func TestOIDCReauthEpochInertPostgres(t *testing.T) {
	runOIDCReauthEpochInert(t, seededDB(t, openPostgres))
}

// runOIDCReauthProviderRebind: after a provider is replaced for the same
// byte-exact issuer, an identity recorded against the OLD provider must not
// authenticate through the replacement (A3, provider_id mismatch).
func runOIDCReauthProviderRebind(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, password := oidcAdmin(t, db)
	auth.ReauthWindow = time.Minute
	idp, err := oidctest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)
	for _, slug := range []string{"p1", "p2"} {
		if err := idp.RegisterRedirectURI(strings.TrimRight(auth.ExternalOrigin, "/") + "/api/v1/auth/oidc/" + slug + "/callback"); err != nil {
			t.Fatal(err)
		}
	}
	providers := &service.Providers{DB: auth.DB, Keyring: auth.Keyring, ExternalOrigin: auth.ExternalOrigin}
	policy := strptr(`{"amr_sets":[["mfa"]]}`)
	if _, err := providers.Put(ctx, service.LocalPrincipal(admin), "p1", service.ProviderInput{
		DisplayName: "p1", Issuer: idp.Issuer(), ClientID: "c", ClientSecret: "s", Scopes: "openid",
		AssurancePolicy: policy, Enabled: true,
	}); err != nil {
		t.Fatalf("put p1: %v", err)
	}
	linkOn(t, auth, ctx, "p1", "rebind-user", password)
	// Delete p1 (identity survives — provider_id is provenance, not an FK; the
	// tx rows cascade) then recreate the SAME issuer as a new provider p2.
	if err := providers.Delete(ctx, service.LocalPrincipal(admin), "p1"); err != nil {
		t.Fatalf("delete p1: %v", err)
	}
	if _, err := providers.Put(ctx, service.LocalPrincipal(admin), "p2", service.ProviderInput{
		DisplayName: "p2", Issuer: idp.Issuer(), ClientID: "c", ClientSecret: "s", Scopes: "openid",
		AssurancePolicy: policy, Enabled: true,
	}); err != nil {
		t.Fatalf("put p2: %v", err)
	}
	idp.AuthTime = time.Now()
	idp.AMR = []string{"mfa"}
	relogin, err := auth.LocalLogin(ctx, "oidc-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	before := oidcRefusedCount(t, db, "reconciliation")
	if err := reauthOn(t, auth, ctx, "p2", "rebind-user", relogin.SessionToken); !isUnauth(err) {
		t.Fatalf("reauth through a replacement provider should refuse: %v", err)
	}
	if oidcRefusedCount(t, db, "reconciliation") != before+1 {
		t.Fatalf("provider-rebind refusal was not audited cause=reconciliation")
	}
}

func TestOIDCReauthProviderRebindSQLite(t *testing.T) {
	runOIDCReauthProviderRebind(t, seededDB(t, openSQLite))
}
func TestOIDCReauthProviderRebindPostgres(t *testing.T) {
	runOIDCReauthProviderRebind(t, seededDB(t, openPostgres))
}

// runOIDCReauthDowngrade: a reauth must be same-or-stronger than the session it
// re-authorizes. A phishing-resistant (WebAuthn) session cannot be
// re-authorized by federated evidence (capped at multi-factor); a single-factor
// session can (positive control).
func runOIDCReauthDowngrade(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, password := oidcAdmin(t, db)
	auth.ReauthWindow = time.Minute
	_, idp := configureProvider(t, auth, ctx, admin, "strict", service.ProviderInput{
		DisplayName: "strict", ClientID: "c", ClientSecret: "s", Scopes: "openid",
		AssurancePolicy: strptr(`{"amr_sets":[["hwk"]]}`), Enabled: true,
	})
	linkOn(t, auth, ctx, "strict", "down-user", password)
	idp.AuthTime = time.Now()
	// hwk is a true possession factor (mfa is not); the token both satisfies the
	// policy and carries possession, so it reaches the downgrade/positive legs.
	idp.AMR = []string{"hwk"}

	// A rank-2 (WebAuthn) session: OIDC evidence is rank 1, so this is a
	// downgrade. Forge the factor set directly — the rank comparison is under
	// test, not the WebAuthn ceremony.
	strong, err := auth.LocalLogin(ctx, "oidc-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	execRaw(t, db, "UPDATE sessions SET factors = '[\"webauthn\"]' WHERE id = '"+strong.SessionID+"'")
	before := oidcRefusedCount(t, db, "downgrade")
	if err := reauthOn(t, auth, ctx, "strict", "down-user", strong.SessionToken); !isUnauth(err) {
		t.Fatalf("federated reauth of a WebAuthn session should refuse: %v", err)
	}
	if oidcRefusedCount(t, db, "downgrade") != before+1 {
		t.Fatalf("downgrade refusal was not audited cause=downgrade")
	}

	// Positive control: a single-factor (password) session is re-authorized.
	weak, err := auth.LocalLogin(ctx, "oidc-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	if err := reauthOn(t, auth, ctx, "strict", "down-user", weak.SessionToken); err != nil {
		t.Fatalf("federated reauth of a single-factor session should succeed: %v", err)
	}
}

func TestOIDCReauthDowngradeSQLite(t *testing.T) {
	runOIDCReauthDowngrade(t, seededDB(t, openSQLite))
}
func TestOIDCReauthDowngradePostgres(t *testing.T) {
	runOIDCReauthDowngrade(t, seededDB(t, openPostgres))
}

// runOIDCReauthProviderRace: a provider reconfigure that lands during the code
// exchange (Phase B) must make the Phase-C write refuse — the sweep always wins
// the race, so a stale policy evaluation cannot open a window (A4/TOCTOU).
func runOIDCReauthProviderRace(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, password := oidcAdmin(t, db)
	auth.ReauthWindow = time.Minute
	providers, idp := configureProvider(t, auth, ctx, admin, "race", service.ProviderInput{
		DisplayName: "race", ClientID: "c", ClientSecret: "s", Scopes: "openid",
		AssurancePolicy: strptr(`{"amr_sets":[["mfa"]]}`), Enabled: true,
	})
	linkOn(t, auth, ctx, "race", "race-user", password)
	idp.AuthTime = time.Now()
	idp.AMR = []string{"mfa"}
	// The acting session is a LOCAL login (provider_id NULL) so the mid-exchange
	// sweep does not delete it — the point is the Phase-C revalidation, not the
	// sweep reaching this session.
	relogin, err := auth.LocalLogin(ctx, "oidc-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	// Tighten the provider's policy mid-exchange (bumps row_version, sweeps).
	fired := false
	idp.OnToken = func() {
		if fired {
			return
		}
		fired = true
		if _, err := providers.Put(ctx, service.LocalPrincipal(admin), "race", service.ProviderInput{
			DisplayName: "race", Issuer: idp.Issuer(), ClientID: "c", ClientSecret: "s", Scopes: "openid",
			AssurancePolicy: strptr(`{"amr_sets":[["hwk"]]}`), Enabled: true,
		}); err != nil {
			t.Errorf("mid-exchange provider Put: %v", err)
		}
	}
	before := oidcRefusedCount(t, db, "reconciliation")
	if err := reauthOn(t, auth, ctx, "race", "race-user", relogin.SessionToken); !isUnauth(err) {
		t.Fatalf("reauth racing a provider change should refuse: %v", err)
	}
	if oidcRefusedCount(t, db, "reconciliation") != before+1 {
		t.Fatalf("provider-race refusal was not audited cause=reconciliation")
	}
}

func TestOIDCReauthProviderRaceSQLite(t *testing.T) {
	runOIDCReauthProviderRace(t, seededDB(t, openSQLite))
}
func TestOIDCReauthProviderRacePostgres(t *testing.T) {
	runOIDCReauthProviderRace(t, seededDB(t, openPostgres))
}

// runOIDCLoginProviderRace: a provider reconfigure that lands during a login's
// code exchange (Phase B) must make the Phase-C mint refuse (rA-5/TOCTOU). The
// guard row lock makes the A4 sweep deterministically win, so a live federated
// session swept mid-exchange is NOT resurrected by a fresh mint and no new
// session is created in its place.
func runOIDCLoginProviderRace(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, _ := oidcAdmin(t, db)
	providers, idp := configureProvider(t, auth, ctx, admin, "race-login", service.ProviderInput{
		DisplayName: "race-login", ClientID: "c", ClientSecret: "s", Scopes: "openid",
		JITPolicy: strptr(`{"claim":"sub","values":["race-login-user"]}`), Enabled: true,
	})
	// A live federated session that the mid-exchange sweep must delete.
	victim := oidcLogin(t, auth, ctx, "race-login", "race-login-user")
	if _, err := auth.Identity(ctx, victim.SessionToken); err != nil {
		t.Fatalf("federated session should be live before the race: %v", err)
	}
	// A second login for the same subject; during its exchange, reconfigure the
	// provider (bumps row_version, sweeps every federated session for it).
	fired := false
	idp.OnToken = func() {
		if fired {
			return
		}
		fired = true
		if _, err := providers.Put(ctx, service.LocalPrincipal(admin), "race-login", service.ProviderInput{
			DisplayName: "race-login", Issuer: idp.Issuer(), ClientID: "c2", ClientSecret: "s", Scopes: "openid",
			JITPolicy: strptr(`{"claim":"sub","values":["race-login-user"]}`), Enabled: true,
		}); err != nil {
			t.Errorf("mid-exchange provider Put: %v", err)
		}
	}
	before := oidcRefusedCount(t, db, "reconciliation")
	start, err := auth.OIDCStart(ctx, "race-login", "login", "", "", "")
	if err != nil {
		t.Fatalf("login start: %v", err)
	}
	code, state := driveIdP(t, start.AuthURL+"&sub=race-login-user")
	if _, err := auth.OIDCCallback(ctx, "race-login", code, state, "", "", start.BindingCookie, ""); !isUnauth(err) {
		t.Fatalf("login racing a provider change should refuse the mint: %v", err)
	}
	if oidcRefusedCount(t, db, "reconciliation") != before+1 {
		t.Fatalf("login-race refusal was not audited cause=reconciliation")
	}
	// The swept session stays swept: the refused mint neither resurrected it nor
	// minted a replacement.
	if _, err := auth.Identity(ctx, victim.SessionToken); !isUnauth(err) {
		t.Fatalf("swept federated session was resurrected by the racing login: %v", err)
	}
}

func TestOIDCLoginProviderRaceSQLite(t *testing.T) {
	runOIDCLoginProviderRace(t, seededDB(t, openSQLite))
}
func TestOIDCLoginProviderRacePostgres(t *testing.T) {
	runOIDCLoginProviderRace(t, seededDB(t, openPostgres))
}

// runOIDCLoginProviderDeleteRace: deleting a provider during a login's code
// exchange (Phase B) must refuse the Phase-C mint AND leave no session
// referencing the deleted provider. The delete locks the provider row before
// sweeping, and the FK cascade (A14) is the atomic backstop, so a live
// federated session and any raced mint are both gone once the provider is
// deleted — a compromised provider cannot be deleted yet keep live sessions.
func runOIDCLoginProviderDeleteRace(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, _ := oidcAdmin(t, db)
	providers, idp := configureProvider(t, auth, ctx, admin, "race-del", service.ProviderInput{
		DisplayName: "race-del", ClientID: "c", ClientSecret: "s", Scopes: "openid",
		JITPolicy: strptr(`{"claim":"sub","values":["race-del-user"]}`), Enabled: true,
	})
	// A live federated session the mid-exchange delete's cascade must remove.
	victim := oidcLogin(t, auth, ctx, "race-del", "race-del-user")
	if _, err := auth.Identity(ctx, victim.SessionToken); err != nil {
		t.Fatalf("federated session should be live before the race: %v", err)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM sessions WHERE provider_id IS NOT NULL"); n != 1 {
		t.Fatalf("expected 1 federated session before the race, got %d", n)
	}
	// A second login for the same subject; during its exchange, delete the
	// provider. The mint's guard then finds the row gone and refuses.
	fired := false
	idp.OnToken = func() {
		if fired {
			return
		}
		fired = true
		if err := providers.Delete(ctx, service.LocalPrincipal(admin), "race-del"); err != nil {
			t.Errorf("mid-exchange provider Delete: %v", err)
		}
	}
	before := oidcRefusedCount(t, db, "reconciliation")
	start, err := auth.OIDCStart(ctx, "race-del", "login", "", "", "")
	if err != nil {
		t.Fatalf("login start: %v", err)
	}
	code, state := driveIdP(t, start.AuthURL+"&sub=race-del-user")
	if _, err := auth.OIDCCallback(ctx, "race-del", code, state, "", "", start.BindingCookie, ""); !isUnauth(err) {
		t.Fatalf("login racing a provider delete should refuse the mint: %v", err)
	}
	if oidcRefusedCount(t, db, "reconciliation") != before+1 {
		t.Fatalf("login-delete-race refusal was not audited cause=reconciliation")
	}
	// The victim is gone and no session survives referencing the deleted provider.
	if _, err := auth.Identity(ctx, victim.SessionToken); !isUnauth(err) {
		t.Fatalf("federated session survived its provider's deletion: %v", err)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM sessions WHERE provider_id IS NOT NULL"); n != 0 {
		t.Fatalf("expected 0 sessions after provider delete, got %d", n)
	}
}

func TestOIDCLoginProviderDeleteRaceSQLite(t *testing.T) {
	runOIDCLoginProviderDeleteRace(t, seededDB(t, openSQLite))
}
func TestOIDCLoginProviderDeleteRacePostgres(t *testing.T) {
	runOIDCLoginProviderDeleteRace(t, seededDB(t, openPostgres))
}

// runOIDCProviderDeleteCascade proves the FK cascade (A14) is the atomic
// backstop, not the service sweep: deleting the provider ROW directly (raw
// SQL, bypassing SweepSessionsForProvider entirely) must still remove every
// session referencing it. On sqlite this establishes that PRAGMA
// foreign_keys=ON plus the ADD COLUMN ... REFERENCES ... ON DELETE CASCADE in
// 00007 actually enforces the cascade. Without the FK edit this test fails.
func runOIDCProviderDeleteCascade(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, _ := oidcAdmin(t, db)
	configureProvider(t, auth, ctx, admin, "cascade", service.ProviderInput{
		DisplayName: "cascade", ClientID: "c", ClientSecret: "s", Scopes: "openid",
		JITPolicy: strptr(`{"claim":"sub","values":["cascade-user"]}`), Enabled: true,
	})
	sess := oidcLogin(t, auth, ctx, "cascade", "cascade-user")
	if _, err := auth.Identity(ctx, sess.SessionToken); err != nil {
		t.Fatalf("federated session should be live: %v", err)
	}
	if n := queryInt(t, db, "SELECT COUNT(*) FROM sessions WHERE provider_id IS NOT NULL"); n != 1 {
		t.Fatalf("expected 1 federated session, got %d", n)
	}
	// Delete the provider row directly, NOT via the service (no sweep runs).
	execRaw(t, db, "DELETE FROM oidc_providers WHERE slug = 'cascade'")
	if n := queryInt(t, db, "SELECT COUNT(*) FROM sessions WHERE provider_id IS NOT NULL"); n != 0 {
		t.Fatalf("FK cascade did not remove sessions on provider row delete, got %d", n)
	}
	if _, err := auth.Identity(ctx, sess.SessionToken); !isUnauth(err) {
		t.Fatalf("session survived its provider's row deletion: %v", err)
	}
}

func TestOIDCProviderDeleteCascadeSQLite(t *testing.T) {
	runOIDCProviderDeleteCascade(t, seededDB(t, openSQLite))
}
func TestOIDCProviderDeleteCascadePostgres(t *testing.T) {
	runOIDCProviderDeleteCascade(t, seededDB(t, openPostgres))
}

// runOIDCIATRejected: an ID token whose iat is in the future beyond the skew is
// refused (A validation completeness), audited cause=signature.
func runOIDCIATRejected(t *testing.T, db *store.DB) {
	ctx := t.Context()
	auth, admin, _ := oidcAdmin(t, db)
	_, idp := configureProvider(t, auth, ctx, admin, "idp", service.ProviderInput{
		DisplayName: "IdP", ClientID: "c", ClientSecret: "s", Scopes: "openid",
		JITPolicy: strptr(`{"claim":"sub","values":["iat-user"]}`), Enabled: true,
	})
	// (a) iat far beyond the 2m skew.
	idp.IAT = time.Now().Add(time.Hour)
	start, err := auth.OIDCStart(ctx, "idp", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	code, state := driveIdP(t, start.AuthURL+"&sub=iat-user")
	before := oidcRefusedCount(t, db, "signature")
	if _, err := auth.OIDCCallback(ctx, "idp", code, state, "", "", start.BindingCookie, ""); !isUnauth(err) {
		t.Fatalf("a future-iat token should refuse: %v", err)
	}
	if oidcRefusedCount(t, db, "signature") != before+1 {
		t.Fatalf("future-iat refusal was not audited cause=signature")
	}

	// (b) iat absent entirely (go-oidc's expiry check passes it through to the
	// relying party's zero-check).
	idp.IAT = time.Time{}
	idp.OmitIAT = true
	start2, err := auth.OIDCStart(ctx, "idp", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	code2, state2 := driveIdP(t, start2.AuthURL+"&sub=iat-user")
	before = oidcRefusedCount(t, db, "signature")
	if _, err := auth.OIDCCallback(ctx, "idp", code2, state2, "", "", start2.BindingCookie, ""); !isUnauth(err) {
		t.Fatalf("a missing-iat token should refuse: %v", err)
	}
	if oidcRefusedCount(t, db, "signature") != before+1 {
		t.Fatalf("missing-iat refusal was not audited cause=signature")
	}
}

func TestOIDCIATRejectedSQLite(t *testing.T)   { runOIDCIATRejected(t, seededDB(t, openSQLite)) }
func TestOIDCIATRejectedPostgres(t *testing.T) { runOIDCIATRejected(t, seededDB(t, openPostgres)) }
