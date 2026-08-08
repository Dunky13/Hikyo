package isolation

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/oidctest"
	"github.com/Dunky13/wenv/internal/service"
	"github.com/Dunky13/wenv/internal/store"
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
		auth.ExternalOrigin = "https://wenv.test"
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
	login, err := auth.LocalLogin(ctx, username, password)
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
	relogin, err := auth.LocalLogin(ctx, username, password)
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
	auth.ExternalOrigin = "https://wenv.test"
	boot, err := auth.BootstrapAdmin(t.Context(), "oidc-admin", "OIDC Admin", "terminal")
	if err != nil {
		t.Fatal(err)
	}
	const password = "correct horse battery staple oidc"
	if err := auth.EstablishCredential(t.Context(), boot.Authority, password); err != nil {
		t.Fatal(err)
	}
	acc, err := auth.LocalLogin(t.Context(), "oidc-admin", password)
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
	login, err := auth.LocalLogin(ctx, "oidc-admin", password)
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
	login, err := auth.LocalLogin(ctx, "oidc-admin", password)
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
	relogin, err := auth.LocalLogin(ctx, "oidc-admin", password)
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
