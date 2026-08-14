package isolation

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/samltest"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

func configureSAMLProvider(t *testing.T, auth *service.Auth, admin domain.PrincipalID) *samltest.IdP {
	t.Helper()
	now := time.Now().UTC()
	idp, err := samltest.New(now)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := idp.SignedMetadata(now)
	if err != nil {
		t.Fatal(err)
	}
	providers := &service.SAMLProviders{
		DB: auth.DB, Keyring: auth.Keyring, ExternalOrigin: auth.ExternalOrigin,
	}
	input := service.SAMLProviderInput{
		DisplayName: "SAML test IdP", EntityID: samltest.EntityID,
		MetadataSource: "file", MetadataDocument: metadata, Enabled: true,
	}
	preview, err := providers.Put(t.Context(), service.LocalPrincipal(admin), "saml-idp", input)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Applied || len(preview.RequiredFingerprints) != 1 || len(preview.RequiredEndpoints) != 1 {
		t.Fatalf("provider preview = %#v", preview)
	}
	input.ConfirmedFingerprints = preview.RequiredFingerprints
	input.ConfirmedEndpoints = preview.RequiredEndpoints
	result, err := providers.Put(t.Context(), service.LocalPrincipal(admin), "saml-idp", input)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied {
		t.Fatal("confirmed provider configuration was not applied")
	}
	return idp
}

func samlResponseForStart(t *testing.T, idp *samltest.IdP, start service.SAMLStartResult, responseID, assertionID string) string {
	t.Helper()
	request, err := samltest.DecodeRequest(start.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := idp.SignedResponse(samltest.Response{
		RequestID: request.ID, ResponseID: responseID, AssertionID: assertionID,
		ACSURL:     "https://hikyo.test/api/v1/auth/saml/saml-idp/acs",
		SPEntityID: "https://hikyo.test/api/v1/auth/saml",
		NameID:     "saml-user", Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func runSAMLLoginReplay(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := t.Context()
	auth, admin, password := oidcAdmin(t, db)
	auth.ExternalOrigin = "https://hikyo.test"
	idp := configureSAMLProvider(t, auth, admin)
	providers := &service.SAMLProviders{DB: auth.DB, Keyring: auth.Keyring, ExternalOrigin: auth.ExternalOrigin}
	downgrade := service.SAMLProviderInput{
		DisplayName: "SAML test IdP", EntityID: samltest.EntityID,
		MetadataSource: "file", MetadataDocument: idp.Metadata(time.Now().UTC()), Enabled: true,
	}
	if _, err := providers.Put(ctx, service.LocalPrincipal(admin), "saml-idp", downgrade); !errors.Is(err, service.ErrSAMLMetadataSignatureDowngrade) {
		t.Fatalf("signed metadata replaced by unsigned PUT = %v, want signature downgrade", err)
	}
	duplicate := service.SAMLProviderInput{
		DisplayName: "Duplicate entity IdP", EntityID: samltest.EntityID,
		MetadataSource: "file", MetadataDocument: idp.Metadata(time.Now().UTC()), Enabled: true,
	}
	duplicatePreview, err := providers.Put(ctx, service.LocalPrincipal(admin), "duplicate-entity", duplicate)
	if err != nil {
		t.Fatal(err)
	}
	duplicate.ConfirmedFingerprints = duplicatePreview.RequiredFingerprints
	duplicate.ConfirmedEndpoints = duplicatePreview.RequiredEndpoints
	if _, err := providers.Put(ctx, service.LocalPrincipal(admin), "duplicate-entity", duplicate); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate active entityID = %v, want conflict", err)
	}

	local, err := auth.LocalLogin(ctx, "oidc-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	link, err := auth.SAMLStart(ctx, "saml-idp", "link", "", local.SessionToken, password)
	if err != nil {
		t.Fatal(err)
	}
	linkedResponse := samlResponseForStart(t, idp, link, "_response_link", "_assertion_link")
	if _, err := auth.SAMLACS(ctx, "saml-idp", linkedResponse, samlAuditRelayState(t, link.RedirectURL), link.InitiatorCookie); err != nil {
		payload := queryString(t, db, "SELECT payload FROM audit_instance_events WHERE type = 'auth.saml_login' ORDER BY seq DESC LIMIT 1")
		t.Fatalf("link callback: %v (audit %s)", err, payload)
	}

	start, err := auth.SAMLStart(ctx, "saml-idp", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	loginResponse := samlResponseForStart(t, idp, start, "_response_login", "_assertion_login")
	login, err := auth.SAMLACS(ctx, "saml-idp", loginResponse, samlAuditRelayState(t, start.RedirectURL), start.InitiatorCookie)
	if err != nil {
		t.Fatalf("valid login callback: %v", err)
	}
	identity, err := auth.Identity(ctx, login.SessionToken)
	if err != nil {
		t.Fatalf("SAML session does not resolve: %v", err)
	}
	if identity.Principal != admin || login.Assurance.Method != "saml:"+samltest.EntityID {
		t.Fatalf("SAML login = %#v, identity = %#v", login, identity)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'auth.saml_login' AND outcome = 'success'"); got == 0 {
		t.Fatal("valid SAML login emitted no success audit event")
	}

	concurrent, err := auth.SAMLStart(ctx, "saml-idp", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	const replayedAssertionID = "_assertion_concurrent"
	concurrentResponse := samlResponseForStart(t, idp, concurrent, "_response_concurrent", replayedAssertionID)
	relay := samlAuditRelayState(t, concurrent.RedirectURL)
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, callbackErr := auth.SAMLACS(ctx, "saml-idp", concurrentResponse, relay, concurrent.InitiatorCookie)
			results <- callbackErr
		}()
	}
	wait.Wait()
	close(results)
	successes := 0
	refusals := 0
	for callbackErr := range results {
		switch {
		case callbackErr == nil:
			successes++
		case errors.Is(callbackErr, domain.ErrUnauthenticated):
			refusals++
		default:
			t.Fatalf("concurrent callback: %v", callbackErr)
		}
	}
	if successes != 1 || refusals != 1 {
		t.Fatalf("concurrent callback outcomes = %d success, %d refusal; want 1/1", successes, refusals)
	}

	// A fresh service object has no process-local replay state. Reusing the
	// assertion ID under a new request still fails, proving the cache is durable.
	restarted := &service.Auth{
		DB: auth.DB, Keyring: auth.Keyring, KDF: auth.KDF, Admission: auth.Admission,
		Now: auth.Now, ExternalOrigin: auth.ExternalOrigin, OIDCDiscover: auth.OIDCDiscover,
		WebAuthn: auth.WebAuthn, ReauthWindow: auth.ReauthWindow, ReauthHardCap: auth.ReauthHardCap, Log: auth.Log,
	}
	replayStart, err := restarted.SAMLStart(ctx, "saml-idp", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	replayResponse := samlResponseForStart(t, idp, replayStart, "_response_restart", replayedAssertionID)
	if _, err := restarted.SAMLACS(ctx, "saml-idp", replayResponse, samlAuditRelayState(t, replayStart.RedirectURL), replayStart.InitiatorCookie); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("replay after service restart = %v, want unauthenticated", err)
	}
	if got := queryInt(t, db, fmt.Sprintf("SELECT COUNT(*) FROM saml_replay WHERE issuer = '%s' AND assertion_id = '%s'", samltest.EntityID, replayedAssertionID)); got != 1 {
		t.Fatalf("durable replay rows = %d, want 1", got)
	}

	displayName := "Renamed SAML test IdP"
	if _, err := providers.Patch(ctx, service.LocalPrincipal(admin), "saml-idp", service.SAMLProviderPatch{DisplayName: &displayName}); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Identity(ctx, login.SessionToken); err != nil {
		t.Fatalf("display-only provider change swept a SAML session: %v", err)
	}
	policy := []string{"urn:example:mfa"}
	if _, err := providers.Patch(ctx, service.LocalPrincipal(admin), "saml-idp", service.SAMLProviderPatch{AssurancePolicy: &policy}); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Identity(ctx, login.SessionToken); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("assurance-policy change left SAML session live: %v", err)
	}
}

func TestSAMLLoginReplaySQLite(t *testing.T) {
	runSAMLLoginReplay(t, seededDB(t, openSQLite))
}

func TestSAMLLoginReplayPostgres(t *testing.T) {
	runSAMLLoginReplay(t, seededDB(t, openPostgres))
}

func runSAMLProviderRecreation(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := t.Context()
	auth, admin, password := oidcAdmin(t, db)
	auth.ExternalOrigin = "https://hikyo.test"
	idp := configureSAMLProvider(t, auth, admin)
	providers := &service.SAMLProviders{DB: auth.DB, Keyring: auth.Keyring, ExternalOrigin: auth.ExternalOrigin}

	local, err := auth.LocalLogin(ctx, "oidc-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	link, err := auth.SAMLStart(ctx, "saml-idp", "link", "", local.SessionToken, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.SAMLACS(ctx, "saml-idp",
		samlResponseForStart(t, idp, link, "_response_recreate_link", "_assertion_recreate_link"),
		samlAuditRelayState(t, link.RedirectURL), link.InitiatorCookie); err != nil {
		t.Fatalf("link callback: %v", err)
	}
	oldProviderID := queryString(t, db, "SELECT provider_id FROM external_identities WHERE kind = 'saml' AND issuer = 'https://samltest.example/metadata'")

	if err := providers.Delete(ctx, service.LocalPrincipal(admin), "saml-idp"); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM external_identities WHERE kind = 'saml' AND issuer = 'https://samltest.example/metadata'"); got != 1 {
		t.Fatalf("linked identity rows after provider removal = %d, want 1", got)
	}
	replacementIDP := configureSAMLProvider(t, auth, admin)
	newProviderID := queryString(t, db, "SELECT id FROM saml_providers WHERE slug = 'saml-idp'")
	if newProviderID == oldProviderID {
		t.Fatalf("provider recreation reused row id %q", newProviderID)
	}

	start, err := auth.SAMLStart(ctx, "saml-idp", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	login, err := auth.SAMLACS(ctx, "saml-idp",
		samlResponseForStart(t, replacementIDP, start, "_response_recreated", "_assertion_recreated"),
		samlAuditRelayState(t, start.RedirectURL), start.InitiatorCookie)
	if err != nil {
		t.Fatalf("login after re-adding the same entityID: %v", err)
	}
	identity, err := auth.Identity(ctx, login.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Principal != admin {
		t.Fatalf("recreated-provider principal = %q, want %q", identity.Principal, admin)
	}
	if got := queryString(t, db, "SELECT provider_id FROM external_identities WHERE kind = 'saml' AND issuer = 'https://samltest.example/metadata'"); got != newProviderID {
		t.Fatalf("identity provider provenance = %q, want %q", got, newProviderID)
	}
}

func TestSAMLProviderRecreationSQLite(t *testing.T) {
	runSAMLProviderRecreation(t, seededDB(t, openSQLite))
}

func TestSAMLProviderRecreationPostgres(t *testing.T) {
	runSAMLProviderRecreation(t, seededDB(t, openPostgres))
}

func runSAMLSPKeyLifecycle(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := t.Context()
	auth, admin, _ := oidcAdmin(t, db)
	auth.ExternalOrigin = "https://hikyo.test"
	configureSAMLProvider(t, auth, admin)
	providers := &service.SAMLProviders{DB: auth.DB, Keyring: auth.Keyring, ExternalOrigin: auth.ExternalOrigin}
	actor := service.LocalPrincipal(admin)

	initial, err := providers.ListSPKeys(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	if len(initial) != 1 || initial[0].State != "active" {
		t.Fatalf("initial SP keys = %#v", initial)
	}
	first := initial[0]
	replacement, err := providers.RotateSPKey(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.State != "active" || replacement.Fingerprint == first.Fingerprint {
		t.Fatalf("rotated key = %#v, previous = %#v", replacement, first)
	}
	afterRotate, err := providers.ListSPKeys(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterRotate) != 2 || afterRotate[0].State != "active" || afterRotate[1].State != "retiring" {
		t.Fatalf("keys after rotation = %#v", afterRotate)
	}
	metadata, err := auth.SAMLMetadata(ctx, "saml-idp")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(metadata), "</X509Certificate>"); got != 2 {
		t.Fatalf("published certificates during overlap = %d, want 2: %s", got, metadata)
	}
	if err := providers.RetireSPKey(ctx, actor, replacement.Fingerprint); !errors.Is(err, service.ErrSAMLSPKeyState) {
		t.Fatalf("retiring active key = %v, want state refusal", err)
	}
	if err := providers.RetireSPKey(ctx, actor, first.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if got, err := providers.ListSPKeys(ctx, actor); err != nil || len(got) != 1 || got[0].Fingerprint != replacement.Fingerprint {
		t.Fatalf("keys after retiring old = %#v, err %v", got, err)
	}

	afterCompromise, err := providers.CompromiseRetireSPKey(ctx, actor, replacement.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if afterCompromise.State != "active" || afterCompromise.Fingerprint == replacement.Fingerprint {
		t.Fatalf("compromise replacement = %#v", afterCompromise)
	}
	if got, err := providers.ListSPKeys(ctx, actor); err != nil || len(got) != 1 || got[0].Fingerprint != afterCompromise.Fingerprint {
		t.Fatalf("keys after compromise retirement = %#v, err %v", got, err)
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'auth.saml_sp_key' AND payload LIKE '%compromise_retire%'"); got != 1 {
		t.Fatalf("compromise-retire audit rows = %d, want 1", got)
	}
}

func TestSAMLSPKeyLifecycleSQLite(t *testing.T) {
	runSAMLSPKeyLifecycle(t, seededDB(t, openSQLite))
}

func TestSAMLSPKeyLifecyclePostgres(t *testing.T) {
	runSAMLSPKeyLifecycle(t, seededDB(t, openPostgres))
}
