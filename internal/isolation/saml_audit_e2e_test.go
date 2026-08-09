package isolation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/service"
)

func runSAMLAuditLifecycle(t *testing.T, auth *service.Auth, principal domain.PrincipalID, password string) {
	t.Helper()
	ctx := tctx(t)
	now := time.Now().UTC()
	auth.ExternalOrigin = "https://wenv.example"
	providers := &service.SAMLProviders{
		DB: auth.DB, Keyring: auth.Keyring, ExternalOrigin: auth.ExternalOrigin,
		Now: func() time.Time { return now },
	}
	metadata := samlAuditMetadata(t, now)
	policy := []string{"urn:example:mfa"}
	input := service.SAMLProviderInput{
		DisplayName: "Audit SAML", EntityID: "https://idp.example/metadata",
		MetadataSource: "file", MetadataDocument: metadata, AssurancePolicy: &policy,
		AllowEmailNameID: true, Enabled: true,
	}
	preview, err := providers.Put(ctx, service.LocalPrincipal(principal), "audit-saml", input)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Applied || len(preview.RequiredFingerprints) == 0 || len(preview.RequiredEndpoints) == 0 {
		t.Fatalf("SAML configure preview = %#v", preview)
	}
	input.ConfirmedFingerprints = preview.RequiredFingerprints
	input.ConfirmedEndpoints = preview.RequiredEndpoints
	applied, err := providers.Put(ctx, service.LocalPrincipal(principal), "audit-saml", input)
	if err != nil {
		t.Fatal(err)
	}
	if !applied.Applied {
		t.Fatal("confirmed SAML provider configuration was not applied")
	}
	if got := queryInt(t, auth.DB, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'auth.saml_metadata_expiry_warning'"); got != 0 {
		t.Fatalf("metadata warning emitted before threshold = %d, want 0", got)
	}
	now = now.Add(15 * 24 * time.Hour)
	if _, err := providers.List(ctx, service.LocalPrincipal(principal)); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, auth.DB, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'auth.saml_metadata_expiry_warning'"); got != 1 {
		t.Fatalf("metadata warning emitted after threshold = %d, want 1", got)
	}

	loginStart, err := auth.SAMLStart(ctx, "audit-saml", "login", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	loginRelay := samlAuditRelayState(t, loginStart.RedirectURL)
	if _, err := auth.SAMLACS(ctx, "audit-saml", "%%%", loginRelay, loginStart.InitiatorCookie); err == nil {
		t.Fatal("malformed SAML login response succeeded")
	}

	session, err := auth.LocalLogin(ctx, "e2e-admin", password)
	if err != nil {
		t.Fatal(err)
	}
	reauthStart, err := auth.SAMLStart(ctx, "audit-saml", "reauth", "env_a1", session.SessionToken, "")
	if err != nil {
		t.Fatal(err)
	}
	reauthRelay := samlAuditRelayState(t, reauthStart.RedirectURL)
	if _, err := auth.SAMLACS(ctx, "audit-saml", "%%%", reauthRelay, reauthStart.InitiatorCookie); err == nil {
		t.Fatal("malformed SAML reauth response succeeded")
	}
	if _, err := providers.RefreshMetadata(ctx, service.LocalPrincipal(principal), "audit-saml", service.SAMLMetadataRefreshInput{
		MetadataDocument: []byte("<invalid"),
	}); err == nil {
		t.Fatal("malformed metadata refresh succeeded")
	}
	if got := queryInt(t, auth.DB, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'auth.saml_provider_refresh' AND outcome = 'failure'"); got != 1 {
		t.Fatalf("failed metadata refresh audit rows = %d, want 1", got)
	}

	refreshed, err := providers.RefreshMetadata(ctx, service.LocalPrincipal(principal), "audit-saml", service.SAMLMetadataRefreshInput{
		MetadataDocument: metadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !refreshed.Applied {
		t.Fatalf("unchanged metadata refresh unexpectedly requires confirmation: %#v", refreshed)
	}
	if err := providers.Delete(ctx, service.LocalPrincipal(principal), "audit-saml"); err != nil {
		t.Fatal(err)
	}
}

func samlAuditMetadata(t *testing.T, now time.Time) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(72), Subject: pkix.Name{CommonName: "audit IdP"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := base64.StdEncoding.EncodeToString(der)
	validUntil := now.Add(40 * 24 * time.Hour).Format(time.RFC3339Nano)
	return []byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example/metadata" validUntil="` + validUntil + `">` +
		`<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + certificate + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
		`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>` +
		`</md:IDPSSODescriptor></md:EntityDescriptor>`)
}

func samlAuditRelayState(t *testing.T, redirectURL string) string {
	t.Helper()
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatal(err)
	}
	relay := parsed.Query().Get("RelayState")
	if relay == "" {
		t.Fatal("SAML redirect has no RelayState")
	}
	return relay
}
