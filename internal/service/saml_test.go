package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/samlsp"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestAssessSAMLMetadataReturnsCompleteDiffAndOnlyRequiresNewTrust(t *testing.T) {
	oldCertificate := testSAMLCertificate(t, "old")
	newCertificate := testSAMLCertificate(t, "new")
	oldDER, err := json.Marshal([][]byte{oldCertificate.Raw})
	if err != nil {
		t.Fatal(err)
	}
	oldFingerprint, err := certificateFingerprint(oldCertificate)
	if err != nil {
		t.Fatal(err)
	}
	newFingerprint, err := certificateFingerprint(newCertificate)
	if err != nil {
		t.Fatal(err)
	}
	validUntil := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	previous := &authz.SAMLProvider{
		SSORedirectURL:      "https://old.example/sso",
		SigningCertificates: oldDER,
	}
	metadata := samlsp.Metadata{
		SSOURL:              "https://new.example/sso",
		SigningCertificates: []*x509.Certificate{newCertificate},
		ValidUntil:          &validUntil,
	}

	assessment, err := assessSAMLMetadata(metadata, previous, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := assessment.Diff.CertsAddedFps, []string{newFingerprint}; !slices.Equal(got, want) {
		t.Fatalf("certs added = %v, want %v", got, want)
	}
	if got, want := assessment.Diff.CertsRemovedFps, []string{oldFingerprint}; !slices.Equal(got, want) {
		t.Fatalf("certs removed = %v, want %v", got, want)
	}
	if got, want := assessment.Diff.EndpointsAdded, []string{"https://new.example/sso"}; !slices.Equal(got, want) {
		t.Fatalf("endpoints added = %v, want %v", got, want)
	}
	if got, want := assessment.Diff.EndpointsRemoved, []string{"https://old.example/sso"}; !slices.Equal(got, want) {
		t.Fatalf("endpoints removed = %v, want %v", got, want)
	}
	if assessment.Diff.ValidUntil == nil || !assessment.Diff.ValidUntil.Equal(validUntil) {
		t.Fatalf("valid until = %v, want %v", assessment.Diff.ValidUntil, validUntil)
	}
	if got, want := assessment.RequiredFingerprints, []string{newFingerprint}; !slices.Equal(got, want) {
		t.Fatalf("required fingerprints = %v, want %v", got, want)
	}
	if got, want := assessment.RequiredEndpoints, []string{"https://new.example/sso"}; !slices.Equal(got, want) {
		t.Fatalf("required endpoints = %v, want %v", got, want)
	}

	confirmed, err := assessSAMLMetadata(metadata, previous, []string{newFingerprint}, []string{"https://new.example/sso"})
	if err != nil {
		t.Fatal(err)
	}
	if len(confirmed.RequiredFingerprints) != 0 || len(confirmed.RequiredEndpoints) != 0 {
		t.Fatalf("confirmed requirements = %v / %v, want empty", confirmed.RequiredFingerprints, confirmed.RequiredEndpoints)
	}
}

func testSAMLCertificate(t *testing.T, commonName string) *x509.Certificate {
	now := time.Now()
	return testSAMLCertificateAt(t, commonName, now.Add(-time.Hour), now.Add(time.Hour))
}

func testSAMLCertificateAt(t *testing.T, commonName string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestSAMLSubjectPreservesByteExactNameIDIdentity(t *testing.T) {
	persistent := samlNameIDPersistent
	unspecified := samlNameIDUnspecified
	empty := ""
	cases := []samlsp.NameID{
		{Value: []byte("CaseSensitive"), Format: &persistent},
		{Value: []byte("casesensitive"), Format: &persistent},
		{Value: []byte("CaseSensitive"), Format: &persistent, NameQualifier: &empty},
		{Value: []byte("CaseSensitive")},
		{Value: []byte("CaseSensitive"), Format: &unspecified},
	}
	seen := map[string]bool{}
	for _, nameID := range cases {
		subject, err := samlSubject(nameID, false)
		if err != nil {
			t.Fatal(err)
		}
		if seen[subject] {
			t.Fatalf("distinct byte-exact NameIDs collided at %q", subject)
		}
		seen[subject] = true
	}
}

func TestSAMLSubjectEnforcesNameIDFormatPolicy(t *testing.T) {
	transient := samlNameIDTransient
	if _, err := samlSubject(samlsp.NameID{Value: []byte("x"), Format: &transient}, true); !errors.Is(err, ErrSAMLTransientNameID) {
		t.Fatalf("transient format error = %v, want ErrSAMLTransientNameID", err)
	}
	email := samlNameIDEmail
	nameID := samlsp.NameID{Value: []byte("Case@Example.test"), Format: &email}
	if _, err := samlSubject(nameID, false); !errors.Is(err, ErrSAMLEmailNameIDDisabled) {
		t.Fatalf("email format without opt-in error = %v, want ErrSAMLEmailNameIDDisabled", err)
	}
	if _, err := samlSubject(nameID, true); err != nil {
		t.Fatalf("email format with opt-in refused: %v", err)
	}
}

func TestSAMLEvaluateAssuranceUsesAcceptedContextSet(t *testing.T) {
	policy := `{"authn_context_class_refs":["urn:example:mfa"]}`
	accepted := "urn:example:mfa"
	rejected := "urn:example:password"
	if ok, err := evaluateSAMLAssurance(&policy, &accepted); err != nil || !ok {
		t.Fatalf("accepted context = %v, %v; want true, nil", ok, err)
	}
	if ok, err := evaluateSAMLAssurance(&policy, &rejected); err != nil || ok {
		t.Fatalf("rejected context = %v, %v; want false, nil", ok, err)
	}
	if ok, err := evaluateSAMLAssurance(&policy, nil); err != nil || ok {
		t.Fatalf("missing context = %v, %v; want false, nil", ok, err)
	}
	if ok, err := evaluateSAMLAssurance(nil, &accepted); err != nil || ok {
		t.Fatalf("absent policy = %v, %v; want false, nil", ok, err)
	}
}

func TestSAMLAllPurposesCarryCrossSiteInitiatorBinding(t *testing.T) {
	provider := authz.SAMLProvider{ID: "samlp_1", EntityID: "https://idp.example", ACSURL: "https://hikyo.example/api/v1/auth/saml/idp/acs"}
	for _, purpose := range []string{purposeLogin, purposeLink, purposeReauth} {
		transaction := newSAMLTransaction("samltx_1", "_request", "relay", "initiator",
			provider, purpose, "ses_1", "acc_1", "env_1", 1)
		if len(transaction.InitiatorVerifier) == 0 {
			t.Errorf("purpose %q omitted SameSite=None initiator binding", purpose)
		}
		if got, want := transaction.InitiatorVerifier, crypto.ArtifactVerifier("initiator"); string(got) != string(want) {
			t.Errorf("purpose %q initiator verifier mismatch", purpose)
		}
	}
}

func TestSAMLAuditPayloadSurfacesExpiredPinnedCertificate(t *testing.T) {
	payload := samlCeremonyPayload(audit.OutcomeSuccess, "", "samlp_1", "https://idp.example", purposeLogin, "samltx_1", &samlsp.Claims{
		ExpiredPinnedCertificate: true,
	})
	warned, ok := payload["pinned_certificate_expired"].(bool)
	if !ok || !warned {
		t.Fatalf("expired pinned certificate warning = %#v, want true", payload["pinned_certificate_expired"])
	}
}

func TestSAMLMetadataURLRequiresHTTPS(t *testing.T) {
	providers := &SAMLProviders{}
	for _, rawURL := range []string{
		"http://idp.example/metadata",
		"https://user@idp.example/metadata",
		"https:///metadata",
	} {
		if _, err := providers.fetchMetadata(t.Context(), rawURL); !errors.Is(err, ErrSAMLMetadataFetch) {
			t.Errorf("fetchMetadata(%q) error = %v, want ErrSAMLMetadataFetch", rawURL, err)
		}
	}
}

func TestSAMLMetadataURLRefusesPrivateNetworkTargets(t *testing.T) {
	requests := 0
	providers := &SAMLProviders{HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("<EntityDescriptor/>")),
			Header:     make(http.Header),
		}, nil
	})}}

	for _, rawURL := range []string{
		"https://localhost/metadata",
		"https://127.0.0.1/metadata",
		"https://10.0.0.1/metadata",
		"https://169.254.169.254/latest/meta-data",
		"https://100.64.0.1/metadata",
		"https://[::1]/metadata",
		"https://[fd00::1]/metadata",
	} {
		if _, err := providers.fetchMetadata(t.Context(), rawURL); !errors.Is(err, ErrSAMLMetadataFetch) {
			t.Errorf("fetchMetadata(%q) error = %v, want ErrSAMLMetadataFetch", rawURL, err)
		}
	}
	if requests != 0 {
		t.Fatalf("private metadata URLs made %d outbound requests, want 0", requests)
	}
}

func TestSAMLMetadataIPClassifierAllowsOnlyPublicAddresses(t *testing.T) {
	for _, test := range []struct {
		address   string
		nonPublic bool
	}{
		{"8.8.8.8", false},
		{"2606:4700:4700::1111", false},
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"169.254.169.254", true},
		{"100.64.0.1", true},
		{"192.0.2.1", true},
		{"198.51.100.1", true},
		{"203.0.113.1", true},
		{"::1", true},
		{"fd00::1", true},
		{"64:ff9b:1::1", true},
		{"100::1", true},
		{"2001:2::1", true},
		{"2001:db8::1", true},
		{"2002::1", true},
		{"3fff::1", true},
		{"5f00::1", true},
	} {
		address := netip.MustParseAddr(test.address)
		if got := metadataIPIsNonPublic(address); got != test.nonPublic {
			t.Errorf("metadataIPIsNonPublic(%s) = %v, want %v", address, got, test.nonPublic)
		}
	}
}

func TestSAMLProviderWarningsAreServerAuthoritativeAndDeterministic(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	expired := testSAMLCertificateAt(t, "expired", now.Add(-48*time.Hour), now.Add(-time.Hour))
	future := testSAMLCertificateAt(t, "future", now.Add(time.Hour), now.Add(48*time.Hour))
	encoded, err := json.Marshal([][]byte{expired.Raw, future.Raw})
	if err != nil {
		t.Fatal(err)
	}
	validUntil := now.Add(7 * 24 * time.Hour)
	warnings, err := samlProviderWarnings(authz.SAMLProvider{
		SigningCertificates: encoded, MetadataValidUntil: &validUntil,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	codes := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		codes = append(codes, warning.Code)
	}
	if want := []string{
		"metadata_expires_soon",
		"signing_certificate_expired",
		"signing_certificate_not_yet_valid",
	}; !slices.Equal(codes, want) {
		t.Fatalf("warning codes = %v, want %v", codes, want)
	}
	if warnings[0].Severity != "warning" || !warnings[0].EffectiveAt.Equal(validUntil) || warnings[0].Fingerprint != nil {
		t.Fatalf("metadata warning = %#v", warnings[0])
	}
	if warnings[1].Fingerprint == nil || warnings[2].Fingerprint == nil {
		t.Fatalf("certificate warnings omit fingerprints: %#v", warnings)
	}

	expiredMetadata := now.Add(-time.Minute)
	valid := testSAMLCertificateAt(t, "valid", now.Add(-time.Hour), now.Add(time.Hour))
	validEncoded, err := json.Marshal([][]byte{valid.Raw})
	if err != nil {
		t.Fatal(err)
	}
	warnings, err = samlProviderWarnings(authz.SAMLProvider{SigningCertificates: validEncoded, MetadataValidUntil: &expiredMetadata}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || warnings[0].Code != "metadata_expired" || warnings[0].Severity != "error" {
		t.Fatalf("expired metadata warnings = %#v", warnings)
	}
}

func TestSAMLProviderViewRefusesCorruptStoredTrustState(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	invalidPolicy := "not-json"
	valid := testSAMLCertificateAt(t, "valid", now.Add(-time.Hour), now.Add(time.Hour))
	validEncoded, err := json.Marshal([][]byte{valid.Raw})
	if err != nil {
		t.Fatal(err)
	}

	for name, provider := range map[string]authz.SAMLProvider{
		"certificate set": {SigningCertificates: []byte("not-json")},
		"assurance policy": {
			SigningCertificates: validEncoded,
			AssurancePolicy:     &invalidPolicy,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := samlProviderView(provider, now); err == nil {
				t.Fatal("samlProviderView accepted corrupt stored trust state")
			}
		})
	}
}
