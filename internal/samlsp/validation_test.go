package samlsp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func TestValidateResponseVerifiesExpiredPinnedCertificateAndExtractsClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	raw, certificate := signedResponseFixture(t, now, false)
	claims, err := ValidateResponse(raw, []*x509.Certificate{certificate}, ValidationExpectations{
		ProviderEntityID: "https://idp.example/metadata",
		SPEntityID:       "https://wenv.example/saml/metadata",
		ACSURL:           "https://wenv.example/api/v1/auth/saml/provider/acs",
		RequestID:        "_request",
		Now:              now,
	})
	if err != nil {
		t.Fatalf("ValidateResponse() error = %v", err)
	}
	if !claims.ExpiredPinnedCertificate {
		t.Fatal("ExpiredPinnedCertificate = false, want true")
	}
	if claims.ResponseID != "_response" || claims.AssertionID != "_assertion" {
		t.Fatalf("IDs = (%q, %q)", claims.ResponseID, claims.AssertionID)
	}
	if claims.ResponseIssuer != "https://idp.example/metadata" || claims.AssertionIssuer != claims.ResponseIssuer {
		t.Fatalf("issuers = (%q, %q)", claims.ResponseIssuer, claims.AssertionIssuer)
	}
	if claims.InResponseTo != "_request" || claims.SubjectConfirmation.InResponseTo != "_request" {
		t.Fatalf("InResponseTo = (%q, %q)", claims.InResponseTo, claims.SubjectConfirmation.InResponseTo)
	}
	if got := string(claims.NameID.Value); got != "Alice" {
		t.Fatalf("NameID.Value = %q", got)
	}
	if claims.NameID.Format == nil || *claims.NameID.Format != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" {
		t.Fatalf("NameID.Format = %v", claims.NameID.Format)
	}
	if claims.NameID.NameQualifier == nil || *claims.NameID.NameQualifier != "https://idp.example/metadata" {
		t.Fatalf("NameID.NameQualifier = %v", claims.NameID.NameQualifier)
	}
	if claims.NameID.SPNameQualifier == nil || *claims.NameID.SPNameQualifier != "https://wenv.example/saml/metadata" {
		t.Fatalf("NameID.SPNameQualifier = %v", claims.NameID.SPNameQualifier)
	}
	if claims.Authn.ContextClassRef == nil || *claims.Authn.ContextClassRef != "urn:example:mfa" {
		t.Fatalf("Authn.ContextClassRef = %v", claims.Authn.ContextClassRef)
	}
}

func TestValidateResponseRejectsTamperingAndInvalidPolicyFields(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	raw, certificate := signedResponseFixture(t, now, false)
	expected := ValidationExpectations{
		ProviderEntityID: "https://idp.example/metadata",
		SPEntityID:       "https://wenv.example/saml/metadata",
		ACSURL:           "https://wenv.example/api/v1/auth/saml/provider/acs",
		RequestID:        "_request",
		Now:              now,
	}

	tampered := []byte(strings.Replace(string(raw), ">Alice<", ">Mallory<", 1))
	if _, err := ValidateResponse(tampered, []*x509.Certificate{certificate}, expected); !errors.Is(err, ErrAssertionSignature) {
		t.Fatalf("tampered ValidateResponse() error = %v, want ErrAssertionSignature", err)
	}

	wrongAudience := expected
	wrongAudience.SPEntityID = "https://other.example/saml/metadata"
	if _, err := ValidateResponse(raw, []*x509.Certificate{certificate}, wrongAudience); !errors.Is(err, ErrAudience) {
		t.Fatalf("audience ValidateResponse() error = %v, want ErrAudience", err)
	}
}

func TestValidateResponseRequiresSuccessfulProtocolStatus(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	raw, certificate := signedResponseFixtureWithTransform(t, now, func(xml string) string {
		return strings.Replace(xml,
			`urn:oasis:names:tc:SAML:2.0:status:Success`,
			`urn:oasis:names:tc:SAML:2.0:status:Responder`, 1)
	})
	_, err := ValidateResponse(raw, []*x509.Certificate{certificate}, ValidationExpectations{
		ProviderEntityID: "https://idp.example/metadata",
		SPEntityID:       "https://wenv.example/saml/metadata",
		ACSURL:           "https://wenv.example/api/v1/auth/saml/provider/acs",
		RequestID:        "_request",
		Now:              now,
	})
	if !errors.Is(err, ErrResponseStatus) {
		t.Fatalf("ValidateResponse() error = %v, want ErrResponseStatus", err)
	}
}

func TestValidateResponseRequiresExactlyOneAuthnStatementAndAtMostOneContext(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		transform func(string) string
		want      error
	}{
		{name: "zero statements", transform: func(xml string) string {
			start := strings.Index(xml, "<saml:AuthnStatement")
			end := strings.Index(xml, "</saml:AuthnStatement>") + len("</saml:AuthnStatement>")
			return xml[:start] + xml[end:]
		}, want: ErrAuthnStatementCardinality},
		{name: "two contexts", transform: func(xml string) string {
			return strings.Replace(xml, "</saml:AuthnContext>", "<saml:AuthnContextClassRef>urn:example:other</saml:AuthnContextClassRef></saml:AuthnContext>", 1)
		}, want: ErrAuthnContextCardinality},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			raw, certificate := signedResponseFixtureWithTransform(t, now, tt.transform)
			_, err := ValidateResponse(raw, []*x509.Certificate{certificate}, ValidationExpectations{
				ProviderEntityID: "https://idp.example/metadata",
				SPEntityID:       "https://wenv.example/saml/metadata",
				ACSURL:           "https://wenv.example/api/v1/auth/saml/provider/acs",
				RequestID:        "_request",
				Now:              now,
			})
			if !errors.Is(err, tt.want) {
				t.Fatalf("ValidateResponse() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestValidateResponseRejectsUnsupportedSignedCondition(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	raw, certificate := signedResponseFixtureWithTransform(t, now, func(xml string) string {
		return strings.Replace(xml, `</saml:Conditions>`, `<saml:OneTimeUse/></saml:Conditions>`, 1)
	})
	_, err := ValidateResponse(raw, []*x509.Certificate{certificate}, ValidationExpectations{
		ProviderEntityID: "https://idp.example/metadata",
		SPEntityID:       "https://wenv.example/saml/metadata",
		ACSURL:           "https://wenv.example/api/v1/auth/saml/provider/acs",
		RequestID:        "_request",
		Now:              now,
	})
	if !errors.Is(err, ErrConditions) {
		t.Fatalf("ValidateResponse() error = %v, want ErrConditions", err)
	}
}

func signedResponseFixture(t *testing.T, now time.Time, signResponse bool) ([]byte, *x509.Certificate) {
	t.Helper()
	return signedResponseFixtureWithTransform(t, now, func(xml string) string { return xml })
}

func signedResponseFixtureWithTransform(t *testing.T, now time.Time, transform func(string) string) ([]byte, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fixture IdP"},
		NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	issueInstant := now.Add(-time.Minute).Format(time.RFC3339Nano)
	notBefore := now.Add(-time.Minute).Format(time.RFC3339Nano)
	notOnOrAfter := now.Add(4 * time.Minute).Format(time.RFC3339Nano)
	xml := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_response" InResponseTo="_request" Destination="https://wenv.example/api/v1/auth/saml/provider/acs" IssueInstant="` + issueInstant + `">` +
		`<saml:Issuer>https://idp.example/metadata</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion" IssueInstant="` + issueInstant + `">` +
		`<saml:Issuer>https://idp.example/metadata</saml:Issuer>` +
		`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" NameQualifier="https://idp.example/metadata" SPNameQualifier="https://wenv.example/saml/metadata">Alice</saml:NameID>` +
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="_request" Recipient="https://wenv.example/api/v1/auth/saml/provider/acs" NotOnOrAfter="` + notOnOrAfter + `"/></saml:SubjectConfirmation></saml:Subject>` +
		`<saml:Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notOnOrAfter + `"><saml:AudienceRestriction><saml:Audience>https://wenv.example/saml/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
		`<saml:AuthnStatement AuthnInstant="` + issueInstant + `"><saml:AuthnContext><saml:AuthnContextClassRef>urn:example:mfa</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
		`</saml:Assertion></samlp:Response>`
	xml = transform(xml)

	document := etree.NewDocument()
	if err := document.ReadFromString(xml); err != nil {
		t.Fatal(err)
	}
	assertion := directChildren(document.Root(), SAMLAssertionNamespace, "Assertion")[0]
	signing, err := dsig.NewSigningContext(key, [][]byte{der})
	if err != nil {
		t.Fatal(err)
	}
	signing.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := signing.SetSignatureMethod(SignatureRSASHA256); err != nil {
		t.Fatal(err)
	}
	signedAssertion, err := signing.SignEnveloped(assertion)
	if err != nil {
		t.Fatal(err)
	}
	document.Root().RemoveChild(assertion)
	document.Root().AddChild(signedAssertion)
	raw, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return raw, certificate
}
