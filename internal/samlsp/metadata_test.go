package samlsp

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func TestParseMetadataSelectsExactEntityAndSigningKeys(t *testing.T) {
	t.Parallel()

	_, signingCertificate := requestSigningFixture(t)
	_, encryptionCertificate := requestSigningFixture(t)
	validUntil := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	raw := []byte(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" validUntil="` + validUntil.Format(time.RFC3339Nano) + `">` +
		`<md:EntityDescriptor entityID="https://other.example"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></md:EntityDescriptor>` +
		`<md:EntityDescriptor entityID="https://idp.example/metadata"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true">` +
		metadataKeyDescriptor("signing", signingCertificate.Raw) +
		metadataKeyDescriptor("encryption", encryptionCertificate.Raw) +
		`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>` +
		`</md:IDPSSODescriptor></md:EntityDescriptor></md:EntitiesDescriptor>`)

	metadata, err := ParseMetadata(raw, "https://idp.example/metadata")
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}
	if metadata.EntityID != "https://idp.example/metadata" || metadata.SSOURL != "https://idp.example/sso" {
		t.Fatalf("metadata identity = (%q, %q)", metadata.EntityID, metadata.SSOURL)
	}
	if !metadata.WantAuthnRequestsSigned {
		t.Fatal("WantAuthnRequestsSigned = false")
	}
	if len(metadata.SigningCertificates) != 1 || !metadata.SigningCertificates[0].Equal(signingCertificate) {
		t.Fatalf("SigningCertificates = %d, want selected signing cert", len(metadata.SigningCertificates))
	}
	if metadata.ValidUntil == nil || !metadata.ValidUntil.Equal(validUntil) {
		t.Fatalf("ValidUntil = %v", metadata.ValidUntil)
	}
}

func TestParseMetadataRejectsAmbiguousEntityAndMissingRedirectEndpoint(t *testing.T) {
	t.Parallel()

	duplicate := []byte(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:EntityDescriptor entityID="x"/><md:EntityDescriptor entityID="x"/></md:EntitiesDescriptor>`)
	if _, err := ParseMetadata(duplicate, "x"); !errors.Is(err, ErrMetadataEntityCardinality) {
		t.Fatalf("duplicate ParseMetadata() error = %v, want ErrMetadataEntityCardinality", err)
	}

	missingRedirect := []byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`)
	if _, err := ParseMetadata(missingRedirect, "x"); !errors.Is(err, ErrMetadataSSOEndpoint) {
		t.Fatalf("POST-only ParseMetadata() error = %v, want ErrMetadataSSOEndpoint", err)
	}
}

func TestParseMetadataVerifiesSignedDescriptorBeforeExtraction(t *testing.T) {
	t.Parallel()

	key, certificate := requestSigningFixture(t)
	xml := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_metadata" entityID="https://idp.example/metadata">` +
		`<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + metadataKeyDescriptor("signing", certificate.Raw) +
		`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>` +
		`</md:IDPSSODescriptor></md:EntityDescriptor>`
	document := etree.NewDocument()
	if err := document.ReadFromString(xml); err != nil {
		t.Fatal(err)
	}
	signing, err := dsig.NewSigningContext(key, [][]byte{certificate.Raw})
	if err != nil {
		t.Fatal(err)
	}
	signing.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := signing.SetSignatureMethod(SignatureRSASHA256); err != nil {
		t.Fatal(err)
	}
	signed, err := signing.SignEnveloped(document.Root())
	if err != nil {
		t.Fatal(err)
	}
	document.SetRoot(signed)
	raw, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}

	metadata, err := ParseMetadata(raw, "https://idp.example/metadata")
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}
	if !metadata.Signed || metadata.SignatureCertificate == nil || !metadata.SignatureCertificate.Equal(certificate) {
		t.Fatalf("signature state = (%v, %v)", metadata.Signed, metadata.SignatureCertificate)
	}

	tampered := []byte(strings.Replace(string(raw), "https://idp.example/sso", "https://attacker.example/sso", 1))
	if _, err := ParseMetadata(tampered, "https://idp.example/metadata"); !errors.Is(err, ErrMetadataSignature) {
		t.Fatalf("tampered ParseMetadata() error = %v, want ErrMetadataSignature", err)
	}
}

func metadataKeyDescriptor(use string, certificate []byte) string {
	return `<md:KeyDescriptor use="` + use + `"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
		strings.TrimSpace(base64.StdEncoding.EncodeToString(certificate)) +
		`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
}
