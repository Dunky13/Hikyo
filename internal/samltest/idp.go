// Package samltest provides a deliberately small SAML IdP fixture for Wenv's
// end-to-end tests. It produces real signed assertions; it is not a protocol
// implementation and must not be used outside tests.
package samltest

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"time"

	"github.com/Dunky13/wenv/internal/samlsp"
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	EntityID = "https://samltest.example/metadata"
	SSOURL   = "https://samltest.example/sso"
)

// IdP owns the signing material used by one test identity provider.
type IdP struct {
	key         *rsa.PrivateKey
	certificate *x509.Certificate
	der         []byte
}

// Response describes the assertion fields a test wants to bind.
type Response struct {
	RequestID    string
	ResponseID   string
	AssertionID  string
	ACSURL       string
	SPEntityID   string
	NameID       string
	NameIDFormat string
	AuthnContext string
	Now          time.Time
	Validity     time.Duration
}

// Request is the binding-relevant part of a Redirect AuthnRequest.
type Request struct {
	ID         string
	ForceAuthn bool
}

// New creates a self-signed IdP certificate valid around now.
func New(now time.Time) (*IdP, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Wenv SAML test IdP"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &IdP{key: key, certificate: certificate, der: der}, nil
}

// Metadata returns unsigned metadata whose signing key is explicitly pinned by
// the provider configuration ceremony exercised by the caller.
func (i *IdP) Metadata(now time.Time) []byte {
	return i.metadata(now, "")
}

func (i *IdP) metadata(now time.Time, id string) []byte {
	certificate := base64.StdEncoding.EncodeToString(i.der)
	validUntil := now.AddDate(0, 6, 0).Format(time.RFC3339Nano)
	idAttribute := ""
	if id != "" {
		idAttribute = ` ID="` + id + `"`
	}
	return []byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"` + idAttribute + ` entityID="` + EntityID + `" validUntil="` + validUntil + `">` +
		`<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + certificate + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
		`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + SSOURL + `"/>` +
		`</md:IDPSSODescriptor></md:EntityDescriptor>`)
}

// SignedMetadata returns metadata self-signed by the fixture IdP. Callers
// still exercise the explicit first-seen fingerprint ceremony.
func (i *IdP) SignedMetadata(now time.Time) ([]byte, error) {
	document := etree.NewDocument()
	if err := document.ReadFromBytes(i.metadata(now, "_metadata")); err != nil {
		return nil, err
	}
	signing, err := dsig.NewSigningContext(i.key, [][]byte{i.der})
	if err != nil {
		return nil, err
	}
	signing.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := signing.SetSignatureMethod(samlsp.SignatureRSASHA256); err != nil {
		return nil, err
	}
	signed, err := signing.SignEnveloped(document.Root())
	if err != nil {
		return nil, err
	}
	document.SetRoot(signed)
	return document.WriteToBytes()
}

// SignedResponse returns a base64-encoded HTTP-POST SAMLResponse containing a
// signed Assertion and an unsigned Response envelope.
func (i *IdP) SignedResponse(config Response) (string, error) {
	if config.RequestID == "" || config.ResponseID == "" || config.AssertionID == "" || config.ACSURL == "" || config.SPEntityID == "" || config.NameID == "" {
		return "", errors.New("samltest: incomplete response configuration")
	}
	if config.Validity <= 0 {
		config.Validity = 5 * time.Minute
	}
	if config.NameIDFormat == "" {
		config.NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	}
	if config.AuthnContext == "" {
		config.AuthnContext = "urn:example:mfa"
	}
	issueInstant := config.Now.Add(-time.Second).Format(time.RFC3339Nano)
	notOnOrAfter := config.Now.Add(config.Validity).Format(time.RFC3339Nano)
	document := etree.NewDocument()
	if err := document.ReadFromString(fmt.Sprintf(
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="%s" InResponseTo="%s" Destination="%s" IssueInstant="%s">`+
			`<saml:Issuer>%s</saml:Issuer>`+
			`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`+
			`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" IssueInstant="%s">`+
			`<saml:Issuer>%s</saml:Issuer>`+
			`<saml:Subject><saml:NameID Format="%s" NameQualifier="%s" SPNameQualifier="%s">%s</saml:NameID>`+
			`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="%s" Recipient="%s" NotOnOrAfter="%s"/></saml:SubjectConfirmation></saml:Subject>`+
			`<saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>`+
			`<saml:AuthnStatement AuthnInstant="%s"><saml:AuthnContext><saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`+
			`</saml:Assertion></samlp:Response>`,
		config.ResponseID, config.RequestID, config.ACSURL, issueInstant, EntityID,
		config.AssertionID, issueInstant, EntityID, config.NameIDFormat, EntityID,
		config.SPEntityID, config.NameID, config.RequestID, config.ACSURL, notOnOrAfter,
		issueInstant, notOnOrAfter, config.SPEntityID, issueInstant, config.AuthnContext,
	)); err != nil {
		return "", err
	}
	var assertion *etree.Element
	for _, child := range document.Root().ChildElements() {
		if child.Tag == "Assertion" {
			assertion = child
			break
		}
	}
	if assertion == nil {
		return "", errors.New("samltest: assertion construction failed")
	}
	signing, err := dsig.NewSigningContext(i.key, [][]byte{i.der})
	if err != nil {
		return "", err
	}
	signing.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := signing.SetSignatureMethod(samlsp.SignatureRSASHA256); err != nil {
		return "", err
	}
	signedAssertion, err := signing.SignEnveloped(assertion)
	if err != nil {
		return "", err
	}
	document.Root().RemoveChild(assertion)
	document.Root().AddChild(signedAssertion)
	raw, err := document.WriteToBytes()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// DecodeRequest reads the ID and ForceAuthn flag from a Redirect-binding URL.
func DecodeRequest(redirectURL string) (Request, error) {
	target, err := url.Parse(redirectURL)
	if err != nil {
		return Request{}, err
	}
	encoded := target.Query().Get("SAMLRequest")
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return Request{}, err
	}
	reader := flate.NewReader(bytes.NewReader(compressed))
	raw, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil {
		return Request{}, err
	}
	if closeErr != nil {
		return Request{}, closeErr
	}
	document := etree.NewDocument()
	if err := document.ReadFromBytes(raw); err != nil {
		return Request{}, err
	}
	root := document.Root()
	if root == nil || root.Tag != "AuthnRequest" {
		return Request{}, errors.New("samltest: redirect did not contain an AuthnRequest")
	}
	request := Request{ID: root.SelectAttrValue("ID", "")}
	request.ForceAuthn = root.SelectAttrValue("ForceAuthn", "") == "true"
	if request.ID == "" {
		return Request{}, errors.New("samltest: AuthnRequest has no ID")
	}
	return request, nil
}

// Certificate returns the fixture's signing certificate.
func (i *IdP) Certificate() *x509.Certificate { return i.certificate }
