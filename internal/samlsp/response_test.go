package samlsp

import (
	"errors"
	"strings"
	"testing"
)

const validResponse = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_response">
<saml:Assertion ID="_assertion">
<ds:Signature><ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="#_assertion"><ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AA==</ds:DigestValue></ds:Reference>
</ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>
</saml:Assertion></samlp:Response>`

func TestParseResponseAcceptsStrictStructure(t *testing.T) {
	t.Parallel()

	response, err := ParseResponse([]byte(validResponse))
	if err != nil {
		t.Fatalf("ParseResponse() error = %v", err)
	}
	if response.AssertionID() != "_assertion" {
		t.Fatalf("AssertionID() = %q, want _assertion", response.AssertionID())
	}
}

func TestParseResponseRefusesStructuralWrappingShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
		want error
	}{
		{name: "duplicate ID", xml: strings.Replace(validResponse, `ID="_response"`, `ID="_assertion"`, 1), want: ErrDuplicateID},
		{name: "empty ID", xml: strings.Replace(validResponse, `ID="_assertion"`, `ID=""`, 1), want: ErrEmptyID},
		{name: "nested assertion", xml: strings.Replace(strings.Replace(validResponse, `<saml:Assertion`, `<samlp:Extensions><saml:Assertion`, 1), `</saml:Assertion>`, `</saml:Assertion></samlp:Extensions>`, 1), want: ErrAssertionPosition},
		{name: "two assertions", xml: strings.Replace(validResponse, `</samlp:Response>`, `<saml:Assertion ID="_other"/></samlp:Response>`, 1), want: ErrAssertionCardinality},
		{name: "encrypted assertion", xml: strings.Replace(validResponse, `</samlp:Response>`, `<saml:EncryptedAssertion/></samlp:Response>`, 1), want: ErrEncryptedAssertion},
		{name: "no reference", xml: strings.Replace(validResponse, `<ds:Reference URI="#_assertion">`, `<ds:Reference URI="#_assertion"><ds:Reference URI="#_other"/>`, 1), want: ErrSignatureReference},
		{name: "empty reference", xml: strings.Replace(validResponse, `URI="#_assertion"`, `URI=""`, 1), want: ErrSignatureReference},
		{name: "external reference", xml: strings.Replace(validResponse, `URI="#_assertion"`, `URI="https://idp.example/assertion"`, 1), want: ErrSignatureReference},
		{name: "other node reference", xml: strings.Replace(validResponse, `URI="#_assertion"`, `URI="#_response"`, 1), want: ErrSignatureReference},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseResponse([]byte(tt.xml))
			if !errors.Is(err, tt.want) {
				t.Fatalf("ParseResponse() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParseResponseRefusesAlgorithmsOutsideClosedAllowlist(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
		want error
	}{
		{name: "RSA SHA-1", xml: strings.Replace(validResponse, SignatureRSASHA256, `http://www.w3.org/2000/09/xmldsig#rsa-sha1`, 1), want: ErrSignatureAlgorithm},
		{name: "SHA-1 digest", xml: strings.Replace(validResponse, DigestSHA256, `http://www.w3.org/2000/09/xmldsig#sha1`, 1), want: ErrDigestAlgorithm},
		{name: "inclusive canonicalization", xml: strings.Replace(validResponse, ExclusiveC14N, `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`, 1), want: ErrCanonicalizationAlgorithm},
		{name: "with-comments transform", xml: strings.Replace(validResponse, `<ds:Transform Algorithm="`+ExclusiveC14N+`"/>`, `<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>`, 1), want: ErrTransformAlgorithm},
		{name: "XPath transform", xml: strings.Replace(validResponse, EnvelopedSignatureTransform, `http://www.w3.org/TR/1999/REC-xpath-19991116`, 1), want: ErrTransformAlgorithm},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseResponse([]byte(tt.xml))
			if !errors.Is(err, tt.want) {
				t.Fatalf("ParseResponse() error = %v, want %v", err, tt.want)
			}
		})
	}
}
