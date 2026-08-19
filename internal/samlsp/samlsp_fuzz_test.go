package samlsp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

// FuzzParseXML checks the SAML document byte, depth, and token bounds on arbitrary XML.
func FuzzParseXML(f *testing.F) {
	f.Add([]byte(`<root/>`))
	f.Add([]byte(`<root>`))
	f.Add([]byte{0xff, 0, '<', 'x', '>'})

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseXML(raw)
	})
}

// FuzzParseResponse checks the SAML response parser returns normally within the shared XML bounds.
func FuzzParseResponse(f *testing.F) {
	f.Add([]byte(validResponse))
	f.Add([]byte(validResponse[:len(validResponse)/2]))
	f.Add([]byte("not XML"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseResponse(raw)
	})
}

// FuzzParseMetadata checks the SAML metadata parser returns normally within the shared XML bounds.
func FuzzParseMetadata(f *testing.F) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fuzz IdP"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<31, 0), KeyUsage: x509.KeyUsageDigitalSignature,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		f.Fatal(err)
	}
	valid := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://sp.example/metadata"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + base64.StdEncoding.EncodeToString(certificate) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`
	if _, err := ParseMetadata([]byte(valid), "https://sp.example/metadata"); err != nil {
		f.Fatalf("valid metadata seed: %v", err)
	}
	f.Add([]byte(valid))
	f.Add([]byte(valid[:len(valid)/2]))
	f.Add([]byte("arbitrary"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseMetadata(raw, "https://sp.example/metadata")
	})
}
