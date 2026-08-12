package samlsp

import (
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

func TestBuildAuthnRequestBuildsSignedRedirectOverExactWireValues(t *testing.T) {
	t.Parallel()

	key, certificate := requestSigningFixture(t)
	result, err := BuildAuthnRequest(AuthnRequestConfig{
		IDPSSOURL:   "https://idp.example/sso?tenant=example",
		SPEntityID:  "https://hikyo.example/saml/metadata",
		ACSURL:      "https://hikyo.example/api/v1/auth/saml/provider/acs",
		RelayState:  "opaque state/+",
		ForceAuthn:  true,
		Sign:        true,
		Signer:      key,
		Certificate: certificate.Raw,
		Now:         time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("BuildAuthnRequest() error = %v", err)
	}
	parsed, err := url.Parse(result.URL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("tenant") != "example" {
		t.Fatalf("tenant query = %q", parsed.Query().Get("tenant"))
	}
	if parsed.Query().Get("RelayState") != "opaque state/+" {
		t.Fatalf("RelayState = %q", parsed.Query().Get("RelayState"))
	}
	if parsed.Query().Get("SigAlg") != SignatureRSASHA256 {
		t.Fatalf("SigAlg = %q", parsed.Query().Get("SigAlg"))
	}

	rawValues := rawQueryValues(t, parsed.RawQuery)
	signedOctets := "SAMLRequest=" + rawValues["SAMLRequest"] + "&RelayState=" + rawValues["RelayState"] + "&SigAlg=" + rawValues["SigAlg"]
	digest := sha256.Sum256([]byte(signedOctets))
	signature, err := base64.StdEncoding.DecodeString(parsed.Query().Get("Signature"))
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("redirect signature does not cover exact encoded wire values: %v", err)
	}

	compressed, err := base64.StdEncoding.DecodeString(parsed.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	reader := flate.NewReader(strings.NewReader(string(compressed)))
	xml, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	document := etree.NewDocument()
	if err := document.ReadFromBytes(xml); err != nil {
		t.Fatal(err)
	}
	root := document.Root()
	if result.RequestID == "" || root.SelectAttrValue("ID", "") != result.RequestID {
		t.Fatalf("request IDs = (%q, %q)", result.RequestID, root.SelectAttrValue("ID", ""))
	}
	if root.SelectAttrValue("ForceAuthn", "") != "true" {
		t.Fatalf("ForceAuthn = %q", root.SelectAttrValue("ForceAuthn", ""))
	}
	if len(directChildren(root, XMLDSIGNamespace, "Signature")) != 0 {
		t.Fatal("Redirect AuthnRequest contains an enveloped XML signature")
	}
}

func TestBuildAuthnRequestBuildsUnsignedLoginRequest(t *testing.T) {
	t.Parallel()

	result, err := BuildAuthnRequest(AuthnRequestConfig{
		IDPSSOURL:  "https://idp.example/sso",
		SPEntityID: "https://hikyo.example/saml/metadata",
		ACSURL:     "https://hikyo.example/api/v1/auth/saml/provider/acs",
		RelayState: "opaque",
		Now:        time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("BuildAuthnRequest() error = %v", err)
	}
	parsed, err := url.Parse(result.URL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Has("Signature") || parsed.Query().Has("SigAlg") {
		t.Fatalf("unsigned query = %q", parsed.RawQuery)
	}
}

func rawQueryValues(t *testing.T, rawQuery string) map[string]string {
	t.Helper()
	values := make(map[string]string)
	for _, pair := range strings.Split(rawQuery, "&") {
		key, value, found := strings.Cut(pair, "=")
		if found {
			values[key] = value
		}
	}
	return values
}

func requestSigningFixture(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "fixture SP"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
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
	return key, certificate
}
