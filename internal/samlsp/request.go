package samlsp

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

var (
	ErrInvalidAuthnRequestConfig = errors.New("samlsp: invalid AuthnRequest configuration")
	ErrAuthnRequestSigningKey    = errors.New("samlsp: AuthnRequest signing requires a matching RSA key and certificate")
)

type AuthnRequestConfig struct {
	IDPSSOURL   string
	SPEntityID  string
	ACSURL      string
	RelayState  string
	ForceAuthn  bool
	Sign        bool
	Signer      crypto.Signer
	Certificate []byte
	Now         time.Time
}

type AuthnRequest struct {
	URL       string
	RequestID string
}

// BuildAuthnRequest builds the profile's HTTP-Redirect AuthnRequest. gosaml2
// owns XML construction, DEFLATE encoding, and Redirect-binding signing. The
// request document is deliberately built without an enveloped XML signature;
// when requested, gosaml2 signs the exact encoded query values sent on wire.
func BuildAuthnRequest(config AuthnRequestConfig) (AuthnRequest, error) {
	if err := validateAuthnRequestConfig(config); err != nil {
		return AuthnRequest{}, err
	}

	provider := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:         config.IDPSSOURL,
		AssertionConsumerServiceURL:    config.ACSURL,
		ServiceProviderIssuer:          config.SPEntityID,
		SignAuthnRequests:              config.Sign,
		SignAuthnRequestsAlgorithm:     SignatureRSASHA256,
		SignAuthnRequestsCanonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
		ForceAuthn:                     config.ForceAuthn,
		Clock:                          dsig.NewFakeClockAt(config.Now),
	}
	if config.Sign {
		if err := provider.SetSPSigningKeyStore(&saml2.KeyStore{Signer: config.Signer, Cert: config.Certificate}); err != nil {
			return AuthnRequest{}, fmt.Errorf("%w: %v", ErrAuthnRequestSigningKey, err)
		}
	}

	document, err := provider.BuildAuthRequestDocumentNoSig()
	if err != nil {
		return AuthnRequest{}, fmt.Errorf("samlsp: build AuthnRequest: %w", err)
	}
	requestID := document.Root().SelectAttrValue("ID", "")
	if requestID == "" {
		return AuthnRequest{}, fmt.Errorf("%w: generated request has no ID", ErrInvalidAuthnRequestConfig)
	}
	redirectURL, err := provider.BuildAuthURLRedirect(config.RelayState, document)
	if err != nil {
		return AuthnRequest{}, fmt.Errorf("samlsp: build AuthnRequest redirect: %w", err)
	}
	return AuthnRequest{URL: redirectURL, RequestID: requestID}, nil
}

func validateAuthnRequestConfig(config AuthnRequestConfig) error {
	if config.IDPSSOURL == "" || config.SPEntityID == "" || config.ACSURL == "" || config.RelayState == "" || config.Now.IsZero() {
		return ErrInvalidAuthnRequestConfig
	}
	for _, rawURL := range []string{config.IDPSSOURL, config.SPEntityID, config.ACSURL} {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return ErrInvalidAuthnRequestConfig
		}
	}
	if !config.Sign {
		return nil
	}
	if config.Signer == nil || len(config.Certificate) == 0 {
		return ErrAuthnRequestSigningKey
	}
	if _, ok := config.Signer.Public().(*rsa.PublicKey); !ok {
		return ErrAuthnRequestSigningKey
	}
	certificate, err := x509.ParseCertificate(config.Certificate)
	if err != nil {
		return ErrAuthnRequestSigningKey
	}
	certificateKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return ErrAuthnRequestSigningKey
	}
	signerKey, err := x509.MarshalPKIXPublicKey(config.Signer.Public())
	if err != nil || !bytes.Equal(certificateKey, signerKey) {
		return ErrAuthnRequestSigningKey
	}
	return nil
}
