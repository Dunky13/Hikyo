package samlsp

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
)

const (
	SAMLMetadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata"
	BindingHTTPRedirect   = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
)

var (
	ErrMetadataRoot               = errors.New("samlsp: root is not SAML metadata")
	ErrMetadataEntityCardinality  = errors.New("samlsp: metadata must contain exactly one matching EntityDescriptor")
	ErrMetadataIDPDescriptor      = errors.New("samlsp: metadata must contain exactly one SAML 2.0 IDPSSODescriptor")
	ErrMetadataSSOEndpoint        = errors.New("samlsp: metadata must contain exactly one HTTP-Redirect SSO endpoint")
	ErrMetadataSigningCertificate = errors.New("samlsp: metadata has no usable assertion-signing certificate")
	ErrMetadataValidUntil         = errors.New("samlsp: invalid metadata validUntil")
	ErrMetadataSignature          = errors.New("samlsp: invalid metadata signature")
)

// Metadata is the provider material extracted from one bounded etree. When a
// metadata signature exists, fields come from the exact descriptor within the
// subtree returned by goxmldsig. SignatureCertificate is the self-verified key
// candidate; the caller must compare or explicitly confirm its fingerprint
// before applying configuration.
type Metadata struct {
	EntityID                string
	SSOURL                  string
	WantAuthnRequestsSigned bool
	SigningCertificates     []*x509.Certificate
	ValidUntil              *time.Time
	Signed                  bool
	SignatureCertificate    *x509.Certificate
}

// ParseMetadata selects one exact IdP entity. Signed metadata is
// cryptographically self-verified and structurally bound to the selected
// descriptor; this does not establish trust in a first-seen signing key.
func ParseMetadata(raw []byte, entityID string) (Metadata, error) {
	if entityID == "" {
		return Metadata{}, ErrMetadataEntityCardinality
	}
	document, err := ParseXML(raw)
	if err != nil {
		return Metadata{}, err
	}
	root := document.tree.Root()
	if !isElement(root, SAMLMetadataNamespace, "EntityDescriptor") && !isElement(root, SAMLMetadataNamespace, "EntitiesDescriptor") {
		return Metadata{}, ErrMetadataRoot
	}

	descriptor, err := selectMetadataEntity(root, entityID)
	if err != nil {
		return Metadata{}, err
	}
	extractionRoot := root
	metadata := Metadata{}
	signatures := descendantsIncludingSelf(root, XMLDSIGNamespace, "Signature")
	if len(signatures) > 1 {
		return Metadata{}, ErrMetadataSignature
	}
	if len(signatures) == 1 {
		signature := signatures[0]
		signedElement := signature.Parent()
		if signedElement == nil || !isAncestorOrSelf(signedElement, descriptor) {
			return Metadata{}, ErrMetadataSignature
		}
		targetID, present := plainAttr(signedElement, "ID")
		if !present || targetID == "" {
			return Metadata{}, ErrMetadataSignature
		}
		if err := validateSignatureProfile(signature, targetID); err != nil {
			return Metadata{}, fmt.Errorf("%w: %v", ErrMetadataSignature, err)
		}
		certificate, err := certificateFromSignature(signature)
		if err != nil {
			return Metadata{}, fmt.Errorf("%w: %v", ErrMetadataSignature, err)
		}
		verified, _, err := verifyPinnedElement(signedElement, []*x509.Certificate{certificate}, certificate.NotBefore)
		if err != nil {
			return Metadata{}, fmt.Errorf("%w: %v", ErrMetadataSignature, err)
		}
		extractionRoot = verified
		descriptor, err = selectMetadataEntity(extractionRoot, entityID)
		if err != nil {
			return Metadata{}, fmt.Errorf("%w: selected descriptor outside verified subtree", ErrMetadataSignature)
		}
		metadata.Signed = true
		metadata.SignatureCertificate = certificate
	}

	metadata.EntityID = entityID
	metadata.ValidUntil, err = effectiveValidUntil(descriptor, extractionRoot)
	if err != nil {
		return Metadata{}, err
	}
	descriptors := directChildren(descriptor, SAMLMetadataNamespace, "IDPSSODescriptor")
	var samlDescriptors []*etree.Element
	for _, candidate := range descriptors {
		protocols, _ := plainAttr(candidate, "protocolSupportEnumeration")
		for _, protocol := range strings.Fields(protocols) {
			if protocol == SAMLProtocolNamespace {
				samlDescriptors = append(samlDescriptors, candidate)
				break
			}
		}
	}
	if len(samlDescriptors) != 1 {
		return Metadata{}, ErrMetadataIDPDescriptor
	}
	idp := samlDescriptors[0]
	if rawSigned, present := plainAttr(idp, "WantAuthnRequestsSigned"); present {
		switch rawSigned {
		case "true", "1":
			metadata.WantAuthnRequestsSigned = true
		case "false", "0":
		default:
			return Metadata{}, ErrMetadataIDPDescriptor
		}
	}

	for _, service := range directChildren(idp, SAMLMetadataNamespace, "SingleSignOnService") {
		binding, _ := plainAttr(service, "Binding")
		if binding != BindingHTTPRedirect {
			continue
		}
		location, _ := plainAttr(service, "Location")
		if location == "" || metadata.SSOURL != "" {
			return Metadata{}, ErrMetadataSSOEndpoint
		}
		metadata.SSOURL = location
	}
	if metadata.SSOURL == "" {
		return Metadata{}, ErrMetadataSSOEndpoint
	}
	metadata.SigningCertificates, err = assertionSigningCertificates(idp)
	if err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func selectMetadataEntity(root *etree.Element, entityID string) (*etree.Element, error) {
	var matches []*etree.Element
	for _, element := range descendantsIncludingSelf(root, SAMLMetadataNamespace, "EntityDescriptor") {
		candidate, present := plainAttr(element, "entityID")
		if present && candidate == entityID {
			matches = append(matches, element)
		}
	}
	if len(matches) != 1 {
		return nil, ErrMetadataEntityCardinality
	}
	return matches[0], nil
}

func descendantsIncludingSelf(root *etree.Element, namespace, local string) []*etree.Element {
	var found []*etree.Element
	if isElement(root, namespace, local) {
		found = append(found, root)
	}
	return append(found, descendants(root, namespace, local)...)
}

func isAncestorOrSelf(ancestor, element *etree.Element) bool {
	for current := element; current != nil; current = current.Parent() {
		if current == ancestor {
			return true
		}
	}
	return false
}

func certificateFromSignature(signature *etree.Element) (*x509.Certificate, error) {
	keyInfos := directChildren(signature, XMLDSIGNamespace, "KeyInfo")
	if len(keyInfos) != 1 {
		return nil, ErrMetadataSignature
	}
	x509Data := directChildren(keyInfos[0], XMLDSIGNamespace, "X509Data")
	if len(x509Data) != 1 {
		return nil, ErrMetadataSignature
	}
	certificates := directChildren(x509Data[0], XMLDSIGNamespace, "X509Certificate")
	if len(certificates) != 1 {
		return nil, ErrMetadataSignature
	}
	return parseMetadataCertificate(certificates[0].Text())
}

func effectiveValidUntil(descriptor, extractionRoot *etree.Element) (*time.Time, error) {
	var earliest *time.Time
	for current := descriptor; current != nil; current = current.Parent() {
		if raw, present := plainAttr(current, "validUntil"); present {
			parsed, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				return nil, ErrMetadataValidUntil
			}
			if earliest == nil || parsed.Before(*earliest) {
				value := parsed
				earliest = &value
			}
		}
		if current == extractionRoot {
			break
		}
	}
	return earliest, nil
}

func assertionSigningCertificates(idp *etree.Element) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	seen := make(map[string]struct{})
	for _, descriptor := range directChildren(idp, SAMLMetadataNamespace, "KeyDescriptor") {
		use, present := plainAttr(descriptor, "use")
		if present && use != "signing" {
			continue
		}
		for _, element := range descendants(descriptor, XMLDSIGNamespace, "X509Certificate") {
			certificate, err := parseMetadataCertificate(element.Text())
			if err != nil {
				return nil, ErrMetadataSigningCertificate
			}
			key := string(certificate.Raw)
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			certificates = append(certificates, certificate)
		}
	}
	if len(certificates) == 0 {
		return nil, ErrMetadataSigningCertificate
	}
	return certificates, nil
}

func parseMetadataCertificate(encoded string) (*x509.Certificate, error) {
	compact := strings.Map(func(character rune) rune {
		if character == ' ' || character == '\n' || character == '\r' || character == '\t' {
			return -1
		}
		return character
	}, encoded)
	der, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}
