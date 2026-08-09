package samlsp

import (
	"errors"
	"fmt"

	"github.com/beevik/etree"
)

const (
	SAMLProtocolNamespace  = "urn:oasis:names:tc:SAML:2.0:protocol"
	SAMLAssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
	XMLDSIGNamespace       = "http://www.w3.org/2000/09/xmldsig#"

	SignatureRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	SignatureRSASHA384   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	SignatureRSASHA512   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	SignatureECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	SignatureECDSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	SignatureECDSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"

	DigestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	DigestSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	DigestSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"

	ExclusiveC14N               = "http://www.w3.org/2001/10/xml-exc-c14n#"
	EnvelopedSignatureTransform = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

var (
	ErrResponseRoot              = errors.New("samlsp: root is not a SAML Response")
	ErrAssertionCardinality      = errors.New("samlsp: Response must contain exactly one Assertion")
	ErrAssertionPosition         = errors.New("samlsp: Assertion must be a direct child of Response")
	ErrEncryptedAssertion        = errors.New("samlsp: encrypted assertions are unsupported")
	ErrSignatureStructure        = errors.New("samlsp: invalid signature structure")
	ErrSignatureReference        = errors.New("samlsp: signature Reference does not cover its exact element")
	ErrSignatureAlgorithm        = errors.New("samlsp: disallowed signature algorithm")
	ErrDigestAlgorithm           = errors.New("samlsp: disallowed digest algorithm")
	ErrCanonicalizationAlgorithm = errors.New("samlsp: disallowed canonicalization algorithm")
	ErrTransformAlgorithm        = errors.New("samlsp: disallowed signature transform")
)

var allowedSignatureMethods = map[string]struct{}{
	SignatureRSASHA256: {}, SignatureRSASHA384: {}, SignatureRSASHA512: {},
	SignatureECDSASHA256: {}, SignatureECDSASHA384: {}, SignatureECDSASHA512: {},
}

var allowedDigestMethods = map[string]struct{}{
	DigestSHA256: {}, DigestSHA384: {}, DigestSHA512: {},
}

// Response is a structurally validated SAML response. It retains the exact
// Assertion node from Document's sole etree parse for signature verification.
type Response struct {
	document  *Document
	root      *etree.Element
	assertion *etree.Element
}

// ParseResponse bounds and parses raw once, then applies the complete
// structural XSW and algorithm-URI policy before cryptographic verification.
func ParseResponse(raw []byte) (*Response, error) {
	document, err := ParseXML(raw)
	if err != nil {
		return nil, err
	}
	root := document.tree.Root()
	if !isElement(root, SAMLProtocolNamespace, "Response") {
		return nil, ErrResponseRoot
	}

	assertions := descendants(root, SAMLAssertionNamespace, "Assertion")
	if len(assertions) != 1 {
		return nil, fmt.Errorf("%w: got %d", ErrAssertionCardinality, len(assertions))
	}
	directAssertions := directChildren(root, SAMLAssertionNamespace, "Assertion")
	if len(directAssertions) != 1 || directAssertions[0] != assertions[0] {
		return nil, ErrAssertionPosition
	}
	if encrypted := descendants(root, SAMLAssertionNamespace, "EncryptedAssertion"); len(encrypted) != 0 {
		return nil, ErrEncryptedAssertion
	}

	assertion := assertions[0]
	assertionID, present := plainAttr(assertion, "ID")
	if !present || assertionID == "" {
		return nil, ErrEmptyID
	}
	assertionSignatures := directChildren(assertion, XMLDSIGNamespace, "Signature")
	if len(assertionSignatures) != 1 {
		return nil, ErrSignatureStructure
	}
	responseSignatures := directChildren(root, XMLDSIGNamespace, "Signature")
	if len(responseSignatures) > 1 {
		return nil, ErrSignatureStructure
	}
	allSignatures := descendants(root, XMLDSIGNamespace, "Signature")
	if len(allSignatures) != 1+len(responseSignatures) {
		return nil, ErrSignatureStructure
	}
	if err := validateSignatureProfile(assertionSignatures[0], assertionID); err != nil {
		return nil, err
	}
	if len(responseSignatures) == 1 {
		responseID, present := plainAttr(root, "ID")
		if !present || responseID == "" {
			return nil, ErrEmptyID
		}
		if err := validateSignatureProfile(responseSignatures[0], responseID); err != nil {
			return nil, err
		}
	}

	return &Response{document: document, root: root, assertion: assertion}, nil
}

func (r *Response) AssertionID() string {
	id, _ := plainAttr(r.assertion, "ID")
	return id
}

func validateSignatureProfile(signature *etree.Element, targetID string) error {
	signedInfos := directChildren(signature, XMLDSIGNamespace, "SignedInfo")
	if len(signedInfos) != 1 {
		return ErrSignatureStructure
	}
	signedInfo := signedInfos[0]

	canonicalization := directChildren(signedInfo, XMLDSIGNamespace, "CanonicalizationMethod")
	if len(canonicalization) != 1 {
		return ErrSignatureStructure
	}
	if algorithm, _ := plainAttr(canonicalization[0], "Algorithm"); algorithm != ExclusiveC14N {
		return fmt.Errorf("%w: %q", ErrCanonicalizationAlgorithm, algorithm)
	}

	signatureMethods := directChildren(signedInfo, XMLDSIGNamespace, "SignatureMethod")
	if len(signatureMethods) != 1 {
		return ErrSignatureStructure
	}
	signatureAlgorithm, _ := plainAttr(signatureMethods[0], "Algorithm")
	if _, allowed := allowedSignatureMethods[signatureAlgorithm]; !allowed {
		return fmt.Errorf("%w: %q", ErrSignatureAlgorithm, signatureAlgorithm)
	}

	references := descendants(signature, XMLDSIGNamespace, "Reference")
	directReferences := directChildren(signedInfo, XMLDSIGNamespace, "Reference")
	if len(references) != 1 || len(directReferences) != 1 || references[0] != directReferences[0] {
		return ErrSignatureReference
	}
	reference := references[0]
	uri, present := plainAttr(reference, "URI")
	if !present || uri != "#"+targetID {
		return fmt.Errorf("%w: %q", ErrSignatureReference, uri)
	}

	transformsContainers := directChildren(reference, XMLDSIGNamespace, "Transforms")
	if len(transformsContainers) != 1 {
		return ErrSignatureStructure
	}
	transforms := directChildren(transformsContainers[0], XMLDSIGNamespace, "Transform")
	if len(transforms) != 2 {
		return ErrTransformAlgorithm
	}
	wantTransforms := [...]string{EnvelopedSignatureTransform, ExclusiveC14N}
	for i, transform := range transforms {
		algorithm, _ := plainAttr(transform, "Algorithm")
		if algorithm != wantTransforms[i] {
			return fmt.Errorf("%w: %q", ErrTransformAlgorithm, algorithm)
		}
	}

	digestMethods := directChildren(reference, XMLDSIGNamespace, "DigestMethod")
	if len(digestMethods) != 1 {
		return ErrSignatureStructure
	}
	digestAlgorithm, _ := plainAttr(digestMethods[0], "Algorithm")
	if _, allowed := allowedDigestMethods[digestAlgorithm]; !allowed {
		return fmt.Errorf("%w: %q", ErrDigestAlgorithm, digestAlgorithm)
	}
	return nil
}

func isElement(element *etree.Element, namespace, local string) bool {
	return element != nil && element.Tag == local && element.NamespaceURI() == namespace
}

func directChildren(parent *etree.Element, namespace, local string) []*etree.Element {
	var found []*etree.Element
	for _, child := range parent.ChildElements() {
		if isElement(child, namespace, local) {
			found = append(found, child)
		}
	}
	return found
}

func descendants(parent *etree.Element, namespace, local string) []*etree.Element {
	var found []*etree.Element
	var visit func(*etree.Element)
	visit = func(current *etree.Element) {
		for _, child := range current.ChildElements() {
			if isElement(child, namespace, local) {
				found = append(found, child)
			}
			visit(child)
		}
	}
	visit(parent)
	return found
}

func plainAttr(element *etree.Element, name string) (string, bool) {
	for _, attr := range element.Attr {
		if attr.Space == "" && attr.Key == name {
			return attr.Value, true
		}
	}
	return "", false
}
