package samlsp

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	DefaultClockSkew   = time.Minute
	DefaultMaxIssueAge = 5 * time.Minute

	SubjectConfirmationBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

var (
	ErrInvalidExpectations              = errors.New("samlsp: invalid validation expectations")
	ErrNoPinnedCertificate              = errors.New("samlsp: no pinned signing certificate")
	ErrAssertionSignature               = errors.New("samlsp: assertion signature verification failed")
	ErrResponseSignature                = errors.New("samlsp: response signature verification failed")
	ErrResponseStatus                   = errors.New("samlsp: Response status is not success")
	ErrResponseIssuer                   = errors.New("samlsp: invalid Response Issuer")
	ErrAssertionIssuer                  = errors.New("samlsp: invalid Assertion Issuer")
	ErrInResponseTo                     = errors.New("samlsp: invalid InResponseTo")
	ErrDestination                      = errors.New("samlsp: invalid Destination")
	ErrAudience                         = errors.New("samlsp: invalid AudienceRestriction")
	ErrAudienceMissing                  = errors.New("samlsp: AudienceRestriction is missing")
	ErrAudienceMismatch                 = errors.New("samlsp: AudienceRestriction does not contain the SP entityID")
	ErrNameIDCardinality                = errors.New("samlsp: Assertion must contain exactly one NameID")
	ErrSubjectConfirmation              = errors.New("samlsp: invalid bearer SubjectConfirmation")
	ErrSubjectConfirmationMissing       = errors.New("samlsp: bearer SubjectConfirmation is missing or duplicated")
	ErrSubjectConfirmationMethod        = errors.New("samlsp: unsupported SubjectConfirmation method")
	ErrSubjectConfirmationRecipient     = errors.New("samlsp: SubjectConfirmationData Recipient mismatch")
	ErrSubjectConfirmationInResponseTo  = errors.New("samlsp: SubjectConfirmationData InResponseTo mismatch")
	ErrSubjectConfirmationExpiryMissing = errors.New("samlsp: SubjectConfirmationData NotOnOrAfter is missing")
	ErrSubjectConfirmationExpired       = errors.New("samlsp: SubjectConfirmationData has expired")
	ErrConditions                       = errors.New("samlsp: invalid Conditions")
	ErrConditionsMissing                = errors.New("samlsp: Conditions is missing or duplicated")
	ErrConditionsNotBefore              = errors.New("samlsp: Conditions NotBefore is invalid or too early")
	ErrConditionsExpiryMissing          = errors.New("samlsp: Conditions NotOnOrAfter is missing")
	ErrConditionsExpired                = errors.New("samlsp: Conditions has expired")
	ErrIssueInstant                     = errors.New("samlsp: invalid IssueInstant")
	ErrResponseIssueInstant             = errors.New("samlsp: invalid Response IssueInstant")
	ErrAssertionIssueInstant            = errors.New("samlsp: invalid Assertion IssueInstant")
	ErrAuthnStatementCardinality        = errors.New("samlsp: Assertion must contain exactly one AuthnStatement")
	ErrAuthnContextCardinality          = errors.New("samlsp: AuthnStatement must contain at most one AuthnContextClassRef")
	ErrInvalidAuthnInstant              = errors.New("samlsp: invalid AuthnInstant")
)

// ValidationExpectations binds a signed assertion to the provider, SP, ACS,
// and server-side request selected before parsing the response. Now is always
// supplied by the caller so SAML freshness never shares goxmldsig's synthetic
// certificate-validity clock.
type ValidationExpectations struct {
	ProviderEntityID string
	SPEntityID       string
	ACSURL           string
	RequestID        string
	Now              time.Time
	ClockSkew        time.Duration
	MaxIssueAge      time.Duration
}

type SubjectConfirmationClaims struct {
	Method       string
	Recipient    string
	InResponseTo string
	NotOnOrAfter time.Time
}

type ConditionsClaims struct {
	NotBefore    *time.Time
	NotOnOrAfter time.Time
}

type AuthnClaims struct {
	Instant         time.Time
	ContextClassRef *string
}

// Claims contains only fields extracted from the exact assertion node returned
// by goxmldsig, plus envelope fields from the sole bounded etree document (or
// the verified Response node when an optional envelope signature is present).
type Claims struct {
	ResponseID               string
	AssertionID              string
	ResponseIssuer           string
	AssertionIssuer          string
	InResponseTo             string
	Destination              string
	ResponseIssueInstant     time.Time
	AssertionIssueInstant    time.Time
	NameID                   NameID
	Audiences                []string
	SubjectConfirmation      SubjectConfirmationClaims
	Conditions               ConditionsClaims
	Authn                    AuthnClaims
	ExpiredPinnedCertificate bool
}

// ValidateResponse performs the ADR's structural checks, verifies the exact
// Assertion and optional Response nodes against raw pinned certificates, then
// extracts and validates policy fields from those same nodes.
func ValidateResponse(raw []byte, certificates []*x509.Certificate, expected ValidationExpectations) (Claims, error) {
	if err := normalizeExpectations(&expected); err != nil {
		return Claims{}, err
	}
	response, err := ParseResponse(raw)
	if err != nil {
		return Claims{}, err
	}

	verifiedAssertion, assertionCertExpired, err := verifyPinnedElement(response.assertion, certificates, expected.Now)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrAssertionSignature, err)
	}

	responseElement := response.root
	responseCertExpired := false
	if len(directChildren(response.root, XMLDSIGNamespace, "Signature")) == 1 {
		responseElement, responseCertExpired, err = verifyPinnedElement(response.root, certificates, expected.Now)
		if err != nil {
			return Claims{}, fmt.Errorf("%w: %w", ErrResponseSignature, err)
		}
	}

	claims, err := extractAndValidateClaims(responseElement, verifiedAssertion, expected)
	if err != nil {
		return Claims{}, err
	}
	claims.ExpiredPinnedCertificate = assertionCertExpired || responseCertExpired
	return claims, nil
}

func normalizeExpectations(expected *ValidationExpectations) error {
	if expected.ProviderEntityID == "" || expected.SPEntityID == "" || expected.ACSURL == "" || expected.RequestID == "" || expected.Now.IsZero() {
		return ErrInvalidExpectations
	}
	if expected.ClockSkew == 0 {
		expected.ClockSkew = DefaultClockSkew
	}
	if expected.MaxIssueAge == 0 {
		expected.MaxIssueAge = DefaultMaxIssueAge
	}
	if expected.ClockSkew < 0 || expected.MaxIssueAge < 0 {
		return ErrInvalidExpectations
	}
	return nil
}

func verifyPinnedElement(element *etree.Element, certificates []*x509.Certificate, realNow time.Time) (*etree.Element, bool, error) {
	if len(certificates) == 0 {
		return nil, false, ErrNoPinnedCertificate
	}
	var lastErr error
	for _, certificate := range certificates {
		if certificate == nil || certificate.NotAfter.Before(certificate.NotBefore) {
			continue
		}
		store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{certificate}}
		context := dsig.NewDefaultValidationContext(store)
		context.IdAttribute = "ID"
		// goxmldsig couples key pinning to X.509 wall-clock validity. SAML pins
		// raw public keys, so run only its crypto at a time inside this cert's
		// validity interval. SAML timestamps remain checked against realNow.
		cryptoTime := certificate.NotBefore.Add(certificate.NotAfter.Sub(certificate.NotBefore) / 2)
		context.Clock = dsig.NewFakeClockAt(cryptoTime)
		verified, err := context.Validate(element)
		if err != nil {
			lastErr = err
			continue
		}
		expired := realNow.Before(certificate.NotBefore) || realNow.After(certificate.NotAfter)
		return verified, expired, nil
	}
	if lastErr == nil {
		lastErr = ErrNoPinnedCertificate
	}
	return nil, false, lastErr
}

func extractAndValidateClaims(response, assertion *etree.Element, expected ValidationExpectations) (Claims, error) {
	claims := Claims{}
	claims.ResponseID, _ = plainAttr(response, "ID")
	claims.AssertionID, _ = plainAttr(assertion, "ID")
	if err := validateResponseStatus(response); err != nil {
		return Claims{}, err
	}

	var err error
	claims.ResponseIssuer, err = requiredSingleText(response, SAMLAssertionNamespace, "Issuer", ErrResponseIssuer)
	if err != nil || claims.ResponseIssuer != expected.ProviderEntityID {
		return Claims{}, ErrResponseIssuer
	}
	claims.AssertionIssuer, err = requiredSingleText(assertion, SAMLAssertionNamespace, "Issuer", ErrAssertionIssuer)
	if err != nil || claims.AssertionIssuer != expected.ProviderEntityID {
		return Claims{}, ErrAssertionIssuer
	}

	claims.InResponseTo, _ = plainAttr(response, "InResponseTo")
	if claims.InResponseTo != expected.RequestID {
		return Claims{}, ErrInResponseTo
	}
	claims.Destination, _ = plainAttr(response, "Destination")
	if claims.Destination != expected.ACSURL {
		return Claims{}, ErrDestination
	}

	claims.ResponseIssueInstant, err = requiredTimeAttr(response, "IssueInstant", ErrResponseIssueInstant)
	if err != nil || !freshIssueInstant(claims.ResponseIssueInstant, expected) {
		return Claims{}, fmt.Errorf("%w: %w", ErrIssueInstant, ErrResponseIssueInstant)
	}
	claims.AssertionIssueInstant, err = requiredTimeAttr(assertion, "IssueInstant", ErrAssertionIssueInstant)
	if err != nil || !freshIssueInstant(claims.AssertionIssueInstant, expected) {
		return Claims{}, fmt.Errorf("%w: %w", ErrIssueInstant, ErrAssertionIssueInstant)
	}

	claims.NameID, err = extractNameID(assertion)
	if err != nil {
		return Claims{}, err
	}
	claims.SubjectConfirmation, err = extractSubjectConfirmation(assertion, expected)
	if err != nil {
		return Claims{}, err
	}
	claims.Conditions, claims.Audiences, err = extractConditions(assertion, expected)
	if err != nil {
		return Claims{}, err
	}
	claims.Authn, err = extractAuthn(assertion)
	if err != nil {
		return Claims{}, err
	}
	return claims, nil
}

func validateResponseStatus(response *etree.Element) error {
	statuses := directChildren(response, SAMLProtocolNamespace, "Status")
	if len(statuses) != 1 {
		return ErrResponseStatus
	}
	statusCodes := directChildren(statuses[0], SAMLProtocolNamespace, "StatusCode")
	if len(statusCodes) != 1 {
		return ErrResponseStatus
	}
	value, present := plainAttr(statusCodes[0], "Value")
	if !present || value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return ErrResponseStatus
	}
	if len(directChildren(statusCodes[0], SAMLProtocolNamespace, "StatusCode")) != 0 {
		return ErrResponseStatus
	}
	return nil
}

func requiredSingleText(parent *etree.Element, namespace, local string, failure error) (string, error) {
	elements := directChildren(parent, namespace, local)
	if len(elements) != 1 || elements[0].Text() == "" {
		return "", failure
	}
	return elements[0].Text(), nil
}

func requiredTimeAttr(element *etree.Element, name string, failure error) (time.Time, error) {
	raw, present := plainAttr(element, name)
	if !present || raw == "" {
		return time.Time{}, failure
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, failure
	}
	return parsed, nil
}

func freshIssueInstant(instant time.Time, expected ValidationExpectations) bool {
	if instant.After(expected.Now.Add(expected.ClockSkew)) {
		return false
	}
	return expected.Now.Sub(instant) <= expected.MaxIssueAge+expected.ClockSkew
}

func extractNameID(assertion *etree.Element) (NameID, error) {
	subjects := directChildren(assertion, SAMLAssertionNamespace, "Subject")
	if len(subjects) != 1 {
		return NameID{}, ErrNameIDCardinality
	}
	nameIDs := directChildren(subjects[0], SAMLAssertionNamespace, "NameID")
	if len(nameIDs) != 1 {
		return NameID{}, ErrNameIDCardinality
	}
	element := nameIDs[0]
	id := NameID{Value: []byte(element.Text())}
	id.Format = optionalAttr(element, "Format")
	id.NameQualifier = optionalAttr(element, "NameQualifier")
	id.SPNameQualifier = optionalAttr(element, "SPNameQualifier")
	if len(id.Value) == 0 {
		return NameID{}, ErrEmptyNameID
	}
	return id, nil
}

func optionalAttr(element *etree.Element, name string) *string {
	value, present := plainAttr(element, name)
	if !present {
		return nil
	}
	return &value
}

func extractSubjectConfirmation(assertion *etree.Element, expected ValidationExpectations) (SubjectConfirmationClaims, error) {
	subjects := directChildren(assertion, SAMLAssertionNamespace, "Subject")
	if len(subjects) != 1 {
		return SubjectConfirmationClaims{}, fmt.Errorf("%w: %w", ErrSubjectConfirmation, ErrSubjectConfirmationMissing)
	}
	confirmations := directChildren(subjects[0], SAMLAssertionNamespace, "SubjectConfirmation")
	if len(confirmations) != 1 {
		return SubjectConfirmationClaims{}, fmt.Errorf("%w: %w", ErrSubjectConfirmation, ErrSubjectConfirmationMissing)
	}
	method, _ := plainAttr(confirmations[0], "Method")
	if method != SubjectConfirmationBearer {
		return SubjectConfirmationClaims{}, fmt.Errorf("%w: %w", ErrSubjectConfirmation, ErrSubjectConfirmationMethod)
	}
	data := directChildren(confirmations[0], SAMLAssertionNamespace, "SubjectConfirmationData")
	if len(data) != 1 {
		return SubjectConfirmationClaims{}, fmt.Errorf("%w: %w", ErrSubjectConfirmation, ErrSubjectConfirmationMissing)
	}
	claims := SubjectConfirmationClaims{Method: method}
	claims.Recipient, _ = plainAttr(data[0], "Recipient")
	claims.InResponseTo, _ = plainAttr(data[0], "InResponseTo")
	if claims.Recipient != expected.ACSURL {
		return SubjectConfirmationClaims{}, fmt.Errorf("%w: %w", ErrSubjectConfirmation, ErrSubjectConfirmationRecipient)
	}
	if claims.InResponseTo != expected.RequestID {
		return SubjectConfirmationClaims{}, fmt.Errorf("%w: %w", ErrSubjectConfirmation, ErrSubjectConfirmationInResponseTo)
	}
	rawExpiry, present := plainAttr(data[0], "NotOnOrAfter")
	if !present || rawExpiry == "" {
		return SubjectConfirmationClaims{}, fmt.Errorf("%w: %w", ErrSubjectConfirmation, ErrSubjectConfirmationExpiryMissing)
	}
	parsedExpiry, err := time.Parse(time.RFC3339Nano, rawExpiry)
	claims.NotOnOrAfter = parsedExpiry
	if err != nil || !beforeExpiry(expected.Now, claims.NotOnOrAfter, expected.ClockSkew) {
		return SubjectConfirmationClaims{}, fmt.Errorf("%w: %w", ErrSubjectConfirmation, ErrSubjectConfirmationExpired)
	}
	return claims, nil
}

func extractConditions(assertion *etree.Element, expected ValidationExpectations) (ConditionsClaims, []string, error) {
	elements := directChildren(assertion, SAMLAssertionNamespace, "Conditions")
	if len(elements) != 1 {
		return ConditionsClaims{}, nil, fmt.Errorf("%w: %w", ErrConditions, ErrConditionsMissing)
	}
	conditions := ConditionsClaims{}
	if raw, present := plainAttr(elements[0], "NotBefore"); present {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil || expected.Now.Add(expected.ClockSkew).Before(parsed) {
			return ConditionsClaims{}, nil, fmt.Errorf("%w: %w", ErrConditions, ErrConditionsNotBefore)
		}
		conditions.NotBefore = &parsed
	}
	rawExpiry, present := plainAttr(elements[0], "NotOnOrAfter")
	if !present || rawExpiry == "" {
		return ConditionsClaims{}, nil, fmt.Errorf("%w: %w", ErrConditions, ErrConditionsExpiryMissing)
	}
	parsedExpiry, err := time.Parse(time.RFC3339Nano, rawExpiry)
	conditions.NotOnOrAfter = parsedExpiry
	if err != nil || !beforeExpiry(expected.Now, conditions.NotOnOrAfter, expected.ClockSkew) {
		return ConditionsClaims{}, nil, fmt.Errorf("%w: %w", ErrConditions, ErrConditionsExpired)
	}

	restrictions := directChildren(elements[0], SAMLAssertionNamespace, "AudienceRestriction")
	if len(restrictions) == 0 {
		return ConditionsClaims{}, nil, fmt.Errorf("%w: %w", ErrAudience, ErrAudienceMissing)
	}
	if len(elements[0].ChildElements()) != len(restrictions) {
		return ConditionsClaims{}, nil, ErrConditions
	}
	var audiences []string
	for _, restriction := range restrictions {
		audienceElements := directChildren(restriction, SAMLAssertionNamespace, "Audience")
		if len(audienceElements) == 0 || len(restriction.ChildElements()) != len(audienceElements) {
			return ConditionsClaims{}, nil, ErrAudience
		}
		matched := false
		for _, audience := range audienceElements {
			value := audience.Text()
			audiences = append(audiences, value)
			if value == expected.SPEntityID {
				matched = true
			}
		}
		if !matched {
			return ConditionsClaims{}, nil, fmt.Errorf("%w: %w", ErrAudience, ErrAudienceMismatch)
		}
	}
	return conditions, audiences, nil
}

func beforeExpiry(now, expiry time.Time, skew time.Duration) bool {
	return now.Before(expiry.Add(skew))
}

func extractAuthn(assertion *etree.Element) (AuthnClaims, error) {
	statements := directChildren(assertion, SAMLAssertionNamespace, "AuthnStatement")
	if len(statements) != 1 {
		return AuthnClaims{}, ErrAuthnStatementCardinality
	}
	instant, err := requiredTimeAttr(statements[0], "AuthnInstant", ErrInvalidAuthnInstant)
	if err != nil {
		return AuthnClaims{}, err
	}
	contexts := directChildren(statements[0], SAMLAssertionNamespace, "AuthnContext")
	if len(contexts) > 1 {
		return AuthnClaims{}, ErrAuthnContextCardinality
	}
	claims := AuthnClaims{Instant: instant}
	if len(contexts) == 0 {
		return claims, nil
	}
	classRefs := directChildren(contexts[0], SAMLAssertionNamespace, "AuthnContextClassRef")
	if len(classRefs) > 1 {
		return AuthnClaims{}, ErrAuthnContextCardinality
	}
	if len(classRefs) == 1 {
		value := classRefs[0].Text()
		claims.ContextClassRef = &value
	}
	return claims, nil
}
