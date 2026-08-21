package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/admission"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

// Uniform error rendering.
//
// The message is FIXED per code — never derived from the request — so two
// refusals of the same class are byte-identical on the wire. That is the
// application-layer half of unauthorized ≡ nonexistent: a prober comparing
// two 404 bodies learns nothing, because there is nothing in them that could
// differ.
//
// `bad_request` is the single exception, and only for its `detail` member.
// Request-shape validation runs before any tenant resolution, so naming the
// offending member reveals nothing about what exists or who may reach it —
// and withholding it would make every malformed request a guessing game for
// no security gain.

// limitExceededMessage is the one fixed message that states the bounds. The ops
// spec requires a structural cap to be a NAMED refusal, and a body that may
// carry nothing derived from the request can still carry a constant — but the
// numbers are built from the constants the service enforces, not retyped here.
// Two hand-written 50s is one of them going stale the day the cap moves.
//
// It enumerates every bound rather than naming the one that fired, because
// "fixed message per code" means exactly one body for `limit_exceeded`: a
// message that varied by which cap was hit would be a body derived from the
// request. Which bound fired is in the server's own error, which is logged and
// never returned. Giving each bound its own code — so the response could name
// it — is recorded as a disposition item rather than smuggled in here.
var limitExceededMessage = fmt.Sprintf(
	"a structural bound was reached: a project holds at most %d environments, "+
		"declares at most %d keys, and declares at most %d key groups",
	service.MaxEnvironmentsPerProject, schema.MaxKeysPerProject, schema.MaxKeyGroupsPerProject)

type detailPolicy uint8

const (
	redactDetail detailPolicy = iota
	allowSafeDetail
)

// WireError is the closed server-layer policy for one public error class.
// Its fields stay private so handlers cannot assemble status, code, message,
// and detail handling independently.
type WireError struct {
	status       int
	code         apigen.ErrorCode
	message      string
	detailPolicy detailPolicy
}

// wirePolicies is the one total public-code policy. A contract test compares
// this table with the OpenAPI enum, so adding a public code without deciding
// all four fields fails the suite.
var wirePolicies = map[apigen.ErrorCode]WireError{
	apigen.ErrorCodeBadRequest:      {status: http.StatusBadRequest, code: apigen.ErrorCodeBadRequest, message: "the request does not satisfy the API contract", detailPolicy: allowSafeDetail},
	apigen.ErrorCodeUnauthenticated: {status: http.StatusUnauthorized, code: apigen.ErrorCodeUnauthenticated, message: "authentication required", detailPolicy: redactDetail},
	apigen.ErrorCodeForbidden:       {status: http.StatusForbidden, code: apigen.ErrorCodeForbidden, message: "not permitted", detailPolicy: redactDetail},
	apigen.ErrorCodeNotFound:        {status: http.StatusNotFound, code: apigen.ErrorCodeNotFound, message: "not found", detailPolicy: redactDetail},
	apigen.ErrorCodeConflict:        {status: http.StatusConflict, code: apigen.ErrorCodeConflict, message: "the current state of this resource refuses the request", detailPolicy: allowSafeDetail},
	apigen.ErrorCodeLimitExceeded:   {status: http.StatusConflict, code: apigen.ErrorCodeLimitExceeded, message: limitExceededMessage, detailPolicy: redactDetail},
	apigen.ErrorCodeTooManyRequests: {status: http.StatusTooManyRequests, code: apigen.ErrorCodeTooManyRequests, message: "too many requests", detailPolicy: redactDetail},
	apigen.ErrorCodeInternal:        {status: http.StatusInternalServerError, code: apigen.ErrorCodeInternal, message: "internal error", detailPolicy: redactDetail},
}

// wirePolicyForCode fails closed for an unrecognized public code. Callers that
// receive a future or invalid code can never render an empty status or body.
func wirePolicyForCode(code apigen.ErrorCode) WireError {
	if policy, ok := wirePolicies[code]; ok {
		return policy
	}
	return wirePolicies[apigen.ErrorCodeInternal]
}

// errorBody builds the wire body for a code. detail is honoured only for
// bad_request and conflict; everywhere else it is dropped, because a uniform
// response with a varying member is not uniform.
//
// detail ONLY ever arrives from an explicit SafeDetail-carrying error (see
// writeHandlerError). A plain conflict — one that wraps domain.ErrConflict with
// no SafeDetail — carries no detail and stays byte-identical to every other
// conflict. The single conflict that opts in is the protected-destination
// refusal, whose detail is the caller's OWN destination id (post-authorization,
// so naming it discloses nothing).
func errorBody(code apigen.ErrorCode, detail string) apigen.Error {
	return wirePolicyForCode(code).bodyWithDetail(detail)
}

func (policy WireError) body(err error) apigen.Error {
	return policy.bodyWithDetail(safeDetailOf(err))
}

func (policy WireError) bodyWithDetail(detail string) apigen.Error {
	var body apigen.Error
	body.Error.Code = policy.code
	body.Error.Message = policy.message
	if policy.detailPolicy == allowSafeDetail && detail != "" {
		body.Error.Detail = &detail
	}
	return body
}

// wireScanFindings maps the service's redacted findings onto the wire type
// (#74). It carries the rule id, surface, locator and — where present — the
// opaque acknowledgement token, and NOTHING derived from the matched material.
func wireScanFindings(findings []service.Finding) []apigen.ScanFinding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]apigen.ScanFinding, len(findings))
	for i, f := range findings {
		out[i] = apigen.ScanFinding{
			RuleId:  f.RuleID,
			Surface: apigen.ScanFindingSurface(f.Surface),
			Locator: f.Locator,
		}
		if f.Acknowledgement != "" {
			ack := f.Acknowledgement
			out[i].Acknowledgement = &ack
		}
	}
	return out
}

// safeDetailOf lifts a caller-safe detail off an error that opts in via a
// SafeDetail carrier, or "" when it carries none. It is the same extraction
// writeHandlerError performs inline, for handlers that build a typed response
// (not every route funnels through writeHandlerError) yet still need to honour a
// SafeDetail on the codes errorBody carries it for (bad_request, conflict).
func safeDetailOf(err error) string {
	var sd interface{ SafeDetail() string }
	if errors.As(err, &sd) {
		return sd.SafeDetail()
	}
	return ""
}

// writeError renders a refusal. It never writes anything derived from the
// cause beyond the code itself; the cause is the process log's business.
func writeError(w http.ResponseWriter, policy WireError, detail string) {
	if policy.code == apigen.ErrorCodeTooManyRequests {
		w.Header().Set("Retry-After", strconv.Itoa(int(admission.RetryAfter.Seconds())))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(policy.status)
	_ = json.NewEncoder(w).Encode(policy.bodyWithDetail(detail))
}

// wireErrorRules is the single mapping from recognized Hikyo error classes to
// public policies. Protocol-specific SCIM errors are intentionally excluded:
// that wire uses RFC 7644 envelopes and owns its closed policy in scim_wire.go.
var wireErrorRules = []struct {
	match error
	code  apigen.ErrorCode
}{
	// Reveal and account-security refusals.
	{service.ErrNoReauthWindow, apigen.ErrorCodeForbidden},
	{service.ErrReauthWindowExpired, apigen.ErrorCodeForbidden},
	{service.ErrReauthUnitMismatch, apigen.ErrorCodeForbidden},
	{service.ErrReauthWindowSpent, apigen.ErrorCodeForbidden},
	{service.ErrReauthWindowClosed, apigen.ErrorCodeConflict},
	{service.ErrTOTPCodeAlreadyUsed, apigen.ErrorCodeConflict},
	{service.ErrCLIReauthInvalid, apigen.ErrorCodeConflict},
	{service.ErrReauthRequired, apigen.ErrorCodeConflict},
	{service.ErrWeakPassword, apigen.ErrorCodeBadRequest},
	{service.ErrCommonPassword, apigen.ErrorCodeBadRequest},
	{service.ErrTOTPAlreadyEnrolled, apigen.ErrorCodeBadRequest},
	{service.ErrNoPendingTOTP, apigen.ErrorCodeBadRequest},
	{service.ErrNoTOTPFactor, apigen.ErrorCodeBadRequest},
	{service.ErrNoProofCredential, apigen.ErrorCodeBadRequest},
	{service.ErrWebAuthnUnavailable, apigen.ErrorCodeBadRequest},
	{service.ErrNoWebAuthnCeremony, apigen.ErrorCodeBadRequest},
	{service.ErrNoPasskey, apigen.ErrorCodeBadRequest},
	{service.ErrPasskeyOnlyViolation, apigen.ErrorCodeBadRequest},

	// OIDC and SAML provider administration.
	{service.ErrProviderNotFound, apigen.ErrorCodeNotFound},
	{service.ErrBadPurpose, apigen.ErrorCodeBadRequest},
	{service.ErrReauthNoPolicy, apigen.ErrorCodeBadRequest},
	{service.ErrReauthNoEnvironment, apigen.ErrorCodeBadRequest},
	{service.ErrIdentityNotFound, apigen.ErrorCodeBadRequest},
	{service.ErrLastCredential, apigen.ErrorCodeBadRequest},
	{service.ErrIssuerImmutable, apigen.ErrorCodeBadRequest},
	{service.ErrProviderDiscovery, apigen.ErrorCodeBadRequest},
	{service.ErrProviderExists, apigen.ErrorCodeBadRequest},
	{service.ErrProviderRace, apigen.ErrorCodeConflict},
	{service.ErrSAMLProviderNotFound, apigen.ErrorCodeNotFound},
	{service.ErrSAMLSPKeyNotFound, apigen.ErrorCodeNotFound},
	{service.ErrSAMLSPKeyState, apigen.ErrorCodeConflict},
	{service.ErrSAMLSPKeyRace, apigen.ErrorCodeConflict},
	{service.ErrSAMLProviderRace, apigen.ErrorCodeConflict},
	{service.ErrSAMLEntityIDImmutable, apigen.ErrorCodeConflict},
	{service.ErrSAMLReauthNoPolicy, apigen.ErrorCodeBadRequest},
	{service.ErrSAMLReauthNoEnvironment, apigen.ErrorCodeBadRequest},
	{service.ErrSAMLMetadataSource, apigen.ErrorCodeBadRequest},
	{service.ErrSAMLMetadataFetch, apigen.ErrorCodeBadRequest},
	{service.ErrSAMLMetadataInvalid, apigen.ErrorCodeBadRequest},
	{service.ErrSAMLMetadataSignatureDowngrade, apigen.ErrorCodeBadRequest},
	{service.ErrSAMLMetadataExpired, apigen.ErrorCodeConflict},

	// Enumeration-safe server surfaces.
	{service.ErrNoResetTarget, apigen.ErrorCodeNotFound},

	// Domain and admission classes are deliberately last: specific service
	// errors may wrap one of these while carrying a narrower public meaning.
	{domain.ErrUnauthenticated, apigen.ErrorCodeUnauthenticated},
	{domain.ErrNotFound, apigen.ErrorCodeNotFound},
	{domain.ErrUnauthorized, apigen.ErrorCodeForbidden},
	{domain.ErrLimitExceeded, apigen.ErrorCodeLimitExceeded},
	{domain.ErrConflict, apigen.ErrorCodeConflict},
	{domain.ErrInvalid, apigen.ErrorCodeBadRequest},
	{admission.ErrOverloaded, apigen.ErrorCodeTooManyRequests},
}

// wireErrorFor maps an internal outcome onto one closed wire policy. It is the
// single place that decision is made, so a handler cannot invent a status that
// leaks what the sentinels are built to hide.
//
//   - ErrNotFound is BOTH "no such row" and "you may not reach it", and the
//     two are indistinguishable by design.
//   - ErrUnauthorized is the instance-scope refusal: there is no tenant object
//     whose nonexistence could be mimicked, so the contract is grant refusal.
//   - ErrOverloaded is the same 429 on every pre-auth path.
//   - Anything else is a fault: 500, with the cause logged and never returned.
//   - ErrConflict and ErrLimitExceeded are decided AFTER authorization
//     succeeded, so they disclose nothing a caller could not already read.
//   - ErrInvalid is decided before or independently of tenant resolution.
//   - The reveal-ceremony refusals (#58) are `forbidden`. They are decided
//     AFTER authorize() has already succeeded, so they disclose nothing beyond
//     the caller's own capability — which they can read off their own grants —
//     and they must not be 500s: a missing ceremony is a routine, actionable
//     state, not a fault. They are deliberately NOT distinguishable from one
//     another on the wire: whether a window was absent, lapsed, spent or bound
//     to different keys, the client's correct move is the same (re-run the
//     ceremony the guard's own state route describes), and the enum is closed.
func wireErrorFor(err error) WireError {
	for _, rule := range wireErrorRules {
		if errors.Is(err, rule.match) {
			return wirePolicyForCode(rule.code)
		}
	}
	return wirePolicyForCode(apigen.ErrorCodeInternal)
}

// workspaceHandoffLookupWireErrorFor is the sole contextual override in the
// Hikyo JSON policy. ErrHandoffInvalid normally follows its wrapped
// ErrUnauthorized to 403 for approve/redeem. The authenticated transaction
// lookup deliberately answers 404 for unknown, stale, consumed, or non-owned
// state so those cases remain indistinguishable.
func workspaceHandoffLookupWireErrorFor(err error) WireError {
	if errors.Is(err, service.ErrHandoffInvalid) {
		return wirePolicyForCode(apigen.ErrorCodeNotFound)
	}
	return wireErrorFor(err)
}

// The helpers below identify the few endpoint-specific precondition families
// whose timing or enumeration contract deliberately collapses only a subset of
// otherwise-recognized classes. Keeping the membership here leaves handlers to
// adapt a decided WireError to generated response types, not classify causes.
func passwordPrecondition(err error) bool {
	return errors.Is(err, service.ErrWeakPassword) || errors.Is(err, service.ErrCommonPassword)
}

func factorPrecondition(err error) bool {
	return errors.Is(err, service.ErrTOTPAlreadyEnrolled) ||
		errors.Is(err, service.ErrNoPendingTOTP) ||
		errors.Is(err, service.ErrNoTOTPFactor) ||
		errors.Is(err, service.ErrNoProofCredential)
}

func recoveryPrecondition(err error) bool {
	return errors.Is(err, service.ErrPasskeyOnlyViolation)
}

func webauthnPrecondition(err error) bool {
	return errors.Is(err, service.ErrWebAuthnUnavailable) ||
		errors.Is(err, service.ErrNoWebAuthnCeremony) ||
		errors.Is(err, service.ErrNoPasskey) ||
		errors.Is(err, service.ErrPasskeyOnlyViolation) ||
		errors.Is(err, service.ErrNoProofCredential)
}

func loginPrecondition(err error) bool {
	// ONLY the instance-wide "WebAuthn not configured" refusal is a loud 400
	// on pre-auth login. Every per-account outcome stays the uniform 401.
	return errors.Is(err, service.ErrWebAuthnUnavailable)
}
