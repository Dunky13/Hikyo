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

var messages = map[apigen.ErrorCode]string{
	apigen.ErrorCodeBadRequest:      "the request does not satisfy the API contract",
	apigen.ErrorCodeUnauthenticated: "authentication required",
	apigen.ErrorCodeForbidden:       "not permitted",
	apigen.ErrorCodeNotFound:        "not found",
	apigen.ErrorCodeConflict:        "the current state of this resource refuses the request",
	apigen.ErrorCodeLimitExceeded:   limitExceededMessage,
	apigen.ErrorCodeTooManyRequests: "too many requests",
	apigen.ErrorCodeInternal:        "internal error",
}

var statuses = map[apigen.ErrorCode]int{
	apigen.ErrorCodeBadRequest:      http.StatusBadRequest,
	apigen.ErrorCodeUnauthenticated: http.StatusUnauthorized,
	apigen.ErrorCodeForbidden:       http.StatusForbidden,
	apigen.ErrorCodeNotFound:        http.StatusNotFound,
	apigen.ErrorCodeConflict:        http.StatusConflict,
	apigen.ErrorCodeLimitExceeded:   http.StatusConflict,
	apigen.ErrorCodeTooManyRequests: http.StatusTooManyRequests,
	apigen.ErrorCodeInternal:        http.StatusInternalServerError,
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
	var body apigen.Error
	body.Error.Code = code
	body.Error.Message = messages[code]
	if (code == apigen.ErrorCodeBadRequest || code == apigen.ErrorCodeConflict) && detail != "" {
		body.Error.Detail = &detail
	}
	return body
}

// writeError renders a refusal. It never writes anything derived from the
// cause beyond the code itself; the cause is the process log's business.
func writeError(w http.ResponseWriter, code apigen.ErrorCode, detail string) {
	if code == apigen.ErrorCodeTooManyRequests {
		w.Header().Set("Retry-After", strconv.Itoa(int(admission.RetryAfter.Seconds())))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statuses[code])
	_ = json.NewEncoder(w).Encode(errorBody(code, detail))
}

// classify maps a domain outcome onto a wire code. It is the single place
// that decision is made, so a handler cannot invent a status that leaks what
// the sentinels are built to hide.
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
func classify(err error) apigen.ErrorCode {
	switch {
	case errors.Is(err, service.ErrNoReauthWindow),
		errors.Is(err, service.ErrReauthWindowExpired),
		errors.Is(err, service.ErrReauthUnitMismatch),
		errors.Is(err, service.ErrReauthWindowSpent):
		return apigen.ErrorCodeForbidden
	case errors.Is(err, domain.ErrUnauthenticated):
		return apigen.ErrorCodeUnauthenticated
	case errors.Is(err, domain.ErrNotFound):
		return apigen.ErrorCodeNotFound
	case errors.Is(err, domain.ErrUnauthorized):
		return apigen.ErrorCodeForbidden
	case errors.Is(err, domain.ErrLimitExceeded):
		return apigen.ErrorCodeLimitExceeded
	case errors.Is(err, domain.ErrConflict):
		return apigen.ErrorCodeConflict
	case errors.Is(err, domain.ErrInvalid):
		return apigen.ErrorCodeBadRequest
	case errors.Is(err, admission.ErrOverloaded):
		return apigen.ErrorCodeTooManyRequests
	default:
		return apigen.ErrorCodeInternal
	}
}
