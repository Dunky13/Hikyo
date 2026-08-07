package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/Dunky13/wenv/api/apigen"
	"github.com/Dunky13/wenv/internal/admission"
	"github.com/Dunky13/wenv/internal/domain"
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

var messages = map[apigen.ErrorCode]string{
	apigen.ErrorCodeBadRequest:      "the request does not satisfy the API contract",
	apigen.ErrorCodeUnauthenticated: "authentication required",
	apigen.ErrorCodeForbidden:       "not permitted",
	apigen.ErrorCodeNotFound:        "not found",
	apigen.ErrorCodeTooManyRequests: "too many requests",
	apigen.ErrorCodeInternal:        "internal error",
}

var statuses = map[apigen.ErrorCode]int{
	apigen.ErrorCodeBadRequest:      http.StatusBadRequest,
	apigen.ErrorCodeUnauthenticated: http.StatusUnauthorized,
	apigen.ErrorCodeForbidden:       http.StatusForbidden,
	apigen.ErrorCodeNotFound:        http.StatusNotFound,
	apigen.ErrorCodeTooManyRequests: http.StatusTooManyRequests,
	apigen.ErrorCodeInternal:        http.StatusInternalServerError,
}

// errorBody builds the wire body for a code. detail is honoured only for
// bad_request; everywhere else it is dropped, because a uniform response with
// a varying member is not uniform.
func errorBody(code apigen.ErrorCode, detail string) apigen.Error {
	var body apigen.Error
	body.Error.Code = code
	body.Error.Message = messages[code]
	if code == apigen.ErrorCodeBadRequest && detail != "" {
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
func classify(err error) apigen.ErrorCode {
	switch {
	case errors.Is(err, domain.ErrUnauthenticated):
		return apigen.ErrorCodeUnauthenticated
	case errors.Is(err, domain.ErrNotFound):
		return apigen.ErrorCodeNotFound
	case errors.Is(err, domain.ErrUnauthorized):
		return apigen.ErrorCodeForbidden
	case errors.Is(err, admission.ErrOverloaded):
		return apigen.ErrorCodeTooManyRequests
	default:
		return apigen.ErrorCodeInternal
	}
}
