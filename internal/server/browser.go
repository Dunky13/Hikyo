package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Dunky13/hikyo/api/apigen"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/service"
)

// The browser leg of the transport (#56), completing what #54 deferred: the
// synchronizer token is delivered, and it is required.
//
// Shape, and why:
//
//   - The session token rides `__Host-hikyo`, HttpOnly, so injected same-origin
//     script cannot read it (#54 B2).
//   - The synchronizer token rides `__Host-hikyo-csrf`, deliberately NOT
//     HttpOnly, and must be echoed on `X-Hikyo-CSRF`. A cross-origin page can
//     cause the browser to SEND our cookies; it cannot READ them, so it cannot
//     produce the header. The `__Host-` prefix additionally denies a
//     compromised sibling subdomain the ability to plant one.
//   - The presented header is verified against the session row's verifier at
//     the chokepoint, in the transaction that authorizes the operation. That
//     makes this a true synchronizer token rather than a bare double-submit:
//     a value the attacker somehow set in the cookie still has to match a
//     verifier only the server minted.
//   - The requirement is decided by TRANSPORT, never inferred from the row
//     (#54 A10): a request that authenticated on the cookie leg and changes
//     state needs the header; a `Authorization: Bearer` caller has no cookie
//     the browser attaches by itself and therefore no CSRF contract.
//
// Recorded deviation from the #54 blueprint's A9 line ("CSRF token delivered
// via authenticated GET /auth/whoami"): the verifier is a one-way SHA-256, so
// whoami could only deliver a token by MINTING a new one — a write on a GET,
// and a token that a second tab's boot silently invalidates. The cookie
// channel delivers the same value to the same origin under the same
// restrictions, survives a reload, and needs no write. The ADR's issuer
// wording is owed an amendment; see docs/handoff/56-ui-shell.md.

const (
	// browserCSRFCookie carries the synchronizer token to script on this
	// origin. Readable by design — see above.
	browserCSRFCookie = "__Host-hikyo-csrf"
	// csrfHeader is where the SPA echoes it back.
	csrfHeader = "X-Hikyo-CSRF"
)

// browserCookiesFor builds the cookie pair for a minted or rotated browser
// session. The CSRF cookie is emitted only when the mint produced a token:
// a rotation that leaves the verifier alone must not clear the client's
// still-valid one.
func browserCookiesFor(sessionToken, csrfToken string) []*http.Cookie {
	cookies := make([]*http.Cookie, 0, 2)
	if sessionToken != "" {
		cookies = append(cookies, &http.Cookie{
			Name: browserSessionCookie, Value: sessionToken,
			Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	}
	if csrfToken != "" {
		cookies = append(cookies, &http.Cookie{
			Name: browserCSRFCookie, Value: csrfToken,
			// Strict, not Lax: nothing navigates to hikyo expecting to arrive
			// already able to mutate. The session cookie stays Lax because the
			// OIDC callback is a top-level cross-site navigation that must
			// carry it.
			Path: "/", Secure: true, HttpOnly: false, SameSite: http.SameSiteStrictMode,
		})
	}
	return cookies
}

// expiredBrowserCookies clears both cookies. Logout deletes the row, which is
// what actually revokes; clearing the cookies stops the browser from
// presenting a value that can only ever be refused now.
func expiredBrowserCookies() []*http.Cookie {
	return []*http.Cookie{
		{Name: browserSessionCookie, Value: "", Path: "/", MaxAge: -1,
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode},
		{Name: browserCSRFCookie, Value: "", Path: "/", MaxAge: -1,
			Secure: true, HttpOnly: false, SameSite: http.SameSiteStrictMode},
	}
}

// safeMethod reports whether a method is defined not to change state. These
// are exempt from the CSRF requirement because a cross-origin page can already
// cause them and learn nothing: the response is unreadable to it.
func safeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// requireCSRF is the enforcement leg: a state-changing request that
// authenticated on the cookie leg must echo the session's synchronizer token.
//
// "Authenticated on the cookie leg" means the cookie resolves to a LIVE
// session — not merely that a cookie is present. A dead artifact authorizes
// nothing, so there is nothing for the gate to protect, and refusing there
// would be actively harmful: an expired browser session leaves its cookie in
// the browser, the human's next act is to sign in again, and that login POST
// carries the dead cookie. Keying on presence would refuse it 401 before the
// handler and lock the account out of its own login page.
//
// Both halves are checked, in this order, because each catches what the other
// cannot: the row's verifier proves the token is this session's (a bare
// double-submit would not), and the companion cookie proves the caller could
// READ our cookies (which a cross-origin page cannot). The refusal is the same
// uniform 401 every other unauthenticated refusal uses.
func (a *API) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if safeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		session, err := r.Cookie(browserSessionCookie)
		if err != nil || session.Value == "" {
			// No cookie at all: a bearer caller, or an anonymous login POST.
			next.ServeHTTP(w, r)
			return
		}
		presented := r.Header.Get(csrfHeader)
		switch err := a.Auth.VerifyBrowserCSRF(r.Context(), session.Value, presented); {
		case errors.Is(err, domain.ErrUnauthenticated):
			// The cookie resolves to nothing. Not a cookie leg — let the
			// request through and let the chokepoint judge it, which for an
			// authenticated operation is the same 401 and for a login is a
			// login.
			next.ServeHTTP(w, r)
			return
		case err != nil:
			refuseUnauthenticated(w)
			return
		}
		companion, cerr := r.Cookie(browserCSRFCookie)
		if cerr != nil ||
			subtle.ConstantTimeCompare([]byte(presented), []byte(companion.Value)) != 1 {
			refuseUnauthenticated(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// refuseUnauthenticated writes the uniform refusal from middleware, where the
// strict server's own writer is not reachable yet.
func refuseUnauthenticated(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(errorBody(apigen.ErrorCodeUnauthenticated, ""))
}

// writeJSONWithCookies is the response shape every cookie-bearing operation
// shares: set what the mint produced, then the JSON body. The generated strict
// server gives each operation its own response interface, so the TYPES cannot
// be merged — but the behaviour is one behaviour and lives in one place.
func writeJSONWithCookies(w http.ResponseWriter, cookies []*http.Cookie, status int, body any) error {
	for _, c := range cookies {
		http.SetCookie(w, c)
	}
	if body == nil {
		w.WriteHeader(status)
		return nil
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(body)
}

// ---------------------------------------------------------------------------
// Reissued sessions
// ---------------------------------------------------------------------------

// Every account-security mutation reissues or rotates the acting session, and
// every one of them therefore has the same delivery obligation: a browser
// artifact leaves on its cookies and nowhere else, a CLI artifact leaves in
// the body. Getting that wrong is not cosmetic — a browser handed a rotated
// token in the JSON body is simultaneously logged out (its cookie now points
// at a dead verifier) and holding a long-lived credential script can read.
//
// The generated strict server gives each operation its own response
// interface, so the Visit methods cannot be merged; the behaviour behind them
// is one behaviour and lives in one place.

type reissuedSessionResponse struct {
	body    apigen.LoginResult
	cookies []*http.Cookie
}

func (r reissuedSessionResponse) write(w http.ResponseWriter) error {
	return writeJSONWithCookies(w, r.cookies, http.StatusOK, r.body)
}

func (r reissuedSessionResponse) VisitEnrolPasskeyFinishResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func (r reissuedSessionResponse) VisitPasskeyLoginFinishResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func (r reissuedSessionResponse) VisitStepUpPasskeyFinishResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func (r reissuedSessionResponse) VisitRemovePasskeyResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func (r reissuedSessionResponse) VisitEnrolTotpConfirmResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func (r reissuedSessionResponse) VisitStepUpTotpResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func (r reissuedSessionResponse) VisitRemoveTotpResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func (r reissuedSessionResponse) VisitUnlinkIdentityResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func (r reissuedSessionResponse) VisitLocalLoginResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func (r reissuedSessionResponse) VisitOidcCallbackResponse(w http.ResponseWriter) error {
	return r.write(w)
}

// sessionResponse renders a reissued session, attaching the cookie pair only
// when the result is a browser artifact — a CLI-bearer caller must not receive
// a browser cookie holding a cli-kind token, or its next request would carry
// both legs and trip the A10 dual-presentation refusal.
//
// A rotation that left the CSRF verifier alone (TOTP step-up) carries no CSRF
// token, and `browserCookiesFor` then emits only the session cookie: clearing
// a still-valid synchronizer token would break the very next mutation.
func sessionResponse(result service.LoginResult) reissuedSessionResponse {
	resp := reissuedSessionResponse{body: loginResultOf(result)}
	if result.Artifact == service.ArtifactBrowser && result.SessionToken != "" {
		resp.cookies = browserCookiesFor(result.SessionToken, result.CSRFToken)
	}
	return resp
}

// recoveryCodesResponse is the one reissuing operation whose body is not a
// bare LoginResult: the display-once batch travels beside it.
type recoveryCodesResponse struct {
	body    apigen.RecoveryCodesResult
	cookies []*http.Cookie
}

func (r recoveryCodesResponse) VisitRegenerateRecoveryCodesResponse(w http.ResponseWriter) error {
	return writeJSONWithCookies(w, r.cookies, http.StatusOK, r.body)
}
