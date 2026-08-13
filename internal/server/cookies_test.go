package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCookieWritersEnforceSecurityAtTheResponseBoundary(t *testing.T) {
	t.Run("session artifact", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		writeHTTPOnlyCookie(recorder, &http.Cookie{Name: "session", Value: "secret"})
		cookies := recorder.Result().Cookies()
		if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly {
			t.Fatalf("session cookie = %#v, want Secure+HttpOnly", cookies)
		}
	})

	t.Run("script-readable CSRF artifact", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		writeScriptReadableCookie(recorder, &http.Cookie{Name: "csrf", Value: "token", HttpOnly: true})
		cookies := recorder.Result().Cookies()
		if len(cookies) != 1 || !cookies[0].Secure || cookies[0].HttpOnly {
			t.Fatalf("CSRF cookie = %#v, want Secure and script-readable", cookies)
		}
	})
}
