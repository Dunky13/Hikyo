package service

import "testing"

func TestCLIRedirectIsExactEphemeralLoopbackCallback(t *testing.T) {
	for _, valid := range []string{
		"http://127.0.0.1:43123/callback",
		"http://[::1]:43123/callback",
	} {
		if !validCLILoopbackRedirect(valid) {
			t.Errorf("valid redirect refused: %s", valid)
		}
	}
	for _, invalid := range []string{
		"https://127.0.0.1:43123/callback",
		"http://localhost:43123/callback",
		"http://127.0.0.1/callback",
		"http://127.0.0.1:43123/other",
		"http://127.0.0.1:43123/callback?next=evil",
		"http://127.0.0.1:43123/callback#fragment",
		"http://127.0.0.2:43123/callback",
	} {
		if validCLILoopbackRedirect(invalid) {
			t.Errorf("invalid redirect accepted: %s", invalid)
		}
	}
}
