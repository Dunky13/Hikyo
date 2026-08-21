package cli_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/cli"
)

// The inline TOTP disclosure ceremony (reveal_window.go): a dead window with
// TOTP offered prompts for a code, opens the window, rotates and PERSISTS the
// session token, and then runs the disclosure. A 0-window environment is
// refused naming the browser path and the project-settings knob.
func ceremonyServer(t *testing.T, window apigen.RevealWindow) (http.Handler, *[]string) {
	t.Helper()
	var seen []string
	live := window.Live
	rotated := "hik_1_cli_rotated-token"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/reveal-window"):
			window.Live = live
			_ = json.NewEncoder(w).Encode(window)
		case strings.HasSuffix(r.URL.Path, "/auth/totp"):
			// The inline path dispatches on enrolment: an authenticator stands.
			_ = json.NewEncoder(w).Encode(apigen.TotpStatus{Confirmed: true})
		case strings.HasSuffix(r.URL.Path, "/auth/reauth/totp"):
			var body apigen.TotpReauthRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Code != "123456" || body.EnvironmentId == nil || string(*body.EnvironmentId) != "env_70" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"code":"unauthenticated","message":"authentication required"}}`))
				return
			}
			live = true
			_ = json.NewEncoder(w).Encode(apigen.ReauthResult{
				EnvironmentId: "env_70", SessionId: "ses_rotated", SessionToken: &rotated,
				WindowExpires: apigen.Timestamp(time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)),
			})
		case strings.HasSuffix(r.URL.Path, "/values/export"):
			if !live || !strings.Contains(r.Header.Get("Authorization"), rotated) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":{"code":"forbidden","message":"not permitted"}}`))
				return
			}
			v := "s3cret"
			_ = json.NewEncoder(w).Encode(apigen.ExportedValues{Items: []apigen.ExportedValue{{Name: "DATABASE_PASSWORD", Classification: apigen.KeyClassificationSecret, Value: &v}}})
		case strings.HasSuffix(r.URL.Path, "/values/DATABASE_PASSWORD/reveal"):
			if !live || !strings.Contains(r.Header.Get("Authorization"), rotated) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":{"code":"forbidden","message":"not permitted"}}`))
				return
			}
			v := "s3cret"
			_ = json.NewEncoder(w).Encode(apigen.ValueCell{Name: "DATABASE_PASSWORD", Classification: "secret", KeyId: "key_1", Set: true, Revealed: true, Value: &v})
		default:
			http.NotFound(w, r)
		}
	}), &seen
}

func revealArgs() []string {
	return []string{"values", "get", "DATABASE_PASSWORD", "--reveal", "--dangerously-print",
		"--instance", "local", "--org", "org_70", "--project", "prj_70", "--env", "env_70"}
}

func TestRevealCeremonyOpensWindowByTOTPAndPersistsRotatedToken(t *testing.T) {
	handler, seen := ceremonyServer(t, apigen.RevealWindow{CanReveal: true, EffectiveWindowSeconds: 300, TotpOffered: true})
	ios, stdout, stderr := definitionsTestIO(t, handler)
	prompts := 0
	ios.ReadPassword = func(prompt string) (string, error) {
		prompts++
		if !strings.Contains(prompt, "env_70") || !strings.Contains(prompt, "300s") {
			t.Errorf("prompt does not name the environment and window: %q", prompt)
		}
		return "123456", nil
	}
	if code := cli.Run(t.Context(), ios, revealArgs()); code != cli.ExitOK {
		t.Fatalf("exit %d, want ok; stderr=%s", code, stderr.String())
	}
	if prompts != 1 {
		t.Fatalf("prompted %d times, want exactly once", prompts)
	}
	if !strings.Contains(stdout.String(), "s3cret") {
		t.Fatalf("the revealed value did not reach the chosen destination: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "reauthentication window open over env_70") {
		t.Errorf("no window-open notice: %s", stderr.String())
	}
	// Order: refused disclosure, window read, TOTP reauth, retried disclosure
	// under the ROTATED bearer.
	var order []string
	for _, s := range *seen {
		switch {
		case strings.Contains(s, "/reveal-window"):
			order = append(order, "window")
		case strings.Contains(s, "/reauth/totp"):
			order = append(order, "totp")
		case strings.Contains(s, "/reveal"):
			order = append(order, "reveal")
		}
	}
	if got := strings.Join(order, ","); got != "reveal,window,totp,reveal" {
		t.Fatalf("call order %s, want reveal,window,totp,reveal", got)
	}
	state, err := cli.NewState(ios.Env)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := state.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	session, ok := sessions["local"]
	if !ok || session.Token != "hik_1_cli_rotated-token" || session.SessionID != "ses_rotated" {
		t.Fatalf("the rotated session was not persisted: %+v", session)
	}
}

func TestRevealCeremonyRefusesZeroWindowNamingTheBrowserPath(t *testing.T) {
	handler, _ := ceremonyServer(t, apigen.RevealWindow{CanReveal: true, EffectiveWindowSeconds: 0, Protected: true})
	ios, _, stderr := definitionsTestIO(t, handler)
	ios.ReadPassword = func(string) (string, error) {
		t.Fatal("a 0-window environment must not prompt for a code")
		return "", nil
	}
	if code := cli.Run(t.Context(), ios, revealArgs()); code != cli.ExitAuth {
		t.Fatalf("exit %d, want ExitAuth; stderr=%s", code, stderr.String())
	}
	for _, want := range []string{"protected environment", "ceremony is the browser's", "project-settings set --env env_70 --reauth-window-seconds"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("refusal lacks %q: %s", want, stderr.String())
		}
	}
}

func TestRevealCeremonyHandsBackTheRefusalWithoutReveal(t *testing.T) {
	handler, _ := ceremonyServer(t, apigen.RevealWindow{CanReveal: false, EffectiveWindowSeconds: 300, TotpOffered: true})
	ios, _, stderr := definitionsTestIO(t, handler)
	ios.ReadPassword = func(string) (string, error) {
		t.Fatal("a principal without reveal must not be offered a ceremony")
		return "", nil
	}
	if code := cli.Run(t.Context(), ios, revealArgs()); code != cli.ExitRefused {
		t.Fatalf("exit %d, want refused; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "not permitted") {
		t.Errorf("the server's own refusal was replaced: %s", stderr.String())
	}
}

func TestRevealCeremonyCoversExport(t *testing.T) {
	handler, _ := ceremonyServer(t, apigen.RevealWindow{CanReveal: true, EffectiveWindowSeconds: 300, TotpOffered: true})
	ios, stdout, stderr := definitionsTestIO(t, handler)
	ios.ReadPassword = func(string) (string, error) { return "123456", nil }
	args := []string{"values", "export", "--reveal", "--format", "dotenv", "--dangerously-print",
		"--instance", "local", "--org", "org_70", "--project", "prj_70", "--env", "env_70"}
	if code := cli.Run(t.Context(), ios, args); code != cli.ExitOK {
		t.Fatalf("exit %d, want ok; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "DATABASE_PASSWORD=s3cret") {
		t.Fatalf("export did not carry the revealed value after the ceremony: %q", stdout.String())
	}
}

// A 0-window environment hands off to the browser's purpose-bound,
// enumerated-key-set ceremony: the CLI resolves the unit (the secret keys the
// act opens), starts a disclosure-purpose handoff carrying it, opens the
// browser, redeems the code for a rotated bearer, and runs the disclosure
// under it. The bearer never reaches stdout/stderr.
func TestRevealCeremonyHandsOffToTheBrowserAtZeroWindow(t *testing.T) {
	const rotated = "hik_1_cli_handoff-rotated"
	live := false
	var callbackURI string
	var startBody map[string]any
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/reveal-window"):
			_ = json.NewEncoder(w).Encode(apigen.RevealWindow{CanReveal: true, Protected: true, EffectiveWindowSeconds: 0, Live: live})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/environments/env_70/values"):
			_ = json.NewEncoder(w).Encode(apigen.ValueList{Items: []apigen.ValueCell{
				{Name: "DATABASE_PASSWORD", Classification: "secret", KeyId: "key_pw", Set: true},
				{Name: "LOG_LEVEL", Classification: "config", KeyId: "key_ll", Set: true},
			}})
		case strings.HasSuffix(r.URL.Path, "/auth/cli-reauth/start"):
			_ = json.NewDecoder(r.Body).Decode(&startBody)
			callbackURI, _ = startBody["redirect_uri"].(string)
			_, _ = w.Write([]byte(`{"state":"hik_1_hs_reveal","expires_at":"2030-01-01T00:00:00Z"}`))
		case strings.HasSuffix(r.URL.Path, "/auth/cli-reauth/redeem"):
			live = true
			_, _ = w.Write([]byte(`{"session_id":"ses_handoff","session_token":"` + rotated + `","windows":[{"environment_id":"env_70","session_id":"ses_handoff","single_decision":true,"window_expires":"2030-01-01T00:00:00Z"}]}`))
		case strings.HasSuffix(r.URL.Path, "/values/DATABASE_PASSWORD/reveal"):
			if !live || !strings.Contains(r.Header.Get("Authorization"), rotated) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":{"code":"forbidden","message":"not permitted"}}`))
				return
			}
			v := "s3cret"
			_ = json.NewEncoder(w).Encode(apigen.ValueCell{Name: "DATABASE_PASSWORD", Classification: "secret", KeyId: "key_pw", Set: true, Revealed: true, Value: &v})
		default:
			http.NotFound(w, r)
		}
	})
	ios, stdout, stderr := definitionsTestIO(t, handler)
	ios.ReadPassword = func(string) (string, error) { t.Fatal("a 0-window handoff must not prompt for a code"); return "", nil }
	ios.OpenURL = func(browserURL string) error {
		if !strings.Contains(browserURL, "/reauth/cli?transaction=hik_1_hs_reveal") {
			t.Errorf("browser opened at %q", browserURL)
		}
		go func() {
			resp, _ := http.Get(callbackURI + "?code=hik_1_hc_reveal&state=hik_1_hs_reveal")
			if resp != nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
	if code := cli.Run(t.Context(), ios, revealArgs()); code != cli.ExitOK {
		t.Fatalf("exit %d, want ok; stderr=%s", code, stderr.String())
	}
	if startBody["purpose"] != "reveal" || startBody["operation"] != "value.reveal" {
		t.Fatalf("handoff started with purpose=%v operation=%v", startBody["purpose"], startBody["operation"])
	}
	keys, _ := startBody["key_ids"].([]any)
	if len(keys) != 1 || keys[0] != "key_pw" {
		t.Fatalf("handoff bound key set %v, want exactly the one secret key the act opens", keys)
	}
	if !strings.Contains(stdout.String(), "s3cret") {
		t.Fatalf("the disclosure did not run under the redeemed bearer: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), rotated) || strings.Contains(stderr.String(), rotated) {
		t.Fatal("the rotated bearer reached command output")
	}
}

// A sliding window on an account WITHOUT an authenticator: the inline prompt
// would be a dead end, so the CLI hands off to the browser, whose page offers
// the passkey (and no code).
func TestRevealCeremonyHandsOffWhenNoAuthenticatorIsEnrolled(t *testing.T) {
	var started bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/reveal-window"):
			_ = json.NewEncoder(w).Encode(apigen.RevealWindow{CanReveal: true, EffectiveWindowSeconds: 300, TotpOffered: true, Live: started})
		case strings.HasSuffix(r.URL.Path, "/auth/totp"):
			_ = json.NewEncoder(w).Encode(apigen.TotpStatus{Confirmed: false})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/environments/env_70/values"):
			_ = json.NewEncoder(w).Encode(apigen.ValueList{Items: []apigen.ValueCell{{Name: "DATABASE_PASSWORD", Classification: "secret", KeyId: "key_pw", Set: true}}})
		case strings.HasSuffix(r.URL.Path, "/auth/cli-reauth/start"):
			started = true
			// The handoff began; the test needs no browser round trip to prove
			// the dispatch, so it ends the flow here with a refusal.
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":{"code":"conflict","message":"the current state of this resource refuses the request"}}`))
		case strings.HasSuffix(r.URL.Path, "/values/DATABASE_PASSWORD/reveal"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"code":"forbidden","message":"not permitted"}}`))
		default:
			http.NotFound(w, r)
		}
	})
	ios, _, stderr := definitionsTestIO(t, handler)
	ios.ReadPassword = func(string) (string, error) {
		t.Fatal("no authenticator is enrolled: a code prompt is a dead end")
		return "", nil
	}
	ios.OpenURL = func(string) error { t.Fatal("the handoff was refused at start; the browser must not open"); return nil }
	_ = cli.Run(t.Context(), ios, revealArgs())
	if !started {
		t.Fatalf("no handoff was started for an account without an authenticator; stderr=%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "no authenticator is enrolled") {
		t.Errorf("the reason was not named: %s", stderr.String())
	}
}
