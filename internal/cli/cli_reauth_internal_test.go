package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAdapterCreateCeremonyPrecedesSecretInputAndMutationDispatch(t *testing.T) {
	const (
		oldBearer = "old-session-secret"
		newBearer = "rotated-session-secret"
		handoff   = "hik_1_hs_create-order"
	)
	var mu sync.Mutex
	order := []string{}
	record := func(step string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, step)
	}
	var callbackURI string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/cli-reauth/start":
			record("start")
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				return
			}
			callbackURI, _ = body["redirect_uri"].(string)
			_, _ = io.WriteString(w, `{"state":"`+handoff+`","expires_at":"2030-01-01T00:00:00Z"}`)
		case "/api/v1/auth/cli-reauth/redeem":
			record("redeem")
			_, _ = io.WriteString(w, `{"session_id":"ses_new","session_token":"`+newBearer+`","windows":[]}`)
		case "/api/v1/orgs/org_one/projects/prj_one/adapters":
			record("create")
			if r.Header.Get("Authorization") != "Bearer "+newBearer {
				t.Errorf("create used bearer %q", r.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				return
			}
			if body["credential"] != "forgejo-pat" {
				t.Errorf("credential=%v", body["credential"])
			}
			_, _ = io.WriteString(w, `{"authority_principal_id":"usr_one","created_at":"2026-08-17T22:00:00Z","credential_present":true,"id":"adp_one","origin":"https://forgejo.example","provider":"forgejo","state":"active","targets":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	stateDir := t.TempDir()
	st := &State{dir: stateDir}
	if err := st.Trust().Put(TrustEntry{Name: "local", Origin: server.URL}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutSession(SessionArtifact{Instance: "local", Origin: server.URL, Token: oldBearer, SessionID: "ses_old", Principal: "usr_one", ExpiresAt: "2030-01-01T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	ios := IO{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
		Env: Env{Getenv: func(name string) string {
			if name == "HIKYO_STATE_DIR" {
				return stateDir
			}
			return ""
		}},
		ReadPassword: func(string) (string, error) {
			record("secret")
			return "forgejo-pat", nil
		},
		OpenURL: func(browserURL string) error {
			record("open")
			if parsed, err := url.Parse(browserURL); err != nil || parsed.Path != "/reauth/cli" || parsed.Query().Get("transaction") != handoff {
				return io.ErrUnexpectedEOF
			}
			go func() {
				response, _ := http.Get(callbackURI + "?code=hik_1_hc_create&state=" + url.QueryEscape(handoff))
				if response != nil {
					_ = response.Body.Close()
				}
			}()
			return nil
		},
	}
	code := Run(t.Context(), ios, []string{"adapter", "create", "--instance", "local", "--org", "org_one", "--project", "prj_one", "--env", "env_one", "--origin", "https://forgejo.example", "--kind", "repository", "--owner", "team", "--repo", "app", "--keys", "key_one"})
	if code != ExitOK {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(order, ","); got != "start,open,redeem,secret,create" {
		t.Fatalf("ordering=%s", got)
	}
	if strings.Contains(stdout.String(), oldBearer) || strings.Contains(stdout.String(), newBearer) || strings.Contains(stderr.String(), oldBearer) || strings.Contains(stderr.String(), newBearer) {
		t.Fatal("a bearer reached command output")
	}
}

func TestAdapterTargetNarrowingSkipsCeremonyAndUsesSynchronousTargetResponse(t *testing.T) {
	const bearer = "session-secret"
	var getCount, patchCount, openCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+bearer {
			t.Errorf("authorization=%q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/orgs/org_one/projects/prj_one/adapter-targets/tgt_one":
			getCount++
			_, _ = io.WriteString(w, `{"target":{"id":"tgt_one","adapter_id":"adp_one","environment_id":"env_one","destination_kind":"repository","destination_owner":"team","destination_name":"app","destination_id":42,"name_prefix":"PROD_","generation":1,"state":"active","sync_status":"converged","converged_revision":7,"failure_names":[]},"mapping":[{"key_id":"key_one","canonical_name":"ONE","surface":"secret","effective_name":"PROD_ONE"},{"key_id":"key_two","canonical_name":"TWO","surface":"secret","effective_name":"PROD_TWO"}],"conflicts":[]}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/orgs/org_one/projects/prj_one/adapter-targets/tgt_one":
			patchCount++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				return
			}
			keys, _ := body["key_ids"].([]any)
			if len(keys) != 1 || keys[0] != "key_one" || body["expected_generation"] != float64(1) {
				t.Errorf("patch body=%v", body)
			}
			_, _ = io.WriteString(w, `{"id":"tgt_one","adapter_id":"adp_one","environment_id":"env_one","destination_kind":"repository","destination_owner":"team","destination_name":"app","destination_id":42,"name_prefix":"PROD_","generation":2,"state":"active","sync_status":"converging","converged_revision":7,"failure_names":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	stateDir := t.TempDir()
	st := &State{dir: stateDir}
	if err := st.Trust().Put(TrustEntry{Name: "local", Origin: server.URL}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutSession(SessionArtifact{Instance: "local", Origin: server.URL, Token: bearer, SessionID: "ses_one", Principal: "usr_one", ExpiresAt: "2030-01-01T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run(t.Context(), IO{
		Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
		Env: Env{Getenv: func(name string) string {
			if name == "HIKYO_STATE_DIR" {
				return stateDir
			}
			return ""
		}},
		OpenURL: func(string) error { openCount++; return errors.New("ceremony must not run") },
	}, []string{"adapter", "update", "adp_one", "--instance", "local", "--org", "org_one", "--project", "prj_one", "--env", "env_one", "--target", "tgt_one", "--kind", "repository", "--owner", "team", "--repo", "app", "--prefix", "PROD_", "--keys", "key_one"})
	if code != ExitOK {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if getCount != 1 || patchCount != 1 || openCount != 0 {
		t.Fatalf("get=%d patch=%d open=%d", getCount, patchCount, openCount)
	}
	if !strings.Contains(stdout.String(), "converging") || strings.Contains(stdout.String(), "MOVE") {
		t.Fatalf("target response output=%q", stdout.String())
	}
}

func TestAdapterTargetMutationCLIAPIParity(t *testing.T) {
	tests := []struct {
		name        string
		destination string
		status      int
		response    string
		wantOutput  string
	}{
		{
			name: "metadata update", destination: "app", status: http.StatusOK,
			response:   `{"id":"tgt_one","adapter_id":"adp_one","environment_id":"env_one","destination_kind":"repository","destination_owner":"team","destination_name":"app","destination_id":42,"name_prefix":"NEXT_","generation":2,"state":"active","sync_status":"converging","failure_names":[]}`,
			wantOutput: "converging",
		},
		{
			name: "move started", destination: "next", status: http.StatusAccepted,
			response:   `{"id":"mov_one","adapter_id":"adp_one","kind":"target","state":"scrubbing","keep_remote":false,"pending_origin":"","targets":[{"target_id":"tgt_one","environment_id":"env_one","destination_kind":"repository","destination_owner":"team","destination_name":"next","visibility":"","selected_repository_ids":[],"name_prefix":"NEXT_","key_ids":["key_one"],"jobs":[],"orphaned_names":[]}],"created_at":"2026-08-17T00:00:00Z"}`,
			wantOutput: "mov_one",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var patchCount int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/v1/orgs/org_one/projects/prj_one/adapter-targets/tgt_one":
					_, _ = io.WriteString(w, `{"target":{"id":"tgt_one","adapter_id":"adp_one","environment_id":"env_one","destination_kind":"repository","destination_owner":"team","destination_name":"app","destination_id":42,"name_prefix":"PROD_","generation":1,"state":"active","sync_status":"converged","failure_names":[]},"mapping":[{"key_id":"key_one","canonical_name":"ONE","surface":"secret","effective_name":"PROD_ONE"}],"conflicts":[]}`)
				case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/orgs/org_one/projects/prj_one/adapter-targets/tgt_one":
					patchCount++
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
						return
					}
					if body["destination_name"] != tt.destination || body["expected_generation"] != float64(1) {
						t.Errorf("patch body=%v", body)
					}
					if _, ok := body["move"]; ok {
						t.Errorf("transport supplied move decision: %v", body)
					}
					w.WriteHeader(tt.status)
					_, _ = io.WriteString(w, tt.response)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			stateDir := t.TempDir()
			st := &State{dir: stateDir}
			if err := st.Trust().Put(TrustEntry{Name: "local", Origin: server.URL}); err != nil {
				t.Fatal(err)
			}
			if err := st.PutSession(SessionArtifact{Instance: "local", Origin: server.URL, Token: "session-secret", SessionID: "ses_one", Principal: "usr_one", ExpiresAt: "2030-01-01T00:00:00Z"}); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := Run(t.Context(), IO{
				Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
				Env: Env{Getenv: func(name string) string {
					if name == "HIKYO_STATE_DIR" {
						return stateDir
					}
					return ""
				}},
			}, []string{"adapter", "update", "adp_one", "--instance", "local", "--org", "org_one", "--project", "prj_one", "--env", "env_one", "--target", "tgt_one", "--kind", "repository", "--owner", "team", "--repo", tt.destination, "--prefix", "NEXT_", "--keys", "key_one"})
			if code != ExitOK || patchCount != 1 || !strings.Contains(stdout.String(), tt.wantOutput) {
				t.Fatalf("exit=%d patches=%d stdout=%q stderr=%q", code, patchCount, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunCLIAdapterReauthBindsExactLoopbackStateAndSilentlyRotatesBearer(t *testing.T) {
	const (
		oldBearer = "old-session-secret"
		newBearer = "rotated-session-secret"
		handoff   = "hik_1_hs_opaque-browser-state"
		code      = "hik_1_hc_single-use-code"
	)
	var redirect, challenge string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+oldBearer {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/cli-reauth/start":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			redirect, _ = body["redirect_uri"].(string)
			challenge, _ = body["pkce_challenge"].(string)
			parsed, err := url.Parse(redirect)
			if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.Path != "/callback" || parsed.Port() == "" || parsed.RawQuery != "" {
				t.Fatalf("redirect_uri=%q err=%v", redirect, err)
			}
			if body["purpose"] != "adapter" || body["operation"] != "adapter.sync" {
				t.Fatalf("start body=%v", body)
			}
			_, _ = io.WriteString(w, `{"state":"`+handoff+`","expires_at":"2030-01-01T00:00:00Z"}`)
		case "/api/v1/auth/cli-reauth/redeem":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["code"] != code || body["pkce_verifier"] == "" || challenge == "" {
				t.Fatalf("redeem body=%v challenge=%q", body, challenge)
			}
			_, _ = io.WriteString(w, `{"session_id":"ses_019c1234-1234-7123-8123-123456789abc","session_token":"`+newBearer+`","windows":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	state := &State{dir: t.TempDir()}
	artifact := SessionArtifact{Instance: "local", Origin: server.URL, Token: oldBearer, SessionID: "ses_old", Principal: "prn_test", ExpiresAt: "2030-01-01T00:00:00Z"}
	if err := state.PutSession(artifact); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(TrustEntry{Name: "local", Origin: server.URL}, oldBearer)
	if err != nil {
		t.Fatal(err)
	}
	opened := make(chan string, 1)
	opener := func(browserURL string) error {
		opened <- browserURL
		parsed, err := url.Parse(browserURL)
		if err != nil {
			return err
		}
		if parsed.Path != "/reauth/cli" || parsed.Query().Get("transaction") != handoff || len(parsed.Query()) != 1 || strings.Contains(browserURL, oldBearer) || strings.Contains(browserURL, newBearer) {
			return io.ErrUnexpectedEOF
		}
		go func() {
			wrong, _ := http.Get(redirect + "?code=" + url.QueryEscape(code) + "&state=wrong")
			if wrong != nil {
				_ = wrong.Body.Close()
			}
			valid, _ := http.Get(redirect + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(handoff))
			if valid != nil {
				_ = valid.Body.Close()
			}
		}()
		return nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := runCLIAdapterReauth(ctx, client, state, artifact, "adapter.sync", []string{"env_one"}, opener); err != nil {
		t.Fatal(err)
	}
	select {
	case browserURL := <-opened:
		if strings.Contains(browserURL, "verifier") || strings.Contains(browserURL, "bearer") {
			t.Fatalf("browser URL disclosed credential material: %s", browserURL)
		}
	default:
		t.Fatal("browser was not opened")
	}
	sessions, err := state.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	if sessions["local"].Token != newBearer || client.Bearer != newBearer {
		t.Fatalf("bearer was not silently rotated: stored=%q live=%q", sessions["local"].Token, client.Bearer)
	}
}

func TestCLIReauthCallbackQueryIsClosedAndExact(t *testing.T) {
	state := "hik_1_hs_opaque"
	if !exactCallbackQuery(url.Values{"code": {"one"}, "state": {state}}, state) {
		t.Fatal("exact code and state were refused")
	}
	for _, invalid := range []url.Values{
		{"code": {"one"}, "state": {"wrong"}},
		{"code": {"one"}, "state": {state}, "next": {"evil"}},
		{"code": {"one", "two"}, "state": {state}},
		{"code": {""}, "state": {state}},
	} {
		if exactCallbackQuery(invalid, state) {
			t.Fatalf("invalid callback accepted: %v", invalid)
		}
	}
}

func TestRedeemCLIReauthSilentlyReplacesStoredBearer(t *testing.T) {
	const (
		oldBearer = "old-session-secret"
		newBearer = "rotated-session-secret"
		verifier  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+oldBearer {
			t.Fatalf("authorization=%q", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["code"] != "single-use-code" || body["pkce_verifier"] != verifier {
			t.Fatalf("redeem body=%v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session_id":"ses_019c1234-1234-7123-8123-123456789abc","session_token":"` + newBearer + `","windows":[]}`))
	}))
	defer server.Close()

	state := &State{dir: t.TempDir()}
	artifact := SessionArtifact{Instance: "local", Origin: server.URL, Token: oldBearer, SessionID: "ses_old", Principal: "prn_test", ExpiresAt: "2030-01-01T00:00:00Z"}
	if err := state.PutSession(artifact); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(TrustEntry{Name: "local", Origin: server.URL}, oldBearer)
	if err != nil {
		t.Fatal(err)
	}
	if err := redeemCLIReauth(t.Context(), client, state, artifact, "single-use-code", []byte(verifier)); err != nil {
		t.Fatal(err)
	}

	sessions, err := state.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	stored := sessions["local"]
	if stored.Token != newBearer || stored.SessionID != "ses_019c1234-1234-7123-8123-123456789abc" {
		t.Fatalf("stored session was not rotated: %+v", stored)
	}
	if client.Bearer != newBearer {
		t.Fatalf("live client bearer=%q", client.Bearer)
	}
	raw, err := json.Marshal(struct {
		Stored SessionArtifact
		Client string
	}{Stored: stored, Client: client.Bearer})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), oldBearer) {
		t.Fatalf("old bearer remained after rotation: %s", raw)
	}
}
