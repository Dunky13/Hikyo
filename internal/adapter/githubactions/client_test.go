package githubactions

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
)

type staticNetworkResolver []netip.Addr

func (r staticNetworkResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r...), nil
}

type recordingNetworkDialer struct{ attempts []string }

func (d *recordingNetworkDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.attempts = append(d.attempts, address)
	client, server := net.Pipe()
	server.Close()
	return client, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func response(status int, body string, headers ...http.Header) *http.Response {
	header := http.Header{}
	if len(headers) != 0 {
		header = headers[0]
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}
}

func TestClientRefusesClassicPATBeforeProviderContact(t *testing.T) {
	if _, err := NewTestClient("https://api.github.com", "ghp_classic", &http.Client{}); err == nil || !strings.Contains(err.Error(), "classic") {
		t.Fatalf("NewTestClient() = %v, want named classic PAT refusal", err)
	}
}

func TestClientRetainsProviderPolicyOutsidePublicDialer(t *testing.T) {
	client, err := NewClient(ClientConfig{
		Origin:     "https://api.github.com",
		Credential: "github_pat_transport_policy",
		Deadline:   15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Forget)
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.http.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("GitHub Actions transport unexpectedly accepted an ambient or opaque proxy")
	}
	if transport.DialContext == nil {
		t.Fatal("GitHub Actions transport omitted the public-address dialer")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS policy = %#v, want TLS 1.2 minimum", transport.TLSClientConfig)
	}
	if err := client.http.CheckRedirect(&http.Request{}, nil); err == nil || !strings.Contains(err.Error(), "redirects are refused") {
		t.Fatalf("redirect policy error = %v, want provider-specific refusal", err)
	}
}

func TestClientRoutesAllowedAndMixedAnswersThroughPublicDialer(t *testing.T) {
	allowedDialer := &recordingNetworkDialer{}
	client, err := newClient(ClientConfig{
		Origin:       "https://api.github.com",
		Credential:   "github_pat_allowed_network",
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.24.0.0/16")},
		Deadline:     15 * time.Second,
	}, staticNetworkResolver{netip.MustParseAddr("10.24.3.9")}, allowedDialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Forget)
	transport := client.http.Transport.(*http.Transport)
	conn, err := transport.DialContext(t.Context(), "tcp", "api.github.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if want := []string{"10.24.3.9:443"}; !slices.Equal(allowedDialer.attempts, want) {
		t.Fatalf("allowed dial attempts = %v, want %v", allowedDialer.attempts, want)
	}

	mixedDialer := &recordingNetworkDialer{}
	mixed, err := newClient(ClientConfig{
		Origin: "https://api.github.com", Credential: "github_pat_mixed_network", Deadline: 15 * time.Second,
	}, staticNetworkResolver{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, mixedDialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mixed.Forget)
	transport = mixed.http.Transport.(*http.Transport)
	if _, err := transport.DialContext(t.Context(), "tcp", "api.github.com:443"); err == nil {
		t.Fatal("mixed public/private resolution unexpectedly dialed")
	}
	if len(mixedDialer.attempts) != 0 {
		t.Fatalf("mixed-answer dial attempts = %v, want none", mixedDialer.attempts)
	}
}

func TestClientRejectsInvalidAllowedCIDRAtConstruction(t *testing.T) {
	_, err := NewClient(ClientConfig{
		Origin: "https://api.github.com", Credential: "github_pat_invalid_network", AllowedCIDRs: []netip.Prefix{{}}, Deadline: 15 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid allowed CIDR") {
		t.Fatalf("NewClient() error = %v, want invalid-CIDR refusal", err)
	}
}

func resetCredentialStatesForTest(t *testing.T) {
	t.Helper()
	credentialStates.Lock()
	credentialStates.entries = map[[32]byte]*credentialState{}
	credentialStates.Unlock()
	t.Cleanup(func() {
		credentialStates.Lock()
		credentialStates.entries = map[[32]byte]*credentialState{}
		credentialStates.Unlock()
	})
}

func TestSequentialProductionClientsRetainCredentialPacingWithoutRawTokenKey(t *testing.T) {
	resetCredentialStatesForTest(t)
	first, err := NewClient(ClientConfig{Origin: "https://api.github.com", Credential: "github_pat_shared", Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.pacer.Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	firstState := first.credentialState
	first.Forget()
	second, err := NewClient(ClientConfig{Origin: "https://api.github.com", Credential: "github_pat_shared", Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewClient(ClientConfig{Origin: "https://api.github.com", Credential: "github_pat_other", Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if firstState != second.credentialState || firstState == other.credentialState {
		t.Fatalf("credential states first=%p second=%p other=%p", firstState, second.credentialState, other.credentialState)
	}
	waitCtx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := second.pacer.Wait(waitCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("sequential client mutation was not held behind shared >=1s pace: %v", err)
	}
	second.Forget()
	other.Forget()
	credentialStates.Lock()
	defer credentialStates.Unlock()
	if len(credentialStates.entries) != 2 {
		t.Fatalf("credential state registry entries=%d, want hashed retained states", len(credentialStates.entries))
	}
}

func TestCredentialStateEvictsAfterBoundedStaleWindow(t *testing.T) {
	resetCredentialStatesForTest(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	clock := func() time.Time { return now }
	_, release := acquireCredentialState("github_pat_stale", clock)
	release()
	staleKey := crypto.CredentialFingerprint([]byte("github_pat_stale"))
	now = now.Add(credentialStateTTL)
	_, release = acquireCredentialState("github_pat_fresh", clock)
	release()
	credentialStates.Lock()
	defer credentialStates.Unlock()
	if _, retained := credentialStates.entries[staleKey]; retained {
		t.Fatal("stale hashed credential state survived bounded eviction window")
	}
}

func TestCredentialStateAtCapacityRetainsReloadedCredential(t *testing.T) {
	resetCredentialStatesForTest(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	clock := func() time.Time { return now }
	wantedKey := crypto.CredentialFingerprint([]byte("github_pat_wanted"))
	wanted := &credentialState{pacer: &serialPacer{now: clock}, lastUsed: now}
	credentialStates.Lock()
	credentialStates.entries[wantedKey] = wanted
	for i := 1; i < maxCredentialStates; i++ {
		key := crypto.CredentialFingerprint([]byte(fmt.Sprintf("github_pat_%d", i)))
		credentialStates.entries[key] = &credentialState{pacer: &serialPacer{now: clock}, lastUsed: now.Add(time.Duration(i) * time.Nanosecond)}
	}
	credentialStates.Unlock()
	got, release := acquireCredentialState("github_pat_wanted", clock)
	release()
	if got != wanted {
		t.Fatal("capacity eviction discarded the credential state being reloaded")
	}
}

func TestEnvironmentPathsEncodeEachSegmentExactlyOnce(t *testing.T) {
	var got string
	client, err := NewTestClient("https://api.github.com", "github_pat_fine", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		got = req.URL.EscapedPath()
		return response(http.StatusOK, `{"id":73}`), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	destination := adapter.Destination{Kind: adapter.Environment, Owner: "team", Name: "repo", Environment: "prod/100%"}
	if _, err := client.ResolveDestination(t.Context(), destination); err != nil {
		t.Fatal(err)
	}
	if want := "/repos/team/repo/environments/prod%2F100%25"; got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

func TestEnvironmentDestinationPinsRepositoryBeforeEnvironment(t *testing.T) {
	var paths []string
	client, err := NewTestClient("https://api.github.com", "github_pat_fine", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.EscapedPath())
		if len(paths) == 1 {
			return response(http.StatusOK, `{"id":41}`), nil
		}
		return response(http.StatusOK, `{"id":73}`), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	destination := adapter.Destination{Kind: adapter.Environment, Owner: "team", Name: "repo", Environment: "prod", RepositoryID: 42}
	if _, err := client.ResolveDestination(t.Context(), destination); !errors.Is(err, adapter.ErrDestinationID) {
		t.Fatalf("ResolveDestination() = %v, want repository identity refusal", err)
	}
	if len(paths) != 1 || paths[0] != "/repos/team/repo" {
		t.Fatalf("paths = %v; environment lookup must not follow repo mismatch", paths)
	}
}

func TestCreateEnvironmentUsesSettingsFreePut(t *testing.T) {
	var method, path, body string
	client, err := NewTestClient("https://api.github.com", "github_pat_fine", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		method, path = req.Method, req.URL.EscapedPath()
		var raw []byte
		if req.Body != nil {
			raw, _ = io.ReadAll(req.Body)
		}
		body = string(raw)
		return response(http.StatusOK, `{}`), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	err = client.CreateEnvironment(t.Context(), adapter.Destination{Kind: adapter.Environment, Owner: "team", Name: "repo", Environment: "prod"})
	if err != nil || method != http.MethodPut || path != "/repos/team/repo/environments/prod" || body != "{}" {
		t.Fatalf("CreateEnvironment() err=%v request=%s %s %q", err, method, path, body)
	}
}

func TestClientCapturesCredentialExpirationHeaderWithoutCredentialInspection(t *testing.T) {
	client, err := NewTestClient("https://api.github.com", "github_pat_fine", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := response(http.StatusOK, `{"id":42}`)
		response.Header.Set("GitHub-Authentication-Token-Expiration", "2026-09-30 12:34:56 UTC")
		return response, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ResolveDestination(t.Context(), adapter.Destination{Kind: adapter.Repository, Owner: "team", Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 9, 30, 12, 34, 56, 0, time.UTC)
	if got := client.CredentialExpiresAt(); !got.Equal(want) {
		t.Fatalf("CredentialExpiresAt() = %s, want %s", got, want)
	}
}

func TestSelectedRepositoriesAreVerifiedByIDAndFullyReplaced(t *testing.T) {
	var requests []string
	client, err := NewTestClient("https://api.github.com", "github_pat_fine", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var raw []byte
		if req.Body != nil {
			raw, _ = io.ReadAll(req.Body)
		}
		requests = append(requests, req.Method+" "+req.URL.EscapedPath()+" "+string(raw))
		if req.Method == http.MethodGet {
			return response(http.StatusOK, `{"id":11,"owner":{"login":"acme"}}`), nil
		}
		return response(http.StatusNoContent, ``), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	destination := adapter.Destination{Kind: adapter.Organization, Owner: "acme", Visibility: "selected", SelectedRepositoryIDs: []int64{11}}
	if err := client.VerifySelectedRepositories(t.Context(), destination); err != nil {
		t.Fatal(err)
	}
	if err := client.ReplaceSelectedRepositories(t.Context(), destination, adapter.Secret, "TOKEN"); err != nil {
		t.Fatal(err)
	}
	want := []string{"GET /repositories/11 ", `PUT /orgs/acme/actions/secrets/TOKEN/repositories {"selected_repository_ids":[11]}`}
	if !slices.Equal(requests, want) {
		t.Fatalf("requests = %v, want %v", requests, want)
	}
}

func TestSelectedRepositoryIDsAreOnlySentToReplacementEndpoint(t *testing.T) {
	destination := adapter.Destination{Kind: adapter.Organization, Owner: "acme", Visibility: "selected", SelectedRepositoryIDs: []int64{11}}
	secret := secretBody(destination, "sealed", "key")
	variable := variableBody(destination, "MODE", "safe", true)
	for name, body := range map[string]map[string]any{"secret": secret, "variable": variable} {
		if _, present := body["selected_repository_ids"]; present {
			t.Fatalf("%s primary body redundantly contains selected_repository_ids: %#v", name, body)
		}
		if body["visibility"] != "selected" {
			t.Fatalf("%s primary body lost visibility: %#v", name, body)
		}
	}
}

func TestSecretListingIsExhaustiveAndFailsClosed(t *testing.T) {
	pages := 0
	client, err := NewTestClient("https://api.github.com", "github_pat_fine", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		pages++
		if pages == 1 {
			rows := make([]map[string]string, 100)
			for i := range rows {
				rows[i] = map[string]string{"name": "KEY"}
			}
			raw, _ := json.Marshal(map[string]any{"total_count": 101, "secrets": rows})
			return response(http.StatusOK, string(raw)), nil
		}
		if pages == 2 {
			return response(http.StatusOK, `{"total_count":101,"secrets":[{"name":"LATE_CONFLICT"}]}`), nil
		}
		return response(http.StatusInternalServerError, `{}`), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	names, err := client.ListSecretNames(t.Context(), adapter.Destination{Kind: adapter.Repository, Owner: "team", Name: "repo"})
	if err != nil || len(names) != 101 || names[100] != "LATE_CONFLICT" || pages != 2 {
		t.Fatalf("ListSecretNames() = %v, %v after %d pages", names, err, pages)
	}
}

func TestProviderSurfaceHasNoVariableReadOperation(t *testing.T) {
	typeOf := reflect.TypeOf((*API)(nil)).Elem()
	got := make([]string, 0, typeOf.NumMethod())
	for i := range typeOf.NumMethod() {
		got = append(got, typeOf.Method(i).Name)
	}
	want := []string{"CreateEnvironment", "CreateVariable", "DeleteSecret", "DeleteVariable", "ListSecretNames", "PublicKey", "PutSecret", "ReplaceSelectedRepositories", "ResolveDestination", "UpdateVariable", "VerifySelectedRepositories"}
	if !slices.Equal(got, want) {
		t.Fatalf("linked GitHub API operations = %v, want closed value-blind set %v", got, want)
	}
	for name, op := range operationRegistry {
		if strings.Contains(name, "variable") && op.Method == http.MethodGet {
			t.Fatalf("variable read linked: %s %+v", name, op)
		}
	}
}

func TestSecretWriteSendsCiphertextAndKeyIDOnly(t *testing.T) {
	var got map[string]any
	client, err := NewTestClient("https://api.github.com", "github_pat_fine", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(req.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return response(http.StatusCreated, ``), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.PutSecret(t.Context(), adapter.Destination{Kind: adapter.Repository, Owner: "team", Name: "repo"}, "TOKEN", "sealed", "kid")
	if err != nil || result.Status != http.StatusCreated {
		t.Fatalf("PutSecret() = %+v, %v", result, err)
	}
	if got["encrypted_value"] != "sealed" || got["key_id"] != "kid" || len(got) != 2 {
		t.Fatalf("body = %#v", got)
	}
}

func TestRateLimitDecisionTreeCarriesRetryDeadline(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	tests := []struct {
		name    string
		status  int
		headers http.Header
		want    time.Time
	}{
		{name: "retry-after", status: 429, headers: http.Header{"Retry-After": []string{"7"}}, want: now.Add(7 * time.Second)},
		{name: "reset", status: 403, headers: http.Header{"X-Ratelimit-Remaining": []string{"0"}, "X-Ratelimit-Reset": []string{"1800000011"}}, want: now.Add(11 * time.Second)},
		{name: "headerless secondary", status: 403, headers: http.Header{}, want: now.Add(time.Minute)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := newTestClientAt("https://api.github.com", "github_pat_fine", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response(tt.status, `{}`, tt.headers), nil
			})}, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.ResolveDestination(context.Background(), adapter.Destination{Kind: adapter.Repository, Owner: "team", Name: "repo"})
			got, ok := adapter.ProviderRetryAt(err)
			if !ok || !got.Equal(tt.want) {
				t.Fatalf("retry = %s, %v from %v; want %s", got, ok, err, tt.want)
			}
		})
	}
}

func TestPermissionHeaderKeeps403OutOfRateBranch(t *testing.T) {
	client, err := NewTestClient("https://api.github.com", "github_pat_fine", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusForbidden, `{}`, http.Header{"X-Accepted-GitHub-Permissions": []string{"administration=write"}}), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	err = client.CreateEnvironment(t.Context(), adapter.Destination{Kind: adapter.Environment, Owner: "team", Name: "repo", Environment: "prod"})
	if !IsStatus(err, http.StatusForbidden) {
		t.Fatalf("CreateEnvironment() = %v, want permission refusal", err)
	}
	if _, ok := adapter.ProviderRetryAt(err); ok {
		t.Fatal("permission refusal was misclassified as rate limit")
	}
}

func TestHeaderlessRateFallbackExponentiatesAndCaps(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	client, err := newTestClientAt("https://api.github.com", "github_pat_fine", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusTooManyRequests, `{}`), nil
	})}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour}
	for i, delay := range want {
		_, err := client.ResolveDestination(t.Context(), adapter.Destination{Kind: adapter.Repository, Owner: "team", Name: "repo"})
		at, ok := adapter.ProviderRetryAt(err)
		if !ok || !at.Equal(now.Add(delay)) {
			t.Fatalf("attempt %d retry=%s,%v want %s", i+1, at, ok, now.Add(delay))
		}
	}
}

func TestHeaderlessRateExponentSurvivesClientReloadAndSuccessResetsIt(t *testing.T) {
	resetCredentialStatesForTest(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	clock := func() time.Time { return now }
	state, release := acquireCredentialState("github_pat_reload", clock)
	first, err := newTestClientAt("https://api.github.com", "github_pat_reload", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusTooManyRequests, `{}`), nil
	})}, clock)
	if err != nil {
		t.Fatal(err)
	}
	first.credentialState = state
	if _, err := first.ResolveDestination(t.Context(), adapter.Destination{Kind: adapter.Repository, Owner: "team", Name: "repo"}); err == nil {
		t.Fatal("first headerless rate response succeeded")
	} else if at, ok := adapter.ProviderRetryAt(err); !ok || !at.Equal(now.Add(time.Minute)) {
		t.Fatalf("first retry=%s,%v want +1m", at, ok)
	}
	release()

	state, release = acquireCredentialState("github_pat_reload", clock)
	second, err := newTestClientAt("https://api.github.com", "github_pat_reload", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusTooManyRequests, `{}`), nil
	})}, clock)
	if err != nil {
		t.Fatal(err)
	}
	second.credentialState = state
	if _, err := second.ResolveDestination(t.Context(), adapter.Destination{Kind: adapter.Repository, Owner: "team", Name: "repo"}); err == nil {
		t.Fatal("second headerless rate response succeeded")
	} else if at, ok := adapter.ProviderRetryAt(err); !ok || !at.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("reload retry=%s,%v want shared +2m", at, ok)
	}
	release()

	state, release = acquireCredentialState("github_pat_reload", clock)
	success, err := newTestClientAt("https://api.github.com", "github_pat_reload", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, `{"id":42}`), nil
	})}, clock)
	if err != nil {
		t.Fatal(err)
	}
	success.credentialState = state
	if _, err := success.ResolveDestination(t.Context(), adapter.Destination{Kind: adapter.Repository, Owner: "team", Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	release()

	state, release = acquireCredentialState("github_pat_reload", clock)
	defer release()
	reset, err := newTestClientAt("https://api.github.com", "github_pat_reload", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusTooManyRequests, `{}`), nil
	})}, clock)
	if err != nil {
		t.Fatal(err)
	}
	reset.credentialState = state
	if _, err := reset.ResolveDestination(t.Context(), adapter.Destination{Kind: adapter.Repository, Owner: "team", Name: "repo"}); err == nil {
		t.Fatal("post-success headerless rate response succeeded")
	} else if at, ok := adapter.ProviderRetryAt(err); !ok || !at.Equal(now.Add(time.Minute)) {
		t.Fatalf("post-success retry=%s,%v want reset +1m", at, ok)
	}
}
