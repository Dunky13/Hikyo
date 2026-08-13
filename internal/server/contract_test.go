package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Dunky13/hikyo/api"
	"github.com/Dunky13/hikyo/api/apigen"
	"github.com/Dunky13/hikyo/internal/admission"
	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/server"
	"github.com/Dunky13/hikyo/internal/service"
)

// HTTP contract tests (mvp-boundary S1): the wire response is validated
// against api/openapi.yaml, not against what a handler intended. A handler
// that returns a shape the document does not describe fails here even if it
// compiles and even if every unit test passes, which is the point — the
// document is the contract, so the bytes have to satisfy it.

// stubAuth and stubOrgs let the transport be exercised without a datastore.
// The service layer's own behaviour is covered end to end on both engines in
// internal/isolation; what these prove is the TRANSPORT's contract, which is
// a different claim and needs a different fixture.
type stubAuth struct {
	login         func(ctx context.Context, u, p string, artifact service.Artifact) (service.LoginResult, error)
	identity      func(ctx context.Context, presented string) (service.Identity, error)
	logout        func(ctx context.Context, presented string) error
	estab         func(ctx context.Context, authority, password string) error
	verifyCSRF    func(ctx context.Context, presented, csrfToken string) error
	reissue       func() (service.LoginResult, error)
	passkeyStart  func(ctx context.Context) ([]byte, error)
	passkeyFinish func(ctx context.Context, response []byte) (service.LoginResult, error)
}

func (s stubAuth) LocalLogin(ctx context.Context, u, p string, artifact service.Artifact) (service.LoginResult, error) {
	if s.login == nil {
		return service.LoginResult{}, domain.ErrUnauthenticated
	}
	return s.login(ctx, u, p, artifact)
}

// VerifyBrowserCSRF defaults to accepting: most fixtures are about the
// transport's decision to DEMAND the token, not about the row it is checked
// against. The fixture that cares supplies its own.
func (s stubAuth) VerifyBrowserCSRF(ctx context.Context, presented, csrfToken string) error {
	if s.verifyCSRF == nil {
		return nil
	}
	return s.verifyCSRF(ctx, presented, csrfToken)
}

func (s stubAuth) EstablishCredential(ctx context.Context, a, p string) error {
	if s.estab == nil {
		return domain.ErrUnauthenticated
	}
	return s.estab(ctx, a, p)
}

func (s stubAuth) Identity(ctx context.Context, presented string) (service.Identity, error) {
	if s.identity == nil {
		return service.Identity{}, domain.ErrUnauthenticated
	}
	return s.identity(ctx, presented)
}

func (s stubAuth) Logout(ctx context.Context, presented string) error {
	if s.logout == nil {
		return domain.ErrUnauthenticated
	}
	return s.logout(ctx, presented)
}

func (s stubAuth) SlideIdleClock(context.Context, string) error { return nil }

// Factor endpoints (#54): the transport contract for these is exercised in the
// isolation suite end to end; the stubs here keep the interface satisfied and
// default to the uniform refusal.
func (s stubAuth) EnrolTOTPStart(context.Context, string, string) (string, error) {
	return "", domain.ErrUnauthenticated
}

// reissue is the shared stub for every account-security mutation: each of them
// reissues or rotates the acting session, and the transport's obligation is
// identical for all of them, so one hook drives them all.
func (s stubAuth) reissued() (service.LoginResult, error) {
	if s.reissue == nil {
		return service.LoginResult{}, domain.ErrUnauthenticated
	}
	return s.reissue()
}

func (s stubAuth) EnrolTOTPConfirm(context.Context, string, string) (service.LoginResult, error) {
	return s.reissued()
}

func (s stubAuth) StepUpTOTP(context.Context, string, string) (service.LoginResult, error) {
	return s.reissued()
}

func (s stubAuth) RemoveTOTP(context.Context, string, string) (service.LoginResult, error) {
	return s.reissued()
}

func (s stubAuth) GenerateRecoveryCodes(context.Context, string, string) ([]string, service.LoginResult, error) {
	result, err := s.reissued()
	return []string{"hik_1_rc_one", "hik_1_rc_two"}, result, err
}

func (s stubAuth) ConsumeRecoveryCode(context.Context, string, string) (service.RecoveryResult, error) {
	return service.RecoveryResult{}, domain.ErrUnauthenticated
}

func (s stubAuth) AuthMethods(context.Context) ([]service.AuthMethodProvider, bool, error) {
	return nil, true, nil
}

func (s stubAuth) OIDCStart(context.Context, string, string, string, string, string) (service.OIDCStartResult, error) {
	return service.OIDCStartResult{}, domain.ErrUnauthenticated
}

func (s stubAuth) OIDCCallback(context.Context, string, string, string, string, string, string, string) (service.OIDCCallbackResult, error) {
	return service.OIDCCallbackResult{}, domain.ErrUnauthenticated
}

func (s stubAuth) ListIdentities(context.Context, string) ([]service.ExternalIdentityView, error) {
	return nil, domain.ErrUnauthenticated
}

func (s stubAuth) UnlinkIdentity(context.Context, string, string, string) (service.LoginResult, error) {
	return s.reissued()
}

// WebAuthn (#54): the transport contract for the opaque-JSON bridging is
// smoke-tested through PasskeyLoginStart; the rest keep the interface satisfied
// and default to the uniform refusal.
func (s stubAuth) EnrolPasskeyStart(context.Context, string, string, string) ([]byte, error) {
	return nil, domain.ErrUnauthenticated
}

func (s stubAuth) EnrolPasskeyFinish(context.Context, string, []byte) (service.LoginResult, error) {
	return service.LoginResult{}, domain.ErrUnauthenticated
}

func (s stubAuth) PasskeyLoginStart(ctx context.Context) ([]byte, error) {
	if s.passkeyStart == nil {
		return nil, domain.ErrUnauthenticated
	}
	return s.passkeyStart(ctx)
}

func (s stubAuth) PasskeyLoginFinish(ctx context.Context, response []byte) (service.LoginResult, error) {
	if s.passkeyFinish == nil {
		return service.LoginResult{}, domain.ErrUnauthenticated
	}
	return s.passkeyFinish(ctx, response)
}

func (s stubAuth) StepUpPasskeyStart(context.Context, string) ([]byte, error) {
	return nil, domain.ErrUnauthenticated
}

func (s stubAuth) StepUpPasskeyFinish(context.Context, string, []byte) (service.LoginResult, error) {
	return service.LoginResult{}, domain.ErrUnauthenticated
}

func (s stubAuth) ReauthPasskeyStart(context.Context, string, service.ReauthPurpose, string, []string) ([]byte, error) {
	return nil, domain.ErrUnauthenticated
}

func (s stubAuth) ReauthPasskeyFinish(context.Context, string, []byte) (service.ReauthResult, error) {
	return service.ReauthResult{}, domain.ErrUnauthenticated
}

func (s stubAuth) ReauthTOTP(context.Context, string, string, string) (service.ReauthResult, error) {
	return service.ReauthResult{}, domain.ErrUnauthenticated
}

func (s stubAuth) RemovePasskey(context.Context, string, string, string, string) (service.LoginResult, error) {
	return service.LoginResult{}, domain.ErrUnauthenticated
}

func (s stubAuth) ListPasskeys(context.Context, string) ([]service.PasskeyView, error) {
	return nil, domain.ErrUnauthenticated
}

func (s stubAuth) ResetCredential(context.Context, service.Actor, string, string) (service.ResetResult, error) {
	return service.ResetResult{}, domain.ErrUnauthenticated
}

type stubProviders struct{}

func (stubProviders) Put(context.Context, service.Actor, string, service.ProviderInput) (service.ProviderView, error) {
	return service.ProviderView{}, domain.ErrUnauthorized
}
func (stubProviders) Get(context.Context, service.Actor, string) (service.ProviderView, error) {
	return service.ProviderView{}, domain.ErrUnauthorized
}
func (stubProviders) List(context.Context, service.Actor) ([]service.ProviderView, error) {
	return nil, domain.ErrUnauthorized
}
func (stubProviders) Delete(context.Context, service.Actor, string) error {
	return domain.ErrUnauthorized
}

type stubOrgs struct {
	create func(ctx context.Context, a service.Actor, name string, active bool, meta json.RawMessage) (service.Org, error)
	get    func(ctx context.Context, a service.Actor, org domain.OrgID) (service.Org, error)
	list   func(ctx context.Context, a service.Actor) ([]service.Org, error)
	mine   func(ctx context.Context, a service.Actor) ([]service.MyOrg, error)
	rename func(ctx context.Context, a service.Actor, org domain.OrgID, name string) (service.Org, error)
	del    func(ctx context.Context, a service.Actor, org domain.OrgID) error
}

func (s stubOrgs) ListMine(ctx context.Context, a service.Actor) ([]service.MyOrg, error) {
	if s.mine == nil {
		// The honest default for a caller whose grants name no org: an empty
		// list, not a refusal. Nothing about this surface can fail on
		// authorization — that is the point of it.
		return nil, nil
	}
	return s.mine(ctx, a)
}

func (s stubOrgs) Create(ctx context.Context, a service.Actor, n string, active bool, m json.RawMessage) (service.Org, error) {
	if s.create == nil {
		return service.Org{}, domain.ErrUnauthorized
	}
	return s.create(ctx, a, n, active, m)
}

func (s stubOrgs) Get(ctx context.Context, a service.Actor, org domain.OrgID) (service.Org, error) {
	if s.get == nil {
		return service.Org{}, domain.ErrNotFound
	}
	return s.get(ctx, a, org)
}

func (s stubOrgs) Rename(ctx context.Context, a service.Actor, org domain.OrgID, name string) (service.Org, error) {
	if s.rename == nil {
		return service.Org{}, domain.ErrNotFound
	}
	return s.rename(ctx, a, org, name)
}

func (s stubOrgs) Delete(ctx context.Context, a service.Actor, org domain.OrgID) error {
	if s.del == nil {
		return domain.ErrNotFound
	}
	return s.del(ctx, a, org)
}

func (s stubOrgs) List(ctx context.Context, a service.Actor) ([]service.Org, error) {
	if s.list == nil {
		return nil, domain.ErrUnauthorized
	}
	return s.list(ctx, a)
}

type stubReady struct{ err error }

func (s stubReady) Ready(context.Context) error { return s.err }

const testOrgID = "org_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f11"

var liveIdentity = service.Identity{
	Principal: "usr_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f22",
	SessionID: "ses_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f33",
	Artifact:  "cli",
	Assurance: service.Assurance{
		Method: "local-password", Factors: []string{"password"},
		AuthenticatedAt: time.Unix(1_800_000_000, 0).UTC(),
	},
	CreatedAt:         time.Unix(1_800_000_000, 0).UTC(),
	IdleExpiresAt:     time.Unix(1_802_000_000, 0).UTC(),
	AbsoluteExpiresAt: time.Unix(1_808_000_000, 0).UTC(),
}

func newTestServer(t *testing.T, auth server.AuthService, orgs server.OrgService) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(server.New(stubReady{}, &server.API{
		Auth: auth, Orgs: orgs, Providers: stubProviders{}, Version: "test",
		// The hierarchy services default to the uniform nonexistent answer, so a
		// contract test that does not care about them still exercises the real
		// router and the real response validation rather than nil-panicking.
		Projects: stubHierarchy{}, Environments: stubEnvs{}, Values: stubValues{}, Folders: stubFolders{},
	}, nil))
	t.Cleanup(srv.Close)
	return srv
}

// call issues a request and validates the RESPONSE against the contract.
// Every test in this file goes through it, so no assertion can accidentally
// skip the validation step.
func call(t *testing.T, srv *httptest.Server, method, path, bearer string, body any) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	// The S1 duty: validate what actually went over the socket.
	validationReq, err := http.NewRequest(method, "http://contract"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		validationReq.Header.Set("Content-Type", "application/json")
	}
	if err := api.ValidateResponse(validationReq, resp.StatusCode, resp.Header, payload); err != nil {
		if !errors.Is(err, api.ErrNoRoute) {
			t.Fatalf("%s %s -> %d: the wire response does not satisfy the contract: %v\nbody: %s",
				method, path, resp.StatusCode, err, payload)
		}
	}
	return resp, payload
}

func decodeError(t *testing.T, payload []byte) apigen.Error {
	t.Helper()
	var body apigen.Error
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("error body is not the contract's shape: %v (%s)", err, payload)
	}
	return body
}

func TestMetaIsTheClosedAllowlist(t *testing.T) {
	srv := newTestServer(t, stubAuth{}, stubOrgs{})
	resp, payload := call(t, srv, http.MethodGet, api.PathPrefix+"/meta", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	// additionalProperties:false is validated above; this asserts the
	// allowlist's CONTENT — an instance must not advertise a protocol flow it
	// does not serve, because `login` picks its transport from this list.
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"server_version", "api_revision", "protocol_capabilities"} {
		if _, ok := raw[want]; !ok {
			t.Errorf("meta omits %q", want)
		}
	}
	if len(raw) != 3 {
		t.Errorf("meta carries %d members, want exactly the three the allowlist names: %v", len(raw), raw)
	}
	var meta apigen.Meta
	if err := json.Unmarshal(payload, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.ApiRevision != api.Revision {
		t.Errorf("advertised revision %d, this build serves %d", meta.ApiRevision, api.Revision)
	}
}

func TestUnauthenticatedRefusalsAreByteIdentical(t *testing.T) {
	// The uniformity claim, asserted on real bytes rather than on sentinels
	// (the obligation #44 handed to this ticket). Absent, malformed and
	// unknown artifacts must be indistinguishable.
	srv := newTestServer(t, stubAuth{}, stubOrgs{})
	var bodies [][]byte
	var statuses []int
	for _, bearer := range []string{"", "not-a-token", "hik_1_cli_totallyfabricated000000", "hik_9_xx_nonsense"} {
		resp, payload := call(t, srv, http.MethodGet, api.PathPrefix+"/auth/whoami", bearer, nil)
		statuses = append(statuses, resp.StatusCode)
		bodies = append(bodies, payload)
	}
	for i := range bodies {
		if statuses[i] != http.StatusUnauthorized {
			t.Errorf("artifact %d: status %d, want 401", i, statuses[i])
		}
		if !bytes.Equal(bodies[i], bodies[0]) {
			t.Errorf("artifact %d body differs from artifact 0:\n  %s\n  %s", i, bodies[i], bodies[0])
		}
	}
	body := decodeError(t, bodies[0])
	if body.Error.Detail != nil {
		t.Error("a 401 carries a detail member — only bad_request may, and only because it is decided before tenant resolution")
	}
}

func TestNotFoundAndUnauthorizedAreIndistinguishable(t *testing.T) {
	// unauthorized ≡ nonexistent, on the wire. A tenant read the principal may
	// not perform and one addressing nothing must produce the same bytes.
	missing := newTestServer(t, stubAuth{identity: liveIdentityFn}, stubOrgs{
		get: func(context.Context, service.Actor, domain.OrgID) (service.Org, error) {
			return service.Org{}, domain.ErrNotFound
		},
	})
	forbidden := newTestServer(t, stubAuth{identity: liveIdentityFn}, stubOrgs{
		get: func(context.Context, service.Actor, domain.OrgID) (service.Org, error) {
			// The service maps a tenant-class refusal onto ErrNotFound at the
			// chokepoint; this fixture stands in for that having happened.
			return service.Org{}, domain.ErrNotFound
		},
	})
	respA, bodyA := call(t, missing, http.MethodGet, api.PathPrefix+"/orgs/"+testOrgID, "hik_1_cli_x", nil)
	respB, bodyB := call(t, forbidden, http.MethodGet, api.PathPrefix+"/orgs/"+testOrgID, "hik_1_cli_x", nil)
	if respA.StatusCode != respB.StatusCode || respA.StatusCode != http.StatusNotFound {
		t.Fatalf("statuses %d and %d, want both 404", respA.StatusCode, respB.StatusCode)
	}
	if !bytes.Equal(bodyA, bodyB) {
		t.Fatalf("bodies differ:\n  %s\n  %s", bodyA, bodyB)
	}
}

func TestAnUndescribedPathIsTheSameAsOneYouCannotReach(t *testing.T) {
	srv := newTestServer(t, stubAuth{}, stubOrgs{})
	resp, payload := call(t, srv, http.MethodGet, api.PathPrefix+"/does-not-exist", "", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
	if code := decodeError(t, payload).Error.Code; code != apigen.ErrorCodeNotFound {
		t.Errorf("code %q, want not_found", code)
	}
}

func TestMalformedRequestNamesTheOffendingMemberAndNothingElse(t *testing.T) {
	srv := newTestServer(t, stubAuth{}, stubOrgs{})
	resp, payload := call(t, srv, http.MethodPost, api.PathPrefix+"/auth/local/login", "",
		map[string]any{"username": "", "password": "x"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
	body := decodeError(t, payload)
	if body.Error.Detail == nil || *body.Error.Detail != "username" {
		t.Fatalf("detail = %v, want \"username\"", body.Error.Detail)
	}
}

func TestUnknownRequestMembersAreRefused(t *testing.T) {
	// additionalProperties:false on every request body, enforced at runtime:
	// silently dropping an unknown member hides a client that believes
	// something untrue about this server.
	srv := newTestServer(t, stubAuth{}, stubOrgs{})
	resp, _ := call(t, srv, http.MethodPost, api.PathPrefix+"/orgs", "hik_1_cli_x",
		map[string]any{"name": "acme", "tier": "gold"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 — an unknown request member was accepted", resp.StatusCode)
	}
}

func TestSuccessfulLoginMatchesTheContract(t *testing.T) {
	srv := newTestServer(t, stubAuth{
		login: func(context.Context, string, string, service.Artifact) (service.LoginResult, error) {
			return service.LoginResult{
				SessionToken: "hik_1_cli_stub", SessionID: liveIdentity.SessionID,
				Artifact: "cli", CreatedAt: liveIdentity.CreatedAt,
				IdleExpires: liveIdentity.IdleExpiresAt, AbsExpires: liveIdentity.AbsoluteExpiresAt,
				Principal: liveIdentity.Principal, DisplayName: "Admin",
				Assurance: liveIdentity.Assurance,
			}, nil
		},
	}, stubOrgs{})
	resp, payload := call(t, srv, http.MethodPost, api.PathPrefix+"/auth/local/login", "",
		map[string]any{"username": "admin", "password": "correct horse battery staple"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, payload)
	}
	var result apigen.LoginResult
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	if result.SessionToken == nil || *result.SessionToken == "" {
		t.Error("the response carries no session token")
	}
}

func TestNullableMetadataRoundTripsAbsentNullAndValue(t *testing.T) {
	// The 3.1 nullability profile, proven through the real Go consumer:
	// absent, null and a value are three distinct facts and stay distinct.
	var seen []json.RawMessage
	srv := newTestServer(t, stubAuth{identity: liveIdentityFn}, stubOrgs{
		create: func(_ context.Context, _ service.Actor, name string, active bool, meta json.RawMessage) (service.Org, error) {
			seen = append(seen, meta)
			return service.Org{
				ID: testOrgID, Name: name, Active: active, Metadata: meta,
				CreatedAt: liveIdentity.CreatedAt,
			}, nil
		},
	})
	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"absent", map[string]any{"name": "a"}, `{}`},
		{"null", map[string]any{"name": "a", "metadata": nil}, `{}`},
		{"value", map[string]any{"name": "a", "metadata": map[string]any{"team": "platform"}}, `{"team":"platform"}`},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, payload := call(t, srv, http.MethodPost, api.PathPrefix+"/orgs", "hik_1_cli_x", tc.body)
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("status %d: %s", resp.StatusCode, payload)
			}
			if got := string(seen[i]); got != tc.want {
				t.Fatalf("service saw metadata %s, want %s", got, tc.want)
			}
		})
	}
}

func TestOverloadIsUniformAndCarriesRetryAfter(t *testing.T) {
	srv := newTestServer(t, stubAuth{
		login: func(context.Context, string, string, service.Artifact) (service.LoginResult, error) {
			return service.LoginResult{}, admission.ErrOverloaded
		},
	}, stubOrgs{})
	resp, payload := call(t, srv, http.MethodPost, api.PathPrefix+"/auth/local/login", "",
		map[string]any{"username": "admin", "password": "whatever at all"})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", resp.StatusCode)
	}
	retry := resp.Header.Get("Retry-After")
	if retry == "" {
		t.Fatal("no Retry-After header")
	}
	if n, err := strconv.Atoi(retry); err != nil || n < 1 {
		t.Fatalf("Retry-After = %q, want whole seconds >= 1", retry)
	}
	if code := decodeError(t, payload).Error.Code; code != apigen.ErrorCodeTooManyRequests {
		t.Errorf("code %q", code)
	}
}

func TestHealthProbesSitOutsideTheAPIStack(t *testing.T) {
	// A liveness probe refused by the admission budget would turn a login
	// flood into a restart loop, so the probes must not carry the API
	// middleware at all.
	srv := newTestServer(t, stubAuth{}, stubOrgs{})
	for path, want := range map[string]int{"/healthz": http.StatusOK, "/readyz": http.StatusOK} {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: status %d, want %d", path, resp.StatusCode, want)
		}
	}
}

func liveIdentityFn(context.Context, string) (service.Identity, error) { return liveIdentity, nil }

func TestPasskeyLoginStartBridgesOpaqueOptions(t *testing.T) {
	// The one end-to-end check of the opaque-JSON wire bridging: the service
	// returns raw options bytes, the handler round-trips them through the
	// free-form object, and the response satisfies the contract (validated by
	// call()). The base64url fields the authenticator signs over must survive.
	opts := []byte(`{"publicKey":{"challenge":"Y2hhbGxlbmdl","rpId":"hikyo.example","timeout":60000}}`)
	srv := newTestServer(t, stubAuth{
		passkeyStart: func(context.Context) ([]byte, error) { return opts, nil },
	}, stubOrgs{})
	resp, payload := call(t, srv, http.MethodPost, api.PathPrefix+"/auth/webauthn/login/start", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, payload)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("response is not a JSON object: %v (%s)", err, payload)
	}
	pk, ok := got["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("options lost their publicKey member: %s", payload)
	}
	if pk["challenge"] != "Y2hhbGxlbmdl" {
		t.Fatalf("the signed-over challenge did not round-trip: %v", pk["challenge"])
	}
}

// TestBrowserPasskeyLoginTokenOnlyOnCookie is the B2 regression: a passkey login
// mints a BROWSER session, whose token must reach the caller ONLY on the
// __Host-hikyo HttpOnly cookie — never echoed into the script-readable JSON body
// where injected same-origin script could exfiltrate the bearer.
func TestBrowserPasskeyLoginTokenOnlyOnCookie(t *testing.T) {
	token, _, err := crypto.NewArtifact(crypto.ArtifactBrowserSession)
	if err != nil {
		t.Fatal(err)
	}
	srv := newTestServer(t, stubAuth{
		passkeyFinish: func(context.Context, []byte) (service.LoginResult, error) {
			return service.LoginResult{
				SessionToken: token, SessionID: liveIdentity.SessionID,
				Artifact: "browser", CreatedAt: liveIdentity.CreatedAt,
				IdleExpires: liveIdentity.IdleExpiresAt, AbsExpires: liveIdentity.AbsoluteExpiresAt,
				Principal: liveIdentity.Principal, DisplayName: "Admin",
				Assurance: liveIdentity.Assurance,
			}, nil
		},
	}, stubOrgs{})
	resp, payload := call(t, srv, http.MethodPost, api.PathPrefix+"/auth/webauthn/login/finish", "",
		map[string]any{"id": "cred", "response": map[string]any{}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, payload)
	}

	// The body carries the session and principal but NOT the token.
	var result apigen.LoginResult
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	if result.SessionToken != nil {
		t.Errorf("a browser-artifact login body must omit session_token, got %q", *result.SessionToken)
	}
	// The raw bytes must not contain the token anywhere either.
	if bytes.Contains(payload, []byte(token)) {
		t.Errorf("the session token leaked into the response body: %s", payload)
	}

	// The token is delivered on the __Host-hikyo cookie, HttpOnly + Secure.
	var got *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-hikyo" {
			got = c
		}
	}
	if got == nil {
		t.Fatal("no __Host-hikyo session cookie was set")
	}
	if got.Value != token {
		t.Errorf("cookie token = %q, want %q", got.Value, token)
	}
	if !got.HttpOnly || !got.Secure {
		t.Errorf("session cookie must be HttpOnly+Secure, got HttpOnly=%v Secure=%v", got.HttpOnly, got.Secure)
	}
}

// stubHierarchy answers every project, environment and folder operation with a
// configurable outcome. It defaults to ErrNotFound, which is the answer the
// unauthorized ≡ nonexistent rule makes indistinguishable from a refusal — so a
// stub that "does nothing" is a stub that behaves correctly.
type stubHierarchy struct {
	err error
}

func (s stubHierarchy) outcome() error {
	if s.err == nil {
		return domain.ErrNotFound
	}
	return s.err
}

func (s stubHierarchy) Create(context.Context, service.Actor, domain.OrgID, string) (service.Project, error) {
	return service.Project{}, s.outcome()
}

func (s stubHierarchy) Get(context.Context, service.Actor, domain.Scope) (service.Project, error) {
	return service.Project{}, s.outcome()
}

func (s stubHierarchy) List(context.Context, service.Actor, domain.OrgID) ([]service.Project, error) {
	return nil, s.outcome()
}

func (s stubHierarchy) Rename(context.Context, service.Actor, domain.Scope, string) (service.Project, error) {
	return service.Project{}, s.outcome()
}

func (s stubHierarchy) Delete(context.Context, service.Actor, domain.Scope) error {
	return s.outcome()
}

// The environment and folder surfaces share the type; Go's method sets keep
// them apart by signature, so the compiler still checks each interface.
type stubEnvs struct{ stubHierarchy }

func (s stubEnvs) Create(context.Context, service.Actor, domain.Scope, string) (service.Environment, error) {
	return service.Environment{}, s.outcome()
}

func (s stubEnvs) Clone(context.Context, service.Actor, domain.Scope, string, string) (service.Environment, service.CloneResult, error) {
	return service.Environment{}, service.CloneResult{}, s.outcome()
}

func (s stubEnvs) Get(context.Context, service.Actor, domain.Scope) (service.Environment, error) {
	return service.Environment{}, s.outcome()
}

func (s stubEnvs) List(context.Context, service.Actor, domain.Scope) ([]service.Environment, error) {
	return nil, s.outcome()
}

func (s stubEnvs) Rename(context.Context, service.Actor, domain.Scope, string) (service.Environment, error) {
	return service.Environment{}, s.outcome()
}

func (s stubEnvs) Reorder(context.Context, service.Actor, domain.Scope, []string) ([]service.Environment, error) {
	return nil, s.outcome()
}

// stubValues is the value surface's uniformity fixture (#50): every method
// answers the SAME injected outcome, so the transport has no way to tell an
// absent cell from one the caller may not reach.
type stubValues struct{ stubHierarchy }

func (s stubValues) Get(context.Context, service.Actor, domain.Scope, string, bool) (service.ValueCell, error) {
	return service.ValueCell{}, s.outcome()
}

func (s stubValues) List(context.Context, service.Actor, domain.Scope, bool) ([]service.ValueCell, error) {
	return nil, s.outcome()
}

func (s stubValues) Set(context.Context, service.Actor, domain.Scope, string, string) (service.ValueCell, error) {
	return service.ValueCell{}, s.outcome()
}

func (s stubValues) Clear(context.Context, service.Actor, domain.Scope, string) error {
	return s.outcome()
}

func (s stubValues) Declare(context.Context, service.Actor, domain.Scope, []string, string, string) ([]service.ValueCell, error) {
	return nil, s.outcome()
}

func (s stubValues) Copy(context.Context, service.Actor, domain.Scope, service.CopyRequest) (service.CopyResult, error) {
	return service.CopyResult{}, s.outcome()
}

func (s stubValues) Diff(context.Context, service.Actor, domain.Scope, string, string, bool) ([]service.DiffRow, error) {
	return nil, s.outcome()
}

func (s stubValues) Occurrences(context.Context, service.Actor, domain.Scope, []service.ImportCandidate) (service.ImportPresence, error) {
	return service.ImportPresence{}, s.outcome()
}

func (s stubValues) Import(context.Context, service.Actor, domain.Scope, service.ImportRequest) (service.ImportResult, error) {
	return service.ImportResult{}, s.outcome()
}

// stubKeys and stubKeyGroups are the key catalogue's uniformity fixtures
// (#49). Every method answers the SAME injected outcome, which is what makes
// the uniformity test meaningful: the transport is given no way to tell a
// missing key from one the caller may not reach — including on the two
// reveal-gated routes, where a distinguishable refusal would be the one-bit
// oracle the gate exists to close.
type stubKeys struct{ stubHierarchy }

func (s stubKeys) Create(context.Context, service.Actor, domain.Scope, service.KeySpec) (service.Key, error) {
	return service.Key{}, s.outcome()
}

func (s stubKeys) Get(context.Context, service.Actor, domain.Scope, string) (service.Key, error) {
	return service.Key{}, s.outcome()
}

func (s stubKeys) List(context.Context, service.Actor, domain.Scope) ([]service.Key, int64, error) {
	return nil, 0, s.outcome()
}

func (s stubKeys) Rename(context.Context, service.Actor, domain.Scope, string, string) (service.Key, error) {
	return service.Key{}, s.outcome()
}

func (s stubKeys) UpdateMetadata(context.Context, service.Actor, domain.Scope, string, service.KeyMetadataUpdate) (service.Key, error) {
	return service.Key{}, s.outcome()
}

func (s stubKeys) UpdateDeclaration(context.Context, service.Actor, domain.Scope, string, service.KeyDeclarationUpdate) (service.Key, error) {
	return service.Key{}, s.outcome()
}

func (s stubKeys) Reclassify(context.Context, service.Actor, domain.Scope, string, string) (service.Key, error) {
	return service.Key{}, s.outcome()
}

func (s stubKeys) SetGroup(context.Context, service.Actor, domain.Scope, string, string) (service.Key, error) {
	return service.Key{}, s.outcome()
}

func (s stubKeys) Delete(context.Context, service.Actor, domain.Scope, string) error {
	return s.outcome()
}

type stubKeyGroups struct{ stubHierarchy }

func (s stubKeyGroups) Create(context.Context, service.Actor, domain.Scope, string) (service.KeyGroupView, error) {
	return service.KeyGroupView{}, s.outcome()
}

func (s stubKeyGroups) Get(context.Context, service.Actor, domain.Scope, string) (service.KeyGroupView, error) {
	return service.KeyGroupView{}, s.outcome()
}

func (s stubKeyGroups) List(context.Context, service.Actor, domain.Scope) ([]service.KeyGroupView, error) {
	return nil, s.outcome()
}

func (s stubKeyGroups) Rename(context.Context, service.Actor, domain.Scope, string, string) (service.KeyGroupView, error) {
	return service.KeyGroupView{}, s.outcome()
}

func (s stubKeyGroups) Delete(context.Context, service.Actor, domain.Scope, string) error {
	return s.outcome()
}

type stubFolders struct{ stubHierarchy }

func (s stubFolders) Create(context.Context, service.Actor, domain.Scope, string) (service.Folder, error) {
	return service.Folder{}, s.outcome()
}

func (s stubFolders) Get(context.Context, service.Actor, domain.Scope, string) (service.Folder, error) {
	return service.Folder{}, s.outcome()
}

func (s stubFolders) List(context.Context, service.Actor, domain.Scope) ([]service.Folder, error) {
	return nil, s.outcome()
}

func (s stubFolders) Rename(context.Context, service.Actor, domain.Scope, string, string) (service.Folder, error) {
	return service.Folder{}, s.outcome()
}

func (s stubFolders) Delete(context.Context, service.Actor, domain.Scope, string) error {
	return s.outcome()
}

const (
	testProjectID  = "prj_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f44"
	testEnvID      = "env_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f55"
	testFolderID   = "fld_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f66"
	testKeyID      = "key_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f77"
	testKeyGroupID = "kgr_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f88"
	// The grant target for the access-surface uniformity routes (#55).
	testPrincipalID = "usr_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f99"
	// The SCIM administration uniformity routes (#73).
	testBindingID   = "scb_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f88"
	testSCIMGroupID = "scg_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f99"
	testSCIMCredID  = "scr_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0faa"
)

// stubSCIM is the SCIM administration surface's uniformity fixture (#73). Like
// every other stub here it answers ONE outcome for everything, so the
// uniformity tests differ only in which sentinel the service returned.
type stubSCIM struct{ stubHierarchy }

func (s stubSCIM) CreateBinding(context.Context, service.Actor, domain.OrgID, service.SCIMBindingInput) (service.SCIMBindingView, error) {
	return service.SCIMBindingView{}, s.outcome()
}

func (s stubSCIM) ListBindings(context.Context, service.Actor, domain.OrgID) ([]service.SCIMBindingView, error) {
	return nil, s.outcome()
}

func (s stubSCIM) GetBinding(context.Context, service.Actor, domain.OrgID, string) (service.SCIMBindingView, error) {
	return service.SCIMBindingView{}, s.outcome()
}

func (s stubSCIM) DeleteBinding(context.Context, service.Actor, domain.OrgID, string) error {
	return s.outcome()
}

func (s stubSCIM) CreateMapping(context.Context, service.Actor, domain.OrgID, string, service.SCIMMappingSpec) (service.SCIMMappingResult, error) {
	return service.SCIMMappingResult{}, s.outcome()
}

func (s stubSCIM) UpdateMapping(context.Context, service.Actor, domain.OrgID, string, service.SCIMMappingSpec) (service.SCIMMappingResult, error) {
	return service.SCIMMappingResult{}, s.outcome()
}

func (s stubSCIM) DeleteMapping(context.Context, service.Actor, domain.OrgID, string, service.SCIMMappingSpec) (service.SCIMMappingResult, error) {
	return service.SCIMMappingResult{}, s.outcome()
}

func (s stubSCIM) ListMappings(context.Context, service.Actor, domain.OrgID, string) ([]service.SCIMMappingView, error) {
	return nil, s.outcome()
}

func (s stubSCIM) MintCredential(context.Context, service.Actor, domain.OrgID, string, bool, string) (service.SCIMMintResult, error) {
	return service.SCIMMintResult{}, s.outcome()
}

func (s stubSCIM) ListCredentials(context.Context, service.Actor, domain.OrgID, string) ([]service.SCIMCredentialView, error) {
	return nil, s.outcome()
}

func (s stubSCIM) GetCredential(context.Context, service.Actor, domain.OrgID, string, string) (service.SCIMCredentialView, error) {
	return service.SCIMCredentialView{}, s.outcome()
}

func (s stubSCIM) RevokeCredential(context.Context, service.Actor, domain.OrgID, string, string) error {
	return s.outcome()
}

func (s stubSCIM) DirectoryUsers(context.Context, service.Actor, domain.OrgID, string) ([]service.SCIMDirectoryUser, error) {
	return nil, s.outcome()
}

func (s stubSCIM) DirectoryGroups(context.Context, service.Actor, domain.OrgID, string) ([]service.SCIMDirectoryGroup, error) {
	return nil, s.outcome()
}

// stubGrants and stubSettings are the access surface's uniformity fixtures
// (#55). Like the hierarchy stubs they answer one outcome for everything, so
// the uniformity tests differ ONLY in which sentinel the service returned.
type stubGrants struct{ stubHierarchy }

func (s stubGrants) Create(context.Context, service.Actor, service.GrantSpec) (service.GrantResult, error) {
	return service.GrantResult{}, s.outcome()
}

func (s stubGrants) Revoke(context.Context, service.Actor, service.GrantSpec) error {
	return s.outcome()
}

func (s stubGrants) List(context.Context, service.Actor, domain.Scope) ([]service.Membership, error) {
	return nil, s.outcome()
}

func (s stubGrants) ApplyTemplate(context.Context, service.Actor, domain.Template, domain.PrincipalID, domain.Scope) ([]service.GrantResult, error) {
	return nil, s.outcome()
}

type stubSettings struct{ stubHierarchy }

func (s stubSettings) GetEnvironment(context.Context, service.Actor, domain.Scope) (service.EnvironmentSettings, error) {
	return service.EnvironmentSettings{}, s.outcome()
}

func (s stubSettings) SetEnvironment(context.Context, service.Actor, domain.Scope, service.EnvironmentSettings) (service.EnvironmentSettings, error) {
	return service.EnvironmentSettings{}, s.outcome()
}

func hierarchyServer(t *testing.T, outcome error) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(server.New(stubReady{}, &server.API{
		Auth: stubAuth{identity: liveIdentityFn}, Orgs: stubOrgs{}, Providers: stubProviders{},
		Projects:     stubHierarchy{err: outcome},
		Environments: stubEnvs{stubHierarchy{err: outcome}}, Values: stubValues{stubHierarchy{err: outcome}},
		Folders:   stubFolders{stubHierarchy{err: outcome}},
		Keys:      stubKeys{stubHierarchy{err: outcome}},
		KeyGroups: stubKeyGroups{stubHierarchy{err: outcome}},
		Grants:    stubGrants{stubHierarchy{err: outcome}},
		Settings:  stubSettings{stubHierarchy{err: outcome}},
		SCIM:      stubSCIM{stubHierarchy{err: outcome}},
		Version:   "test",
	}, nil))
	t.Cleanup(srv.Close)
	return srv
}

// hierarchyRoutes is every by-id read and mutation on the hierarchy, one entry
// per level, used by the uniformity tests below.
func hierarchyRoutes() []struct {
	method string
	path   string
	body   any
} {
	base := api.PathPrefix + "/orgs/" + testOrgID
	project := base + "/projects/" + testProjectID
	rename := apigen.RenameRequest{Name: "renamed"}
	grantBody := apigen.CreateGrantRequest{Principal: testPrincipalID, Capability: "read"}
	templateBody := apigen.ApplyTemplateRequest{Principal: testPrincipalID, Template: apigen.Viewer}
	scimBase := base + "/scim-bindings"
	scimBinding := scimBase + "/" + testBindingID
	mappingBody := apigen.ScimMappingRequest{GroupId: testSCIMGroupID, Template: "viewer"}
	return []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, base, nil},
		{http.MethodPatch, base, rename},
		{http.MethodDelete, base, nil},
		{http.MethodGet, base + "/projects", nil},
		{http.MethodPost, base + "/projects", apigen.CreateProjectRequest{Name: "p"}},
		{http.MethodGet, project, nil},
		{http.MethodPatch, project, rename},
		{http.MethodDelete, project, nil},
		{http.MethodGet, project + "/environments", nil},
		{http.MethodPost, project + "/environments", apigen.CreateEnvironmentRequest{Name: "e"}},
		{http.MethodPut, project + "/environments/order", apigen.EnvironmentOrderRequest{EnvironmentIds: []string{testEnvID}}},
		{http.MethodGet, project + "/environments/" + testEnvID, nil},
		{http.MethodPatch, project + "/environments/" + testEnvID, rename},
		{http.MethodDelete, project + "/environments/" + testEnvID, nil},
		{http.MethodGet, project + "/folders", nil},
		{http.MethodPost, project + "/folders", apigen.CreateFolderRequest{Path: "f"}},
		{http.MethodGet, project + "/folders/" + testFolderID, nil},
		{http.MethodPatch, project + "/folders/" + testFolderID, apigen.RenameFolderRequest{Path: "g"}},
		{http.MethodDelete, project + "/folders/" + testFolderID, nil},

		// The access surface (#55). Handoff 44 passed the byte-shape
		// obligation to the response layer "when routes land"; these are the
		// grant routes landing, so they join the same assertion rather than
		// getting a weaker one of their own. The list routes are here for the
		// count half: a refused listing must be the uniform 404, never a 200
		// carrying `count: 0`, which would confirm the scope exists.
		{http.MethodGet, base + "/grants", nil},
		{http.MethodPost, base + "/grants", grantBody},
		{http.MethodDelete, base + "/grants?principal=" + testPrincipalID + "&capability=read", nil},
		{http.MethodPost, base + "/grants/template", templateBody},
		{http.MethodGet, project + "/grants", nil},
		{http.MethodPost, project + "/grants", grantBody},
		{http.MethodDelete, project + "/grants?principal=" + testPrincipalID + "&capability=read", nil},
		{http.MethodPost, project + "/grants/template", templateBody},
		{http.MethodPost, project + "/environments/" + testEnvID + "/grants", grantBody},
		{http.MethodDelete, project + "/environments/" + testEnvID + "/grants?principal=" + testPrincipalID + "&capability=read", nil},
		{http.MethodPost, project + "/environments/" + testEnvID + "/grants/template", templateBody},
		{http.MethodGet, project + "/environments/" + testEnvID + "/settings", nil},
		{http.MethodPut, project + "/environments/" + testEnvID + "/settings", apigen.EnvironmentSettings{Protected: true}},
		// The key catalogue (#49). The declaration and classification routes
		// are in this list deliberately: they are the reveal-gated ones, and
		// their refusal MUST be byte-identical to a missing key.
		{http.MethodGet, project + "/keys", nil},
		{http.MethodPost, project + "/keys", apigen.CreateKeyRequest{
			Name: "K", Classification: "config",
			Declaration: apigen.KeyDeclaration{Rule: &apigen.KeyRule{Type: "string"}},
		}},
		{http.MethodGet, project + "/keys/" + testKeyID, nil},
		{http.MethodPatch, project + "/keys/" + testKeyID, apigen.UpdateKeyMetadataRequest{}},
		{http.MethodDelete, project + "/keys/" + testKeyID, nil},
		{http.MethodPut, project + "/keys/" + testKeyID + "/name", apigen.RenameKeyRequest{Name: "K2"}},
		{http.MethodPut, project + "/keys/" + testKeyID + "/declaration", apigen.UpdateKeyDeclarationRequest{
			Declaration: apigen.KeyDeclaration{Rule: &apigen.KeyRule{Type: "string"}},
			Presence: apigen.KeyPresenceRules{
				RequiredIn: apigen.KeyPresence{Mode: "none"}, ForbiddenIn: apigen.KeyPresence{Mode: "none"},
			},
		}},
		{http.MethodPut, project + "/keys/" + testKeyID + "/classification", apigen.ReclassifyKeyRequest{Classification: "config"}},
		{http.MethodPut, project + "/keys/" + testKeyID + "/group", apigen.SetKeyGroupRequest{GroupId: ""}},
		{http.MethodGet, project + "/key-groups", nil},
		{http.MethodPost, project + "/key-groups", apigen.CreateKeyGroupRequest{Name: "g"}},
		{http.MethodGet, project + "/key-groups/" + testKeyGroupID, nil},
		{http.MethodPatch, project + "/key-groups/" + testKeyGroupID, apigen.RenameKeyGroupRequest{Name: "g2"}},
		{http.MethodDelete, project + "/key-groups/" + testKeyGroupID, nil},

		// The SCIM ADMINISTRATION surface (#73). It joins the same byte-shape
		// assertion rather than getting a weaker one: a binding the caller may
		// not reach must answer exactly like one that is not there, or the
		// mount becomes an oracle for "does this org have SCIM configured?".
		//
		// The WIRE routes are deliberately absent from this table. They answer
		// the RFC 7644 error shape, not the Hikyo envelope — that is the ADR's
		// requirement, not an omission — and their uniformity is asserted in
		// internal/scimproto and in the isolation suite instead.
		{http.MethodGet, scimBase, nil},
		{http.MethodPost, scimBase, apigen.CreateScimBindingRequest{
			ProviderKind: "oidc", ProviderSlug: "okta", SubjectSource: "externalId"}},
		{http.MethodGet, scimBinding, nil},
		{http.MethodDelete, scimBinding, nil},
		{http.MethodGet, scimBinding + "/mappings", nil},
		{http.MethodPost, scimBinding + "/mappings", mappingBody},
		{http.MethodPut, scimBinding + "/mappings", mappingBody},
		{http.MethodDelete, scimBinding + "/mappings?group=" + testSCIMGroupID, nil},
		{http.MethodGet, scimBinding + "/credentials", nil},
		{http.MethodPost, scimBinding + "/credentials", apigen.MintScimCredentialRequest{}},
		{http.MethodGet, scimBinding + "/credentials/" + testSCIMCredID, nil},
		{http.MethodDelete, scimBinding + "/credentials/" + testSCIMCredID, nil},
		{http.MethodGet, scimBinding + "/directory/users", nil},
		{http.MethodGet, scimBinding + "/directory/groups", nil},
	}
}

// TestOrdinaryUpdateRefusesAClassificationChange is mvp-boundary C1's
// "classification changes only via the reclassification ceremony", asserted at
// the transport where the refusal lives. The field exists in the contract ONLY
// so the refusal can name the ceremony; a body carrying it is refused whatever
// its value, and refusing the FIELD rather than the CHANGE costs no read and
// cannot become a way to probe the current classification.
func TestOrdinaryUpdateRefusesAClassificationChange(t *testing.T) {
	// The stub answers the uniform nonexistent for everything it is asked, so
	// the two outcomes below are distinguishable ONLY by where the request
	// stopped: 400 means the transport refused the field, 404 means it reached
	// the service.
	srv := httptest.NewServer(server.New(stubReady{}, &server.API{
		Auth: stubAuth{identity: liveIdentityFn}, Orgs: stubOrgs{}, Providers: stubProviders{},
		Keys: stubKeys{}, Version: "test",
	}, nil))
	t.Cleanup(srv.Close)
	path := api.PathPrefix + "/orgs/" + testOrgID + "/projects/" + testProjectID + "/keys/" + testKeyID
	for _, classification := range []apigen.KeyClassification{"secret", "config"} {
		resp, payload := call(t, srv, http.MethodPatch, path, "hik_1_cli_x",
			apigen.UpdateKeyMetadataRequest{Classification: &classification})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("classification %q in an ordinary update answered %d, want 400", classification, resp.StatusCode)
		}
		if code := decodeError(t, payload).Error.Code; code != apigen.ErrorCodeBadRequest {
			t.Fatalf("code %q, want bad_request", code)
		}
	}
	// The same request without the field reaches the service, whose stub
	// answers the uniform nonexistent — a different outcome from the refusal
	// above, which is what proves the refusal is the transport's and not an
	// accident of the fixture.
	resp, _ := call(t, srv, http.MethodPatch, path, "hik_1_cli_x", apigen.UpdateKeyMetadataRequest{})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a metadata update without a classification answered %d, want the service's 404", resp.StatusCode)
	}
}

// TestUniformNonexistentAtEveryLevel is mvp-boundary C1's wire half: at org,
// project, environment AND folder level, a refusal and a genuine miss are the
// same status and the same bytes. The two servers differ only in which sentinel
// the service returned — ErrNotFound for a missing row, ErrNotFound again for a
// tenant-class refusal, which is the whole point: the transport is given no way
// to tell them apart.
func TestUniformNonexistentAtEveryLevel(t *testing.T) {
	missing := hierarchyServer(t, domain.ErrNotFound)
	refused := hierarchyServer(t, fmt.Errorf("refused at the chokepoint: %w", domain.ErrNotFound))
	for _, route := range hierarchyRoutes() {
		respA, bodyA := call(t, missing, route.method, route.path, "hik_1_cli_x", route.body)
		respB, bodyB := call(t, refused, route.method, route.path, "hik_1_cli_x", route.body)
		if respA.StatusCode != http.StatusNotFound || respB.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: statuses %d and %d, want both 404", route.method, route.path, respA.StatusCode, respB.StatusCode)
			continue
		}
		if !bytes.Equal(bodyA, bodyB) {
			t.Errorf("%s %s: bodies differ:\n  %s\n  %s", route.method, route.path, bodyA, bodyB)
		}
		body := decodeError(t, bodyA)
		if body.Error.Detail != nil {
			t.Errorf("%s %s: a 404 carries a detail member", route.method, route.path)
		}
	}
}

// TestRefusedListingLeaksNoCount is the "counts" half of unauthorized ≡
// nonexistent for bulk reads (mvp-boundary A2). Byte-equality above already
// proves the two servers agree; this asserts the stronger property directly,
// because the failure it guards against is a plausible one: answering a
// refused membership listing with 200 and `{"items":[],"count":0}` would be a
// perfectly reasonable-looking handler that confirms the scope exists and that
// the caller may enumerate it.
func TestRefusedListingLeaksNoCount(t *testing.T) {
	refused := hierarchyServer(t, fmt.Errorf("refused at the chokepoint: %w", domain.ErrNotFound))
	base := api.PathPrefix + "/orgs/" + testOrgID
	for _, path := range []string{
		base + "/grants",
		base + "/projects/" + testProjectID + "/grants",
		base + "/projects",
		base + "/projects/" + testProjectID + "/environments",
	} {
		resp, body := call(t, refused, http.MethodGet, path, "hik_1_cli_x", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", path, resp.StatusCode)
			continue
		}
		if bytes.Contains(body, []byte(`"count"`)) || bytes.Contains(body, []byte(`"items"`)) {
			t.Errorf("GET %s: a refused listing carried a count or an items member: %s", path, body)
		}
	}
}

// TestConflictAndLimitRenderUniformly covers the two refusals this surface
// adds. Both are decided AFTER authorization succeeded, so unlike a 404 they may
// exist as their own codes — but the message is still fixed per code, and the
// limit refusal must name its bound because the ops spec requires a named
// refusal and a body may carry nothing derived from the request.
func TestConflictAndLimitRenderUniformly(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code apigen.ErrorCode
	}{
		{"conflict", domain.ErrConflict, apigen.ErrorCodeConflict},
		{"limit", domain.ErrLimitExceeded, apigen.ErrorCodeLimitExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := hierarchyServer(t, fmt.Errorf("wrapped: %w", tc.err))
			resp, payload := call(t, srv, http.MethodPost,
				api.PathPrefix+"/orgs/"+testOrgID+"/projects", "hik_1_cli_x",
				apigen.CreateProjectRequest{Name: "p"})
			if resp.StatusCode != http.StatusConflict {
				t.Fatalf("status %d, want 409", resp.StatusCode)
			}
			body := decodeError(t, payload)
			if body.Error.Code != tc.code {
				t.Fatalf("code %q, want %q", body.Error.Code, tc.code)
			}
			if body.Error.Detail != nil {
				t.Error("a 409 carries a detail member — only bad_request may")
			}
			if tc.code == apigen.ErrorCodeLimitExceeded && !strings.Contains(body.Error.Message, "50 environments") {
				t.Errorf("the limit refusal does not name its bound: %q", body.Error.Message)
			}
		})
	}
}

// TestAssuranceRefusalOnATenantRouteIsForbidden is the non-tautological half of
// the uniformity story. TestUniformNonexistentAtEveryLevel feeds both fixtures
// ErrNotFound and proves the transport adds no difference; it cannot see a
// mapping that turns some OTHER sentinel into a different status. This one
// feeds ErrUnauthorized — the sentinel authorize() returns when the caller HOLDS
// the grant but the session's assurance is short of an MFA-mandatory operation
// (internal/authz/authorize.go, the assurance leg) — and pins that it renders
// the declared 403 with the uniform body, not a 404 and not a 500.
//
// The org rename is the route under test because its formula atom
// `instance-config` is in authz.MFAMandatory. That a tenant route declares 403
// IF AND ONLY IF its formula is MFA-mandatory is asserted against the registry
// in internal/isolation/contract_test.go, which can see both.
func TestAssuranceRefusalOnATenantRouteIsForbidden(t *testing.T) {
	srv := httptest.NewServer(server.New(stubReady{}, &server.API{
		Auth: stubAuth{identity: liveIdentityFn}, Providers: stubProviders{},
		Orgs: stubOrgs{
			rename: func(context.Context, service.Actor, domain.OrgID, string) (service.Org, error) {
				return service.Org{}, fmt.Errorf("step up first: %w", domain.ErrUnauthorized)
			},
		},
		Projects: stubHierarchy{}, Environments: stubEnvs{}, Values: stubValues{}, Folders: stubFolders{},
		Version: "test",
	}, nil))
	t.Cleanup(srv.Close)

	resp, payload := call(t, srv, http.MethodPatch, api.PathPrefix+"/orgs/"+testOrgID,
		"hik_1_cli_x", apigen.RenameRequest{Name: "renamed"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403 — an assurance refusal on a held grant is a grant-class refusal, not the nonexistent mask", resp.StatusCode)
	}
	body := decodeError(t, payload)
	if body.Error.Code != apigen.ErrorCodeForbidden {
		t.Fatalf("code %q, want forbidden", body.Error.Code)
	}
	if body.Error.Detail != nil {
		t.Error("a 403 carries a detail member — only bad_request may")
	}
}

// The value-surface transport contracts (#50 review fixes).

const (
	// testProjectID and testEnvID are declared with the hierarchy fixtures above.
	testEnvID2     = "env_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f56"
	cloneRoutePath = "/orgs/" + testOrgID + "/projects/" + testProjectID + "/environments/clone"
	copyRoutePath  = "/orgs/" + testOrgID + "/projects/" + testProjectID + "/values/copy"
)

// newValueServer builds a test server with injectable environment and value
// surfaces, so a test can drive one handler's exact refusal without a datastore.
func newValueServer(t *testing.T, envs server.EnvironmentService, values server.ValueService) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(server.New(stubReady{}, &server.API{
		Auth: stubAuth{identity: liveIdentityFn}, Orgs: stubOrgs{}, Providers: stubProviders{}, Version: "test",
		Projects: stubHierarchy{}, Environments: envs, Values: values, Folders: stubFolders{},
	}, nil))
	t.Cleanup(srv.Close)
	return srv
}

// safeDetailErr stands in for the service's clone-abort error: an ErrInvalid
// that exposes a caller-safe detail (the stranded key names). It is the shape
// writeHandlerError extracts via errors.As and errorBody honours for
// bad_request, which is the contract this test pins.
type safeDetailErr struct{ detail string }

func (e safeDetailErr) Error() string      { return e.detail }
func (e safeDetailErr) Unwrap() error      { return domain.ErrInvalid }
func (e safeDetailErr) SafeDetail() string { return e.detail }

// TestCloneAbortBodyCarriesTheStrandedKeys is the E2E half of the clone-abort
// fix: a refusal naming the stranded keys must REACH the caller, not be flattened
// to the bare bad_request message. writeHandlerError lifts the safe detail and
// errorBody carries it. Detail is honoured only for bad_request and conflict, and
// only when an explicit SafeDetail carrier supplies it — the uniform-response rule
// still stands for every plain refusal.
func TestCloneAbortBodyCarriesTheStrandedKeys(t *testing.T) {
	const detail = "cloning env_src would leave required secret(s) absent in the new environment: REQUIRED_TOKEN"
	srv := newValueServer(t, stubEnvs{stubHierarchy{err: safeDetailErr{detail: detail}}}, stubValues{})
	resp, payload := call(t, srv, http.MethodPost, api.PathPrefix+cloneRoutePath, "hik_1_cli_x",
		map[string]any{"name": "clone-x", "source_environment_id": testEnvID})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
	body := decodeError(t, payload)
	if body.Error.Detail == nil || !strings.Contains(*body.Error.Detail, "REQUIRED_TOKEN") {
		t.Fatalf("clone-abort 400 detail = %v, want it to name the stranded key REQUIRED_TOKEN", body.Error.Detail)
	}
}

// TestUnconfirmedProtectedDestinationIs409NotFault pins that the protected-
// destination refusal — a documented post-authorization state refusal — answers
// 409, never the 500 fault a bare error would produce, AND that its body names
// the destination environment id. The id is the caller's own request field and
// the refusal is post-authorization, so it rides the SafeDetail channel errorBody
// honours for conflict; a PLAIN conflict still carries no detail (asserted by the
// bare-sentinel case below).
func TestUnconfirmedProtectedDestinationIs409NotFault(t *testing.T) {
	refusal := service.ProtectedDestinationRefusal(domain.EnvID(testEnvID2))
	srv := newValueServer(t, stubEnvs{}, stubValues{stubHierarchy{err: refusal}})
	resp, payload := call(t, srv, http.MethodPost, api.PathPrefix+copyRoutePath, "hik_1_cli_x",
		map[string]any{
			"source_environment_id":       testEnvID,
			"keys":                        []string{"TOKEN"},
			"destination_environment_ids": []string{testEnvID2},
		})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status %d, want 409 — a documented protected-destination refusal, not a 500 fault", resp.StatusCode)
	}
	body := decodeError(t, payload)
	if body.Error.Code != apigen.ErrorCodeConflict {
		t.Errorf("code %q, want conflict", body.Error.Code)
	}
	if body.Error.Detail == nil || !strings.Contains(*body.Error.Detail, testEnvID2) {
		t.Fatalf("protected-destination 409 detail = %v, want it to name the destination %q", body.Error.Detail, testEnvID2)
	}

	// A PLAIN conflict — one that wraps domain.ErrConflict with no SafeDetail —
	// must stay uniform: errorBody keys on an explicit detail carrier, not on the
	// code, so widening detail to conflict did not leak every conflict body.
	plain := newValueServer(t, stubEnvs{}, stubValues{stubHierarchy{err: domain.ErrConflict}})
	resp2, payload2 := call(t, plain, http.MethodPost, api.PathPrefix+copyRoutePath, "hik_1_cli_x",
		map[string]any{
			"source_environment_id":       testEnvID,
			"keys":                        []string{"TOKEN"},
			"destination_environment_ids": []string{testEnvID2},
		})
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("plain-conflict status %d, want 409", resp2.StatusCode)
	}
	if d := decodeError(t, payload2).Error.Detail; d != nil {
		t.Fatalf("plain conflict carried detail %q, want none — uniform response", *d)
	}
}
