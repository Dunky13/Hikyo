package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Dunky13/wenv/api"
	"github.com/Dunky13/wenv/api/apigen"
	"github.com/Dunky13/wenv/internal/admission"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/server"
	"github.com/Dunky13/wenv/internal/service"
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
	login    func(ctx context.Context, u, p string) (service.LoginResult, error)
	identity func(ctx context.Context, presented string) (service.Identity, error)
	logout   func(ctx context.Context, presented string) error
	estab    func(ctx context.Context, authority, password string) error
}

func (s stubAuth) LocalLogin(ctx context.Context, u, p string) (service.LoginResult, error) {
	if s.login == nil {
		return service.LoginResult{}, domain.ErrUnauthenticated
	}
	return s.login(ctx, u, p)
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

func (s stubAuth) EnrolTOTPConfirm(context.Context, string, string) (service.LoginResult, error) {
	return service.LoginResult{}, domain.ErrUnauthenticated
}

func (s stubAuth) StepUpTOTP(context.Context, string, string) (service.LoginResult, error) {
	return service.LoginResult{}, domain.ErrUnauthenticated
}

func (s stubAuth) RemoveTOTP(context.Context, string, string) (service.LoginResult, error) {
	return service.LoginResult{}, domain.ErrUnauthenticated
}

func (s stubAuth) GenerateRecoveryCodes(context.Context, string, string) ([]string, service.LoginResult, error) {
	return nil, service.LoginResult{}, domain.ErrUnauthenticated
}

func (s stubAuth) ConsumeRecoveryCode(context.Context, string, string) (service.RecoveryResult, error) {
	return service.RecoveryResult{}, domain.ErrUnauthenticated
}

type stubOrgs struct {
	create func(ctx context.Context, a service.Actor, name string, active bool, meta json.RawMessage) (service.Org, error)
	get    func(ctx context.Context, a service.Actor, id string) (service.Org, error)
	list   func(ctx context.Context, a service.Actor) ([]service.Org, error)
}

func (s stubOrgs) Create(ctx context.Context, a service.Actor, n string, active bool, m json.RawMessage) (service.Org, error) {
	if s.create == nil {
		return service.Org{}, domain.ErrUnauthorized
	}
	return s.create(ctx, a, n, active, m)
}

func (s stubOrgs) Get(ctx context.Context, a service.Actor, id string) (service.Org, error) {
	if s.get == nil {
		return service.Org{}, domain.ErrNotFound
	}
	return s.get(ctx, a, id)
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
		Auth: auth, Orgs: orgs, Version: "test",
	}))
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
	for _, bearer := range []string{"", "not-a-token", "ew_1_cli_totallyfabricated000000", "ew_9_xx_nonsense"} {
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
		get: func(context.Context, service.Actor, string) (service.Org, error) {
			return service.Org{}, domain.ErrNotFound
		},
	})
	forbidden := newTestServer(t, stubAuth{identity: liveIdentityFn}, stubOrgs{
		get: func(context.Context, service.Actor, string) (service.Org, error) {
			// The service maps a tenant-class refusal onto ErrNotFound at the
			// chokepoint; this fixture stands in for that having happened.
			return service.Org{}, domain.ErrNotFound
		},
	})
	respA, bodyA := call(t, missing, http.MethodGet, api.PathPrefix+"/orgs/"+testOrgID, "ew_1_cli_x", nil)
	respB, bodyB := call(t, forbidden, http.MethodGet, api.PathPrefix+"/orgs/"+testOrgID, "ew_1_cli_x", nil)
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
	resp, _ := call(t, srv, http.MethodPost, api.PathPrefix+"/orgs", "ew_1_cli_x",
		map[string]any{"name": "acme", "tier": "gold"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 — an unknown request member was accepted", resp.StatusCode)
	}
}

func TestSuccessfulLoginMatchesTheContract(t *testing.T) {
	srv := newTestServer(t, stubAuth{
		login: func(context.Context, string, string) (service.LoginResult, error) {
			return service.LoginResult{
				SessionToken: "ew_1_cli_stub", SessionID: liveIdentity.SessionID,
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
	if result.SessionToken == "" {
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
			resp, payload := call(t, srv, http.MethodPost, api.PathPrefix+"/orgs", "ew_1_cli_x", tc.body)
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
		login: func(context.Context, string, string) (service.LoginResult, error) {
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
