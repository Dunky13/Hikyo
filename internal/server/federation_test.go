package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/delivery"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/server"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

// The HTTP leg of #62. The isolation suite drives the federation and delivery
// SERVICES against a real datastore and a real issuer; this drives the ROUTER —
// the handler plumbing, the render functions, and the response validation the
// contract test harness performs on every call.
//
// It is a separate concern from the service tests and the reason is specific:
// the delivery route is the first in the contract to declare
// `machine-credential` artifact eligibility, and the mint-shaped render paths
// (`wireBinding`, `FetchDelivery`) are the two places a nullable member could be
// rendered wrong without any service-level test noticing.

// stubDelivery answers a fixed projection, so the assertions are about the wire
// rather than about the datastore.
type stubDelivery struct {
	cursor              string
	credentialExpiresAt time.Time
	err                 error
	// got records the options the transport passed through, so a wire test can
	// assert the projection and acknowledgement query params reached the service
	// unmangled. It is a pointer because the stub is handed to the server by
	// value; the pointee is shared with the test.
	got *service.FetchOptions
}

func (s stubDelivery) Fetch(_ context.Context, presented string, scope domain.Scope, cursor string, opts service.FetchOptions) (service.FetchResult, error) {
	if s.got != nil {
		*s.got = opts
	}
	if s.err != nil {
		return service.FetchResult{}, s.err
	}
	// The presented artifact reaches the service RAW — that is the one thing this
	// route does differently from every other, because the artifact class decides
	// how the caller is resolved.
	if presented == "" {
		return service.FetchResult{}, domain.ErrUnauthenticated
	}
	if cursor == s.cursor && cursor != "" {
		return service.FetchResult{Current: true, Cursor: s.cursor, ChangeToken: "v1:token", SchemaRevision: 7}, nil
	}
	// A delivered value carries plaintext; a presence-only secret carries none,
	// so the render half is exercised on both a non-nil and a nil `value`.
	delivered := "postgres://render-test"
	return service.FetchResult{
		Cursor: s.cursor, ChangeToken: "v1:token", SchemaRevision: 7,
		CredentialExpiresAt: s.credentialExpiresAt,
		Keys: []service.DeliveredKey{
			{Name: "DATABASE_URL", Classification: "config", Presence: delivery.PresenceSet, Value: &delivered},
			{Name: "DATABASE_PASSWORD", Classification: "secret", Presence: delivery.PresenceSet},
		},
	}, nil
}

type stubFederation struct{ err error }

func (s stubFederation) CreateIssuer(context.Context, service.Actor, service.IssuerRequest) (service.IssuerView, error) {
	return service.IssuerView{}, s.err
}

func (s stubFederation) UpdateIssuer(context.Context, service.Actor, string, domain.JWKSMode, string, []string) (service.IssuerView, error) {
	return service.IssuerView{}, s.err
}

func (s stubFederation) ListIssuers(context.Context, service.Actor) ([]service.IssuerView, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []service.IssuerView{{
		ID: "fis_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f15", Issuer: "https://issuer.test", Type: domain.IssuerKubernetes,
		Mode: domain.JWKSDiscovery, RefusedAudiences: []string{"https://kubernetes.default.svc"},
		CreatedAt: time.Unix(1_800_000_000, 0).UTC(), CreatedBy: "usr_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f17", Bindings: 2,
	}}, nil
}

func (s stubFederation) DeleteIssuer(context.Context, service.Actor, string) error { return s.err }

func (s stubFederation) CreateBinding(_ context.Context, _ service.Actor, _ domain.Scope, _ string, req service.BindingRequest) (service.BindingView, error) {
	if s.err != nil {
		return service.BindingView{}, s.err
	}
	return service.BindingView{
		CredentialID: "mcr_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f16", IssuerID: "fis_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f15", Issuer: req.Issuer,
		IssuerType: domain.IssuerGitHubActions, Subject: req.Subject, Audience: req.Audience,
		RequiredClaims: req.RequiredClaims, Lifetime: domain.LifetimeFinite,
		ExpiresAt: time.Unix(1_810_000_000, 0).UTC(),
		CreatedAt: time.Unix(1_800_000_000, 0).UTC(), CreatedBy: "usr_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f17",
		ReplacedID: req.Replaces,
	}, nil
}

func federationServer(t *testing.T, fed server.FederationService, del server.DeliveryService) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(server.New(stubReady{}, &server.API{
		Auth: stubAuth{}, Orgs: stubOrgs{}, Providers: stubProviders{}, Version: "test",
		Projects: stubHierarchy{}, Environments: stubEnvs{}, Folders: stubFolders{},
		Federation: fed, Delivery: del,
	}, nil))
	t.Cleanup(srv.Close)
	return srv
}

const deliveryPath = api.PathPrefix + "/orgs/org_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f11/projects/prj_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f12/environments/env_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f13/delivery"

// TestDeliveryRouteRendersBothDispositions is the render half: a full delivery
// carries its keys, a `current` answer carries a NON-NULL EMPTY array, and both
// carry the cursor. The empty array matters — a client that had to distinguish
// "no keys" from "field absent" would be deciding disclosure by JSON shape.
func TestDeliveryRouteRendersBothDispositions(t *testing.T) {
	srv := federationServer(t, stubFederation{}, stubDelivery{cursor: "v1:cursor"})

	resp, payload := call(t, srv, http.MethodGet, deliveryPath, "hik_1_wl_abc", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("full fetch -> %d: %s", resp.StatusCode, payload)
	}
	var full apigen.DeliveryResponse
	if err := json.Unmarshal(payload, &full); err != nil {
		t.Fatal(err)
	}
	if full.Current || len(full.Keys) != 2 || full.Cursor != "v1:cursor" || full.ChangeToken != "v1:token" {
		t.Fatalf("full fetch rendered %+v", full)
	}
	if full.SchemaRevision != 7 {
		t.Errorf("schema_revision = %d, want 7", full.SchemaRevision)
	}

	resp, payload = call(t, srv, http.MethodGet, deliveryPath+"?cursor=v1:cursor", "hik_1_wl_abc", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("conditional fetch -> %d: %s", resp.StatusCode, payload)
	}
	var current apigen.DeliveryResponse
	if err := json.Unmarshal(payload, &current); err != nil {
		t.Fatal(err)
	}
	if !current.Current {
		t.Fatal("presenting the served cursor did not answer `current`")
	}
	if current.Keys == nil {
		t.Fatal("`current` rendered keys as JSON null; it must be an empty array")
	}
	if len(current.Keys) != 0 {
		t.Fatalf("`current` carried %d keys, want none", len(current.Keys))
	}
}

// TestDeliveryRouteCarriesTheProjectionAndValue pins the new fetch surface at
// the wire: the `projection` and `acknowledged_keys` query params reach the
// service unmangled, a delivered value renders as the optional `value` member
// while a presence-only key omits it, and a finite `credential_expires_at`
// renders while a zero one stays absent.
func TestDeliveryRouteCarriesTheProjectionAndValue(t *testing.T) {
	var got service.FetchOptions
	expires := time.Unix(1_820_000_000, 0).UTC()
	srv := federationServer(t, stubFederation{}, stubDelivery{
		cursor: "v1:cursor", credentialExpiresAt: expires, got: &got,
	})

	resp, payload := call(t, srv, http.MethodGet,
		deliveryPath+"?projection=config-only&acknowledged_keys=PATH,LD_PRELOAD", "hik_1_wl_abc", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch -> %d: %s", resp.StatusCode, payload)
	}
	// The authorized term and the acknowledgement reached the service verbatim.
	if got.Projection != delivery.ModeConfigOnly {
		t.Errorf("service saw projection %q, want config-only", got.Projection)
	}
	if len(got.AcknowledgedKeys) != 2 || got.AcknowledgedKeys[0] != "PATH" || got.AcknowledgedKeys[1] != "LD_PRELOAD" {
		t.Errorf("service saw acknowledged_keys %v, want [PATH LD_PRELOAD] in order", got.AcknowledgedKeys)
	}

	var full apigen.DeliveryResponse
	if err := json.Unmarshal(payload, &full); err != nil {
		t.Fatal(err)
	}
	// The delivered value renders; the presence-only secret omits `value`.
	byName := map[string]apigen.DeliveredKey{}
	for _, k := range full.Keys {
		byName[k.Name] = k
	}
	if v := byName["DATABASE_URL"].Value; v == nil || *v != "postgres://render-test" {
		t.Errorf("DATABASE_URL value = %v, want the delivered plaintext", v)
	}
	if byName["DATABASE_PASSWORD"].Value != nil {
		t.Error("a presence-only secret rendered a value; it must omit the member")
	}
	if full.CredentialExpiresAt == nil || !full.CredentialExpiresAt.Equal(expires) {
		t.Errorf("credential_expires_at = %v, want %v", full.CredentialExpiresAt, expires)
	}

	// A default (cursor-only) request carries no projection or acknowledgement,
	// and an indefinite credential (zero expiry) renders no member. A fresh
	// server whose stub returns the zero expiry drives the absence.
	var gotDefault service.FetchOptions
	indef := federationServer(t, stubFederation{}, stubDelivery{cursor: "v1:cursor", got: &gotDefault})
	resp, payload = call(t, indef, http.MethodGet, deliveryPath, "hik_1_wl_abc", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("default fetch -> %d: %s", resp.StatusCode, payload)
	}
	// oapi fills the spec default, so a request omitting `projection` reaches
	// the service as `full` (the empty mode normalizes to the same thing), and
	// an omitted acknowledgement carries no keys.
	if m := delivery.NormalizeMode(gotDefault.Projection); m != delivery.ModeFull {
		t.Errorf("default projection reached the service as %q, want full", gotDefault.Projection)
	}
	if len(gotDefault.AcknowledgedKeys) != 0 {
		t.Errorf("default request carried acknowledged_keys %v, want none", gotDefault.AcknowledgedKeys)
	}
	var dflt apigen.DeliveryResponse
	if err := json.Unmarshal(payload, &dflt); err != nil {
		t.Fatal(err)
	}
	if dflt.CredentialExpiresAt != nil {
		t.Errorf("indefinite credential rendered credential_expires_at = %v, want absent", dflt.CredentialExpiresAt)
	}
}

// TestDeliveryRouteRefusesWithoutAnArtifact pins that the route reaches the
// service with the RAW presented value and that an absent one is the uniform
// refusal — the same 401 body every other unauthenticated refusal returns.
func TestDeliveryRouteRefusesWithoutAnArtifact(t *testing.T) {
	srv := federationServer(t, stubFederation{}, stubDelivery{cursor: "v1:cursor"})
	resp, payload := call(t, srv, http.MethodGet, deliveryPath, "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("artifact-less fetch -> %d: %s", resp.StatusCode, payload)
	}
	if code := decodeError(t, payload).Error.Code; code != apigen.ErrorCodeUnauthenticated {
		t.Errorf("error code %q, want unauthenticated", code)
	}
}

// TestDeliveryRouteIsIndistinguishableWhenUnauthorized is the ADR's rule at the
// transport: a caller who may not read the environment gets the uniform
// nonexistent answer, never "current" and never a 403.
func TestDeliveryRouteIsIndistinguishableWhenUnauthorized(t *testing.T) {
	srv := federationServer(t, stubFederation{}, stubDelivery{err: domain.ErrNotFound})
	resp, payload := call(t, srv, http.MethodGet, deliveryPath+"?cursor=v1:cursor", "hik_1_wl_abc", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized conditional fetch -> %d: %s", resp.StatusCode, payload)
	}
	withoutCursor, plain := call(t, srv, http.MethodGet, deliveryPath, "hik_1_wl_abc", nil)
	if withoutCursor.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized full fetch -> %d: %s", withoutCursor.StatusCode, plain)
	}
	// Byte-identical: presenting a cursor must not be a way to learn anything a
	// cursor-less caller could not learn.
	if string(payload) != string(plain) {
		t.Fatalf("refusal bodies differ:\n  with cursor:    %s\n  without cursor: %s", payload, plain)
	}
}

// TestBindingRouteRendersTheDiscriminatedPins is the other render half. The
// pinned-claim types must survive the round trip: a number stays a number, so a
// binding written against `repository_id: 4242` is not silently satisfiable by
// the string "4242".
func TestBindingRouteRendersTheDiscriminatedPins(t *testing.T) {
	srv := federationServer(t, stubFederation{}, stubDelivery{})
	repoID := int64(4242)
	event := "push"
	body := apigen.CreateBindingRequest{
		Issuer:  "https://token.actions.githubusercontent.com",
		Subject: "repo:acme/service:ref:refs/heads/main", Audience: "hikyo://instance",
		RequiredClaims: []apigen.FederatedClaimPin{
			{Claim: "repository_id", NumberValue: &repoID},
			{Claim: "event_name", StringValue: &event},
		},
	}
	resp, payload := call(t, srv, http.MethodPost,
		api.PathPrefix+"/orgs/org_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f11/projects/prj_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f12/service-accounts/sa_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f14/bindings", "hik_1_cli_abc", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create binding -> %d: %s", resp.StatusCode, payload)
	}
	var out apigen.FederatedBinding
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatal(err)
	}
	if out.Credential.Kind != apigen.CredentialKind(domain.CredentialOIDCFederation) {
		t.Errorf("credential kind %q, want oidc-federation", out.Credential.Kind)
	}
	// A binding has no minted value, so it has no prefix hint. The absence is the
	// shape rule, not an omission.
	if out.Credential.PrefixHint != nil {
		t.Errorf("a federated binding rendered a prefix hint: %q", *out.Credential.PrefixHint)
	}
	if out.Credential.Subject == nil || *out.Credential.Subject != body.Subject {
		t.Errorf("subject round-tripped as %v", out.Credential.Subject)
	}
	if out.Credential.RequiredClaims == nil || len(*out.Credential.RequiredClaims) != 2 {
		t.Fatalf("pinned claims round-tripped as %v", out.Credential.RequiredClaims)
	}
	for _, pin := range *out.Credential.RequiredClaims {
		switch pin.Claim {
		case "repository_id":
			if pin.NumberValue == nil || *pin.NumberValue != repoID {
				t.Errorf("repository_id round-tripped as %+v, want the number %d", pin, repoID)
			}
			if pin.StringValue != nil {
				t.Errorf("repository_id round-tripped as a STRING %q: the type was folded", *pin.StringValue)
			}
		case "event_name":
			if pin.StringValue == nil || *pin.StringValue != event {
				t.Errorf("event_name round-tripped as %+v, want the string %q", pin, event)
			}
		default:
			t.Errorf("unexpected pin %q", pin.Claim)
		}
	}
}

// TestFederationIssuerRouteHidesTheStaticDocument pins the one thing the read
// shape must not carry. The generated type has no member for it, so this is a
// regression guard on the contract rather than on the handler.
func TestFederationIssuerRouteHidesTheStaticDocument(t *testing.T) {
	srv := federationServer(t, stubFederation{}, stubDelivery{})
	resp, payload := call(t, srv, http.MethodGet, api.PathPrefix+"/instance/federation-issuers", "hik_1_cli_abc", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list issuers -> %d: %s", resp.StatusCode, payload)
	}
	var raw []map[string]any
	var envelope struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	raw = envelope.Items
	if len(raw) != 1 {
		t.Fatalf("listed %d issuers, want 1", len(raw))
	}
	for _, forbidden := range []string{"static_jwks", "jwks", "keys"} {
		if _, present := raw[0][forbidden]; present {
			t.Errorf("the issuer read shape carries %q", forbidden)
		}
	}
}
