package forgejo

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
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

// API is the import boundary Sync can link. Its exact method set contains a
// name-only secret read and no variable read. The production HTTP client is
// registry-driven; checking that same registry catches a split route builder
// or generic request helper that source-string scanning could miss.
func TestVariableReadPathDoesNotExist(t *testing.T) {
	typeOf := reflect.TypeOf((*API)(nil)).Elem()
	got := make([]string, 0, typeOf.NumMethod())
	for i := range typeOf.NumMethod() {
		got = append(got, typeOf.Method(i).Name)
	}
	want := []string{
		"CreateVariable", "DeleteSecret", "DeleteVariable", "ListSecretNames",
		"PutSecret", "ResolveDestination", "UpdateVariable", "Version",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("linked Forgejo API operations = %v, want closed value-blind set %v", got, want)
	}
	for name, operation := range operationRegistry {
		if operation.Method == http.MethodGet && strings.Contains(operation.Path, "variables") {
			t.Errorf("operation %s links forbidden variable read %s %s", name, operation.Method, operation.Path)
		}
	}
}

func TestClientRefusesDeadlineThatCanOutliveProviderFence(t *testing.T) {
	_, err := NewClient(ClientConfig{Origin: "https://git.example", Credential: "token", Deadline: adapter.LeaseTime})
	if err == nil || !strings.Contains(err.Error(), "shorter than") {
		t.Fatalf("NewClient() error = %v, want provider-write lease bound", err)
	}
	if _, err := NewClient(ClientConfig{Origin: "https://git.example", Credential: "token", Deadline: 15 * time.Second}); err != nil {
		t.Fatalf("15s production deadline rejected: %v", err)
	}
}

func TestClientRetainsProviderPolicyOutsidePublicDialer(t *testing.T) {
	client, err := NewClient(ClientConfig{Origin: "https://git.example", Credential: "token", Deadline: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.http.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("Forgejo transport unexpectedly accepted an ambient or opaque proxy")
	}
	if transport.DialContext == nil {
		t.Fatal("Forgejo transport omitted the public-address dialer")
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
		Origin:       "https://git.example",
		Credential:   "token",
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.24.0.0/16")},
		Deadline:     15 * time.Second,
	}, staticNetworkResolver{netip.MustParseAddr("10.24.3.9")}, allowedDialer)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.http.Transport.(*http.Transport)
	conn, err := transport.DialContext(t.Context(), "tcp", "git.example:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if want := []string{"10.24.3.9:443"}; !slices.Equal(allowedDialer.attempts, want) {
		t.Fatalf("allowed dial attempts = %v, want %v", allowedDialer.attempts, want)
	}

	mixedDialer := &recordingNetworkDialer{}
	mixed, err := newClient(ClientConfig{
		Origin: "https://git.example", Credential: "token", Deadline: 15 * time.Second,
	}, staticNetworkResolver{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, mixedDialer)
	if err != nil {
		t.Fatal(err)
	}
	transport = mixed.http.Transport.(*http.Transport)
	if _, err := transport.DialContext(t.Context(), "tcp", "git.example:443"); err == nil {
		t.Fatal("mixed public/private resolution unexpectedly dialed")
	}
	if len(mixedDialer.attempts) != 0 {
		t.Fatalf("mixed-answer dial attempts = %v, want none", mixedDialer.attempts)
	}
}

func TestClientRejectsInvalidAllowedCIDRAtConstruction(t *testing.T) {
	_, err := NewClient(ClientConfig{
		Origin: "https://git.example", Credential: "token", AllowedCIDRs: []netip.Prefix{{}}, Deadline: 15 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid allowed CIDR") {
		t.Fatalf("NewClient() error = %v, want invalid-CIDR refusal", err)
	}
}

func TestPaginatedSecretListFindsSecondPageUnownedConflict(t *testing.T) {
	for _, destination := range []adapter.Destination{
		{Kind: adapter.Repository, Owner: "acme", Name: "app", NumericID: 42},
		{Kind: adapter.Organization, Owner: "acme", NumericID: 42},
	} {
		t.Run(string(destination.Kind), func(t *testing.T) {
			pages := []int{}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/actions/secrets") {
					if r.URL.Query().Get("limit") != "50" {
						t.Errorf("limit=%q", r.URL.Query().Get("limit"))
					}
					page, _ := strconv.Atoi(r.URL.Query().Get("page"))
					pages = append(pages, page)
					rows := make([]map[string]string, 0, 50)
					if page == 1 {
						for i := 0; i < 50; i++ {
							rows = append(rows, map[string]string{"name": fmt.Sprintf("OTHER_%02d", i)})
						}
					} else if page == 2 {
						rows = append(rows, map[string]string{"name": "TOKEN"})
					}
					_ = json.NewEncoder(w).Encode(rows)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]int64{"id": 42})
			}))
			defer server.Close()
			client, err := NewTestClient(server.URL, "token", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			journal := newFakeJournal()
			result, err := (&Module{API: client}).Sync(t.Context(), adapter.SyncRequest{
				Target:   adapter.Target{ID: "target", Environment: "env", Generation: 1, Destination: destination},
				Manifest: []adapter.ManifestEntry{{KeyID: "key", CanonicalName: "TOKEN", Classification: adapter.SecretClassification, Value: "secret"}},
			}, journal)
			if !errors.Is(err, adapter.ErrConflict) || len(result.Conflicts) != 1 {
				t.Fatalf("Sync() result=%+v error=%v, want second-page conflict", result, err)
			}
			if !slices.Equal(pages, []int{1, 2}) {
				t.Fatalf("secret pages=%v", pages)
			}
		})
	}
}

func TestSecretPaginationRefusesAtLedgerSafetyBound(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests > 200 {
			http.Error(w, "client crossed pagination bound", http.StatusInternalServerError)
			return
		}
		rows := make([]map[string]string, 0, providerPageLimit)
		for i := 0; i < providerPageLimit; i++ {
			rows = append(rows, map[string]string{"name": fmt.Sprintf("NAME_%05d", (requests-1)*providerPageLimit+i)})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rows)
	}))
	defer server.Close()
	client, err := NewTestClient(server.URL, "token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListSecretNames(t.Context(), adapter.Destination{Kind: adapter.Repository, Owner: "acme", Name: "app"})
	if !errors.Is(err, ErrSecretListLimit) {
		t.Fatalf("ListSecretNames() error = %v, want named safety refusal", err)
	}
	if requests != 200 {
		t.Fatalf("page requests = %d, want 200", requests)
	}
}
