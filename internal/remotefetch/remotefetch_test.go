package remotefetch

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCONNECTCancellationClosesAStalledProxyConnection(t *testing.T) {
	client, proxy := net.Pipe()
	requestRead := make(chan struct{})
	peerDone := make(chan error, 1)
	go func() {
		defer proxy.Close()
		if _, err := http.ReadRequest(bufio.NewReader(proxy)); err != nil {
			peerDone <- err
			return
		}
		close(requestRead)
		var oneByte [1]byte
		_, err := proxy.Read(oneByte[:])
		peerDone <- err
	}()

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		result <- establishCONNECT(ctx, client, "remote.example:443", time.Minute)
	}()

	<-requestRead
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("CONNECT cancellation = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled CONNECT remained blocked on the proxy response")
	}
	select {
	case err := <-peerDone:
		if err == nil {
			t.Fatal("the proxy connection remained open after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("the stalled proxy retained its connection after cancellation")
	}
}

func testClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{Deadline: 5 * time.Second, ResponseCap: 1 << 20, FanOut: 4})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// The pin is the trust root, so the two cases that matter are that the RIGHT
// key connects and the WRONG key does not. Without the negative case the
// InsecureSkipVerify in the transport would be exactly the hole it looks like.
func TestPinAcceptsTheServersOwnKeyAndRefusesAnother(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	good := SPKIFingerprint(srv.Certificate())
	c := testClient(t)

	if _, err := c.httpClient(good).Get(srv.URL); err != nil {
		t.Fatalf("the server's own SPKI pin was refused: %v", err)
	}

	// A syntactically valid but different fingerprint must abort the
	// handshake, BEFORE any request line or credential reaches the wire.
	const wrong = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	_, err := c.httpClient(wrong).Get(srv.URL)
	if err == nil {
		t.Fatal("a mismatched pin was accepted — the pin is the only trust root on this channel")
	}
	if got := ClassifyError(err, 0); got != OutcomePinMismatch {
		t.Errorf("outcome = %q, want %q; the operator must see a pin mismatch as its own loud "+
			"state, not as generic unreachability", got, OutcomePinMismatch)
	}
}

// A redirect is a fetch failure BY NAME. Following one would let a remote move
// the credential's destination after the pin was confirmed.
func TestRedirectIsRefusedByName(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.invalid/", http.StatusFound)
	}))
	defer srv.Close()

	_, err := testClient(t).httpClient(SPKIFingerprint(srv.Certificate())).Get(srv.URL)
	if err == nil {
		t.Fatal("a redirect was followed")
	}
	if got := ClassifyError(err, 0); got != OutcomeRedirectRefused {
		t.Errorf("outcome = %q, want %q", got, OutcomeRedirectRefused)
	}
}

// Acceptance criterion 6's instrumentation, proven to be live: the counter has
// to move when a connection IS originated, or asserting that it does not move
// during workspace use would prove nothing.
func TestDialsCountsOriginatedConnections(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	before := Dials()
	resp, err := testClient(t).httpClient(SPKIFingerprint(srv.Certificate())).Get(srv.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	defer resp.Body.Close()

	if Dials() <= before {
		t.Fatal("Dials() did not move for a connection this package originated — the " +
			"outbound-byte instrumentation is inert, and every assertion built on it is vacuous")
	}
}

// The URL grammar: a canonical https origin and nothing else. Each refusal
// below is a stored value that would either steer the request or put a
// credential somewhere it does not belong.
func TestValidateRemoteURL(t *testing.T) {
	valid := []string{
		"https://hikyo.went.io",
		"https://hikyo.went.io/",
		"https://192.168.1.10:8443", // LAN remotes are the homelab's normal case
	}
	for _, raw := range valid {
		if err := ValidateRemoteURL(raw); err != nil {
			t.Errorf("ValidateRemoteURL(%q) = %v, want nil", raw, err)
		}
	}

	invalid := map[string]string{
		"http://hikyo.went.io":          "plaintext",
		"https://user:pw@hikyo.went.io": "userinfo",
		"https://hikyo.went.io/api/v1":  "path",
		"https://hikyo.went.io?a=b":     "query",
		"https://hikyo.went.io#frag":    "fragment",
		"https://":                      "no host",
		"ftp://hikyo.went.io":           "wrong scheme",
		"//hikyo.went.io":               "no scheme",
	}
	for raw, why := range invalid {
		if err := ValidateRemoteURL(raw); err == nil {
			t.Errorf("ValidateRemoteURL(%q) = nil, want a refusal (%s)", raw, why)
		}
	}
}

// A configuration with a missing bound is refused loudly rather than defaulted:
// a bound that silently defaults is a bound nobody chose.
func TestIncompleteConfigIsRefused(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no deadline":     {ResponseCap: 1, FanOut: 1},
		"no response cap": {Deadline: time.Second, FanOut: 1},
		"no fan-out":      {Deadline: time.Second, ResponseCap: 1},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New accepted an incomplete config", name)
		}
	}
}

// Ambient proxy discovery must never apply: a process's environment must not be
// able to redirect authenticated fleet traffic. Only explicit configuration.
func TestProxyIsExplicitConfigurationOnly(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://attacker.invalid:3128")

	c := testClient(t)
	transport, ok := c.httpClient("pin").Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected transport type")
	}
	if transport.Proxy != nil {
		t.Error("a proxy was configured from the environment; egress must traverse a forward " +
			"proxy only under explicit instance configuration")
	}

	configured, err := New(Config{
		Deadline: time.Second, ResponseCap: 1, FanOut: 1,
		Proxy: &url.URL{Scheme: "https", Host: "proxy.internal:3128"},
	})
	if err != nil {
		t.Fatalf("New with explicit proxy: %v", err)
	}
	explicit, ok := configured.httpClient("pin").Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected transport type")
	}
	// Transport.Proxy stays NIL even with a proxy configured, and that is the
	// fix rather than a regression: Go applies one TLSClientConfig to both hops,
	// so letting the transport do the CONNECT would compare the PROXY's
	// certificate against the REMOTE's SPKI pin and fail every proxied fetch.
	// The tunnel is opened in DialContext under WebPKI instead, and the pinned
	// config then applies to exactly the end-to-end handshake inside it.
	if explicit.Proxy != nil {
		t.Error("the transport is doing its own CONNECT; the proxy hop would then be " +
			"verified against the remote's pin")
	}
	// The dial path is what must honour it. A configured proxy that nothing
	// reads is the same defect wearing a different shape, so this asserts the
	// dial actually goes to the proxy's address and not the remote's.
	_, err = configured.httpClient("pin").Transport.(*http.Transport).
		DialContext(t.Context(), "tcp", "remote.invalid:443")
	if err == nil {
		t.Fatal("dialling an unreachable proxy succeeded")
	}
	if !strings.Contains(err.Error(), "proxy.internal") {
		t.Errorf("the dial did not go through the configured proxy (%v)", err)
	}

	// Plaintext proxies are refused at construction.
	if _, err := New(Config{
		Deadline: time.Second, ResponseCap: 1, FanOut: 1,
		Proxy: &url.URL{Scheme: "http", Host: "proxy.internal:3128"},
	}); err == nil {
		t.Error("a plaintext forward proxy was accepted; the CONNECT request names the " +
			"remote host, so an http proxy publishes the fleet topology to the path")
	}
}

// A stored origin with a trailing slash and one without are the same origin,
// and exactly one of them concatenates onto the directory path correctly.
func TestCanonicalRemoteURLHasNoTrailingSlash(t *testing.T) {
	for _, raw := range []string{"https://peer.example", "https://peer.example/"} {
		got, err := CanonicalRemoteURL(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got != "https://peer.example" {
			t.Errorf("%s canonicalized to %q, want the slash-free origin — the other "+
				"spelling builds //api/v1/instance/directory", raw, got)
		}
	}
	if _, err := CanonicalRemoteURL("http://peer.example"); err == nil {
		t.Error("a plaintext remote URL was canonicalized rather than refused")
	}
}

// A ROUND MUST NOT MANUFACTURE EVIDENCE ABOUT REMOTES IT NEVER DIALLED.
//
// The fan-out cap forces a fleet into waves. A whole-round budget that does not
// account for them cancels the later waves, and — before this — every cancelled
// request came back as an ordinary `unreachable` result, indistinguishable from
// a remote that was contacted and did not answer. The caller then persisted a
// fetch-failure snapshot and an audit event per remote, for connections nobody
// opened.
func TestRoundBudgetCoversEveryWaveAndUnattemptedTargetsAreOmitted(t *testing.T) {
	c, err := New(Config{Deadline: 10 * time.Second, ResponseCap: 1 << 20, FanOut: 4})
	if err != nil {
		t.Fatal(err)
	}
	// 50 remotes at a fan-out of 4 is thirteen waves. A flat two-deadline
	// budget gave the round 20s of a 130s job.
	if got, want := c.RoundBudget(50), 14*10*time.Second; got != want {
		t.Errorf("RoundBudget(50) = %v, want %v (ceil(50/4) waves + 1 of margin, each "+
			"allowed the per-remote deadline)", got, want)
	}
	if got := c.RoundBudget(1); got < 10*time.Second {
		t.Errorf("RoundBudget(1) = %v, want at least one per-remote deadline", got)
	}

	// Three waves' worth of targets against a round context that is already
	// over: nothing is attempted, so nothing is reported.
	targets := make([]Target, 12)
	for i := range targets {
		targets[i] = Target{ID: "rmt_" + string(rune('a'+i)), Origin: "https://unreachable.invalid", Pin: "x"}
	}
	dead, cancel := context.WithCancel(t.Context())
	cancel()
	if got := c.FetchAll(dead, targets); len(got) != 0 {
		t.Errorf("a cancelled round reported %d results; a target that was never dialled "+
			"has produced no evidence and must be OMITTED, so the caller serves its "+
			"last-known snapshot instead of persisting a fabricated failure", len(got))
	}
}
