// Package remotefetch is the directory tier's outbound client (#71,
// multi-instance ADR § The outbound client).
//
// It is a NEW OUTBOUND SURFACE ON THE SERVER, and the threat model's amendment
// enumerates it as one class — configured remote hikyo instances — under the
// full user-configured-outbound control set. Every exported knob below is one
// of that set's normative members, and the package exists as its own package
// so the set is enforced in one place rather than re-derived per caller.
//
// The property that makes the air-gap statement survive this feature: an
// instance with zero configured remotes performs ZERO outbound connections.
// Nothing here runs on a timer — there is deliberately no background poller
// (the architecture ADR fixed no generic job framework, and a standing
// authenticated heartbeat toward every remote for a health dot nobody is
// looking at is exactly what that rules out). A fetch happens because a holder
// of `instance-directory` is looking at the directory, and at no other moment.
package remotefetch

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// Outcome is the closed result enum the snapshot's `last_outcome` column and
// the `remote.fetch_failed` audit event both carry. A failure's KIND is the
// operator-visible part: "unreachable" and "credential-rejected" are different
// states because the operator's fix differs, and collapsing them into one
// "error" is what makes a directory card useless.
type Outcome string

const (
	OutcomeOK Outcome = "ok"
	// OutcomeUnreachable is any transport-level failure: DNS, connection
	// refused, timeout, TLS handshake other than a pin mismatch.
	OutcomeUnreachable Outcome = "unreachable"
	// OutcomeCredentialRejected is a 401 or 403 — a revoked or expired
	// directory credential, loud and distinct from unreachability.
	OutcomeCredentialRejected Outcome = "credential-rejected"
	// OutcomePinMismatch is the hard, loud entry error. Never a retry-through.
	OutcomePinMismatch Outcome = "pin-mismatch"
	// OutcomeRedirectRefused: a redirect response is a fetch failure BY NAME,
	// never followed. Following one would let a compromised or misconfigured
	// remote move the credential's destination after the pin was confirmed.
	OutcomeRedirectRefused Outcome = "redirect-refused"
	// OutcomeIdentityConflict is the same instance identity arriving from two
	// different entries — a restored clone left running. Both entries are
	// marked duplicated and neither is served as current.
	OutcomeIdentityConflict Outcome = "identity-conflict"
	// OutcomeSelfConnected is an entry that returned THIS instance's identity.
	// Refused loudly at the authenticated fetch, and re-checked on every
	// subsequent one, so a URL that later comes to resolve to the instance
	// itself fails at fetch time rather than rendering it as its own remote.
	OutcomeSelfConnected Outcome = "self-connected"
)

// ErrPinMismatch is the pin failure, surfaced as its own error so the caller
// can map it to its own outcome rather than parsing a TLS error string.
var ErrPinMismatch = errors.New("remotefetch: server public key does not match the pinned fingerprint")

// dials counts every outbound connection this package originates.
//
// It exists for acceptance criterion 6's second half, which the MVP boundary
// recasts as "outbound-byte instrumentation in the harness (server originates
// no connection during workspace use)". A workspace is browser-to-remote by
// construction, so the correct server-side observation is that the number does
// not move — and an assertion about an absence needs a counter that would have
// moved if the absence were violated.
//
// ponytail: one process-wide counter, not per-remote accounting. It answers
// the one question the criterion asks. Per-remote or per-byte accounting is a
// metrics concern; add it when something actually consumes it.
var dials atomic.Uint64

// Dials returns the number of outbound connections originated since process
// start. Monotonic, never reset — a test takes a delta.
func Dials() uint64 { return dials.Load() }

// ValidateRemoteURL enforces the ADR's URL grammar: a canonical https origin
// and nothing else.
//
// The fetch path is appended by the client from the API contract and NEVER
// from configuration, which is why a path, query or fragment here is an error
// rather than something to strip: a stored value that carries one was either a
// mistake or an attempt to steer the request, and silently normalising it
// would hide both. Userinfo is refused because a credential belongs in the
// entry's sealed column, not in a URL that appears in logs and audit payloads.
func ValidateRemoteURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("remotefetch: unparseable remote URL: %w", err)
	}
	switch {
	case u.Scheme != "https":
		// Plaintext is refused outright. The pin authenticates the peer, but
		// it cannot protect a credential written onto an unencrypted wire.
		return errors.New("remotefetch: a remote URL must be https")
	case u.User != nil:
		return errors.New("remotefetch: a remote URL must not carry userinfo")
	case u.Path != "" && u.Path != "/":
		return errors.New("remotefetch: a remote URL must be a bare origin, with no path")
	case u.RawQuery != "":
		return errors.New("remotefetch: a remote URL must not carry a query")
	case u.Fragment != "":
		return errors.New("remotefetch: a remote URL must not carry a fragment")
	case u.Host == "":
		return errors.New("remotefetch: a remote URL must name a host")
	}
	return nil
}

// CanonicalRemoteURL validates and returns the ONE spelling of a remote origin:
// scheme://host[:port], with no trailing slash.
//
// `https://peer.example/` and `https://peer.example` are the same origin and a
// human types either, so both are accepted — but exactly one is stored and
// used, because the other one concatenates into `https://peer.example//api/v1/
// instance/directory`. A double slash is a different path to most routers and
// an outright 404 to some, so the difference between the two spellings would
// show up as an unreachable remote with no explanation.
func CanonicalRemoteURL(raw string) (string, error) {
	if err := ValidateRemoteURL(raw); err != nil {
		return "", err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return u.Scheme + "://" + u.Host, nil
}

// SPKIFingerprint is the pinned value: base64(sha256(SubjectPublicKeyInfo)).
//
// It is over the PUBLIC KEY, not the certificate, so an ordinary certificate
// renewal that keeps the key does not break a pin and force every viewing
// instance through the re-add ceremony. This is the same construction the
// CLI's local trust store uses; one fingerprint spelling for the whole
// product.
func SPKIFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// Config is the composable-maxima catalogue's outbound half. Zero values are
// refused rather than defaulted: a bound that silently defaults is a bound
// nobody chose, and the ops spec is where these numbers are ratified.
type Config struct {
	// Deadline bounds one remote's whole fetch, connect through body read.
	Deadline time.Duration
	// ResponseCap bounds the bytes read from one remote. Foreign bytes are
	// parsed only after being bounded.
	ResponseCap int64
	// FanOut bounds how many remotes are fetched in parallel.
	FanOut int
	// Proxy, when set, is the ONLY way egress traverses a forward proxy:
	// explicit instance configuration, never ambient environment discovery.
	// It is used with CONNECT so TLS and the pin verify end-to-end against the
	// remote — a proxy is a network hop, never a trust party — and a
	// plaintext-to-proxy URL is refused at construction.
	Proxy *url.URL
}

// Client performs pinned fetches under one Config.
type Client struct {
	cfg Config
}

// New builds a client, refusing an incomplete or unsafe configuration loudly.
func New(cfg Config) (*Client, error) {
	switch {
	case cfg.Deadline <= 0:
		return nil, errors.New("remotefetch: a per-remote deadline is required")
	case cfg.ResponseCap <= 0:
		return nil, errors.New("remotefetch: a response size cap is required")
	case cfg.FanOut <= 0:
		return nil, errors.New("remotefetch: a fan-out cap is required")
	}
	if cfg.Proxy != nil {
		// PLAINTEXT PROXIES ARE REFUSED, for the same reason a plaintext remote
		// URL is: the CONNECT request names the remote host, so an http proxy
		// publishes which installations this one talks to, to anything on the
		// path, and offers an unauthenticated hop to redirect the tunnel. The
		// end-to-end pin still protects the credential, but "nobody can read
		// the payload" is not the whole of the control set.
		if cfg.Proxy.Scheme != "https" {
			return nil, fmt.Errorf("remotefetch: a forward proxy must be https, got %q", cfg.Proxy.Scheme)
		}
		if cfg.Proxy.Host == "" {
			return nil, errors.New("remotefetch: a forward proxy must name a host")
		}
	}
	return &Client{cfg: cfg}, nil
}

// httpClient builds the transport for one pinned remote.
//
// The pin is verified BEFORE ANY BYTES ARE WRITTEN, on every connection, by
// VerifyPeerCertificate — which TLS runs during the handshake, so a mismatch
// aborts before the request line, let alone the credential, reaches the wire.
//
// InsecureSkipVerify is set, and that name is misleading here: it disables
// WebPKI chain validation and nothing else, because the pin REPLACES the CA as
// the trust root. That is the deliberate design — the ADR's two-trust-model
// split says the directory channel is authenticated by the pin, which is
// strictly stronger than WebPKI for this purpose and is what lets a homelab
// remote on a LAN address with a private CA work without weakening anything.
// The verification below is mandatory, not optional: an empty chain fails.
func (c *Client) httpClient(pin string) *http.Client {
	dialer := &net.Dialer{Timeout: c.cfg.Deadline}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Counted here, at the one place a connection is actually
			// originated, so the instrumentation cannot be bypassed by a
			// different call path.
			if c.cfg.Proxy != nil {
				return c.dialThroughProxy(ctx, addr)
			}
			dials.Add(1)
			// Private-range targets are explicitly PERMITTED: remotes on LAN
			// addresses are the homelab's normal case. Rebinding is defeated by
			// the pin rather than by an address filter — a rebound host cannot
			// present the pinned key — and an address filter would break the
			// deployment this product is built for.
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// See the doc comment: the pin is the trust root, not the CA.
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return ErrPinMismatch
				}
				leaf, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return ErrPinMismatch
				}
				if SPKIFingerprint(leaf) != pin {
					return ErrPinMismatch
				}
				return nil
			},
		},
		// Proxy is deliberately NIL even when a proxy is configured. Go applies
		// ONE TLSClientConfig to both hops, so with the pinned config above the
		// proxy's own certificate would be compared against the REMOTE's SPKI
		// pin and every proxied fetch would fail as a pin mismatch. The two
		// hops have two different trust models — the proxy is an ordinary
		// WebPKI peer, the remote is pinned — so the CONNECT tunnel is
		// established in DialContext instead, under its own WebPKI config, and
		// the transport's pinned config then applies to exactly the end-to-end
		// handshake inside it.
		//
		// http.ProxyFromEnvironment stays unused whatever happens here: ambient
		// environment discovery would let a process's environment redirect
		// authenticated fleet traffic.
		Proxy: nil,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   c.cfg.Deadline,
		// A redirect is a fetch failure by name, never followed.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirect
		},
	}
}

var errRedirect = errors.New("remotefetch: the remote answered with a redirect, which is a fetch failure")

// dialThroughProxy opens a CONNECT tunnel to addr through the configured
// forward proxy and returns the tunnelled connection.
//
// The proxy hop is verified as an ORDINARY WEBPKI PEER — a real chain, a real
// hostname match, no pin — because that is what it is: a piece of the
// operator's own network, named in the operator's own configuration. The remote
// hop keeps the pin, and gets it by handshaking INSIDE this connection under
// the transport's own TLSClientConfig. Two hops, two trust models, neither one
// borrowing the other's root.
func (c *Client) dialThroughProxy(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: c.cfg.Deadline},
		Config:    &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.cfg.Proxy.Hostname()},
	}
	host := c.cfg.Proxy.Host
	if c.cfg.Proxy.Port() == "" {
		host = net.JoinHostPort(host, "443")
	}
	dials.Add(1)
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	if err := establishCONNECT(ctx, conn, addr, c.cfg.Deadline); err != nil {
		return nil, err
	}
	return conn, nil
}

// establishCONNECT owns conn until a tunnel is established. Both blocking
// writes and reads are bounded by the smaller of the request context and the
// configured remote deadline; cancellation actively wakes either syscall.
// Any failure closes the connection before returning, so a stalled proxy
// cannot retain a goroutine and file descriptor past the request budget.
func establishCONNECT(ctx context.Context, conn net.Conn, addr string, deadline time.Duration) error {
	closeWithError := func(err error) error {
		_ = conn.Close()
		return err
	}
	ioDeadline := time.Now().Add(deadline)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(ioDeadline) {
		ioDeadline = contextDeadline
	}
	if err := conn.SetDeadline(ioDeadline); err != nil {
		return closeWithError(err)
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: http.Header{},
	}
	if err := req.Write(conn); err != nil {
		stopCancellation()
		return closeWithError(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		stopCancellation()
		if ctx.Err() != nil {
			return closeWithError(ctx.Err())
		}
		return closeWithError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		stopCancellation()
		return closeWithError(fmt.Errorf("remotefetch: the forward proxy refused CONNECT with %s", resp.Status))
	}
	if !stopCancellation() {
		return closeWithError(ctx.Err())
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return closeWithError(err)
	}
	return nil
}

// ClassifyError maps a transport or status failure to its outcome. It is
// exported because the snapshot writer and the audit event must agree about
// what happened, and two independent mappings would eventually disagree.
func ClassifyError(err error, statusCode int) Outcome {
	switch {
	case errors.Is(err, ErrPinMismatch) || (err != nil && strings.Contains(err.Error(), ErrPinMismatch.Error())):
		return OutcomePinMismatch
	case errors.Is(err, errRedirect) || (err != nil && strings.Contains(err.Error(), errRedirect.Error())):
		return OutcomeRedirectRefused
	case err != nil:
		return OutcomeUnreachable
	case statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden:
		return OutcomeCredentialRejected
	case statusCode != http.StatusOK:
		return OutcomeUnreachable
	}
	return OutcomeOK
}
