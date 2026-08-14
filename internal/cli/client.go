package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
)

// Client is the origin-bound HTTP client.
//
// Two properties it enforces that a bare http.Client does not:
//
//   - the recorded SPKI pin is verified on connect, so a validly-certificated
//     impostor is refused even though its chain is real;
//   - a redirect is NEVER followed with a credential attached. A redirect off
//     the recorded origin is the exfiltration path the trust store exists to
//     close, and following it would hand the bearer to whoever answered.
type Client struct {
	Entry TrustEntry
	HTTP  *http.Client
	// Bearer is the session artifact, presented only to Entry.Origin.
	Bearer string
	// UserAgent identifies the client class in the audit trail.
	UserAgent string
}

// NewClient builds a client bound to a trust entry.
func NewClient(entry TrustEntry, bearer string) (*Client, error) {
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	if strings.HasPrefix(entry.Origin, "https://") {
		if entry.SPKIPin == "" {
			return nil, failf(ExitRefused,
				"trust entry %q names an https origin with no recorded certificate pin; re-establish it", entry.Name)
		}
		pin := entry.SPKIPin
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			// The pin REPLACES chain and hostname verification rather than
			// supplementing it, deliberately: the self-hosted audience this
			// product is built for routinely runs a certificate their own CA
			// issued, and refusing that would push them to a worse workaround.
			// What is left is strictly stronger than a chain for this purpose
			// — an impostor needs the pinned private key, and a
			// publicly-trusted certificate for the same hostname does not
			// become acceptable just because it chains to a public root.
			//
			// The pin is checked against the LEAF ONLY (rawCerts[0]).
			// Scanning the whole chain would let an attacker satisfy it by
			// including the legitimate certificate as an intermediate while
			// presenting a leaf whose private key they hold — the pin would
			// match a certificate that is not the one terminating the
			// connection.
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("%s presented no certificate", entry.Origin)
				}
				leaf, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return fmt.Errorf("%s presented an unparseable certificate: %w", entry.Origin, err)
				}
				if SPKIFingerprint(leaf) == pin {
					return nil
				}
				return fmt.Errorf(
					"certificate identity for %s does not match the pin recorded at establishment (%s). "+
						"This is what an interception looks like; it is also what a re-keyed certificate looks like. "+
						"If the change is legitimate, re-establish the instance deliberately",
					entry.Origin, shortPin(pin))
			},
			// Chain verification is intentionally replaced by the exact leaf
			// SPKI check above so operator-issued certificates remain usable.
			// codeql[go/disabled-certificate-check]
			InsecureSkipVerify: true, //nolint:gosec // replaced by the leaf public-key pin above, which a valid chain alone cannot satisfy
		}
	} else if !isLoopbackOrigin(entry.Origin) {
		// http to anywhere but loopback would put the bearer on the wire in
		// clear. There is no flag for this.
		return nil, failf(ExitRefused,
			"refusing to use plaintext http for a non-loopback instance (%s): the session artifact is a bearer credential",
			entry.Origin)
	}

	return &Client{
		Entry:  entry,
		Bearer: bearer,
		HTTP: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				return failf(ExitRefused,
					"refusing to follow a redirect to %s: a credential is never presented off the origin it was established against",
					req.URL.Scheme+"://"+req.URL.Host)
			},
		},
		UserAgent: "hikyo-cli",
	}, nil
}

// isLoopbackOrigin decides whether plaintext http is acceptable. url.Hostname
// strips the brackets an IPv6 literal carries, so `http://[::1]:8080` is
// recognised — a hand-rolled colon split reads its host as "[" and refuses a
// perfectly good loopback address.
func isLoopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Do performs a request against the bound origin and decodes the result.
//
// `out` may be nil for endpoints with no body. A non-2xx response is
// converted to an exit code through the contract's closed error enum, so the
// CLI's exit codes and the API's statuses cannot drift apart.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Entry.Origin+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	if c.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.Bearer)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		// A refusal raised by CheckRedirect or the pin check arrives wrapped
		// in a url.Error; unwrap so its exit code survives.
		var ce *Error
		if ok := asCLIError(err, &ce); ok {
			return ce
		}
		return failf(ExitUnavailable, "%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return failf(ExitUnavailable, "reading the response: %v", err)
	}
	if resp.StatusCode >= 400 {
		return errorFromResponse(resp.StatusCode, payload)
	}
	if out == nil || len(payload) == 0 {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return failf(ExitInternal, "the server's response did not match the contract: %v", err)
	}
	return nil
}

// errorFromResponse maps the contract's closed error enum onto the closed
// exit-code set. The status is the fallback, not the mechanism: a server that
// grows a new status without a code the client knows is a skew problem the
// minimum-revision registry is for, and it lands as ExitInternal rather than
// being silently reinterpreted.
func errorFromResponse(status int, payload []byte) error {
	var body apigen.Error
	if err := json.Unmarshal(payload, &body); err != nil {
		return failf(exitForStatus(status), "server returned %d", status)
	}
	code := body.Error.Code
	message := body.Error.Message
	if body.Error.Detail != nil && *body.Error.Detail != "" {
		message += " (" + *body.Error.Detail + ")"
	}
	switch code {
	case apigen.ErrorCodeUnauthenticated:
		return failf(ExitAuth, "%s", message)
	case apigen.ErrorCodeForbidden, apigen.ErrorCodeBadRequest,
		// A conflict and a structural bound are both refusals under the exit-code
		// taxonomy's own wording ("refused: validation, policy, ceremony
		// declined"). Left to the default they landed on ExitInternal, which told
		// a script the server broke when it had in fact answered correctly.
		apigen.ErrorCodeConflict, apigen.ErrorCodeLimitExceeded:
		return failf(ExitRefused, "%s", message)
	case apigen.ErrorCodeNotFound:
		return failf(ExitNotFound, "%s", message)
	case apigen.ErrorCodeTooManyRequests:
		return failf(ExitUnavailable, "%s", message)
	case apigen.ErrorCodeInternal:
		return failf(ExitInternal, "%s", message)
	default:
		return failf(exitForStatus(status), "server returned %d: %s", status, message)
	}
}

func exitForStatus(status int) int {
	switch {
	case status == http.StatusUnauthorized:
		return ExitAuth
	case status == http.StatusNotFound:
		return ExitNotFound
	case status == http.StatusForbidden, status == http.StatusBadRequest,
		status == http.StatusConflict:
		return ExitRefused
	case status >= 500, status == http.StatusTooManyRequests:
		return ExitUnavailable
	default:
		return ExitInternal
	}
}

// Meta fetches the instance's capability advertisement. `login` needs it
// before any session exists, and every verb uses its API revision for the
// skew check below.
func (c *Client) Meta(ctx context.Context) (apigen.Meta, error) {
	var meta apigen.Meta
	if err := c.Do(ctx, http.MethodGet, api.PathPrefix+"/meta", nil, &meta); err != nil {
		return apigen.Meta{}, err
	}
	return meta, nil
}

// CheckRevision refuses an operation the server is too old to serve, NAMING
// the server version. A new client against an old server degrades loudly, not
// silently: the per-operation minimum revision is the mechanism, and a bare
// version string is not.
func CheckRevision(meta apigen.Meta, operationID string) error {
	ops, err := api.Operations()
	if err != nil {
		return err
	}
	op, ok := ops[operationID]
	if !ok {
		return failf(ExitInternal, "this client has no contract entry for %q", operationID)
	}
	if meta.ApiRevision < op.MinRevision {
		return failf(ExitRefused,
			"this instance is running %s (API revision %d) and does not serve %q, which needs revision %d. Upgrade the server.",
			meta.ServerVersion, meta.ApiRevision, operationID, op.MinRevision)
	}
	return nil
}
