// Package client is the operator's HTTP client for the Hikyo delivery surface.
//
// It decodes the delivery response into its OWN small struct rather than the
// server's generated types: the value slice (#63/#64 WP-A) is landing
// concurrently and the operator must not break on additive fields — so decoding
// is lenient (unknown members ignored) over the fields § 0.1 fixes. The
// transport mirrors internal/cli/client.go's discipline: HTTPS only, TLS ≥ 1.2,
// a credential is NEVER carried across a redirect.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// pathPrefix mirrors api.PathPrefix ("/api/v1"). Duplicated as a const so the
// operator client does not import the full openapi spec loader for one string.
const pathPrefix = "/api/v1"

// Outcome classifies a fetch into the ADR's three answers plus the two
// non-delivering statuses (§ 0.4). The reconciler maps each to a Secret
// lifecycle; an unrecognized status is deliberately OutcomeFetchFailed
// (fail-safe: retain, never scrub on a status we do not understand).
type Outcome int

const (
	// OutcomeOK is a 200. The reconciler inspects Response.Current / Keys.
	OutcomeOK Outcome = iota
	// OutcomeFetchFailed is a transport error, 5xx, 429, or 401 — dead/expired/
	// revoked credential, failed TokenRequest, unbound federation. Retain the
	// last-synced Secret, backoff. Never a staleness scrub.
	OutcomeFetchFailed
	// OutcomeScrub is a 404 under an authenticating principal — the scope is
	// nonexistent or the credential lost `read`. Converge the Secret to empty.
	OutcomeScrub
	// OutcomeNotMaterialized is a 409 — no published revision. Retain/empty.
	OutcomeNotMaterialized
)

// DeliveredKey mirrors the § 0.1 wire shape. Value is a pointer so
// presence-only (no value member) is distinguishable from an empty value: the
// all-or-nothing refusal turns on exactly that distinction.
type DeliveredKey struct {
	Name           string  `json:"name"`
	Classification string  `json:"classification"`
	Presence       string  `json:"presence"`
	Value          *string `json:"value,omitempty"`
}

// DeliveryResponse is the operator's decode of the delivery response. Only the
// fields § 0.1 fixes are decoded; any additive member the server grows is
// ignored (no DisallowUnknownFields).
type DeliveryResponse struct {
	Current             bool           `json:"current"`
	Cursor              string         `json:"cursor"`
	ChangeToken         string         `json:"change_token"`
	SchemaRevision      int64          `json:"schema_revision"`
	PinnedRevision      *int64         `json:"pinned_revision,omitempty"`
	PinExpired          bool           `json:"pin_expired"`
	CredentialExpiresAt *time.Time     `json:"credential_expires_at,omitempty"`
	Keys                []DeliveredKey `json:"keys"`
}

// FetchRequest is one conditional fetch. Cursor empty means a full authorized
// fetch. AcknowledgedKeys is sent comma-joined (§ 0.6) so the server records it.
type FetchRequest struct {
	Org, Project, Environment string
	Cursor                    string
	Projection                string
	AcknowledgedKeys          []string
	// Bearer is presented as `Authorization: Bearer <token>`, only to the bound
	// origin — the redirect guard keeps it off any other host.
	Bearer string
}

// Client is bound to one HikyoInstance origin and its trust anchors. Instances
// are immutable, so a caller may cache one per instance UID.
type Client struct {
	origin    string
	http      *http.Client
	userAgent string
}

// NewClient builds a client for an instance. rawURL must be https (CEL enforces
// it on the CRD; this refuses http defensively at the mechanism boundary too).
// caBundlePEM is the instance's trust anchors, or nil for the host's system
// roots. userAgent is `hikyo-operator/<version>`.
func NewClient(rawURL string, caBundlePEM []byte, userAgent string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("operator client: parse instance url: %w", err)
	}
	if u.Scheme != "https" {
		// Defensive: the managed Secret's env delivery is an integrity
		// capability, so a plaintext fetch that could be MITM'd is refused with
		// no flag to loosen it — the same stance as the CLI client and the CRD's
		// missing insecure-skip-verify field.
		return nil, fmt.Errorf("operator client: refusing non-https instance url %q: delivery is an integrity capability", rawURL)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caBundlePEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBundlePEM) {
			return nil, errors.New("operator client: instance caBundle contains no valid PEM certificate")
		}
		// Pin verification to the instance's declared anchors. Absent, the zero
		// RootCAs falls back to the system roots — the ADR's stated default.
		tlsCfg.RootCAs = pool
	}

	return &Client{
		origin:    strings.TrimRight(rawURL, "/"),
		userAgent: userAgent,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				// No ProxyFromEnvironment: an ambient HTTP_PROXY must not
				// redirect authenticated fetch traffic (same reasoning as the
				// server's directory client).
				TLSClientConfig:     tlsCfg,
				TLSHandshakeTimeout: 10 * time.Second,
				ForceAttemptHTTP2:   true,
			},
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				// A redirect off the recorded origin is the exfiltration path the
				// pinned endpoint exists to close; following it would hand the
				// bearer to whoever answered. Mirror the CLI client exactly.
				return fmt.Errorf("operator client: refusing to follow a redirect to %s://%s: a credential is never presented off its instance origin",
					req.URL.Scheme, req.URL.Host)
			},
		},
	}, nil
}

// Fetch performs one conditional delivery fetch. It returns the decoded response
// only on OutcomeOK; the other outcomes carry a descriptive error for the CR
// condition and event, and a nil response.
func (c *Client) Fetch(ctx context.Context, r FetchRequest) (*DeliveryResponse, Outcome, error) {
	endpoint := c.origin + pathPrefix +
		"/orgs/" + url.PathEscape(r.Org) +
		"/projects/" + url.PathEscape(r.Project) +
		"/environments/" + url.PathEscape(r.Environment) +
		"/delivery"

	q := url.Values{}
	if r.Cursor != "" {
		q.Set("cursor", r.Cursor)
	}
	if r.Projection != "" {
		q.Set("projection", r.Projection)
	}
	if len(r.AcknowledgedKeys) > 0 {
		// form/explode:false — comma-joined (§ 0.1).
		q.Set("acknowledged_keys", strings.Join(r.AcknowledgedKeys, ","))
	}
	if enc := q.Encode(); enc != "" {
		endpoint += "?" + enc
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, OutcomeFetchFailed, fmt.Errorf("operator client: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if r.Bearer == "" {
		return nil, OutcomeFetchFailed, errors.New("operator client: refusing to fetch without a credential")
	}
	req.Header.Set("Authorization", "Bearer "+r.Bearer)

	resp, err := c.http.Do(req)
	if err != nil {
		// Transport error (including the redirect refusal) → retain + backoff.
		return nil, OutcomeFetchFailed, fmt.Errorf("operator client: fetch: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
		payload, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if err != nil {
			return nil, OutcomeFetchFailed, fmt.Errorf("operator client: read body: %w", err)
		}
		var out DeliveryResponse
		if err := json.Unmarshal(payload, &out); err != nil {
			// A 200 whose body we cannot decode is not a delivery we can act on;
			// retain rather than scrub.
			return nil, OutcomeFetchFailed, fmt.Errorf("operator client: decode delivery response: %w", err)
		}
		return &out, OutcomeOK, nil
	case resp.StatusCode == http.StatusNotFound:
		return nil, OutcomeScrub, fmt.Errorf("operator client: authoritative refusal (404): scope nonexistent or read withdrawn")
	case resp.StatusCode == http.StatusConflict:
		return nil, OutcomeNotMaterialized, fmt.Errorf("operator client: no published revision (409)")
	case resp.StatusCode == http.StatusUnauthorized,
		resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode >= 500:
		return nil, OutcomeFetchFailed, fmt.Errorf("operator client: fetch failed with status %d", resp.StatusCode)
	default:
		// Unrecognized status → fail-safe retain (§ 0.4: any unrecognized status
		// is case 2).
		return nil, OutcomeFetchFailed, fmt.Errorf("operator client: unexpected status %d treated as fetch-failed", resp.StatusCode)
	}
}
