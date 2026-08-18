// Package forgejo is the Forgejo REST v1 reference deployment adapter.
// Its provider interface deliberately cannot express a variable read.
package forgejo

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/netpolicy"
)

const (
	responseCap             = 1 << 20
	providerPageLimit       = 50
	providerSecretNameLimit = 10_000
)

var ErrSecretListLimit = errors.New("forgejo: secret name listing reached the 10000-name safety limit before exhaustion")

type API interface {
	Version(context.Context) (string, error)
	ResolveDestination(context.Context, adapter.Destination) (int64, error)
	ListSecretNames(context.Context, adapter.Destination) ([]string, error)
	PutSecret(context.Context, adapter.Destination, string, string) error
	DeleteSecret(context.Context, adapter.Destination, string) error
	CreateVariable(context.Context, adapter.Destination, string, string) error
	UpdateVariable(context.Context, adapter.Destination, string, string) error
	DeleteVariable(context.Context, adapter.Destination, string) error
}

type operation struct {
	Method string
	Path   string
}

// operationRegistry is the closed linked provider surface. There is no
// variable GET/list operation; the structural test pins this registry and API.
var operationRegistry = map[string]operation{
	"version":              {Method: http.MethodGet, Path: "/version"},
	"resolve-repository":   {Method: http.MethodGet, Path: "/repos/{owner}/{repo}"},
	"resolve-organization": {Method: http.MethodGet, Path: "/orgs/{org}"},
	"list-secrets":         {Method: http.MethodGet, Path: "/{destination}/actions/secrets"},
	"put-secret":           {Method: http.MethodPut, Path: "/{destination}/actions/secrets/{name}"},
	"delete-secret":        {Method: http.MethodDelete, Path: "/{destination}/actions/secrets/{name}"},
	"create-variable":      {Method: http.MethodPost, Path: "/{destination}/actions/variables/{name}"},
	"update-variable":      {Method: http.MethodPut, Path: "/{destination}/actions/variables/{name}"},
	"delete-variable":      {Method: http.MethodDelete, Path: "/{destination}/actions/variables/{name}"},
}

type ClientConfig struct {
	Origin       string
	Credential   string
	AllowedCIDRs []netip.Prefix
	Deadline     time.Duration
}

type Client struct {
	origin string
	token  string
	http   *http.Client
}

// Forget drops the retained bearer as soon as one outbox attempt ends.
func (c *Client) Forget() { c.token = "" }

func NewClient(cfg ClientConfig) (*Client, error) {
	origin, err := canonicalOrigin(cfg.Origin)
	if err != nil {
		return nil, err
	}
	if cfg.Credential == "" {
		return nil, errors.New("forgejo: a scoped personal access token is required")
	}
	if cfg.Deadline <= 0 {
		return nil, errors.New("forgejo: a request deadline is required")
	}
	if cfg.Deadline >= adapter.LeaseTime {
		return nil, errors.New("forgejo: request deadline must be shorter than the provider-write lease")
	}
	allowed := append([]netip.Prefix(nil), cfg.AllowedCIDRs...)
	dialer := &net.Dialer{Timeout: cfg.Deadline}
	transport := &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("forgejo: destination address: %w", err)
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("forgejo: resolve destination: %w", err)
			}
			for _, ip := range ips {
				if permitted(ip, allowed) {
					return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				}
			}
			return nil, errors.New("forgejo: destination resolved only to non-global or special-use addresses")
		},
	}
	return &Client{
		origin: origin,
		token:  cfg.Credential,
		http: &http.Client{
			Transport: transport,
			Timeout:   cfg.Deadline,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("forgejo: redirects are refused")
			},
		},
	}, nil
}

// NewTestClient permits a test transport while retaining the production
// request construction, response cap, no-variable-read registry, and error
// sanitization. Production callers use NewClient.
func NewTestClient(origin, credential string, client *http.Client) (*Client, error) {
	canonical, err := canonicalOrigin(origin)
	if err != nil {
		return nil, err
	}
	if credential == "" || client == nil {
		return nil, errors.New("forgejo: test client requires credential and HTTP client")
	}
	return &Client{origin: canonical, token: credential, http: client}, nil
}

func canonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("forgejo: parse origin: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("forgejo: origin must be a bare https origin")
	}
	return "https://" + u.Host, nil
}

func permitted(ip netip.Addr, exceptions []netip.Prefix) bool {
	ip = ip.Unmap()
	for _, prefix := range exceptions {
		if prefix.Contains(ip) {
			return true
		}
	}
	return !netpolicy.IsNonPublic(ip)
}

type ResponseError struct {
	Status int
}

func (e *ResponseError) Error() string {
	return "forgejo: provider refused request with status " + strconv.Itoa(e.Status)
}

func (c *Client) do(ctx context.Context, op operation, path string, body any, out any) error {
	var input io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		input = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, op.Method, c.origin+"/api/v1"+path, input)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("forgejo: provider request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, responseCap+1))
	if err != nil {
		return errors.New("forgejo: provider response could not be read")
	}
	if len(raw) > responseCap {
		return errors.New("forgejo: provider response exceeded 1 MiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Provider bodies are intentionally not surfaced: a broken provider can
		// echo request material in an error, and that material may be plaintext.
		responseErr := &ResponseError{Status: resp.StatusCode}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return errors.Join(adapter.ErrProviderAuth, responseErr)
		}
		return responseErr
	}
	if out != nil && len(raw) != 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return errors.New("forgejo: provider response did not match the expected shape")
		}
	}
	return nil
}

func destinationPath(d adapter.Destination) (string, error) {
	switch d.Kind {
	case adapter.Repository:
		if d.Owner == "" || d.Name == "" {
			return "", errors.New("forgejo: repository destination requires owner and repository")
		}
		return "repos/" + url.PathEscape(d.Owner) + "/" + url.PathEscape(d.Name), nil
	case adapter.Organization:
		if d.Owner == "" || d.Name != "" {
			return "", errors.New("forgejo: organization destination requires only organization name")
		}
		return "orgs/" + url.PathEscape(d.Owner), nil
	default:
		return "", errors.New("forgejo: unknown destination kind")
	}
}

func (c *Client) Version(ctx context.Context) (string, error) {
	var out struct {
		Version string `json:"version"`
	}
	err := c.do(ctx, operationRegistry["version"], "/version", nil, &out)
	return out.Version, err
}

func (c *Client) ResolveDestination(ctx context.Context, d adapter.Destination) (int64, error) {
	path, err := destinationPath(d)
	if err != nil {
		return 0, err
	}
	var out struct {
		ID int64 `json:"id"`
	}
	key := "resolve-repository"
	if d.Kind == adapter.Organization {
		key = "resolve-organization"
	}
	err = c.do(ctx, operationRegistry[key], "/"+path, nil, &out)
	return out.ID, err
}

func (c *Client) ListSecretNames(ctx context.Context, d adapter.Destination) ([]string, error) {
	path, err := destinationPath(d)
	if err != nil {
		return nil, err
	}
	var names []string
	for page := 1; ; page++ {
		var rows []struct {
			Name string `json:"name"`
		}
		query := "?page=" + strconv.Itoa(page) + "&limit=" + strconv.Itoa(providerPageLimit)
		if err := c.do(ctx, operationRegistry["list-secrets"], "/"+path+"/actions/secrets"+query, nil, &rows); err != nil {
			return nil, err
		}
		if len(names)+len(rows) > providerSecretNameLimit {
			return nil, ErrSecretListLimit
		}
		for _, row := range rows {
			names = append(names, row.Name)
		}
		if len(rows) < providerPageLimit {
			break
		}
		if len(names) >= providerSecretNameLimit {
			return nil, ErrSecretListLimit
		}
	}
	return names, nil
}

func (c *Client) PutSecret(ctx context.Context, d adapter.Destination, name, value string) error {
	return c.named(ctx, "put-secret", d, name, map[string]string{"data": value})
}
func (c *Client) DeleteSecret(ctx context.Context, d adapter.Destination, name string) error {
	return c.named(ctx, "delete-secret", d, name, nil)
}
func (c *Client) CreateVariable(ctx context.Context, d adapter.Destination, name, value string) error {
	return c.named(ctx, "create-variable", d, name, map[string]string{"value": value})
}
func (c *Client) UpdateVariable(ctx context.Context, d adapter.Destination, name, value string) error {
	return c.named(ctx, "update-variable", d, name, map[string]string{"value": value})
}
func (c *Client) DeleteVariable(ctx context.Context, d adapter.Destination, name string) error {
	return c.named(ctx, "delete-variable", d, name, nil)
}

func (c *Client) named(ctx context.Context, key string, d adapter.Destination, name string, body any) error {
	path, err := destinationPath(d)
	if err != nil {
		return err
	}
	surface := "secrets"
	if strings.Contains(key, "variable") {
		surface = "variables"
	}
	return c.do(ctx, operationRegistry[key], "/"+path+"/actions/"+surface+"/"+url.PathEscape(name), body, nil)
}

func IsConflict(err error) bool {
	var response *ResponseError
	return errors.As(err, &response) && (response.Status == http.StatusConflict || response.Status == http.StatusUnprocessableEntity)
}

func IsNotFound(err error) bool {
	var response *ResponseError
	return errors.As(err, &response) && response.Status == http.StatusNotFound
}
