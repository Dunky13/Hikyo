// Package githubactions implements the GitHub Actions deployment adapter.
// Its provider boundary deliberately cannot express a variable read.
package githubactions

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
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
	"sync"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/netpolicy"
)

const (
	responseCap        = 1 << 20
	pageSize           = 100
	secretNameLimit    = 10_000
	apiVersion         = "2022-11-28"
	defaultRateBackoff = time.Minute
	// Retain rate history beyond the longest provider retry so the next job
	// cannot turn a shared one-hour backoff into a fresh one-minute attempt.
	credentialStateTTL  = 2 * adapter.RetryCap
	maxCredentialStates = 1024
)

var ErrSecretListIncomplete = errors.New("github-actions: secret-name pagination was incomplete")

type PublicKey struct {
	ID  string
	Key [32]byte
}

type WriteResult struct{ Status int }

type DestinationIdentity struct {
	ID           int64
	RepositoryID int64
}

type API interface {
	ResolveDestination(context.Context, adapter.Destination) (DestinationIdentity, error)
	CreateEnvironment(context.Context, adapter.Destination) error
	VerifySelectedRepositories(context.Context, adapter.Destination) error
	ReplaceSelectedRepositories(context.Context, adapter.Destination, adapter.Surface, string) error
	ListSecretNames(context.Context, adapter.Destination) ([]string, error)
	PublicKey(context.Context, adapter.Destination) (PublicKey, error)
	PutSecret(context.Context, adapter.Destination, string, string, string) (WriteResult, error)
	DeleteSecret(context.Context, adapter.Destination, string) error
	CreateVariable(context.Context, adapter.Destination, string, string) (WriteResult, error)
	UpdateVariable(context.Context, adapter.Destination, string, string) (WriteResult, error)
	DeleteVariable(context.Context, adapter.Destination, string) error
}

type operation struct {
	Method   string
	Mutation bool
}

// Closed provider surface. Variable GET/list is intentionally inexpressible.
var operationRegistry = map[string]operation{
	"resolve-repository":    {Method: http.MethodGet},
	"resolve-organization":  {Method: http.MethodGet},
	"resolve-environment":   {Method: http.MethodGet},
	"create-environment":    {Method: http.MethodPut, Mutation: true},
	"resolve-repository-id": {Method: http.MethodGet},
	"replace-selected":      {Method: http.MethodPut, Mutation: true},
	"list-secrets":          {Method: http.MethodGet},
	"public-key":            {Method: http.MethodGet},
	"put-secret":            {Method: http.MethodPut, Mutation: true},
	"delete-secret":         {Method: http.MethodDelete, Mutation: true},
	"create-variable":       {Method: http.MethodPost, Mutation: true},
	"update-variable":       {Method: http.MethodPatch, Mutation: true},
	"delete-variable":       {Method: http.MethodDelete, Mutation: true},
}

func (c *Client) VerifySelectedRepositories(ctx context.Context, d adapter.Destination) error {
	if d.Kind != adapter.Organization || d.Visibility != "selected" {
		return nil
	}
	for _, id := range d.SelectedRepositoryIDs {
		var out struct {
			ID    int64 `json:"id"`
			Owner struct {
				Login string `json:"login"`
			} `json:"owner"`
		}
		if _, err := c.do(ctx, operationRegistry["resolve-repository-id"], "/repositories/"+strconv.FormatInt(id, 10), nil, &out); err != nil {
			return fmt.Errorf("github-actions: selected repository %d unavailable: %w", id, err)
		}
		if out.ID != id || !strings.EqualFold(out.Owner.Login, d.Owner) {
			return fmt.Errorf("%w: selected repository %d no longer belongs to organization %q", adapter.ErrDestinationID, id, d.Owner)
		}
	}
	return nil
}

func (c *Client) ReplaceSelectedRepositories(ctx context.Context, d adapter.Destination, surface adapter.Surface, name string) error {
	if d.Kind != adapter.Organization || d.Visibility != "selected" {
		return nil
	}
	path, err := destinationPath(d)
	if err != nil {
		return err
	}
	path += "/actions/" + string(surface) + "s/" + url.PathEscape(name) + "/repositories"
	_, err = c.do(ctx, operationRegistry["replace-selected"], path, map[string]any{"selected_repository_ids": append([]int64(nil), d.SelectedRepositoryIDs...)}, nil)
	return err
}

func (c *Client) CreateEnvironment(ctx context.Context, d adapter.Destination) error {
	if d.Kind != adapter.Environment {
		return errors.New("github-actions: only environment destinations can be created")
	}
	path, err := destinationPath(d)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, operationRegistry["create-environment"], path, struct{}{}, nil)
	return err
}

type ClientConfig struct {
	Origin       string
	Credential   string
	AllowedCIDRs []netip.Prefix
	Deadline     time.Duration
}

type mutationPacer interface{ Wait(context.Context) error }

type serialPacer struct {
	mu   sync.Mutex
	next time.Time
	now  func() time.Time
}

type credentialState struct {
	pacer                  *serialPacer
	refs                   int
	lastUsed               time.Time
	rateMu                 sync.Mutex
	headerlessRateAttempts int
}

var credentialStates = struct {
	sync.Mutex
	entries map[[32]byte]*credentialState
}{entries: map[[32]byte]*credentialState{}}

func evictStaleCredentialStatesLocked(now time.Time) {
	for key, state := range credentialStates.entries {
		if state.refs == 0 && !state.lastUsed.Add(credentialStateTTL).After(now) {
			delete(credentialStates.entries, key)
		}
	}
}

func evictCredentialStateForInsertLocked() {
	for len(credentialStates.entries) >= maxCredentialStates {
		var oldestKey [32]byte
		var oldest *credentialState
		for key, state := range credentialStates.entries {
			if state.refs == 0 && (oldest == nil || state.lastUsed.Before(oldest.lastUsed)) {
				oldestKey, oldest = key, state
			}
		}
		if oldest == nil {
			return
		}
		delete(credentialStates.entries, oldestKey)
	}
}

func acquireCredentialState(credential string, now func() time.Time) (*credentialState, func()) {
	key := crypto.CredentialFingerprint([]byte(credential))
	stamp := now().UTC()
	credentialStates.Lock()
	evictStaleCredentialStatesLocked(stamp)
	state := credentialStates.entries[key]
	if state == nil {
		evictCredentialStateForInsertLocked()
		state = &credentialState{pacer: &serialPacer{now: now}, lastUsed: stamp}
		credentialStates.entries[key] = state
	}
	state.refs++
	state.lastUsed = stamp
	credentialStates.Unlock()
	var once sync.Once
	return state, func() {
		once.Do(func() {
			credentialStates.Lock()
			defer credentialStates.Unlock()
			state.refs--
			state.lastUsed = now().UTC()
			evictStaleCredentialStatesLocked(state.lastUsed)
		})
	}
}

func (p *serialPacer) Wait(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if wait := p.next.Sub(now); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		now = p.now()
	}
	p.next = now.Add(time.Second)
	return nil
}

type Client struct {
	origin                 string
	token                  string
	http                   *http.Client
	now                    func() time.Time
	pacer                  mutationPacer
	credentialState        *credentialState
	releaseCredentialState func()
	forgetOnce             sync.Once
	expiryMu               sync.RWMutex
	credentialExpiresAt    time.Time
}

// CredentialExpiresAt returns provider metadata only; it never derives or
// decodes credential contents.
func (c *Client) CredentialExpiresAt() time.Time {
	c.expiryMu.RLock()
	defer c.expiryMu.RUnlock()
	return c.credentialExpiresAt
}

func (c *Client) captureCredentialExpiry(header http.Header) {
	raw := headerValue(header, "GitHub-Authentication-Token-Expiration")
	if raw == "" {
		return
	}
	for _, layout := range []string{"2006-01-02 15:04:05 MST", time.RFC3339, time.RFC1123} {
		if expires, err := time.Parse(layout, raw); err == nil {
			c.expiryMu.Lock()
			c.credentialExpiresAt = expires.UTC()
			c.expiryMu.Unlock()
			return
		}
	}
}

func (c *Client) Forget() {
	c.forgetOnce.Do(func() {
		c.token = ""
		if c.releaseCredentialState != nil {
			c.releaseCredentialState()
		}
	})
}

func validateCredential(token string) error {
	switch {
	case strings.HasPrefix(token, "github_pat_"):
		return nil
	case strings.HasPrefix(token, "ghp_"):
		return errors.New("github-actions: classic PAT refused; use a least-privilege fine-grained PAT")
	case token == "":
		return errors.New("github-actions: a fine-grained PAT is required")
	default:
		return errors.New("github-actions: credential is not a fine-grained PAT (expected github_pat_ prefix)")
	}
}

func NewClient(cfg ClientConfig) (*Client, error) {
	origin, err := canonicalOrigin(cfg.Origin)
	if err != nil {
		return nil, err
	}
	if err := validateCredential(cfg.Credential); err != nil {
		return nil, err
	}
	if cfg.Deadline <= 0 || cfg.Deadline >= adapter.LeaseTime {
		return nil, errors.New("github-actions: request deadline must be positive and shorter than the provider-write lease")
	}
	allowed := append([]netip.Prefix(nil), cfg.AllowedCIDRs...)
	dialer := &net.Dialer{Timeout: cfg.Deadline}
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("github-actions: destination address: %w", err)
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("github-actions: resolve destination: %w", err)
			}
			for _, ip := range ips {
				if permitted(ip, allowed) {
					return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				}
			}
			return nil, errors.New("github-actions: destination resolved only to non-global or special-use addresses")
		},
	}
	now := func() time.Time { return time.Now().UTC() }
	state, releaseState := acquireCredentialState(cfg.Credential, now)
	return &Client{origin: origin, token: cfg.Credential, now: now, pacer: state.pacer, credentialState: state, releaseCredentialState: releaseState, http: &http.Client{
		Transport: transport, Timeout: cfg.Deadline,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("github-actions: redirects are refused") },
	}}, nil
}

func NewTestClient(origin, credential string, client *http.Client) (*Client, error) {
	return newTestClientAt(origin, credential, client, func() time.Time { return time.Now().UTC() })
}

func newTestClientAt(origin, credential string, client *http.Client, now func() time.Time) (*Client, error) {
	canonical, err := canonicalOrigin(origin)
	if err != nil {
		return nil, err
	}
	if err := validateCredential(credential); err != nil {
		return nil, err
	}
	if client == nil || now == nil {
		return nil, errors.New("github-actions: test client requires HTTP client and clock")
	}
	state := &credentialState{pacer: &serialPacer{now: now}, lastUsed: now().UTC()}
	return &Client{origin: canonical, token: credential, http: client, now: now, credentialState: state}, nil
}

func canonicalOrigin(raw string) (string, error) {
	if raw == "" {
		raw = "https://api.github.com"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("github-actions: parse origin: %w", err)
	}
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (path != "" && path != "/api/v3") {
		return "", errors.New("github-actions: origin must be https://api.github.com or an HTTPS GHES /api/v3 base URL")
	}
	return "https://" + u.Host + path, nil
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

type ResponseError struct{ Status int }

func (e *ResponseError) Error() string {
	return "github-actions: provider refused request with status " + strconv.Itoa(e.Status)
}

type rateLimitError struct{ at time.Time }

func (e *rateLimitError) Error() string      { return adapter.ErrRateLimited.Error() }
func (e *rateLimitError) Unwrap() error      { return adapter.ErrRateLimited }
func (e *rateLimitError) RetryAt() time.Time { return e.at }

func (c *Client) rateDeadline(status int, header http.Header, now time.Time) (time.Time, bool) {
	if status != http.StatusForbidden && status != http.StatusTooManyRequests {
		return time.Time{}, false
	}
	// GitHub uses this header on fine-grained permission refusals. It is an
	// authorization failure, not a secondary-rate signal, even though both are 403.
	if status == http.StatusForbidden && headerValue(header, "X-Accepted-GitHub-Permissions") != "" {
		return time.Time{}, false
	}
	if raw := header.Get("Retry-After"); raw != "" {
		c.resetHeaderlessRateAttempts()
		if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 0 {
			return now.Add(time.Duration(seconds) * time.Second), true
		}
		if at, err := http.ParseTime(raw); err == nil {
			return at.UTC(), true
		}
	}
	if header.Get("X-Ratelimit-Remaining") == "0" {
		c.resetHeaderlessRateAttempts()
		if seconds, err := strconv.ParseInt(header.Get("X-Ratelimit-Reset"), 10, 64); err == nil {
			return time.Unix(seconds, 0).UTC(), true
		}
	}
	c.credentialState.rateMu.Lock()
	c.credentialState.headerlessRateAttempts++
	attempt := c.credentialState.headerlessRateAttempts
	c.credentialState.rateMu.Unlock()
	delay := defaultRateBackoff
	for i := 1; i < attempt && delay < adapter.RetryCap; i++ {
		delay *= 2
		if delay > adapter.RetryCap {
			delay = adapter.RetryCap
		}
	}
	return now.Add(delay), true
}

func (c *Client) resetHeaderlessRateAttempts() {
	c.credentialState.rateMu.Lock()
	c.credentialState.headerlessRateAttempts = 0
	c.credentialState.rateMu.Unlock()
}

func headerValue(header http.Header, name string) string {
	for key, values := range header {
		if strings.EqualFold(key, name) && len(values) != 0 {
			return values[0]
		}
	}
	return ""
}

func (c *Client) do(ctx context.Context, op operation, path string, body any, out any) (int, error) {
	if op.Mutation && c.pacer != nil {
		if err := c.pacer.Wait(ctx); err != nil {
			return 0, err
		}
	}
	var input io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		input = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, op.Method, c.origin+path, input)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("github-actions: provider request: %w", err)
	}
	defer resp.Body.Close()
	c.captureCredentialExpiry(resp.Header)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, responseCap+1))
	if err != nil {
		return resp.StatusCode, errors.New("github-actions: provider response could not be read")
	}
	if len(raw) > responseCap {
		return resp.StatusCode, errors.New("github-actions: provider response exceeded 1 MiB")
	}
	if at, ok := c.rateDeadline(resp.StatusCode, resp.Header, c.now()); ok {
		return resp.StatusCode, &rateLimitError{at: at}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseErr := &ResponseError{Status: resp.StatusCode}
		if resp.StatusCode == http.StatusUnauthorized {
			return resp.StatusCode, errors.Join(adapter.ErrProviderAuth, responseErr)
		}
		return resp.StatusCode, responseErr
	}
	c.resetHeaderlessRateAttempts()
	if out != nil && len(raw) != 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, errors.New("github-actions: provider response did not match expected shape")
		}
	}
	return resp.StatusCode, nil
}

func repositoryPath(d adapter.Destination) (string, error) {
	if d.Owner == "" || d.Name == "" {
		return "", errors.New("github-actions: repository destination requires owner and repository")
	}
	return "/repos/" + url.PathEscape(d.Owner) + "/" + url.PathEscape(d.Name), nil
}

func destinationPath(d adapter.Destination) (string, error) {
	switch d.Kind {
	case adapter.Repository:
		return repositoryPath(d)
	case adapter.Organization:
		if d.Owner == "" || d.Name != "" || d.Environment != "" {
			return "", errors.New("github-actions: organization destination requires only organization")
		}
		return "/orgs/" + url.PathEscape(d.Owner), nil
	case adapter.Environment:
		base, err := repositoryPath(d)
		if err != nil {
			return "", err
		}
		if d.Environment == "" {
			return "", errors.New("github-actions: environment destination requires environment name")
		}
		return base + "/environments/" + url.PathEscape(d.Environment), nil
	default:
		return "", errors.New("github-actions: unknown destination kind")
	}
}

func (c *Client) ResolveDestination(ctx context.Context, d adapter.Destination) (DestinationIdentity, error) {
	var repositoryID int64
	if d.Kind == adapter.Environment {
		repository, err := repositoryPath(d)
		if err != nil {
			return DestinationIdentity{}, err
		}
		var out struct {
			ID int64 `json:"id"`
		}
		if _, err := c.do(ctx, operationRegistry["resolve-repository"], repository, nil, &out); err != nil {
			return DestinationIdentity{}, err
		}
		repositoryID = out.ID
		if d.RepositoryID != 0 && out.ID != d.RepositoryID {
			return DestinationIdentity{}, fmt.Errorf("%w: configured repository %d, resolved %d", adapter.ErrDestinationID, d.RepositoryID, out.ID)
		}
	}
	path, err := destinationPath(d)
	if err != nil {
		return DestinationIdentity{}, err
	}
	key := "resolve-repository"
	if d.Kind == adapter.Organization {
		key = "resolve-organization"
	} else if d.Kind == adapter.Environment {
		key = "resolve-environment"
	}
	var out struct {
		ID int64 `json:"id"`
	}
	_, err = c.do(ctx, operationRegistry[key], path, nil, &out)
	if err != nil {
		return DestinationIdentity{}, err
	}
	if d.Kind == adapter.Repository {
		repositoryID = out.ID
	}
	return DestinationIdentity{ID: out.ID, RepositoryID: repositoryID}, nil
}

func (c *Client) ListSecretNames(ctx context.Context, d adapter.Destination) ([]string, error) {
	path, err := destinationPath(d)
	if err != nil {
		return nil, err
	}
	var names []string
	for page := 1; ; page++ {
		var out struct {
			Total int `json:"total_count"`
			Rows  []struct {
				Name string `json:"name"`
			} `json:"secrets"`
		}
		query := "?per_page=" + strconv.Itoa(pageSize) + "&page=" + strconv.Itoa(page)
		if _, err := c.do(ctx, operationRegistry["list-secrets"], path+"/actions/secrets"+query, nil, &out); err != nil {
			return nil, err
		}
		if len(names)+len(out.Rows) > secretNameLimit {
			return nil, ErrSecretListIncomplete
		}
		for _, row := range out.Rows {
			names = append(names, row.Name)
		}
		if len(names) >= out.Total {
			if len(names) != out.Total {
				return nil, ErrSecretListIncomplete
			}
			return names, nil
		}
		if len(out.Rows) != pageSize {
			return nil, ErrSecretListIncomplete
		}
	}
}

func (c *Client) PublicKey(ctx context.Context, d adapter.Destination) (PublicKey, error) {
	path, err := destinationPath(d)
	if err != nil {
		return PublicKey{}, err
	}
	var out struct {
		ID  string `json:"key_id"`
		Key string `json:"key"`
	}
	if _, err := c.do(ctx, operationRegistry["public-key"], path+"/actions/secrets/public-key", nil, &out); err != nil {
		return PublicKey{}, err
	}
	raw, err := base64.StdEncoding.DecodeString(out.Key)
	if err != nil || len(raw) != 32 || out.ID == "" {
		return PublicKey{}, errors.New("github-actions: provider public key did not match expected shape")
	}
	var result PublicKey
	result.ID = out.ID
	copy(result.Key[:], raw)
	return result, nil
}

func secretBody(d adapter.Destination, encrypted, keyID string) map[string]any {
	body := map[string]any{"encrypted_value": encrypted, "key_id": keyID}
	if d.Kind == adapter.Organization {
		body["visibility"] = d.Visibility
	}
	return body
}

func (c *Client) PutSecret(ctx context.Context, d adapter.Destination, name, encrypted, keyID string) (WriteResult, error) {
	path, err := destinationPath(d)
	if err != nil {
		return WriteResult{}, err
	}
	status, err := c.do(ctx, operationRegistry["put-secret"], path+"/actions/secrets/"+url.PathEscape(name), secretBody(d, encrypted, keyID), nil)
	return WriteResult{Status: status}, err
}

func variableBody(d adapter.Destination, name, value string, includeName bool) map[string]any {
	body := map[string]any{"value": value}
	if includeName {
		body["name"] = name
	}
	if d.Kind == adapter.Organization {
		body["visibility"] = d.Visibility
	}
	return body
}

func (c *Client) CreateVariable(ctx context.Context, d adapter.Destination, name, value string) (WriteResult, error) {
	path, err := destinationPath(d)
	if err != nil {
		return WriteResult{}, err
	}
	status, err := c.do(ctx, operationRegistry["create-variable"], path+"/actions/variables", variableBody(d, name, value, true), nil)
	return WriteResult{Status: status}, err
}

func (c *Client) UpdateVariable(ctx context.Context, d adapter.Destination, name, value string) (WriteResult, error) {
	path, err := destinationPath(d)
	if err != nil {
		return WriteResult{}, err
	}
	status, err := c.do(ctx, operationRegistry["update-variable"], path+"/actions/variables/"+url.PathEscape(name), variableBody(d, name, value, false), nil)
	return WriteResult{Status: status}, err
}

func (c *Client) DeleteSecret(ctx context.Context, d adapter.Destination, name string) error {
	path, err := destinationPath(d)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, operationRegistry["delete-secret"], path+"/actions/secrets/"+url.PathEscape(name), nil, nil)
	return err
}

func (c *Client) DeleteVariable(ctx context.Context, d adapter.Destination, name string) error {
	path, err := destinationPath(d)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, operationRegistry["delete-variable"], path+"/actions/variables/"+url.PathEscape(name), nil, nil)
	return err
}

func IsStatus(err error, status int) bool {
	var response *ResponseError
	return errors.As(err, &response) && response.Status == status
}
