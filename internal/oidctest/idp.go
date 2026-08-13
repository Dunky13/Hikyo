// Package oidctest is a test-only OpenID Provider: discovery, JWKS,
// authorization and token endpoints over httptest, RS256-signed ID tokens
// with caller-controlled claims. It exists so the OIDC fixture families
// (mvp-boundary A1: mix-up, byte-exact issuer/subject, purpose walls) run
// against a real wire flow rather than mocks of our own code.
//
// It is imported only from _test files; the boundary test pins that.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"
)

// Code is one minted authorization code and what it will yield.
type Code struct {
	ClientID    string
	RedirectURI string
	Nonce       string
	// PKCE S256 challenge recorded at authorize time; the token endpoint
	// verifies the presented verifier against it, as a real IdP does.
	CodeChallenge string
	// Claims are merged into the ID token. `iss`, `aud`, `exp`, `iat` and
	// `nonce` are set by the IdP unless overridden here — overriding lets a
	// fixture assert that the relying party refuses a wrong value.
	Claims map[string]any
}

// IdP is a fake OpenID Provider.
type IdP struct {
	Server *httptest.Server
	key    *rsa.PrivateKey
	keyID  string

	mu    sync.Mutex
	codes map[string]Code
	// IssuerOverride, when set, is used as the `iss` claim and in the
	// discovery document instead of the server URL. Byte-exact issuer
	// fixtures use it (an issuer differing only in case from another).
	IssuerOverride string
	// SendIssParam controls the RFC 9207 `iss` authorization-response
	// parameter. Real providers vary; both branches need fixtures.
	SendIssParam bool
	// TokenEndpointHits counts code exchanges, so a mix-up fixture can
	// assert the refusal happened before any token was fetched.
	TokenEndpointHits int
	// AuthTime, when non-zero, is asserted as the `auth_time` claim.
	AuthTime time.Time
	// ACR and AMR, when set, are asserted in the ID token.
	ACR string
	AMR []string
	// IAT, when non-zero, overrides the `iat` claim (else now); OmitIAT drops
	// it entirely. Fixtures use them to assert the relying party refuses a
	// future or missing iat.
	IAT     time.Time
	OmitIAT bool
	// OnToken, when set, runs at the start of the token endpoint — i.e. during
	// the relying party's code exchange (Phase B), between the callback's Phase
	// A snapshot and its Phase C write. A race fixture uses it to reconfigure
	// the provider mid-exchange and assert the stale evaluation is refused.
	OnToken func()

	// Offline, when set, makes the discovery and JWKS endpoints answer 503.
	// This is the INDUCED ISSUER OUTAGE the federation staleness fixture needs
	// (#62): closing the server would work once, but the bound has to be
	// exercised on both sides — serve-from-cache inside it, fail closed past it
	// — and that needs the issuer to come back.
	Offline bool
	// retired holds superseded signing keys. Rotate moves the current key here
	// and the JWKS keeps publishing it, which is what a real issuer does and
	// what makes "old and new tokens both verify during a rotation" true rather
	// than hoped for.
	retired []retiredKey
	// PublishRetired, when false, makes the JWKS publish ONLY the current key —
	// an issuer that rotated hard. Default true.
	PublishRetired bool
	// JWKSHits counts JWKS reads this fixture SERVED, so a rate-limit fixture can
	// assert that a throttled unknown-`kid` refresh performed no outbound request.
	JWKSHits int
	// KeyAttempts counts every request to the discovery and JWKS endpoints
	// INCLUDING the ones answered 503 while offline.
	//
	// It exists because JWKSHits cannot answer the question that matters during an
	// outage: a suppressed fetch and a failed fetch both serve nothing, so
	// "attempts stayed bounded" is unassertable from served reads alone. This
	// counts what left the client, which is the property the backoff and the
	// per-issuer allowance exist to bound.
	KeyAttempts int
	// JWKSURIOverride, when set, is advertised as `jwks_uri` in the discovery
	// document instead of this server's own endpoint. It is what makes the
	// plaintext-transport fixture real: an HTTPS discovery document that names an
	// `http://` key endpoint is exactly the attack, and no amount of mocking our
	// own code exercises it.
	JWKSURIOverride string
	// RedirectJWKSTo, when set, makes `/jwks-redirect` answer 302 to it. The
	// second half of the same fixture: an HTTPS `jwks_uri` that redirects to
	// plaintext passes a scheme check on the initial URL and must still be
	// refused.
	RedirectJWKSTo string
}

type retiredKey struct {
	key   *rsa.PrivateKey
	keyID string
}

// New starts a fake IdP over plain HTTP. Callers own Close via t.Cleanup.
func New() (*IdP, error) { return newIdP(false) }

// NewTLS starts the same fake IdP over TLS, so its issuer is an `https://` URL.
//
// It exists for the federation fixtures (#62), which configure an issuer through
// the real API — and that API refuses a non-https issuer, because discovery and
// JWKS are fetched from it and an `http` issuer would rest the instance's whole
// federation trust on whoever holds the network path. Rather than carve a
// loopback exception into production validation to suit a test, the test speaks
// TLS; Client() hands back the client that trusts this server's certificate.
func NewTLS() (*IdP, error) { return newIdP(true) }

func newIdP(useTLS bool) (*IdP, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("oidctest: generate key: %w", err)
	}
	p := &IdP{key: key, keyID: "test-key-1", codes: map[string]Code{}, PublishRetired: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/jwks-redirect", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		target := p.RedirectJWKSTo
		p.mu.Unlock()
		if target == "" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, target, http.StatusFound)
	})
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	if useTLS {
		p.Server = httptest.NewTLSServer(mux)
	} else {
		p.Server = httptest.NewServer(mux)
	}
	return p, nil
}

// Client is an HTTP client that trusts this fixture's certificate. For a plain
// -HTTP fixture it is an ordinary client; for a TLS one it carries the test CA,
// which is what lets the JWKS cache fetch from it without disabling
// verification anywhere in production code.
func (p *IdP) Client() *http.Client { return p.Server.Client() }

// Issuer is the issuer string this IdP asserts.
func (p *IdP) Issuer() string {
	if p.IssuerOverride != "" {
		return p.IssuerOverride
	}
	return p.Server.URL
}

// Close shuts the server down.
func (p *IdP) Close() { p.Server.Close() }

// MintCode registers an authorization code the token endpoint will honour.
func (p *IdP) MintCode(code string, c Code) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.codes[code] = c
}

func (p *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	if p.down(w) {
		return
	}
	base := p.Server.URL
	p.mu.Lock()
	jwksURI := p.JWKSURIOverride
	p.mu.Unlock()
	if jwksURI == "" {
		jwksURI = base + "/jwks"
	}
	writeJSON(w, map[string]any{
		"issuer":                                         p.Issuer(),
		"authorization_endpoint":                         base + "/authorize",
		"token_endpoint":                                 base + "/token",
		"jwks_uri":                                       jwksURI,
		"response_types_supported":                       []string{"code"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": p.SendIssParam,
	})
}

func (p *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	if p.down(w) {
		return
	}
	p.mu.Lock()
	p.JWKSHits++
	keys := []map[string]any{jwkOf(&p.key.PublicKey, p.keyID)}
	if p.PublishRetired {
		for _, r := range p.retired {
			keys = append(keys, jwkOf(&r.key.PublicKey, r.keyID))
		}
	}
	p.mu.Unlock()
	writeJSON(w, map[string]any{"keys": keys})
}

func jwkOf(pub *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// down answers 503 while the fixture is offline, which is what an unreachable
// issuer looks like from the relying party's side: a transport that connects and
// refuses, not a name that fails to resolve. Both exercise the same branch.
//
// It also counts the ATTEMPT, before deciding whether to serve, so an offline
// fixture still records what the client tried.
func (p *IdP) down(w http.ResponseWriter) bool {
	p.mu.Lock()
	p.KeyAttempts++
	offline := p.Offline
	p.mu.Unlock()
	if !offline {
		return false
	}
	http.Error(w, "issuer offline", http.StatusServiceUnavailable)
	return true
}

// Rotate mints a fresh signing key, retiring the current one. The retired key
// keeps being published unless PublishRetired is cleared, so a token minted
// before the rotation still verifies — the behaviour that makes serving a whole
// JWKS correct rather than a shortcut.
func (p *IdP) Rotate() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("oidctest: rotate key: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.retired = append(p.retired, retiredKey{key: p.key, keyID: p.keyID})
	p.key = key
	p.keyID = fmt.Sprintf("test-key-%d", len(p.retired)+1)
	return nil
}

// CurrentKeyID is the `kid` the next MintIDToken will carry.
func (p *IdP) CurrentKeyID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.keyID
}

// SetOffline induces or lifts the outage.
func (p *IdP) SetOffline(offline bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Offline = offline
}

// Fetches reports how many JWKS reads this fixture has SERVED.
func (p *IdP) Fetches() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.JWKSHits
}

// Attempts reports how many discovery or JWKS requests REACHED this fixture,
// served or refused. It is the counter to assert against when the fixture is
// offline.
func (p *IdP) Attempts() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.KeyAttempts
}

// MintIDToken signs an ID token with exactly the claims given — no defaults, no
// merging.
//
// Federation has no authorization-code flow, so there is no `Code` to hang
// claims off: a workload arrives holding a token its platform minted. This is
// therefore the whole minting surface for the federation fixtures, and it takes
// the claim map VERBATIM so a fixture can assert a refusal by omitting `aud`,
// backdating `iat`, or naming the issuer's default audience.
func (p *IdP) MintIDToken(claims map[string]any) (string, error) {
	return p.signJWT(claims)
}

// authorize implements the front-channel leg: it immediately redirects to the
// presented redirect_uri with a fresh code, recording nonce and PKCE
// challenge exactly as presented. The subject minted is `sub` from the query
// when present (fixtures drive it), else "user".
func (p *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := randomToken()
	p.MintCode(code, Code{
		ClientID:      q.Get("client_id"),
		RedirectURI:   q.Get("redirect_uri"),
		Nonce:         q.Get("nonce"),
		CodeChallenge: q.Get("code_challenge"),
		Claims:        map[string]any{"sub": firstNonEmpty(q.Get("sub"), "user")},
	})
	u, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := u.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	if p.SendIssParam {
		rq.Set("iss", p.Issuer())
	}
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.TokenEndpointHits++
	hook := p.OnToken
	p.mu.Unlock()
	if hook != nil {
		hook()
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	code := r.PostFormValue("code")
	p.mu.Lock()
	c, ok := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()
	if !ok {
		oauthError(w, "invalid_grant")
		return
	}
	if c.RedirectURI != r.PostFormValue("redirect_uri") {
		oauthError(w, "invalid_grant")
		return
	}
	if c.CodeChallenge != "" && !VerifierMatchesS256(r.PostFormValue("code_verifier"), c.CodeChallenge) {
		oauthError(w, "invalid_grant")
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss": p.Issuer(),
		"aud": c.ClientID,
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
	}
	if c.Nonce != "" {
		claims["nonce"] = c.Nonce
	}
	if !p.AuthTime.IsZero() {
		claims["auth_time"] = p.AuthTime.Unix()
	}
	if p.ACR != "" {
		claims["acr"] = p.ACR
	}
	if len(p.AMR) > 0 {
		claims["amr"] = p.AMR
	}
	for k, v := range c.Claims {
		claims[k] = v
	}
	if !p.IAT.IsZero() {
		claims["iat"] = p.IAT.Unix()
	}
	if p.OmitIAT {
		delete(claims, "iat")
	}
	idToken, err := p.signJWT(claims)
	if err != nil {
		http.Error(w, "sign", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"access_token": randomToken(),
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idToken,
	})
}

// signJWT signs with the CURRENT key under the lock, so a fixture that rotates
// between mints cannot observe a header `kid` that disagrees with the key that
// signed the body.
func (p *IdP) signJWT(claims map[string]any) (string, error) {
	p.mu.Lock()
	key, keyID := p.key, p.keyID
	p.mu.Unlock()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": keyID}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sig, err := signRS256(key, signing)
	if err != nil {
		return "", err
	}
	return signing + "." + sig, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func oauthError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": code}); err != nil {
		return
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return
	}
}

func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
