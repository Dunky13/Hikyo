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
}

// New starts a fake IdP. Callers own Close via t.Cleanup.
func New() (*IdP, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("oidctest: generate key: %w", err)
	}
	p := &IdP{key: key, keyID: "test-key-1", codes: map[string]Code{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	p.Server = httptest.NewServer(mux)
	return p, nil
}

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
	base := p.Server.URL
	writeJSON(w, map[string]any{
		"issuer":                                         p.Issuer(),
		"authorization_endpoint":                         base + "/authorize",
		"token_endpoint":                                 base + "/token",
		"jwks_uri":                                       base + "/jwks",
		"response_types_supported":                       []string{"code"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": p.SendIssParam,
	})
}

func (p *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := &p.key.PublicKey
	writeJSON(w, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": p.keyID,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
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

func (p *IdP) signJWT(claims map[string]any) (string, error) {
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": p.keyID}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sig, err := signRS256(p.key, signing)
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
