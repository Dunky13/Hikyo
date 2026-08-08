// Package oidcrp is the OIDC relying-party wrapper: discovery, authorization
// URL construction, code exchange and complete ID-token validation, all behind
// go-oidc and golang.org/x/oauth2. It exists so the protocol library is used in
// exactly one place under one policy - the human-auth ADR's "library selection
// is not policy selection" - and the boundary test pins who may import it
// (internal/service and its tests only).
//
// It owns wire mechanics, never product policy: purpose walls, byte-exact
// (issuer, subject) linking, mix-up defence, the browser binding, assurance
// evaluation and the nonce/state single-use bookkeeping all live in
// internal/service, because they are decisions a library does not make.
package oidcrp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// allowedAlgs is the signature-algorithm allowlist. `none` is never in it, and
// go-oidc refuses an unsigned token: algorithm confusion via an unvalidated
// `alg` is closed by pinning the set rather than trusting the header.
var allowedAlgs = []string{
	oidc.RS256, oidc.RS384, oidc.RS512,
	oidc.ES256, oidc.ES384, oidc.ES512,
	oidc.PS256, oidc.PS384, oidc.PS512,
}

// Sentinel refusals, mapped by the service to closed audit causes. Every one is
// a refusal, never a downgrade.
var (
	// ErrDiscovery is a discovery/JWKS fetch or issuer-mismatch failure.
	ErrDiscovery = errors.New("oidcrp: discovery failed")
	// ErrIssuer is a token whose issuer is not the pinned one (belt over
	// go-oidc's own check, A11).
	ErrIssuer = errors.New("oidcrp: token issuer mismatch")
	// ErrEmptySubject is a token with no subject (A15).
	ErrEmptySubject = errors.New("oidcrp: token carries no subject")
	// ErrAudience is a token whose azp, when present, is not this client.
	ErrAudience = errors.New("oidcrp: token azp is not this client")
	// ErrTokenInvalid is any other validation failure (signature, aud, expiry).
	ErrTokenInvalid = errors.New("oidcrp: token validation failed")
	// ErrNoIDToken is a token response carrying no id_token.
	ErrNoIDToken = errors.New("oidcrp: token response carried no id_token")
	// ErrExchange is a code-exchange transport or grant failure.
	ErrExchange = errors.New("oidcrp: code exchange failed")
)

// Provider is a discovered OpenID Provider pinned to a byte-exact issuer.
type Provider struct {
	issuer string
	op     *oidc.Provider
}

// Discover reconstructs a provider via go-oidc NewProvider, which re-asserts
// the byte-exact issuer against the discovery document (A20): every refresh
// rebuilds from the document, never patches a cached endpoint set. The issuer
// passed here is the byte-exact string; NewProvider returns IssuerMismatchError
// when the document disagrees.
func Discover(ctx context.Context, issuer string) (*Provider, error) {
	op, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscovery, err)
	}
	if op.Endpoint().AuthURL == "" || op.Endpoint().TokenURL == "" {
		return nil, fmt.Errorf("%w: discovery document is missing an authorization or token endpoint", ErrDiscovery)
	}
	return &Provider{issuer: issuer, op: op}, nil
}

// Issuer returns the byte-exact issuer this provider is pinned to.
func (p *Provider) Issuer() string { return p.issuer }

func (p *Provider) config(clientID, clientSecret, redirectURI, scopes string) oauth2.Config {
	return oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     p.op.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       splitScopes(scopes),
	}
}

// AuthCodeURL builds the authorization request URL with PKCE S256 always, the
// state and nonce, and - for reauth - prompt=login and max_age=0, which the
// caller passes via extra. It never derives the redirect from a request header.
func (p *Provider) AuthCodeURL(clientID, clientSecret, redirectURI, scopes, state, nonce, pkceVerifier string, extra map[string]string) string {
	cfg := p.config(clientID, clientSecret, redirectURI, scopes)
	opts := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(pkceVerifier),
		oidc.Nonce(nonce),
	}
	for k, v := range extra {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	return cfg.AuthCodeURL(state, opts...)
}

// Exchange trades the authorization code for tokens at the RECORDED provider's
// token endpoint only, presenting the PKCE verifier, and returns the raw ID
// token. The client secret is used here and nowhere else.
func (p *Provider) Exchange(ctx context.Context, clientID, clientSecret, redirectURI, scopes, code, pkceVerifier string) (string, error) {
	cfg := p.config(clientID, clientSecret, redirectURI, scopes)
	tok, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrExchange, err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", ErrNoIDToken
	}
	return raw, nil
}

// Claims is the validated ID-token content the service policy consults. Nonce
// is returned raw for the caller to compare against the hashed transaction
// value (A19); the AMR/ACR/auth_time are what the provider asserted, recorded
// verbatim in the assurance record (A12). Raw carries every claim for the JIT
// policy's issuer-specific claim lookup.
type Claims struct {
	Issuer          string
	Subject         string
	Nonce           string
	ACR             string
	AMR             []string
	AuthorizedParty string
	AuthTime        time.Time
	HasAuthTime     bool
	Raw             map[string]json.RawMessage
}

// Verify validates an ID token completely: exact issuer against the pinned one,
// signature with an algorithm from the allowlist (never none), audience
// contains this client, azp when present equals this client, exp/iat within
// skew. Empty subject is refused (A15). Nonce equality is the caller's, because
// the transaction stores it hashed.
func (p *Provider) Verify(ctx context.Context, clientID, rawIDToken string, now func() time.Time) (Claims, error) {
	verifier := p.op.Verifier(&oidc.Config{
		ClientID:             clientID,
		SupportedSigningAlgs: allowedAlgs,
		Now:                  now,
	})
	tok, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	if tok.Issuer != p.issuer {
		return Claims{}, ErrIssuer
	}
	if tok.Subject == "" {
		return Claims{}, ErrEmptySubject
	}
	var extra struct {
		ACR      string   `json:"acr"`
		AMR      []string `json:"amr"`
		AZP      string   `json:"azp"`
		AuthTime *int64   `json:"auth_time"`
	}
	if err := tok.Claims(&extra); err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	if extra.AZP != "" && extra.AZP != clientID {
		return Claims{}, ErrAudience
	}
	c := Claims{
		Issuer: tok.Issuer, Subject: tok.Subject, Nonce: tok.Nonce,
		ACR: extra.ACR, AMR: extra.AMR, AuthorizedParty: extra.AZP,
	}
	if extra.AuthTime != nil {
		c.AuthTime = time.Unix(*extra.AuthTime, 0).UTC()
		c.HasAuthTime = true
	}
	raw := map[string]json.RawMessage{}
	if err := tok.Claims(&raw); err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	c.Raw = raw
	return c, nil
}

func splitScopes(scopes string) []string {
	fields := strings.Fields(scopes)
	hasOpenID := false
	for _, f := range fields {
		if f == oidc.ScopeOpenID {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		fields = append([]string{oidc.ScopeOpenID}, fields...)
	}
	return fields
}
