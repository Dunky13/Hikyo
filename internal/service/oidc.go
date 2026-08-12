package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/oidcrp"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/tx"
)

// Multi-provider OIDC (#54, human-auth ADR - Login methods, Identity linking,
// The OIDC transaction). The relying-party wire mechanics live behind
// internal/oidcrp; every product decision the library does not make - mix-up
// defence, byte-exact linking, purpose walls, the browser binding, assurance
// evaluation, JIT policy - lives here.

const (
	// OIDCKind is the identity-key discriminator. Only 'oidc' exists in v1; the
	// column reserves room for SAML (#72) without reshaping the key.
	OIDCKind = "oidc"
	// oidcTxLifetime is the transaction's single-use window.
	oidcTxLifetime = 10 * time.Minute
	// oidcAuthTimeBound is the reauth freshness bound on the provider-asserted
	// auth_time (A7): older than this is a stale re-login, refused.
	oidcAuthTimeBound = 5 * time.Minute
	// bindingSession and bindingBrowserCookie are the transaction binding kinds
	// (A2). No default callback branch exists: exactly one is set.
	bindingSession       = "session"
	bindingBrowserCookie = "browser-cookie"
	// OIDC transaction purposes. A response obtained for one cannot complete
	// another (purpose walls).
	purposeLogin  = "login"
	purposeLink   = "link"
	purposeReauth = "reauth"
)

// OIDC refusal causes: the closed enum recorded on auth.oidc_refused. By class,
// never by detail, so the trail is not the oracle the uniform response is not.
const (
	causeMixup           = "mixup"
	causeNonce           = "nonce"
	causePurpose         = "purpose"
	causeState           = "state"
	causeIssuer          = "issuer"
	causeAudience        = "audience"
	causeSignature       = "signature"
	causeEpoch           = "epoch"
	causeIDPError        = "idp-error"
	causeExpired         = "expired"
	causeUnknownIdentity = "unknown-identity"
	causeNoPolicy        = "no-assurance-policy"
	causeNoAuthTime      = "no-auth-time"
	causeBinding         = "binding"
	causeJITRefused      = "jit-refused"
	causeReconciliation  = "reconciliation"
	causeWindowClosed    = "window-zero"
	causeNoPossession    = "no-possession"
	causeDowngrade       = "downgrade"
)

// possessionAMR is the closed set of RFC 8176 amr values hikyo accepts as
// evidence of a possession factor for a reauth: a hardware key, a software key,
// or a one-time password. "pwd"/"pin" (knowledge) and biometric-only values are
// deliberately excluded, so a password-only token can never open a reveal reauth
// window even when it satisfies a policy that keyed on acr alone. "mfa" is
// excluded too: RFC 8176 "mfa" only asserts that multiple factors were used, it
// does NOT prove any of them was a possession factor, so a token asserting only
// amr=["mfa"] carries no possession evidence and is refused (cause=no-possession).
var possessionAMR = map[string]bool{"hwk": true, "swk": true, "otp": true}

// hasPossessionAMR reports whether the token asserted a recognized possession
// factor, INDEPENDENTLY of policy satisfaction. Policy satisfaction (an acr
// match or an amr set) alone must not imply possession.
func hasPossessionAMR(amr []string) bool {
	for _, m := range amr {
		if possessionAMR[m] {
			return true
		}
	}
	return false
}

// Loud, structural OIDC refusals for callers acting on their own instance
// config or account - not the uniform pre-auth mask.
var (
	// ErrProviderExists reports a slug already in use.
	ErrProviderExists = errors.New("service: an OIDC provider with that slug already exists")
	// ErrProviderNotFound reports an unknown provider slug.
	ErrProviderNotFound = errors.New("service: no such OIDC provider")
	// ErrIssuerImmutable reports an attempt to change a provider's issuer (A3).
	ErrIssuerImmutable = errors.New("service: a provider issuer is immutable; delete and recreate")
	// ErrProviderRace reports a lost CAS on a provider reconfigure.
	ErrProviderRace = errors.New("service: provider row changed underneath this write")
	// ErrProviderDiscovery reports a discovery failure at provider write time.
	ErrProviderDiscovery = errors.New("service: provider discovery failed")
	// ErrNoInvitationPath names the invitation-claim seam #55 owns: an unknown
	// identity with no JIT policy has nowhere to land.
	ErrNoInvitationPath = errors.New("service: unknown identity and no JIT policy; invitation claiming is #55")
	// ErrLastCredential refuses unlinking the last remaining credential.
	ErrLastCredential = errors.New("service: cannot unlink the last remaining credential")
	// ErrIdentityNotFound reports an unknown identity id on unlink.
	ErrIdentityNotFound = errors.New("service: no such linked identity")
	// ErrReauthWindowClosed refuses OIDC reauth where the effective window is 0
	// (a 0-window gate needs WebAuthn, which alone can bind the enumerated unit).
	ErrReauthWindowClosed = errors.New("service: reauthentication window is 0; a WebAuthn ceremony is required here")
)

// providerSecretAAD binds a sealed client secret to the provider row that owns
// it, so a secret lifted from one row cannot be replayed into another's.
func providerSecretAAD(providerID string) crypto.InstanceFieldAAD {
	return crypto.InstanceFieldAAD{OwnerTable: "oidc_providers", OwnerRowID: providerID, FieldTag: "client_secret"}
}

// randToken is a high-entropy URL-safe value for a nonce or PKCE verifier. Both
// cross the IdP redirect; the nonce is stored hashed (A19), the PKCE verifier
// raw (it is sent at exchange).
func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("service: random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// discover reconstructs a provider from its issuer. The test seam
// OIDCDiscover, when set, replaces go-oidc discovery so a fixture can drive an
// httptest IdP whose discovery URL differs from a byte-variant issuer.
func (s *Auth) discover(ctx context.Context, issuer string) (*oidcrp.Provider, error) {
	if s.OIDCDiscover != nil {
		return s.OIDCDiscover(ctx, issuer)
	}
	return oidcrp.Discover(ctx, issuer)
}

// assurancePolicy is the parsed per-provider MFA policy (A12): a session gains
// multi-factor assurance only when the ID token carries an accepted acr or a
// required amr combination. Absent policy = single-factor (login yes, reveal no).
type assurancePolicy struct {
	ACRValues []string   `json:"acr_values"`
	AMRSets   [][]string `json:"amr_sets"`
}

// jitPolicy is the parsed JIT provisioning policy: the issuer-specific verified
// claim and its accepted values. Off by default (nil), names its evidence, and
// the account it creates holds zero grants.
type jitPolicy struct {
	Claim  string   `json:"claim"`
	Values []string `json:"values"`
}

// evaluateAssurance reports whether the provider's policy was satisfied by the
// token's acr/amr. Absent policy is never multi-factor.
func evaluateAssurance(policy *string, acr string, amr []string) (bool, error) {
	if policy == nil {
		return false, nil
	}
	var p assurancePolicy
	if err := json.Unmarshal([]byte(*policy), &p); err != nil {
		return false, fmt.Errorf("service: parsing a provider assurance policy: %w", err)
	}
	for _, v := range p.ACRValues {
		if acr == v {
			return true, nil
		}
	}
	have := map[string]bool{}
	for _, m := range amr {
		have[m] = true
	}
	for _, set := range p.AMRSets {
		if len(set) == 0 {
			continue
		}
		all := true
		for _, need := range set {
			if !have[need] {
				all = false
				break
			}
		}
		if all {
			return true, nil
		}
	}
	return false, nil
}

// oidcMethod is the assurance-record method for a federated session.
func oidcMethod(issuer string) string { return "oidc:" + issuer }

// oidcFactors encodes the session factor classes. When the provider policy was
// satisfied the record carries two distinct classes so AdequateAssurance treats
// it as multi-factor; otherwise one, single-factor (login yes, reveal no).
func oidcFactors(mfa bool) []string {
	if mfa {
		return []string{"oidc", "oidc-mfa"}
	}
	return []string{"oidc"}
}

// ---------------------------------------------------------------------------
// Provider administration (proof-bound, instance-config)
// ---------------------------------------------------------------------------

// Providers is the OIDC provider administration service. Configuration is an
// instance-config operation authorized at the chokepoint; a security-material
// change (issuer is immutable, so client, secret, assurance policy, or disable)
// sweeps every session authenticated through the provider in the same tx (A4).
type Providers struct {
	DB      *store.DB
	Keyring *crypto.Keyring
	// ExternalOrigin is the instance's public origin, used to build the
	// per-provider redirect URI (A1). Never derived from a request header.
	ExternalOrigin string
	Now            func() time.Time
	Log            *slog.Logger
}

func (s *Providers) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

// ProviderView is a provider as returned to an administrator. The client secret
// never leaves the server, so it is absent here.
type ProviderView struct {
	Slug            string
	DisplayName     string
	Issuer          string
	ClientID        string
	Scopes          string
	RedirectURI     string
	JITPolicy       *string
	AssurancePolicy *string
	Enabled         bool
}

func providerView(p authz.OIDCProvider) ProviderView {
	return ProviderView{
		Slug: p.Slug, DisplayName: p.DisplayName, Issuer: p.Issuer, ClientID: p.ClientID,
		Scopes: p.Scopes, RedirectURI: p.RedirectURI, JITPolicy: p.JITPolicy,
		AssurancePolicy: p.AssurancePolicy, Enabled: p.Enabled,
	}
}

// ProviderInput is a create-or-update request body.
type ProviderInput struct {
	DisplayName     string
	Issuer          string
	ClientID        string
	ClientSecret    string
	Scopes          string
	JITPolicy       *string
	AssurancePolicy *string
	Enabled         bool
}

func (s *Providers) redirectURI(slug string) string {
	return strings.TrimRight(s.ExternalOrigin, "/") + "/api/v1/auth/oidc/" + slug + "/callback"
}

// Put creates a provider or reconfigures an existing one. The issuer is
// immutable on update (A3): a changed issuer is refused by name. Discovery is
// re-run at write time and the document's issuer must byte-equal the configured
// one. A reconfigure that changes security material sweeps federated sessions.
func (s *Providers) Put(ctx context.Context, actor Actor, slug string, in ProviderInput) (ProviderView, error) {
	var out ProviderView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		// Authorize BEFORE discovery closes an SSRF: only an instance-config
		// holder may make the server fetch an arbitrary issuer URL. Discovery
		// then validates the issuer (byte-exact) before anything is written.
		//
		// ponytail: the discovery fetch runs inside the write transaction, so it
		// holds sqlite's single writer for the length of a network round trip.
		// Acceptable here where login is not: provider configuration is a rare
		// operator action, not a hot path. If provider churn ever matters, split
		// it read/discover/write like the login path.
		p, err := az.Authorize(ctx, caller, authz.OpProviderPut, domain.Scope{})
		if err != nil {
			return err
		}
		if _, derr := oidcrp.Discover(ctx, in.Issuer); derr != nil {
			if s.Log != nil {
				s.Log.WarnContext(ctx, "oidc provider discovery failed", "slug", slug, "err", derr)
			}
			return ErrProviderDiscovery
		}
		existing, err := az.ProviderBySlug(ctx, slug)
		switch {
		case errors.Is(err, domain.ErrNotFound):
			return s.create(ctx, r, az, p, caller.Principal, slug, in, &out)
		case err != nil:
			return err
		}
		if existing.Issuer != in.Issuer {
			return ErrIssuerImmutable
		}
		return s.update(ctx, r, az, p, caller.Principal, existing, in, &out)
	})
	if err != nil {
		return ProviderView{}, err
	}
	return out, nil
}

func (s *Providers) sealSecret(providerID, secret string) ([]byte, int64, error) {
	sealer := s.Keyring.ForInstance()
	sealed, err := sealer.SealField(providerSecretAAD(providerID), []byte(secret))
	if err != nil {
		return nil, 0, err
	}
	return sealed, int64(sealer.Version()), nil
}

func (s *Providers) create(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, p authz.Proof, principal domain.PrincipalID, slug string, in ProviderInput, out *ProviderView) error {
	id, err := newID("oidcp")
	if err != nil {
		return err
	}
	sealed, dek, err := s.sealSecret(id, in.ClientSecret)
	if err != nil {
		return err
	}
	now := s.now()
	prov := authz.NewProvider{
		ID: id, Slug: slug, DisplayName: in.DisplayName, Kind: OIDCKind, Issuer: in.Issuer,
		ClientID: in.ClientID, ClientSecret: sealed, Scopes: in.Scopes, RedirectURI: s.redirectURI(slug),
		JITPolicy: in.JITPolicy, AssurancePolicy: in.AssurancePolicy, Enabled: in.Enabled,
		DEKVersion: dek, CreatedAt: now, UpdatedAt: now,
	}
	if err := az.CreateProvider(ctx, prov); err != nil {
		return err
	}
	if err := s.auditChanged(ctx, r, p, principal, id, "created", 0); err != nil {
		return err
	}
	*out = providerView(authz.OIDCProvider{
		Slug: slug, DisplayName: in.DisplayName, Issuer: in.Issuer, ClientID: in.ClientID,
		Scopes: in.Scopes, RedirectURI: prov.RedirectURI, JITPolicy: in.JITPolicy,
		AssurancePolicy: in.AssurancePolicy, Enabled: in.Enabled,
	})
	return nil
}

func (s *Providers) update(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, p authz.Proof, principal domain.PrincipalID, existing authz.OIDCProvider, in ProviderInput, out *ProviderView) error {
	sealed, dek, err := s.sealSecret(existing.ID, in.ClientSecret)
	if err != nil {
		return err
	}
	upd := authz.ProviderUpdate{
		ID: existing.ID, DisplayName: in.DisplayName, ClientID: in.ClientID, ClientSecret: sealed,
		Scopes: in.Scopes, RedirectURI: s.redirectURI(existing.Slug),
		JITPolicy: in.JITPolicy, AssurancePolicy: in.AssurancePolicy, Enabled: in.Enabled,
		DEKVersion: dek, RowVersion: existing.RowVersion, UpdatedAt: s.now(),
	}
	swapped, err := az.UpdateProvider(ctx, upd)
	if err != nil {
		return err
	}
	if !swapped {
		return ErrProviderRace
	}
	// Any reconfigure changes security material (client, secret, assurance
	// policy, or enabled state; the issuer cannot change), so every session
	// authenticated through this provider is swept in the same tx (A4).
	swept, err := az.SweepSessionsForProvider(ctx, existing.ID)
	if err != nil {
		return err
	}
	if err := s.auditChanged(ctx, r, p, principal, existing.ID, "updated", swept); err != nil {
		return err
	}
	*out = providerView(authz.OIDCProvider{
		Slug: existing.Slug, DisplayName: in.DisplayName, Issuer: existing.Issuer, ClientID: in.ClientID,
		Scopes: in.Scopes, RedirectURI: upd.RedirectURI, JITPolicy: in.JITPolicy,
		AssurancePolicy: in.AssurancePolicy, Enabled: in.Enabled,
	})
	return nil
}

// Get returns one provider by slug.
func (s *Providers) Get(ctx context.Context, actor Actor, slug string) (ProviderView, error) {
	var out ProviderView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpProviderGet, domain.Scope{})
		if err != nil {
			return err
		}
		prov, err := az.ProviderBySlug(ctx, slug)
		if errors.Is(err, domain.ErrNotFound) {
			return ErrProviderNotFound
		}
		if err != nil {
			return err
		}
		out = providerView(prov)
		return s.auditRead(ctx, r, p, caller.Principal, "get", 1)
	})
	return out, err
}

// List returns every configured provider.
func (s *Providers) List(ctx context.Context, actor Actor) ([]ProviderView, error) {
	var out []ProviderView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpProviderList, domain.Scope{})
		if err != nil {
			return err
		}
		rows, err := az.ListProviders(ctx)
		if err != nil {
			return err
		}
		out = make([]ProviderView, 0, len(rows))
		for _, row := range rows {
			out = append(out, providerView(row))
		}
		return s.auditRead(ctx, r, p, caller.Principal, "list", len(rows))
	})
	return out, err
}

// Delete removes a provider and sweeps its federated sessions (A4). Its
// transaction rows and federated sessions cascade on the FK (A14); the sweep
// runs after the provider row is locked so the count is accurate and no mint
// can race the delete.
func (s *Providers) Delete(ctx context.Context, actor Actor, slug string) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpProviderDelete, domain.Scope{})
		if err != nil {
			return err
		}
		prov, err := az.ProviderBySlug(ctx, slug)
		if errors.Is(err, domain.ErrNotFound) {
			return ErrProviderNotFound
		}
		if err != nil {
			return err
		}
		// Lock the provider row BEFORE sweeping, so the sweep runs with the row
		// held: a concurrent Phase-C mint guard either already committed (the
		// sweep then catches its session) or blocks on this lock and finds the
		// row gone once we commit (mint refused). The FK cascade (A14) is the
		// atomic backstop; this ordering keeps the sweep count accurate and is
		// race-safe even if FK enforcement were off.
		if err := az.LockProviderForDelete(ctx, prov.ID); errors.Is(err, domain.ErrNotFound) {
			return ErrProviderNotFound
		} else if err != nil {
			return err
		}
		swept, err := az.SweepSessionsForProvider(ctx, prov.ID)
		if err != nil {
			return err
		}
		if err := az.DeleteProvider(ctx, prov.ID); err != nil {
			return err
		}
		return s.auditChanged(ctx, r, p, caller.Principal, prov.ID, "deleted", swept)
	})
}

func (s *Providers) auditChanged(ctx context.Context, r store.Repos, p authz.Proof, principal domain.PrincipalID, providerID, change string, swept int64) error {
	e, err := newAuditEvent(ctx, audit.EventOIDCProviderChanged, principal,
		audit.Object{Type: "oidc_provider", ID: providerID}, audit.OutcomeSuccess, "",
		audit.Payload{"provider_id": providerID, "change": change, "sessions_swept": int(swept)})
	if err != nil {
		return err
	}
	return r.Audit().InsertInstance(ctx, p, e)
}

func (s *Providers) auditRead(ctx context.Context, r store.Repos, p authz.Proof, principal domain.PrincipalID, query string, count int) error {
	e, err := newAuditEvent(ctx, audit.EventOIDCProviderRead, principal,
		audit.Object{Type: "oidc_provider"}, audit.OutcomeSuccess, "",
		audit.Payload{"query": query, "row_count": count})
	if err != nil {
		return err
	}
	return r.Audit().InsertInstance(ctx, p, e)
}
