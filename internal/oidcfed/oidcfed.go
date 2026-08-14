// Package oidcfed validates externally issued OIDC ID tokens presented as a
// machine credential (#62, machine-identities ADR § Federation), and owns the
// server-side JWKS cache with its bounded staleness window.
//
// It is a sibling of internal/oidcrp, not an extension of it, and the split is
// deliberate: oidcrp is a RELYING PARTY — it runs an authorization-code flow,
// holds a client id and secret, and validates a token it asked for. Federation
// has no flow, no client secret and no redirect: a workload arrives holding a
// token some platform minted for it, and the only questions are whether the
// signature is genuinely that issuer's and whether every pinned claim matches.
// Sharing one type would have meant one struct with two disjoint halves.
//
// What this package does NOT do: hand-roll any JWT or signature verification.
// go-oidc performs the whole cryptographic check against keys this package
// fetched and cached; go-jose parses the JWKS document into public keys and
// reads the unverified header for cache maintenance. The human-auth ADR's
// no-hand-rolled-primitive invariant governs federation unchanged.
package oidcfed

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"

	"github.com/Hikyo-Org/hikyo/internal/domain"
)

// The operations-spec fog values this ticket chose, every one recorded for
// ratification in docs/handoff/62-oidc-federation-cursor.md.
const (
	// RefreshInterval is how old a cached key set may get before a validation
	// tries to refresh it PROACTIVELY. A failed proactive refresh is not a
	// refusal: the ADR rejects "failing closed the moment a scheduled refresh
	// fails" outright, because the failure this must survive is an API-server
	// blip and that would stop every workload fetch cluster-wide.
	RefreshInterval = 15 * time.Minute
	// StalenessBound is the ceiling. Past it, validation FAILS CLOSED AND
	// LOUDLY rather than serving from a key set nobody has been able to
	// confirm. Kubernetes service-account signing keys rotate rarely, so a
	// bounded window costs very little exposure — but it is bounded.
	StalenessBound = 6 * time.Hour
	// UnknownKIDRefreshesPerMinute rate-limits the refresh an unknown `kid`
	// triggers, PER ISSUER. This is load-bearing rather than hygiene: the
	// trigger sits on a pre-authentication path, so a stream of fabricated
	// `kid` values is an outbound-fetch amplifier aimed at the issuer.
	UnknownKIDRefreshesPerMinute = 5
	// RefreshBackoff is how long a FAILED fetch suppresses the next attempt for
	// that issuer.
	//
	// It is the difference between a tolerated outage and a self-inflicted one.
	// Without it, every request during an issuer outage starts its own
	// fetchTimeout-bounded fetch: the stale-but-valid path the ADR insists on
	// becomes an unauthenticated amplifier against both the issuer and this
	// instance. With it, one attempt per issuer per window discovers the outage
	// and every other request serves stale (or fails closed past the bound)
	// without touching the network.
	RefreshBackoff = 30 * time.Second
	// MaxTokenAge caps `now - iat` INDEPENDENTLY of what the issuer chose: a
	// configured issuer that mints long-lived tokens must not thereby mint
	// long-lived Hikyo access.
	//
	// One hour, and the number is a compromise with reality rather than a
	// preference: a Kubernetes projected ServiceAccount token defaults to a
	// one-hour lifetime and the kubelet refreshes it at 80% of that, so a
	// legitimate token on disk can be ~48 minutes old. A tighter cap would
	// refuse the platform's default configuration, which is a cap that gets
	// turned off rather than a cap that holds.
	MaxTokenAge = time.Hour
	// MaxTokenSpan caps `exp - iat`, the issuer's own declared validity
	// window. Two hours leaves headroom above the one-hour Kubernetes default
	// without admitting the day-long tokens some CI platforms can be
	// configured to mint.
	MaxTokenSpan = 2 * time.Hour
	// MaxClockSkew is the accepted positive clock skew, and it does double
	// duty: it bounds how far into Hikyo's future an `iat` may sit, and it IS
	// the margin in the post-restore `iat` predicate (§ Restore: "strictly
	// greater than reactivated_at plus the maximum accepted positive clock
	// skew"). One constant, because two would let the predicate's margin drift
	// below the skew validation accepts — which is exactly the gap the
	// predicate exists to close.
	MaxClockSkew = 2 * time.Minute
	// fetchTimeout bounds one discovery or JWKS HTTP request. It is short on
	// purpose: this runs on a pre-authentication path and a hung issuer must
	// not become a hung Hikyo.
	fetchTimeout = 5 * time.Second
	// maxJWKSBytes bounds a JWKS document before anything parses it. The
	// document comes from a configured issuer, but "configured" is not
	// "trusted to be small".
	maxJWKSBytes = 1 << 20
	// maxTrackedIssuers bounds the cache. Issuers are operator-configured, not
	// attacker-chosen, so this is a sanity ceiling rather than a defence.
	maxTrackedIssuers = 64
)

// allowedAlgs is the signature-algorithm allowlist, and `none` is never in it.
// Algorithm confusion via an unvalidated `alg` header is closed by PINNING THE
// SET here rather than by trusting what the token says about itself; go-oidc
// refuses anything outside it before any key is tried.
var allowedAlgs = []string{
	oidc.RS256, oidc.RS384, oidc.RS512,
	oidc.ES256, oidc.ES384, oidc.ES512,
	oidc.PS256, oidc.PS384, oidc.PS512,
}

// joseAlgs is the same allowlist in go-jose's vocabulary, for the two places
// this package parses a token itself: the unverified header read that drives
// cache maintenance, and JWKS parsing.
var joseAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
}

// Refusals. Every one is a REFUSAL, never a downgrade (§ Federation: "failure
// at any step is a refusal"). They are separate sentinels because each maps to
// a distinct closed audit cause, and an investigator needs to tell "we could
// not reach the issuer" from "the token was forged".
var (
	// ErrNotAToken means the presented value is not a JWS at all. It is
	// returned before anything else so a bearer credential presented on this
	// path is classified rather than refused as a bad signature.
	ErrNotAToken = errors.New("oidcfed: presented value is not a signed token")
	// ErrNoIssuer means the token names an issuer this instance does not
	// configure. It is indistinguishable on the wire from every other refusal.
	ErrNoIssuer = errors.New("oidcfed: token issuer is not configured")
	// ErrKeysUnavailable means no key set could be obtained and none is
	// cached. Fail closed.
	ErrKeysUnavailable = errors.New("oidcfed: issuer keys are unavailable")
	// ErrInsecureTransport means a discovery document, a redirect or an issuer
	// URL named a non-HTTPS endpoint. It is its own sentinel because it is not a
	// transport failure: it is the one failure mode where completing the fetch
	// successfully would be the vulnerability.
	ErrInsecureTransport = errors.New("oidcfed: issuer key material must be fetched over https")
	// ErrKeysStale means the cached key set is older than the staleness bound.
	// This is the LOUD half of "validation continues from cache up to that
	// bound and then fails closed, loudly".
	ErrKeysStale = errors.New("oidcfed: cached issuer keys are past the staleness bound")
	// ErrTokenInvalid is a signature, issuer, audience, expiry or claim
	// failure.
	ErrTokenInvalid = errors.New("oidcfed: token validation failed")
	// ErrTokenAge is a token older than Hikyo's own cap, or whose declared
	// validity span exceeds it. Separate from ErrTokenInvalid because it is
	// Hikyo refusing a token the issuer considers perfectly valid.
	ErrTokenAge = errors.New("oidcfed: token age or validity span exceeds the instance cap")
	// ErrAudience is a token whose audiences do not include the bound one, or
	// which carries an audience the issuer configuration refuses.
	ErrAudience = errors.New("oidcfed: token audience is not the bound audience")
	// ErrClaim is a pinned claim that is absent or does not match byte-exactly.
	ErrClaim = errors.New("oidcfed: a pinned claim is absent or does not match")
	// ErrEventName is the CI-specific refusal: a `pull_request` or
	// `pull_request_target` token presented against a binding that did not
	// separately and deliberately bind that event.
	ErrEventName = errors.New("oidcfed: pull-request events are refused unless separately bound")
	// ErrRestorePredicate is the post-restore `iat` refusal. It is permanent
	// for the life of the binding, not a waiting period.
	ErrRestorePredicate = errors.New("oidcfed: token predates this binding's re-activation")
)

// Issuer is the cache's projection of one configured issuer. It carries only
// what fetching and verifying need, so this package never sees a stored row.
type Issuer struct {
	ID         string
	Issuer     string
	Type       domain.IssuerType
	Mode       domain.JWKSMode
	StaticJWKS string
	// RefusedAudiences are the issuer's default audiences. A token carrying
	// ANY of them is refused even when it also carries the bound one: a token
	// minted for the Kubernetes API server that happens to list Hikyo too is
	// still a token the API server could have been handed.
	RefusedAudiences []string
}

// Claims is a validated token's content. `Raw` carries every claim so the
// binding's pinned set can be compared without this package knowing which
// claims any platform uses.
type Claims struct {
	Issuer   string
	Subject  string
	Audience []string
	IssuedAt time.Time
	Expiry   time.Time
	Raw      map[string]json.RawMessage
}

// Binding is the cache's projection of one federated binding — the policy half
// of validation, evaluated after the signature is proven and the binding found.
type Binding struct {
	Audience string
	// RequiredClaimsJSON is the stored JSON object of pinned claims. Every one
	// is required; a binding pinning nothing is refused at creation, not here.
	RequiredClaimsJSON string
	// ReactivatedAt drives the restore predicate when non-zero.
	ReactivatedAt time.Time
}

// RefreshLimiter is the rate limit an unknown-`kid` refresh runs under. It is
// an interface so this package does not import the admission limiter (and so
// the outage fixtures can drive it), but the production implementation IS that
// limiter: the ADR puts this trigger under the same instance-wide
// pre-authentication budget as every other unauthenticated path.
type RefreshLimiter interface {
	AllowIssuerRefresh(issuer string) bool
}

// Cache is the process-wide JWKS cache. There is deliberately no table behind
// it: a restart empties it, which makes the first validation after a restart
// fetch or fail closed — STRICTER than the staleness bound, never looser.
//
// There is also deliberately no background ticker. Refresh is lazy: a
// validation whose keys are older than RefreshInterval tries to renew them on
// the way past. This binary has no scheduler (see #61's same disposition for
// expiry-threshold events), and a lazy refresh has the property a ticker does
// not: an issuer nobody authenticates against is never polled.
//
// LOCKING, because the naive version is a denial-of-service rather than a
// performance note. `mu` guards the MAP ONLY and is never held across a network
// call; each issuer's own `entry.mu` serializes that issuer's fetches. So
// concurrent validations for one issuer queue behind a single refresh
// (singleflight, which is what we want — they all need the same answer), while
// an unreachable issuer cannot block validation for any OTHER issuer.
//
// Holding one process-wide mutex across the fetch, as the first cut did, meant a
// single dead issuer stalled every federated authentication in the instance for
// `fetchTimeout` per request — an unauthenticated cross-issuer outage lever,
// reachable by anyone who can present a token.
type Cache struct {
	// HTTP is the client discovery and JWKS fetches use. Nil means a client
	// with fetchTimeout. Whatever is supplied, it is used through a COPY
	// carrying the HTTPS redirect guard (see guardedClient).
	HTTP *http.Client
	// Limiter rate-limits OUTBOUND REFRESHES, per issuer. Nil means unlimited,
	// which is only for tests: production wiring passes the admission limiter.
	Limiter RefreshLimiter
	// Now is injectable so the staleness bound is testable without sleeping.
	Nowf func() time.Time

	mu      sync.Mutex
	entries map[string]*entry
}

type entry struct {
	// mu serializes this issuer's fetches and guards the mutable fields below. It
	// is held across the HTTP call deliberately — that is the singleflight — and
	// `Cache.mu` is never held at the same time.
	mu sync.Mutex

	// admitted and inflight are the ONLY fields eviction may read, and both are
	// safe for it to read while another goroutine holds `mu`.
	//
	// `admitted` is written once, before this entry is published into the map, and
	// never again — so reading it under `Cache.mu` alone is not a race. The first
	// cut evicted by `fetchedAt`, which IS mutated under `mu`: that was a data
	// race, and worse than a race, because an in-flight entry has a zero
	// `fetchedAt`, looked like the oldest, and was therefore the FIRST thing
	// eviction chose — so its replacement started a duplicate concurrent fetch for
	// the same issuer and the singleflight this whole design exists for was
	// defeated exactly when it mattered.
	admitted time.Time
	// inflight counts the goroutines that hold or are about to hold `mu`. It is
	// incremented under `Cache.mu` inside entryFor, so an entry cannot be created,
	// handed out and then evicted before its user is counted. Eviction skips any
	// entry with a non-zero count.
	inflight atomic.Int32

	keys      []crypto.PublicKey
	kids      map[string]bool
	fetchedAt time.Time
	// lastAttempt is when a fetch was last ATTEMPTED, successfully or not. It
	// drives RefreshBackoff, so a dead issuer is discovered once per window
	// rather than once per request.
	lastAttempt time.Time
	// lastError is the most recent fetch failure. It is READ on a
	// backoff-suppressed refresh, so an operator sees why the keys are stale
	// even on the requests that did not themselves try.
	lastError error
}

func (c *Cache) now() time.Time {
	if c.Nowf == nil {
		return time.Now().UTC()
	}
	return c.Nowf().UTC()
}

// guardedClient is the only client this package fetches with. It copies whatever
// was configured and installs a redirect policy that refuses any non-HTTPS hop.
//
// The guard is on the CLIENT rather than only on the URL because the URL check
// alone is defeated by a redirect: an HTTPS discovery document naming an HTTPS
// `jwks_uri` that 302s to `http://` would pass a scheme check on the initial URL
// and then be fetched in plaintext. An on-path attacker replaces the key set,
// this instance caches the attacker's key, and tokens forged with any bound
// `iss`/`sub`/audience/claims authenticate. Both halves are therefore required:
// the scheme check on every URL we construct, and this policy on every hop the
// client takes for us.
//
// The copy is deliberate — a caller's client (the test fixture's, which carries
// the fixture CA) must not have its redirect policy mutated by us.
func (c *Cache) guardedClient() *http.Client {
	base := http.Client{Timeout: fetchTimeout}
	if c.HTTP != nil {
		base = *c.HTTP
	}
	base.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return requireHTTPS(req.URL.String())
	}
	return &base
}

// requireHTTPS refuses any URL that is not HTTPS. It is applied to the issuer,
// to the discovery-supplied `jwks_uri`, and to every redirect target.
func requireHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: unparseable url %q: %v", ErrInsecureTransport, rawURL, err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%w: %q", ErrInsecureTransport, rawURL)
	}
	return nil
}

// KeyState is what a validation observed about the key set it used, so the
// caller can emit the ADR's "JWKS refresh failure and staleness-bound breach"
// events without this package owning an audit dependency.
type KeyState struct {
	// Served reports the cache age the validation used. Zero for a static
	// JWKS, which has no age.
	Age time.Duration
	// RefreshFailed is the error a proactive or unknown-`kid` refresh hit and
	// which the cache absorbed by serving stale keys. Nil when nothing failed.
	RefreshFailed error
	// ServedStale reports that the key set was older than RefreshInterval and
	// a refresh did not renew it — the ADR's tolerated window in use.
	ServedStale bool
	// RefreshThrottled reports that an unknown `kid` did NOT trigger a fetch
	// because the per-issuer rate limit refused it.
	RefreshThrottled bool
}

// Peek reads the presented value's UNVERIFIED issuer and key id.
//
// Nothing here is trusted, and the naming says so: the result drives only
// cache maintenance — which issuer configuration to look up, and whether the
// cached key set plausibly contains the key this token was signed with. Every
// security decision happens in Verify, against a key set chosen before the
// signature is checked.
func Peek(presented string) (issuer, kid string, err error) {
	jws, perr := jose.ParseSigned(presented, joseAlgs)
	if perr != nil {
		return "", "", fmt.Errorf("%w: %v", ErrNotAToken, perr)
	}
	if len(jws.Signatures) != 1 {
		// A multi-signature JWS is not an OIDC ID token, and picking one
		// signature to look at would be a policy decision made by accident.
		return "", "", fmt.Errorf("%w: token carries %d signatures", ErrNotAToken, len(jws.Signatures))
	}
	payload := jws.UnsafePayloadWithoutVerification()
	var body struct {
		Issuer string `json:"iss"`
	}
	if uerr := json.Unmarshal(payload, &body); uerr != nil {
		return "", "", fmt.Errorf("%w: %v", ErrNotAToken, uerr)
	}
	if body.Issuer == "" {
		return "", "", fmt.Errorf("%w: token carries no iss", ErrNotAToken)
	}
	return body.Issuer, jws.Signatures[0].Header.KeyID, nil
}

// LooksLikeToken reports whether a presented value is a compact JWS at all. It
// is the transport's classifier: a `hik_` bearer artifact and an ID token
// arrive through the same header, and the branch must be on the SHAPE the
// caller sent rather than on anything the server has yet decided to trust.
func LooksLikeToken(presented string) bool {
	return strings.Count(presented, ".") == 2 && !strings.HasPrefix(presented, "hik_")
}

// Verify performs the complete cryptographic and generic validation: exact
// `iss` against the configured issuer, signature under an algorithm from the
// allowlist (never `none`), `exp`/`iat`/`nbf` within a bounded skew, and
// Hikyo's own caps on token age and declared span.
//
// It deliberately does NOT check the audience or the pinned claims. Those are
// properties of a BINDING, and the binding is found by the `(iss, sub)` pair
// this function produces — so they are CheckBinding's, evaluated in the
// authorizing transaction against the row that was actually resolved.
func (c *Cache) Verify(ctx context.Context, iss Issuer, presented string, now time.Time) (Claims, KeyState, error) {
	tokenIssuer, kid, err := Peek(presented)
	if err != nil {
		return Claims{}, KeyState{}, err
	}
	// Byte-exact, before any key work. The caller found `iss` by this same
	// string, so a mismatch here is a defect rather than an attack — and it is
	// checked anyway, because a validation that trusts its caller's lookup is
	// one refactor away from trusting the token.
	if tokenIssuer != iss.Issuer {
		return Claims{}, KeyState{}, fmt.Errorf("%w: token issuer is not the configured issuer", ErrTokenInvalid)
	}

	keys, state, err := c.keysFor(ctx, iss, kid, now)
	if err != nil {
		return Claims{}, state, err
	}

	verifier := oidc.NewVerifier(iss.Issuer, &oidc.StaticKeySet{PublicKeys: keys}, &oidc.Config{
		SupportedSigningAlgs: allowedAlgs,
		// The audience is the BINDING's, not the issuer configuration's, so it
		// cannot be checked here — CheckBinding does it against the resolved
		// row. Skipping it here and forgetting it there would be the hole, so
		// CheckBinding refuses an empty bound audience rather than treating it
		// as "any".
		SkipClientIDCheck: true,
		Now:               func() time.Time { return now },
	})
	tok, err := verifier.Verify(ctx, presented)
	if err != nil {
		return Claims{}, state, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	if tok.Issuer != iss.Issuer {
		return Claims{}, state, fmt.Errorf("%w: verified issuer is not the configured issuer", ErrTokenInvalid)
	}
	if tok.Subject == "" {
		return Claims{}, state, fmt.Errorf("%w: token carries no sub", ErrTokenInvalid)
	}

	raw := map[string]json.RawMessage{}
	if err := tok.Claims(&raw); err != nil {
		return Claims{}, state, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	claims := Claims{
		Issuer: tok.Issuer, Subject: tok.Subject, Audience: tok.Audience,
		IssuedAt: tok.IssuedAt.UTC(), Expiry: tok.Expiry.UTC(), Raw: raw,
	}
	if err := checkTiming(claims, now); err != nil {
		return Claims{}, state, err
	}
	return claims, state, nil
}

// checkTiming is the ADR's `exp`/`iat`/`nbf` window plus Hikyo's two
// independent caps. go-oidc validates `exp` and leaves the rest to the caller.
func checkTiming(c Claims, now time.Time) error {
	if c.IssuedAt.IsZero() {
		return fmt.Errorf("%w: token carries no iat", ErrTokenInvalid)
	}
	if c.Expiry.IsZero() {
		return fmt.Errorf("%w: token carries no exp", ErrTokenInvalid)
	}
	if c.IssuedAt.After(c.Expiry) {
		return fmt.Errorf("%w: token iat is after exp", ErrTokenInvalid)
	}
	if c.IssuedAt.After(now.Add(MaxClockSkew)) {
		return fmt.Errorf("%w: token iat is beyond the accepted clock skew", ErrTokenInvalid)
	}
	// `nbf` is optional in OIDC and go-oidc does not read it, so it is read
	// here rather than ignored: a token the issuer says is not yet valid must
	// not be accepted because our library happened not to look.
	if rawNbf, ok := c.Raw["nbf"]; ok {
		var nbf int64
		if err := json.Unmarshal(rawNbf, &nbf); err != nil {
			return fmt.Errorf("%w: token nbf is not a numeric date", ErrTokenInvalid)
		}
		if now.Add(MaxClockSkew).Before(time.Unix(nbf, 0)) {
			return fmt.Errorf("%w: token is not yet valid", ErrTokenInvalid)
		}
	}
	// The two Hikyo caps, independent of what the issuer chose.
	if age := now.Sub(c.IssuedAt); age > MaxTokenAge {
		return fmt.Errorf("%w: token is %s old, cap is %s", ErrTokenAge, age.Truncate(time.Second), MaxTokenAge)
	}
	if span := c.Expiry.Sub(c.IssuedAt); span > MaxTokenSpan {
		return fmt.Errorf("%w: token declares a %s validity span, cap is %s", ErrTokenAge, span.Truncate(time.Second), MaxTokenSpan)
	}
	return nil
}

// CheckBinding is the binding half of validation, evaluated against the row the
// `(issuer, subject)` lookup resolved to.
//
// Order matters here and is deliberate: the audience is checked first because
// it is the one the ADR calls MANDATORY and the one whose default the issuer
// itself would otherwise satisfy; the pinned claims next; the CI event rule
// after them, because it reads a claim the pinned set has already been proven
// to contain; the restore predicate last, because it is the only check that can
// pass for a token that is in every other way correct.
func CheckBinding(iss Issuer, b Binding, c Claims, now time.Time) error {
	// ALL TIME-BASED PREDICATES ARE RE-CHECKED HERE, against the caller's clock
	// -- which the chokepoint reads inside the authorizing transaction.
	// Signature-time validation proved the token was live when it was PRESENTED;
	// the sealer preflight between presentation and this predicate can take real
	// time, and a token whose `exp`, `nbf`, or Hikyo-owned age cap passes during
	// it must be refused by the authentication the delivery actually rides.
	if err := checkTiming(c, now); err != nil {
		return err
	}
	if now.After(c.Expiry.Add(MaxClockSkew)) {
		return fmt.Errorf("%w: token expired during validation", ErrTokenInvalid)
	}
	if b.Audience == "" {
		// Structurally impossible through the mint path, which refuses it. It
		// is re-checked because "no bound audience" must never degrade into
		// "any audience".
		return fmt.Errorf("%w: binding names no audience", ErrAudience)
	}
	if !containsString(c.Audience, b.Audience) {
		return fmt.Errorf("%w: token audiences do not include the bound audience", ErrAudience)
	}
	// The issuer's DEFAULT audience is refused even when the bound one is also
	// present. A Kubernetes token minted for the API server that happens to
	// list Hikyo too is still a token the API server could have been handed,
	// and Forgejo's `<instance>/<owner>` default is shared across every
	// repository that owner has.
	for _, refused := range iss.RefusedAudiences {
		if containsString(c.Audience, refused) {
			return fmt.Errorf("%w: token carries the issuer's default audience %q", ErrAudience, refused)
		}
	}

	pinned, err := ParseRequiredClaims(b.RequiredClaimsJSON)
	if err != nil {
		return err
	}
	if len(pinned) == 0 {
		// Same reasoning as the empty audience: the mint refuses it, and the
		// validator refuses it again rather than reading "nothing pinned" as
		// "everything acceptable".
		return fmt.Errorf("%w: binding pins no claims", ErrClaim)
	}
	for name, want := range pinned {
		// resolveClaim, never a bare map lookup: a pinned name may be a JSON
		// Pointer into a nested object, which is the only way a Kubernetes
		// ServiceAccount UID can be pinned at all.
		got, ok := resolveClaim(c.Raw, name)
		if !ok {
			return fmt.Errorf("%w: %q", ErrClaim, name)
		}
		if !sameJSONScalar(want, got) {
			return fmt.Errorf("%w: %q", ErrClaim, name)
		}
	}

	// The CI rule. Forgejo's Actions subject is `repo:<repository>:ref:<ref>`
	// for every event EXCEPT an exact `pull_request` trigger — so
	// `pull_request_target` carries the ORDINARY ref-form subject, the default
	// branch's subject, the one a production binding names. A crafted pull
	// request against a `pull_request_target` workflow that touches untrusted
	// content can leak the ID-token request credentials, and the resulting
	// token bears the bound production subject. The protection is the pinned
	// `event_name`, never the subject's shape.
	if domain.IsCIIssuerType(iss.Type) {
		if err := checkEventName(pinned, c.Raw); err != nil {
			return err
		}
	}

	// The restore predicate (§ Restore). PERMANENT for the life of the
	// binding, not a quarantine window: once a window lifts, a pre-restore
	// token whose `iat` was skewed into Hikyo's future is admitted by ordinary
	// validation, which is the exact artifact this exists to exclude. The
	// margin is the whole point, not padding — an issuer whose clock leads
	// Hikyo by the accepted skew mints tokens with an `iat` in Hikyo's future,
	// and a rule phrased against the re-activation instant alone is defeated
	// by the clock, silently.
	if !b.ReactivatedAt.IsZero() {
		floor := b.ReactivatedAt.Add(MaxClockSkew)
		if !c.IssuedAt.After(floor) {
			return fmt.Errorf("%w: iat %s is not strictly after %s",
				ErrRestorePredicate, c.IssuedAt.Format(time.RFC3339), floor.Format(time.RFC3339))
		}
	}
	return nil
}

// EventNameClaim is the claim every CI binding must pin.
const EventNameClaim = "event_name"

// RefusedEvents are the two triggers a CI binding must not admit unless one of
// them is what it deliberately bound.
var RefusedEvents = []string{"pull_request", "pull_request_target"}

// checkEventName enforces the refusal. The pinned value has already been proven
// equal to the token's, so this reads the PIN: if a binding pinned
// `pull_request_target`, that is the separate, explicit, deliberate binding the
// ADR permits, and the token matching it is admitted. Any other pin refuses a
// token whose event is one of the two — which, because the pin matched, cannot
// happen; the check is here so that a future relaxation of the pin comparison
// cannot silently reopen the hole.
func checkEventName(pinned map[string]json.RawMessage, raw map[string]json.RawMessage) error {
	want, ok := pinned[EventNameClaim]
	if !ok {
		// Refused at creation for a CI issuer; refused again here rather than
		// treated as "no opinion about which events may speak for this repo".
		return fmt.Errorf("%w: a CI binding must pin %q", ErrEventName, EventNameClaim)
	}
	var pinnedEvent string
	if err := json.Unmarshal(want, &pinnedEvent); err != nil {
		return fmt.Errorf("%w: pinned %s is not a string", ErrEventName, EventNameClaim)
	}
	var tokenEvent string
	if got, ok := raw[EventNameClaim]; ok {
		if err := json.Unmarshal(got, &tokenEvent); err != nil {
			return fmt.Errorf("%w: token %s is not a string", ErrEventName, EventNameClaim)
		}
	}
	for _, refused := range RefusedEvents {
		if tokenEvent == refused && pinnedEvent != refused {
			return fmt.Errorf("%w: %q", ErrEventName, refused)
		}
	}
	return nil
}

// ParseRequiredClaims decodes a binding's pinned-claim object. It is exported
// because the mint path validates the same document before storing it, and two
// decoders would be two chances to disagree about what a pinned claim is.
//
// A pinned VALUE is always a scalar — a nested pinned value would make
// "byte-exact" a question about JSON key order and whitespace rather than about
// the value. A pinned NAME may be either a top-level claim name or a JSON
// Pointer (RFC 6901) into a nested object; see resolveClaim.
func ParseRequiredClaims(raw string) (map[string]json.RawMessage, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: binding pins no claims", ErrClaim)
	}
	out := map[string]json.RawMessage{}
	dec := json.NewDecoder(strings.NewReader(raw))
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: pinned claims are not a JSON object: %v", ErrClaim, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: pinned claims carry trailing content", ErrClaim)
	}
	for name, v := range out {
		if name == "" {
			return nil, fmt.Errorf("%w: pinned claim has an empty name", ErrClaim)
		}
		if !isJSONScalar(v) {
			return nil, fmt.Errorf("%w: pinned claim %q is not a string, number or boolean", ErrClaim, name)
		}
		if err := ValidatePointer(name); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// resolveClaim finds a pinned claim's value in a token's claim set.
//
// A name beginning with `/` is a JSON POINTER (RFC 6901) into nested objects;
// any other name is a top-level claim, matched byte-exactly. The discriminator is
// the leading slash and nothing else, because the alternative — a dotted path —
// is AMBIGUOUS on the exact claim this exists for: a Kubernetes projected
// ServiceAccount token nests everything under the literal top-level key
// `kubernetes.io`, whose name already contains a dot.
//
// Nesting support is not a convenience. The ADR requires a binding to pin an
// issuer's immutable identifiers "rather than the names", and Kubernetes exposes
// the ServiceAccount UID only at `/kubernetes.io/serviceaccount/uid`. Without
// pointers that requirement is unsatisfiable against a real token, and the only
// bindings an operator could write would be the name-based ones the ADR forbids.
//
// Traversal is FULL RFC 6901 — object members and array indices both — rather
// than an objects-only subset. Two reasons. A subset would have to be validated
// and documented anyway (an operator writing `/groups/0` deserves a refusal at
// creation, not a pin that can never match), which is the same amount of code as
// supporting it; and `aud` and `amr` are array-valued claims that already exist,
// so "objects only" would be a rule with counterexamples in the specification it
// implements.
//
// The leaf must be a SCALAR: a pointer landing on an object or an array answers
// "not found", so a pin can never be satisfied by a structural match.
func resolveClaim(claims map[string]json.RawMessage, name string) (json.RawMessage, bool) {
	if !strings.HasPrefix(name, "/") {
		v, ok := claims[name]
		return v, ok
	}
	segments := strings.Split(strings.TrimPrefix(name, "/"), "/")
	first, err := unescapePointer(segments[0])
	if err != nil {
		return nil, false
	}
	current, ok := claims[first]
	if !ok {
		return nil, false
	}
	for _, raw := range segments[1:] {
		segment, err := unescapePointer(raw)
		if err != nil {
			return nil, false
		}
		current, ok = descend(current, segment)
		if !ok {
			return nil, false
		}
	}
	if !isJSONScalar(current) {
		return nil, false
	}
	return current, true
}

// descend takes one RFC 6901 step into a node: an object member by name, or an
// array element by index.
//
// The array branch is tried FIRST and only when the segment is a well-formed
// index, because RFC 6901 fixes index syntax as `0` or a non-zero digit followed
// by digits — so `01` is not an index and `/a/01` addresses the object member
// "01". Getting that backwards would make two different pointers resolve to the
// same place.
func descend(node json.RawMessage, segment string) (json.RawMessage, bool) {
	trimmed := strings.TrimSpace(string(node))
	if strings.HasPrefix(trimmed, "[") {
		if !isPointerIndex(segment) {
			return nil, false
		}
		var elements []json.RawMessage
		if err := json.Unmarshal(node, &elements); err != nil {
			return nil, false
		}
		i, err := strconv.Atoi(segment)
		if err != nil || i >= len(elements) {
			return nil, false
		}
		return elements[i], true
	}
	nested := map[string]json.RawMessage{}
	if err := json.Unmarshal(node, &nested); err != nil {
		return nil, false
	}
	v, ok := nested[segment]
	return v, ok
}

// isPointerIndex reports whether a segment is RFC 6901 array-index syntax: `0`,
// or a non-zero digit followed by digits. `-` (the RFC's "past the last element")
// is deliberately not accepted: it addresses a position that holds no value, so it
// can never satisfy a pin.
func isPointerIndex(segment string) bool {
	if segment == "" || (segment[0] == '0' && len(segment) > 1) {
		return false
	}
	for _, r := range segment {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// unescapePointer applies RFC 6901's two escapes and REFUSES anything else.
//
// The order is the one the RFC fixes: `~1` becomes `/`, then `~0` becomes `~`.
// Reversing them would turn `~01` into `/` instead of the correct `~1`.
//
// A `~` followed by anything other than `0` or `1` is an ERROR rather than a
// literal tilde. Accepting it silently — which the first cut did — means
// `/kubernetes.io/serviceaccount/~2uid` is stored as a pin that can never match
// any token, so a binding an operator believed was strict is in fact one nothing
// satisfies. That is a fail-open shape: the pin is inert, and its inertness is
// invisible until someone audits the binding.
func unescapePointer(segment string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(segment); i++ {
		if segment[i] != '~' {
			b.WriteByte(segment[i])
			continue
		}
		if i+1 >= len(segment) {
			return "", fmt.Errorf("%w: pointer segment %q ends with an unescaped ~", ErrClaim, segment)
		}
		switch segment[i+1] {
		case '0':
			b.WriteByte('~')
		case '1':
			b.WriteByte('/')
		default:
			return "", fmt.Errorf("%w: pointer segment %q contains the invalid escape ~%c",
				ErrClaim, segment, segment[i+1])
		}
		i++
	}
	return b.String(), nil
}

// ValidatePointer refuses a malformed pointer at BINDING CREATION rather than
// leaving it to be discovered as a pin that never matches.
//
// It is called from ParseRequiredClaims, which both the creation path and the
// validation path go through — so there is one definition of a well-formed
// pointer and neither path can drift from it.
func ValidatePointer(name string) error {
	if !strings.HasPrefix(name, "/") {
		return nil
	}
	for _, segment := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
		if _, err := unescapePointer(segment); err != nil {
			return fmt.Errorf("%w (pinned claim %q)", err, name)
		}
	}
	return nil
}

// RequiredPins is the closed per-issuer-type set of claims a binding MUST pin,
// enforced at creation.
//
// This is the ADR's rule read as the MUST it is: "where an issuer exposes
// immutable numeric identifiers for the repository and its owner, the binding
// pins those rather than the names. A rename or transfer otherwise silently
// re-points a production binding at whatever now occupies the old path." Leaving
// it to operator diligence — which the first cut did, enforcing only
// `event_name` — accepts a binding pinning nothing but `event_name=push`, and a
// renamed-then-reused repository path inherits the principal.
//
// There is deliberately NO override flag. An override is the thing an operator
// sets once during a migration and never removes, and the ADR does not offer one.
//
//   - github-actions exposes both numeric ids, so both are required, plus
//     `event_name` for the pull-request rule.
//   - kubernetes exposes the ServiceAccount UID, nested — required through its
//     JSON Pointer. A recreated ServiceAccount with the same name has a
//     different UID, which is precisely what this closes.
//   - forgejo exposes NO immutable numeric identifiers for the repository or its
//     owner (its Actions claim set carries `repository` and `repository_owner` as
//     names only), so the strictest available rule is the repository name plus
//     `event_name`. Recorded as a known ceiling in the handoff: a Forgejo
//     repository renamed and its path reused inherits the binding, and the only
//     fix is upstream emitting ids.
var RequiredPins = map[domain.IssuerType][]string{
	domain.IssuerGitHubActions: {"repository_id", "repository_owner_id", EventNameClaim},
	domain.IssuerKubernetes:    {KubernetesServiceAccountUID},
	domain.IssuerForgejo:       {"repository", EventNameClaim},
}

// KubernetesServiceAccountUID is where a projected ServiceAccount token carries
// the immutable UID: nested under the literal `kubernetes.io` claim.
const KubernetesServiceAccountUID = "/kubernetes.io/serviceaccount/uid"

// MissingRequiredPins returns the claims this issuer type demands and the binding
// does not pin, sorted. Empty means the binding satisfies the rule.
func MissingRequiredPins(t domain.IssuerType, pinned map[string]json.RawMessage) []string {
	var missing []string
	for _, name := range RequiredPins[t] {
		if _, ok := pinned[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

// isJSONScalar reports whether a raw value is a string, number, boolean or
// null. Objects and arrays are refused: comparing them byte-exactly would make
// key order and whitespace security-relevant.
func isJSONScalar(v json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(v))
	if trimmed == "" {
		return false
	}
	switch trimmed[0] {
	case '{', '[':
		return false
	}
	var any1 any
	return json.Unmarshal(v, &any1) == nil
}

// sameJSONScalar compares two raw JSON scalars EXACTLY, after whitespace
// trimming and nothing else.
//
// A string is never folded to a number and a number is never folded to a
// string: the GitHub Actions claim `repository_id` is the numeric `123` and the
// value `"123"` is a different claim value, so treating them as equal would let
// a binding written one way be satisfied by a token the other. It also means
// `1` and `1.0` do not match — accepted, because every issuer in the closed set
// emits integers, and normalising numerics would reintroduce the folding this
// rule exists to forbid.
func sameJSONScalar(want, got json.RawMessage) bool {
	return strings.TrimSpace(string(want)) == strings.TrimSpace(string(got))
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// keysFor returns the key set a validation should use, refreshing the cache
// when the age or an unknown `kid` calls for it, and failing closed past the
// staleness bound.
func (c *Cache) keysFor(ctx context.Context, iss Issuer, kid string, now time.Time) ([]crypto.PublicKey, KeyState, error) {
	// A static JWKS is CONFIGURATION, not machinery: it is parsed on the way
	// past, never fetched, and has no age to be stale. That is exactly why it
	// is not the default — a static-only installation breaks silently on the
	// day someone rotates the issuer's keys, and the operator chose that.
	if iss.Mode == domain.JWKSStatic {
		keys, kids, err := parseJWKS([]byte(iss.StaticJWKS))
		if err != nil {
			return nil, KeyState{}, fmt.Errorf("%w: static jwks: %v", ErrKeysUnavailable, err)
		}
		if kid != "" && !kids[kid] {
			// Loud, and this is the failure mode the ADR names for static
			// mode: the issuer rotated and nobody updated the configuration.
			return nil, KeyState{}, fmt.Errorf("%w: static jwks has no key %q", ErrKeysUnavailable, kid)
		}
		return keys, KeyState{}, nil
	}

	// Map access under `mu`, released before anything blocking. entryFor has
	// already counted this goroutine into `inflight`, so the entry it returned
	// cannot be evicted out from under us between here and the lock.
	//
	// LOCK ORDER, stated because there is exactly one and it is what keeps this
	// deadlock-free: `Cache.mu` may be taken while no `entry.mu` is held, and
	// `entry.mu` is never taken while `Cache.mu` is held. entryFor is the only
	// place that touches the map, and it returns before any entry lock is taken.
	e := c.entryFor(iss.Issuer)
	defer e.inflight.Add(-1)
	e.mu.Lock()
	defer e.mu.Unlock()

	// `allow` is the single gate every OUTBOUND fetch passes, and it gates BOTH
	// triggers — staleness and unknown `kid`. Gating only the `kid` trigger, as
	// the first cut did, left the amplifier wide open the moment the keys aged
	// past RefreshInterval: `needRefresh` stayed true whatever the limiter said.
	//
	// The backoff is checked before the limiter because it is the cheaper and
	// stronger of the two: it bounds attempts against a KNOWN-BAD issuer without
	// consuming the instance-wide allowance that healthy issuers share.
	allow := func() (ok bool, suppressed error) {
		// The backoff suppresses only after a FAILED attempt. Backing off after a
		// successful one would make a legitimate key rotation wait out the window
		// — the unknown-`kid` trigger exists precisely to recover from a rotation
		// immediately, and a cache that had just refreshed successfully is exactly
		// the state a rotation arrives in.
		if e.lastError != nil && now.Sub(e.lastAttempt) < RefreshBackoff {
			return false, e.lastError
		}
		if c.Limiter != nil && !c.Limiter.AllowIssuerRefresh(iss.Issuer) {
			return false, nil
		}
		return true, nil
	}
	attempt := func() error {
		e.lastAttempt = now
		fetched, err := c.fetch(ctx, iss, now)
		if err != nil {
			e.lastError = err
			return err
		}
		e.keys, e.kids, e.fetchedAt, e.lastError = fetched.keys, fetched.kids, now, nil
		return nil
	}

	// No cache at all: fetch, and fail closed if that fails. There is nothing
	// stale to fall back to, and inventing a grace period here would mean a
	// restart could admit tokens signed by keys the issuer has retired.
	if e.fetchedAt.IsZero() {
		ok, suppressed := allow()
		if !ok {
			cause := suppressed
			if cause == nil {
				cause = errors.New("refresh suppressed by the instance-wide allowance")
			}
			return nil, KeyState{RefreshFailed: cause, RefreshThrottled: true},
				fmt.Errorf("%w: %v", ErrKeysUnavailable, cause)
		}
		if err := attempt(); err != nil {
			return nil, KeyState{RefreshFailed: err}, fmt.Errorf("%w: %v", ErrKeysUnavailable, err)
		}
		return e.keys, KeyState{}, nil
	}

	age := now.Sub(e.fetchedAt)

	// Past the bound: fail closed LOUDLY unless a fetch renews the keys. This is
	// the half of the rule that makes the staleness window bounded rather than
	// infinite — and it honours the backoff, which only makes it stricter: a
	// suppressed attempt fails closed without an outbound request.
	if age > StalenessBound {
		ok, suppressed := allow()
		if ok {
			if err := attempt(); err == nil {
				return e.keys, KeyState{}, nil
			}
			suppressed = e.lastError
		}
		return nil, KeyState{Age: age, RefreshFailed: suppressed, RefreshThrottled: !ok},
			fmt.Errorf("%w: keys are %s old (bound %s): %v",
				ErrKeysStale, age.Truncate(time.Second), StalenessBound, suppressed)
	}

	state := KeyState{Age: age}
	if age <= RefreshInterval && (kid == "" || e.kids[kid]) {
		// Fresh and the signing key is known. The overwhelmingly common case, and
		// the one that must cost nothing.
		return e.keys, state, nil
	}

	ok, suppressed := allow()
	if !ok {
		// TOLERATED, and the ADR is explicit about why: it rejects failing closed
		// the moment a refresh fails, because the failure this must survive is an
		// API-server blip and refusing would stop every workload fetch
		// cluster-wide on a control plane whose delivery story is
		// stale-but-valid beats not-starting.
		state.RefreshThrottled, state.ServedStale, state.RefreshFailed = true, true, suppressed
		return e.keys, state, nil
	}
	if err := attempt(); err != nil {
		state.RefreshFailed, state.ServedStale = err, true
		return e.keys, state, nil
	}
	return e.keys, KeyState{}, nil
}

// entryFor returns this issuer's cache entry, creating it if absent, and counts
// the caller into `inflight` before returning — the caller owes exactly one
// `inflight.Add(-1)`.
//
// It holds `mu` for map access only, never across a fetch, and it is the ONLY
// function that touches the map.
//
// Eviction reads `admitted` (written once, before publication) and `inflight`
// (atomic), and NEVER `fetchedAt`. An entry with a live user is skipped, so
// eviction cannot replace an entry mid-fetch and turn one fetch into two. If every
// candidate is busy nothing is evicted and the map briefly exceeds the ceiling:
// that ceiling is a sanity bound on operator-configured issuers, not a defence
// against attacker-chosen keys — only an `instance-config` holder can add an
// issuer — so overshooting it by a few is strictly better than breaking the
// singleflight.
func (c *Cache) entryFor(issuer string) *entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]*entry{}
	}
	if e, ok := c.entries[issuer]; ok {
		e.inflight.Add(1)
		return e
	}
	if len(c.entries) >= maxTrackedIssuers {
		var oldest string
		var oldestAt time.Time
		for k, v := range c.entries {
			if v.inflight.Load() != 0 {
				continue
			}
			if oldest == "" || v.admitted.Before(oldestAt) {
				oldest, oldestAt = k, v.admitted
			}
		}
		if oldest != "" {
			delete(c.entries, oldest)
		}
	}
	e := &entry{admitted: c.now()}
	e.inflight.Add(1)
	c.entries[issuer] = e
	return e
}

// fetch performs discovery and then the JWKS read.
//
// Discovery goes through go-oidc's NewProvider, which RE-ASSERTS the byte-exact
// issuer against the document it fetched: a discovery endpoint that answers with
// a different `issuer` is a misconfiguration or an attack, and either way it
// must not silently become the issuer we trust.
func (c *Cache) fetch(ctx context.Context, iss Issuer, now time.Time) (*entry, error) {
	// The issuer itself, before anything is dialled. It is already `https`-only
	// at configuration time; checked again here because this is the function that
	// turns a string into a network fetch, and a validator that trusts its own
	// caller's validation is one refactor away from trusting nothing.
	if err := requireHTTPS(iss.Issuer); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	client := c.guardedClient()
	ctx = oidc.ClientContext(ctx, client)

	provider, err := oidc.NewProvider(ctx, iss.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := provider.Claims(&doc); err != nil {
		return nil, fmt.Errorf("discovery document: %w", err)
	}
	if doc.JWKSURI == "" {
		return nil, errors.New("discovery document names no jwks_uri")
	}
	// The DOCUMENT-SUPPLIED url. This is the one an attacker controls if they
	// control the discovery endpoint, and the one whose plaintext fetch would let
	// them substitute the whole key set.
	if err := requireHTTPS(doc.JWKSURI); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, doc.JWKSURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("jwks read: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("jwks document exceeds %d bytes", maxJWKSBytes)
	}
	keys, kids, err := parseJWKS(body)
	if err != nil {
		return nil, err
	}
	return &entry{keys: keys, kids: kids, fetchedAt: now}, nil
}

// parseJWKS turns a JWKS document into public keys, through go-jose. This is
// key PARSING, not verification: the signature check is go-oidc's, against
// whatever this returns.
//
// A rotation is not a special case: the issuer publishes old and new keys
// together, so both land in the set and tokens signed by either verify. That is
// what makes StaticKeySet's try-every-key behaviour correct here rather than a
// shortcut — the set is exactly the issuer's current published set.
func parseJWKS(body []byte) ([]crypto.PublicKey, map[string]bool, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, nil, fmt.Errorf("jwks parse: %w", err)
	}
	keys := make([]crypto.PublicKey, 0, len(set.Keys))
	kids := map[string]bool{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub := k.Public()
		if pub.Key == nil {
			continue
		}
		keys = append(keys, pub.Key)
		if k.KeyID != "" {
			kids[k.KeyID] = true
		}
	}
	if len(keys) == 0 {
		return nil, nil, errors.New("jwks document carries no usable signing keys")
	}
	return keys, kids, nil
}
