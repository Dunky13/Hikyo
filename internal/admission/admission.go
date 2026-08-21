// Package admission is the pre-authentication admission control the threat
// model requires and the ops spec dimensions: an instance-wide semaphore over
// Argon2id execution, a bounded queue, per-source-IP rate limiting, and
// per-account backoff.
//
// Why instance-wide and not just per-account/per-IP: a distributed attempt
// spread across many usernames and many source IPs never trips either bucket,
// while each accepted attempt consumes 64 MiB of memory and a durable audit
// write. Per-account and per-IP backoff is necessary and insufficient, so
// both exist here.
//
// Deliberately in memory, not in the database. v1's locked deployment
// envelope is a single node with no HA, so process-local state is the whole
// instance's state; a durable throttle table would add a write per failed
// attempt — amplifying exactly the flood it is meant to bound — to buy
// nothing this deployment shape can use. A multi-node build must replace this
// with shared state, which is why the constraint is written down here rather
// than discovered later.
package admission

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Ops-spec values (§ 4, pre-auth admission).
const (
	// DefaultBudgetMiB is 256 MiB of verification work plus 16 MiB of global
	// implementation headroom, reserved once rather than per worker.
	DefaultBudgetMiB = 272
	// HeadroomMiB is that reserved global slice.
	HeadroomMiB = 16
	// MaxConcurrency caps the derived concurrency however large the budget is.
	MaxConcurrency = 8
	// QueueDepth bounds waiters; beyond it the answer is a uniform refusal
	// that performs no unbounded work.
	QueueDepth = 16
	// PerIPPerMinute is the sliding per-source-IP attempt allowance for paths
	// that can run Argon2id.
	PerIPPerMinute = 10
	// MetaPerIPPerMinute is the discovery endpoint's own allowance. It is
	// looser because the endpoint is cheap and `login` legitimately calls it
	// before every authentication — charging it against the verification
	// budget would make the client's own capability check the thing that
	// throttles the client.
	MetaPerIPPerMinute = 60
	// IssuerRefreshPerMinute is how many unknown-`kid` JWKS refreshes one
	// configured issuer may trigger per minute (#62). It is small because it
	// bounds an OUTBOUND fetch amplifier on a pre-authentication path, and
	// because the legitimate trigger — an issuer rotating its signing keys —
	// needs exactly one.
	IssuerRefreshPerMinute = 5
	// FailuresBeforeBackoff is how many consecutive per-account failures pass
	// before the delay starts.
	FailuresBeforeBackoff = 5
	// MaxAccountBackoff caps the exponential delay. There is no hard lockout:
	// locking out a known username is a free denial-of-service lever, and the
	// permission model already refuses unadministrable states.
	MaxAccountBackoff = 60 * time.Second
	// RetryAfter is what an overloaded instance advertises.
	RetryAfter = 5 * time.Second
	// MaxTrackedSubjects bounds how many source IPs and account buckets the
	// limiter remembers. Both maps are keyed by attacker-chosen values — any
	// source address, any presented username — so without a bound the
	// throttle becomes the memory-exhaustion vector it exists to prevent.
	// When the bound is hit, entries whose windows have elapsed are dropped
	// first; only if that frees nothing is the oldest live entry evicted, and
	// evicting a live bucket only ever forgives an attacker, never a
	// legitimate user.
	MaxTrackedSubjects = 4096
)

// ErrOverloaded is the uniform overload outcome. Every pre-auth path answers
// it identically — same status, same body, same timing — which is the
// enumeration-uniformity rule one layer earlier than unauthorized ≡
// nonexistent.
var ErrOverloaded = errors.New("admission: instance-wide budget exhausted")

// Config is the tunable half. ArgonMemoryKiB must be the value the login path
// actually uses: the derived concurrency is a function of it, so raising the
// KDF cost lowers concurrency automatically instead of silently doubling the
// memory bill.
type Config struct {
	BudgetMiB      int
	ArgonMemoryKiB uint32
	// PerIPPerMinute overrides the per-source-IP attempt allowance. Zero means
	// the locked default. It exists for one caller: a test harness driving many
	// authentications from one loopback address, which is not the traffic shape
	// the default is sized for. The server refuses the override outside
	// development mode, so a production instance cannot be handed a raised
	// ceiling by an environment variable.
	PerIPPerMinute int
	// Now is injectable so the backoff and rate-limit curves are testable
	// without sleeping. Nil means time.Now.
	Now func() time.Time
}

// Limiter is one instance's admission state.
type Limiter struct {
	concurrency int
	perIP       int
	slots       chan struct{}
	now         func() time.Time

	mu       sync.Mutex
	waiting  int
	ipHits   map[string][]time.Time
	metaHits map[string][]time.Time
	// issuerRefreshes is keyed by configured issuer, not by source IP: the
	// amplification an unknown `kid` buys is aimed at the ISSUER, so one
	// fabricated-`kid` stream from a thousand addresses is one outbound flood.
	issuerRefreshes map[string][]time.Time
	// accounts is the per-account backoff state. One map, not a count map
	// beside a deadline map: two maps keyed by the same value can disagree
	// about which accounts exist, and every read, write and eviction here
	// depends on them agreeing. A single entry makes the invariant structural.
	accounts map[subjectKey]accountBackoff
}

// subjectKey is the irreversible bucket key for a presented account identifier.
// Keeping the hash as a domain type prevents account state from accepting raw
// identifiers by accident.
type subjectKey [sha256.Size]byte

// accountBackoff is one account's place on the failure curve. The key is the
// hash of the presented identifier, never the identifier itself.
type accountBackoff struct {
	// failures counts consecutive failures; a success deletes the entry.
	failures int
	// until is the instant the delay expires. The zero value means no delay
	// has been set yet, which is the state of every account still under the
	// threshold.
	until time.Time
}

// New derives the concurrency and refuses a configuration in which a single
// verification cannot fit.
//
// Boot invariant, fail fast: budget >= m + headroom. With it held the
// formula's lower bound of 1 always fits inside the budget, so a
// configuration where one verification cannot fit is a config error caught at
// startup, never a runtime surprise.
func New(cfg Config) (*Limiter, error) {
	if cfg.BudgetMiB <= 0 {
		cfg.BudgetMiB = DefaultBudgetMiB
	}
	if cfg.ArgonMemoryKiB == 0 {
		return nil, errors.New("admission: Argon2id memory must be stated — the concurrency budget is derived from it")
	}
	argonMiB := int((cfg.ArgonMemoryKiB + 1023) / 1024)
	if cfg.BudgetMiB < argonMiB+HeadroomMiB {
		return nil, fmt.Errorf(
			"admission: budget %d MiB cannot hold one verification: Argon2id needs %d MiB plus %d MiB headroom — raise the budget or lower the KDF memory",
			cfg.BudgetMiB, argonMiB, HeadroomMiB)
	}
	concurrency := (cfg.BudgetMiB - HeadroomMiB) / argonMiB
	concurrency = max(1, min(MaxConcurrency, concurrency))

	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	perIP := cfg.PerIPPerMinute
	if perIP <= 0 {
		perIP = PerIPPerMinute
	}
	l := &Limiter{
		concurrency:     concurrency,
		perIP:           perIP,
		slots:           make(chan struct{}, concurrency),
		now:             now,
		ipHits:          map[string][]time.Time{},
		metaHits:        map[string][]time.Time{},
		issuerRefreshes: map[string][]time.Time{},
		accounts:        map[subjectKey]accountBackoff{},
	}
	for range concurrency {
		l.slots <- struct{}{}
	}
	return l, nil
}

// Concurrency reports the derived number of simultaneous verifications.
func (l *Limiter) Concurrency() int { return l.concurrency }

// Enter admits one pre-authentication attempt from sourceIP. The returned
// release must be called when the expensive work is done.
//
// Order matters: the per-IP check happens before the semaphore, so a single
// noisy source cannot occupy queue slots that a legitimate caller needs.
func (l *Limiter) Enter(ctx context.Context, sourceIP string) (release func(), err error) {
	if !l.allowIP(sourceIP) {
		return nil, ErrOverloaded
	}
	if !l.enqueue() {
		return nil, ErrOverloaded
	}
	defer l.dequeue()

	select {
	case <-l.slots:
		var once sync.Once
		return func() { once.Do(func() { l.slots <- struct{}{} }) }, nil
	case <-ctx.Done():
		return nil, ErrOverloaded
	}
}

func (l *Limiter) enqueue() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.waiting >= QueueDepth {
		return false
	}
	l.waiting++
	return true
}

func (l *Limiter) dequeue() {
	l.mu.Lock()
	l.waiting--
	l.mu.Unlock()
}

// AllowDiscovery admits one unauthenticated discovery request. It has its own
// bucket rather than sharing the verification budget: /meta performs no
// expensive work, and a cheap endpoint queued behind a semaphore sized for
// 64 MiB derivations would be throttled by a cost it does not incur.
func (l *Limiter) AllowDiscovery(ip string) bool {
	return l.allowIPIn(l.metaHits, ip, MetaPerIPPerMinute)
}

// AllowIssuerRefresh admits one OUTBOUND JWKS refresh triggered by an unknown
// `kid` (#62, machine-identities ADR § JWKS: "unknown-`kid` refresh is
// rate-limited, and that is load-bearing rather than hygiene").
//
// It rides this limiter rather than a bucket of its own inside the JWKS cache,
// because the ADR puts it under the SAME instance-wide pre-authentication
// budget as #16's human paths — and because this limiter already owns the
// bounded-tracking discipline the naive version forgets: the key is an
// operator-configured issuer rather than an attacker-chosen value, but the
// eviction ceiling costs nothing and means one more map cannot become the
// memory-exhaustion vector it exists to prevent.
//
// The allowance is per issuer per minute. Charging it per source IP would miss
// the shape of the attack: the amplification is aimed at the ISSUER, and one
// fabricated-`kid` stream from a thousand addresses is the same outbound flood.
func (l *Limiter) AllowIssuerRefresh(issuer string) bool {
	return l.allowIPIn(l.issuerRefreshes, issuer, IssuerRefreshPerMinute)
}

func (l *Limiter) allowIP(ip string) bool {
	return l.allowIPIn(l.ipHits, ip, l.perIP)
}

func (l *Limiter) allowIPIn(bucket map[string][]time.Time, ip string, allowance int) bool {
	if ip == "" {
		// An unattributable source still consumes the instance-wide budget;
		// it simply has no per-IP bucket to charge. Refusing outright would
		// break loopback callers behind an untrusted-proxy configuration,
		// which is a deployment mistake to surface elsewhere, not here.
		return true
	}
	now := l.now()
	cutoff := now.Add(-time.Minute)
	l.mu.Lock()
	defer l.mu.Unlock()
	hits := bucket[ip]
	kept := hits[:0]
	for _, t := range hits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= allowance {
		bucket[ip] = kept
		return false
	}
	if len(kept) == 0 && len(bucket) >= MaxTrackedSubjects {
		evictStale(bucket, cutoff)
	}
	bucket[ip] = append(kept, now)
	return true
}

// evictStale drops buckets whose windows have entirely elapsed. They carry no
// information — a bucket with no hits inside the window is indistinguishable
// from one that never existed — so this is pure reclamation.
func evictStale(bucket map[string][]time.Time, cutoff time.Time) {
	for k, hits := range bucket {
		live := false
		for _, t := range hits {
			if t.After(cutoff) {
				live = true
				break
			}
		}
		if !live {
			delete(bucket, k)
		}
	}
	// If every tracked subject is live, forget the oldest. Losing a live
	// bucket forgives whoever it belonged to, which is the safe direction:
	// the instance-wide semaphore still bounds the work, and the alternative
	// is unbounded memory.
	if len(bucket) >= MaxTrackedSubjects {
		var oldestKey string
		var oldest time.Time
		for k, hits := range bucket {
			if len(hits) == 0 {
				delete(bucket, k)
				continue
			}
			if oldestKey == "" || hits[0].Before(oldest) {
				oldestKey, oldest = k, hits[0]
			}
		}
		if oldestKey != "" {
			delete(bucket, oldestKey)
		}
	}
}

// AccountDelay reports how long this attempt must wait before verification
// begins. The bucket is keyed on a hash of the PRESENTED identifier, so an
// unknown account gets a bucket exactly like a real one and the presence or
// absence of a per-account bucket is not observable.
func (l *Limiter) AccountDelay(presented string) time.Duration {
	key := bucketKey(presented)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.accountDelay(key)
}

// accountDelay reports the current delay for key. l.mu must be held.
func (l *Limiter) accountDelay(key subjectKey) time.Duration {
	state, ok := l.accounts[key]
	if !ok || state.until.IsZero() {
		return 0
	}
	if d := state.until.Sub(l.now()); d > 0 {
		return d
	}
	return 0
}

// RecordFailure advances the per-account curve: after 5 consecutive failures,
// delay = min(2^(failures-5), 60) s, shared across concurrent attempts on the
// account because it is stored as an absolute instant rather than a per-call
// sleep.
//
// It reports whether this failure crossed the threshold, so the caller can
// emit the audit event the ADR requires on threshold crossing.
func (l *Limiter) RecordFailure(presented string) (crossedThreshold bool) {
	key := bucketKey(presented)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.recordFailure(key)
}

// recordFailure advances key's backoff state. l.mu must be held.
func (l *Limiter) recordFailure(key subjectKey) (crossedThreshold bool) {
	state, tracked := l.accounts[key]
	if !tracked && len(l.accounts) >= MaxTrackedSubjects {
		l.evictAccounts()
	}
	state.failures++
	n := state.failures
	if n <= FailuresBeforeBackoff {
		l.accounts[key] = state
		return false
	}
	delay := time.Duration(1<<min(n-FailuresBeforeBackoff-1, 16)) * time.Second
	delay = min(delay, MaxAccountBackoff)
	state.until = l.now().Add(delay)
	l.accounts[key] = state
	return n == FailuresBeforeBackoff+1
}

// RecordSuccess resets the curve.
func (l *Limiter) RecordSuccess(presented string) {
	key := bucketKey(presented)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recordSuccess(key)
}

// recordSuccess resets key's backoff state. l.mu must be held.
func (l *Limiter) recordSuccess(key subjectKey) {
	delete(l.accounts, key)
}

// evictAccounts drops account buckets whose backoff has elapsed. An account
// with no live delay carries only a failure count, and forgetting it forgives
// an attacker rather than punishing a user — the safe direction when the
// alternative is a map keyed by every username anyone has ever guessed.
//
// If every tracked account still has a live backoff, the stale sweep frees
// nothing and the map would grow past its bound. So, exactly like the IP
// eviction, fall back to forgetting the account whose delay expires soonest:
// it is the one closest to being forgiven anyway, and the instance-wide
// semaphore still bounds the actual work an admitted attempt can do.
//
// Both passes read the same map in the same order — an entry's count and its
// deadline are one value, so there is no way for the sweep to drop one and
// keep the other, and no length comparison between two maps to get backwards.
func (l *Limiter) evictAccounts() {
	now := l.now()
	for key, state := range l.accounts {
		// A zero `until` is an account still under the threshold: no live
		// delay, nothing to lose by forgetting it.
		if !state.until.After(now) {
			delete(l.accounts, key)
		}
	}
	if len(l.accounts) < MaxTrackedSubjects {
		return
	}
	var soonestKey subjectKey
	var soonest time.Time
	found := false
	for key, state := range l.accounts {
		if !found || state.until.Before(soonest) {
			soonestKey, soonest, found = key, state.until, true
		}
	}
	if found {
		delete(l.accounts, soonestKey)
	}
}

// bucketKey hashes the presented identifier. Storing it raw would put every
// attempted username in memory in plaintext for the process lifetime, which
// is a log of who is being attacked that nothing needs.
func bucketKey(presented string) subjectKey {
	return subjectKey(sha256.Sum256([]byte(presented)))
}
