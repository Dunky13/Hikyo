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
	// PerIPPerMinute is the sliding per-source-IP attempt allowance.
	PerIPPerMinute = 10
	// FailuresBeforeBackoff is how many consecutive per-account failures pass
	// before the delay starts.
	FailuresBeforeBackoff = 5
	// MaxAccountBackoff caps the exponential delay. There is no hard lockout:
	// locking out a known username is a free denial-of-service lever, and the
	// permission model already refuses unadministrable states.
	MaxAccountBackoff = 60 * time.Second
	// RetryAfter is what an overloaded instance advertises.
	RetryAfter = 5 * time.Second
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
	// Now is injectable so the backoff and rate-limit curves are testable
	// without sleeping. Nil means time.Now.
	Now func() time.Time
}

// Limiter is one instance's admission state.
type Limiter struct {
	concurrency int
	slots       chan struct{}
	now         func() time.Time

	mu       sync.Mutex
	waiting  int
	ipHits   map[string][]time.Time
	failures map[[32]byte]int
	blocked  map[[32]byte]time.Time
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
	l := &Limiter{
		concurrency: concurrency,
		slots:       make(chan struct{}, concurrency),
		now:         now,
		ipHits:      map[string][]time.Time{},
		failures:    map[[32]byte]int{},
		blocked:     map[[32]byte]time.Time{},
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

func (l *Limiter) allowIP(ip string) bool {
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
	hits := l.ipHits[ip]
	kept := hits[:0]
	for _, t := range hits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= PerIPPerMinute {
		l.ipHits[ip] = kept
		return false
	}
	l.ipHits[ip] = append(kept, now)
	return true
}

// AccountDelay reports how long this attempt must wait before verification
// begins. The bucket is keyed on a hash of the PRESENTED identifier, so an
// unknown account gets a bucket exactly like a real one and the presence or
// absence of a per-account bucket is not observable.
func (l *Limiter) AccountDelay(presented string) time.Duration {
	key := bucketKey(presented)
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.blocked[key]
	if !ok {
		return 0
	}
	if d := until.Sub(l.now()); d > 0 {
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
	l.failures[key]++
	n := l.failures[key]
	if n <= FailuresBeforeBackoff {
		return false
	}
	delay := time.Duration(1<<min(n-FailuresBeforeBackoff-1, 16)) * time.Second
	delay = min(delay, MaxAccountBackoff)
	l.blocked[key] = l.now().Add(delay)
	return n == FailuresBeforeBackoff+1
}

// RecordSuccess resets the curve.
func (l *Limiter) RecordSuccess(presented string) {
	key := bucketKey(presented)
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
	delete(l.blocked, key)
}

// bucketKey hashes the presented identifier. Storing it raw would put every
// attempted username in memory in plaintext for the process lifetime, which
// is a log of who is being attacked that nothing needs.
func bucketKey(presented string) [32]byte {
	return sha256.Sum256([]byte(presented))
}
