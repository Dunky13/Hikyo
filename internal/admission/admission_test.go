package admission

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedClock(t *time.Time) func() time.Time { return func() time.Time { return *t } }

func TestDerivedConcurrency(t *testing.T) {
	// The global-headroom model: concurrency = clamp(floor((budget-16)/m),1,8).
	// Raising the KDF memory lowers concurrency automatically instead of
	// silently doubling the memory bill.
	cases := []struct {
		budgetMiB int
		argonKiB  uint32
		want      int
	}{
		{DefaultBudgetMiB, 64 * 1024, 4}, // the locked floor: (272-16)/64 = 4
		{DefaultBudgetMiB, 128 * 1024, 2},
		{DefaultBudgetMiB, 256 * 1024, 1},
		{1024, 64 * 1024, 8}, // clamped at the ceiling
		{80, 64 * 1024, 1},   // exactly one verification fits
	}
	for _, tc := range cases {
		l, err := New(Config{BudgetMiB: tc.budgetMiB, ArgonMemoryKiB: tc.argonKiB})
		if err != nil {
			t.Fatalf("budget %d / argon %d KiB: %v", tc.budgetMiB, tc.argonKiB, err)
		}
		if got := l.Concurrency(); got != tc.want {
			t.Errorf("budget %d MiB, argon %d KiB: concurrency %d, want %d",
				tc.budgetMiB, tc.argonKiB, got, tc.want)
		}
	}
}

func TestBootRefusesABudgetOneVerificationCannotFit(t *testing.T) {
	_, err := New(Config{BudgetMiB: 79, ArgonMemoryKiB: 64 * 1024})
	if err == nil {
		t.Fatal("a budget too small for one verification was accepted — the server would discover it at runtime")
	}
	if !strings.Contains(err.Error(), "cannot hold one verification") {
		t.Fatalf("refusal does not name the problem: %v", err)
	}
	if _, err := New(Config{BudgetMiB: DefaultBudgetMiB}); err == nil {
		t.Fatal("a limiter was built without stating the KDF memory its budget is derived from")
	}
}

func TestSemaphoreBoundsConcurrentVerifications(t *testing.T) {
	l, err := New(Config{BudgetMiB: DefaultBudgetMiB, ArgonMemoryKiB: 64 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	var releases []func()
	for i := range l.Concurrency() {
		rel, err := l.Enter(context.Background(), "")
		if err != nil {
			t.Fatalf("slot %d refused while the budget still had room: %v", i, err)
		}
		releases = append(releases, rel)
	}
	// Every slot is held; the next caller must not proceed.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := l.Enter(ctx, ""); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("a verification started beyond the derived concurrency: %v", err)
	}
	releases[0]()
	rel, err := l.Enter(context.Background(), "")
	if err != nil {
		t.Fatalf("a released slot was not reusable: %v", err)
	}
	rel()
	for _, r := range releases[1:] {
		r()
	}
}

func TestQueueDepthIsBounded(t *testing.T) {
	l, err := New(Config{BudgetMiB: 80, ArgonMemoryKiB: 64 * 1024}) // concurrency 1
	if err != nil {
		t.Fatal(err)
	}
	held, err := l.Enter(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer held()

	// Fill the queue with blocked waiters, then prove the next caller is
	// refused rather than queued — the overload response performs no
	// unbounded work.
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for range QueueDepth {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = l.Enter(ctx, "") }()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		l.mu.Lock()
		full := l.waiting >= QueueDepth
		l.mu.Unlock()
		if full || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	short, cancelShort := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelShort()
	if _, err := l.Enter(short, ""); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("queue grew past its bound: %v", err)
	}
	cancel()
	wg.Wait()
}

func TestPerIPSlidingWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l, err := New(Config{BudgetMiB: DefaultBudgetMiB, ArgonMemoryKiB: 64 * 1024, Now: fixedClock(&now)})
	if err != nil {
		t.Fatal(err)
	}
	for i := range PerIPPerMinute {
		rel, err := l.Enter(context.Background(), "203.0.113.7")
		if err != nil {
			t.Fatalf("attempt %d refused inside the allowance: %v", i, err)
		}
		rel()
	}
	if _, err := l.Enter(context.Background(), "203.0.113.7"); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("per-IP allowance not enforced: %v", err)
	}
	// A different source is unaffected — the bucket is per IP, not global.
	rel, err := l.Enter(context.Background(), "198.51.100.4")
	if err != nil {
		t.Fatalf("an unrelated source was refused: %v", err)
	}
	rel()
	// The window slides.
	now = now.Add(61 * time.Second)
	rel, err = l.Enter(context.Background(), "203.0.113.7")
	if err != nil {
		t.Fatalf("the window did not slide: %v", err)
	}
	rel()
}

func TestPerAccountBackoffTransitions(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l, err := New(Config{BudgetMiB: DefaultBudgetMiB, ArgonMemoryKiB: 64 * 1024, Now: fixedClock(&now)})
	if err != nil {
		t.Fatal(err)
	}
	const who = "someone"
	transitions := []struct {
		name          string
		advance       time.Duration
		checkBefore   bool
		wantBefore    time.Duration
		failures      int
		success       bool
		wantCrossings int
		wantDelay     time.Duration
	}{
		{name: "below threshold", failures: FailuresBeforeBackoff},
		{name: "threshold crossing", failures: 1, wantCrossings: 1, wantDelay: time.Second},
		{name: "exponential delay", failures: 1, wantDelay: 2 * time.Second},
		{name: "maximum delay", failures: cappedFailures - (FailuresBeforeBackoff + 2), wantDelay: MaxAccountBackoff},
		{name: "expiry preserves failure count", advance: MaxAccountBackoff + time.Second, checkBefore: true, failures: 1, wantDelay: MaxAccountBackoff},
		{name: "success resets delay and count", success: true},
		{name: "first failure after success", failures: 1},
	}

	for _, transition := range transitions {
		t.Run(transition.name, func(t *testing.T) {
			now = now.Add(transition.advance)
			if transition.checkBefore {
				if got := l.AccountDelay(who); got != transition.wantBefore {
					t.Fatalf("delay before transition %v, want %v", got, transition.wantBefore)
				}
			}
			if transition.success {
				l.RecordSuccess(who)
			}
			crossings := 0
			for range transition.failures {
				if l.RecordFailure(who) {
					crossings++
				}
			}
			if crossings != transition.wantCrossings {
				t.Fatalf("threshold crossed %d times, want %d", crossings, transition.wantCrossings)
			}
			if got := l.AccountDelay(who); got != transition.wantDelay {
				t.Fatalf("delay %v, want %v", got, transition.wantDelay)
			}
		})
	}
}

func TestUnknownAccountGetsABucketExactlyLikeARealOne(t *testing.T) {
	// The bucket is keyed on the presented identifier, so its presence or
	// absence reveals nothing about which accounts exist.
	l, err := New(Config{BudgetMiB: DefaultBudgetMiB, ArgonMemoryKiB: 64 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	for range FailuresBeforeBackoff + 1 {
		l.RecordFailure("definitely-not-an-account")
	}
	if l.AccountDelay("definitely-not-an-account") == 0 {
		t.Fatal("an unknown identifier got no backoff bucket, which is observable")
	}
}

// cappedFailures drives an account far enough up the curve that its delay
// clamps at MaxAccountBackoff: 2^(12-5-1) = 64s, over the 60s cap.
const cappedFailures = 12

func TestEvictionForgivesTheAccountClosestToForgiveness(t *testing.T) {
	// At the bound with nothing stale, the sweep frees nothing and the
	// fallback must forget the account whose delay expires soonest — the one
	// closest to being forgiven anyway. Forgiving is the safe direction; the
	// instance-wide semaphore still bounds the work an admitted attempt does.
	now := time.Unix(1_800_000_000, 0)
	l, err := New(Config{BudgetMiB: DefaultBudgetMiB, ArgonMemoryKiB: 64 * 1024, Now: fixedClock(&now)})
	if err != nil {
		t.Fatal(err)
	}
	for i := range MaxTrackedSubjects - 1 {
		who := fmt.Sprintf("long-%d", i)
		for range cappedFailures {
			l.RecordFailure(who)
		}
	}
	const soonest = "soonest"
	for range FailuresBeforeBackoff + 1 {
		l.RecordFailure(soonest)
	}
	if got, want := l.AccountDelay(soonest), 1*time.Second; got != want {
		t.Fatalf("setup: soonest delay %v, want %v", got, want)
	}

	// The clock has not moved, so every tracked account is live and this one
	// new subject puts the map past its bound.
	l.RecordFailure("newcomer")

	if got := l.AccountDelay(soonest); got != 0 {
		t.Fatalf("eviction kept the soonest-expiring account: delay %v", got)
	}
	// Forgiveness is total: count and delay leave together, so the account
	// has to climb the whole curve again.
	for i := range FailuresBeforeBackoff {
		if l.RecordFailure(soonest) {
			t.Fatalf("forgiven account crossed the threshold at failure %d", i+1)
		}
	}
	if !l.RecordFailure(soonest) {
		t.Fatal("forgiven account did not cross the threshold on its 6th fresh failure")
	}
	// Exactly one account went, and it was the right one.
	if got, want := l.AccountDelay("long-0"), MaxAccountBackoff; got != want {
		t.Fatalf("a longer-backoff account was evicted instead: delay %v, want %v", got, want)
	}
}

func TestEvictionDropsStaleAccountsBeforeLiveOnes(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l, err := New(Config{BudgetMiB: DefaultBudgetMiB, ArgonMemoryKiB: 64 * 1024, Now: fixedClock(&now)})
	if err != nil {
		t.Fatal(err)
	}
	const half = MaxTrackedSubjects / 2
	for i := range half {
		who := fmt.Sprintf("short-%d", i)
		for range FailuresBeforeBackoff + 1 { // 1s of backoff
			l.RecordFailure(who)
		}
	}
	for i := range half {
		who := fmt.Sprintf("long-%d", i)
		for range cappedFailures { // 60s of backoff
			l.RecordFailure(who)
		}
	}
	now = now.Add(2 * time.Second) // the short half is now stale

	// A new subject hits the bound. Reclaiming the stale half is enough, so
	// no live backoff may be forgiven.
	l.RecordFailure("newcomer")

	want := MaxAccountBackoff - 2*time.Second
	for i := range half {
		who := fmt.Sprintf("long-%d", i)
		if got := l.AccountDelay(who); got != want {
			t.Fatalf("live account %s: delay %v, want %v — a live entry was evicted while stale ones remained", who, got, want)
		}
	}
}

func TestConcurrentAccountCallsHoldTheCurve(t *testing.T) {
	// One mutex guards the whole account map, so interleaved calls must not
	// tear it or lose failures. Run with -race.
	//
	// The clock is frozen and never advanced once the goroutines are running,
	// so the expected delay is exact rather than a wall-clock tolerance.
	now := time.Unix(1_800_000_000, 0)
	l, err := New(Config{BudgetMiB: DefaultBudgetMiB, ArgonMemoryKiB: 64 * 1024, Now: fixedClock(&now)})
	if err != nil {
		t.Fatal(err)
	}
	const workers = 16
	var wg sync.WaitGroup
	// Each worker owns a key and drives it just past the threshold, so the
	// end state is deterministic however the calls interleave.
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			who := fmt.Sprintf("worker-%d", w)
			for range FailuresBeforeBackoff + 1 {
				l.RecordFailure(who)
				_ = l.AccountDelay(who)
			}
		}()
	}
	// Meanwhile one contended key is failed, read and reset concurrently. Its
	// end state is racy by construction; what must hold is that nothing panics
	// and no reader observes a half-written entry.
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				l.RecordFailure("contended")
				_ = l.AccountDelay("contended")
				l.RecordSuccess("contended")
			}
		}()
	}
	wg.Wait()

	for w := range workers {
		who := fmt.Sprintf("worker-%d", w)
		// Exactly 6 failures landed on this key: one more or one fewer moves
		// the delay off the first rung of the curve.
		if got, want := l.AccountDelay(who), 1*time.Second; got != want {
			t.Fatalf("%s: delay %v, want %v — failures were lost or double-counted", who, got, want)
		}
	}
}

func TestLimiterStateIsBounded(t *testing.T) {
	// Both maps are keyed by attacker-chosen values — any source address, any
	// presented username — so an unbounded limiter is the memory-exhaustion
	// vector it exists to prevent.
	now := time.Unix(1_800_000_000, 0)
	l, err := New(Config{BudgetMiB: DefaultBudgetMiB, ArgonMemoryKiB: 64 * 1024, Now: fixedClock(&now)})
	if err != nil {
		t.Fatal(err)
	}
	for i := range MaxTrackedSubjects * 2 {
		rel, err := l.Enter(context.Background(), fmt.Sprintf("198.51.100.%d", i))
		if err != nil {
			t.Fatalf("attempt %d refused: %v", i, err)
		}
		rel()
		l.RecordFailure(fmt.Sprintf("subject-%d", i))
		// Walk the clock so earlier windows elapse and become reclaimable.
		now = now.Add(time.Second)
	}
	l.mu.Lock()
	ips, accounts := len(l.ipHits), len(l.accounts)
	l.mu.Unlock()
	if ips > MaxTrackedSubjects {
		t.Errorf("tracking %d source IPs, bound is %d", ips, MaxTrackedSubjects)
	}
	if accounts > MaxTrackedSubjects {
		t.Errorf("tracking %d accounts, bound is %d", accounts, MaxTrackedSubjects)
	}
}
