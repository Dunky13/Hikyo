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

func TestPerAccountBackoffCurve(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l, err := New(Config{BudgetMiB: DefaultBudgetMiB, ArgonMemoryKiB: 64 * 1024, Now: fixedClock(&now)})
	if err != nil {
		t.Fatal(err)
	}
	const who = "someone"
	for i := range FailuresBeforeBackoff {
		if crossed := l.RecordFailure(who); crossed {
			t.Fatalf("threshold reported crossed at failure %d", i+1)
		}
		if d := l.AccountDelay(who); d != 0 {
			t.Fatalf("delay %v before the threshold", d)
		}
	}
	// Failure 6 crosses: delay = 2^(6-5) ... the ops spec's min(2^(n-5), 60).
	if !l.RecordFailure(who) {
		t.Fatal("crossing the threshold was not reported — no audit event would be emitted")
	}
	if got, want := l.AccountDelay(who), 1*time.Second; got != want {
		t.Fatalf("first backoff %v, want %v", got, want)
	}
	for want := 2 * time.Second; want <= 32*time.Second; want *= 2 {
		if l.RecordFailure(who) {
			t.Fatal("threshold reported crossed more than once")
		}
		if got := l.AccountDelay(who); got != want {
			t.Fatalf("backoff %v, want %v", got, want)
		}
	}
	// The cap holds, and no hard lockout ever appears.
	for range 20 {
		l.RecordFailure(who)
	}
	if got := l.AccountDelay(who); got != MaxAccountBackoff {
		t.Fatalf("backoff %v, want the %v cap", got, MaxAccountBackoff)
	}

	// The delay is an absolute instant, so concurrent attempts on the account
	// queue behind the same one rather than each serving its own.
	now = now.Add(MaxAccountBackoff)
	if got := l.AccountDelay(who); got != 0 {
		t.Fatalf("delay %v after it should have elapsed", got)
	}

	l.RecordSuccess(who)
	if got := l.AccountDelay(who); got != 0 {
		t.Fatalf("success did not reset the curve: %v", got)
	}
	if crossed := l.RecordFailure(who); crossed {
		t.Fatal("the failure count did not reset")
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
	ips, accounts := len(l.ipHits), len(l.failures)
	l.mu.Unlock()
	if ips > MaxTrackedSubjects {
		t.Errorf("tracking %d source IPs, bound is %d", ips, MaxTrackedSubjects)
	}
	if accounts > MaxTrackedSubjects {
		t.Errorf("tracking %d accounts, bound is %d", accounts, MaxTrackedSubjects)
	}
}
