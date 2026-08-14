package service

import (
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/domain"
)

// The limiter's two bounds, tested where they are deterministic: the window,
// and the HARD map bound. A map that grows past its stated capacity is the
// memory-exhaustion vector the limiter exists to prevent, so at capacity with
// nothing evictable a new subject is refused rather than admitted.

func TestGateAttemptsWindow(t *testing.T) {
	g := &gateAttempts{hits: map[string][]time.Time{}}
	now := time.Now()
	for i := range GateAttemptsPerMinute {
		if !g.allow("usr_a", "key_a", now) {
			t.Fatalf("attempt %d refused inside the allowance", i)
		}
	}
	if g.allow("usr_a", "key_a", now) {
		t.Fatal("the allowance was exceeded without a refusal")
	}
	// A different key is a different bucket.
	if !g.allow("usr_a", "key_b", now) {
		t.Fatal("one exhausted key locked the principal out of another")
	}
	// The window slides.
	if !g.allow("usr_a", "key_a", now.Add(2*time.Minute)) {
		t.Fatal("the window never elapsed")
	}
}

func TestGateAttemptsMapIsHardBounded(t *testing.T) {
	g := &gateAttempts{hits: map[string][]time.Time{}}
	now := time.Now()
	for i := range maxTrackedGateSubjects {
		if !g.allow("usr_a", "key_"+itoa(i), now) {
			t.Fatalf("subject %d refused below capacity", i)
		}
	}
	if len(g.hits) != maxTrackedGateSubjects {
		t.Fatalf("map holds %d subjects, want %d", len(g.hits), maxTrackedGateSubjects)
	}
	// Full, and every entry is live: the new subject is refused, and the map
	// does not grow.
	if g.allow("usr_a", "key_overflow", now) {
		t.Fatal("a new subject was admitted to a full map with nothing evictable")
	}
	if len(g.hits) != maxTrackedGateSubjects {
		t.Fatalf("the map grew to %d past its %d bound", len(g.hits), maxTrackedGateSubjects)
	}
	// Once the windows elapse, capacity is reclaimed rather than lost forever.
	if !g.allow("usr_a", "key_overflow", now.Add(2*time.Minute)) {
		t.Fatal("elapsed buckets were never reclaimed")
	}
}

// The key is length-prefixed, so (principal "ab", key "c") and
// (principal "a", key "bc") are different buckets.
func TestGateSubjectKeysDoNotCollide(t *testing.T) {
	g := &gateAttempts{hits: map[string][]time.Time{}}
	now := time.Now()
	var principals = []domain.PrincipalID{"ab", "a"}
	keys := []string{"c", "bc"}
	for i := range principals {
		if !g.allow(principals[i], keys[i], now) {
			t.Fatal("first attempt refused")
		}
	}
	if len(g.hits) != 2 {
		t.Fatalf("two distinct subjects collided into %d bucket(s)", len(g.hits))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
