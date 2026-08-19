package operator

import (
	"testing"
	"time"

	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// fixedLimiter is a stub inner limiter returning a constant base delay, so the
// jitter clamp can be exercised at both declared bounds.
type fixedLimiter struct{ d time.Duration }

func (f fixedLimiter) When(reconcile.Request) time.Duration { return f.d }
func (f fixedLimiter) Forget(reconcile.Request)             {}
func (f fixedLimiter) NumRequeues(reconcile.Request) int    { return 0 }

var _ workqueue.TypedRateLimiter[reconcile.Request] = fixedLimiter{}

func TestJitterClampsToBounds(t *testing.T) {
	req := reconcile.Request{}

	// At the 1s floor, ±20% jitter would dip to 800ms — the clamp keeps it ≥ 1s.
	low := &jitterLimiter{inner: fixedLimiter{d: backoffBase}}
	for i := 0; i < 500; i++ {
		if d := low.When(req); d < backoffBase {
			t.Fatalf("floor: When() = %v, below backoffBase %v", d, backoffBase)
		}
	}

	// At the 5m ceiling, ±20% jitter would rise to 6m — the clamp keeps it ≤ 5m.
	high := &jitterLimiter{inner: fixedLimiter{d: backoffMax}}
	for i := 0; i < 500; i++ {
		if d := high.When(req); d > backoffMax {
			t.Fatalf("ceiling: When() = %v, above backoffMax %v", d, backoffMax)
		}
	}

	// A mid-range base stays within [base·0.8, base·1.2] and inside the bounds.
	mid := &jitterLimiter{inner: fixedLimiter{d: time.Minute}}
	for i := 0; i < 500; i++ {
		d := mid.When(req)
		if d < backoffBase || d > backoffMax {
			t.Fatalf("mid: When() = %v escaped [%v,%v]", d, backoffBase, backoffMax)
		}
	}
}
