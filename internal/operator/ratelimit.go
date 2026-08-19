package operator

import (
	"context"
	"math/rand/v2"
	"time"

	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	hikyov1 "github.com/Hikyo-Org/hikyo/internal/operator/api/v1alpha1"
)

// jitterLimiter wraps controller-runtime's per-item exponential failure limiter
// and adds up to ±20% jitter to each delay, so a fleet of CRs backing off
// against the same unreachable server spreads its retries instead of retrying in
// lockstep (§ 0.4: "jittered"). Forget/NumRequeues pass through unchanged so the
// exponential curve itself is the inner limiter's.
type jitterLimiter struct {
	inner workqueue.TypedRateLimiter[reconcile.Request]
}

func (j *jitterLimiter) When(item reconcile.Request) time.Duration {
	base := j.inner.When(item)
	// ±20% jitter. rand/v2's default source is fine — this is retry spreading,
	// not anything security-sensitive.
	factor := 0.8 + 0.4*rand.Float64()
	return time.Duration(float64(base) * factor)
}

func (j *jitterLimiter) Forget(item reconcile.Request)          { j.inner.Forget(item) }
func (j *jitterLimiter) NumRequeues(item reconcile.Request) int { return j.inner.NumRequeues(item) }

// instanceHandler enqueues every HikyoSecret referencing a changed
// HikyoInstance. The instance spec is immutable, but its creation (a CR created
// before its instance) and status still warrant a requeue, and the mapping is
// cheap — a namespace-agnostic list filtered by instanceRef.name.
func (r *HikyoSecretReconciler) instanceHandler() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		inst, ok := obj.(*hikyov1.HikyoInstance)
		if !ok {
			return nil
		}
		var list hikyov1.HikyoSecretList
		if err := r.Client.List(ctx, &list); err != nil {
			return nil
		}
		var reqs []reconcile.Request
		for i := range list.Items {
			cr := &list.Items[i]
			if cr.Spec.InstanceRef.Name == inst.Name {
				reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cr)})
			}
		}
		return reqs
	})
}
