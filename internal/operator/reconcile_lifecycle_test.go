package operator

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	hikyov1 "github.com/Hikyo-Org/hikyo/internal/operator/api/v1alpha1"
)

// TestReadyBlockedByUnreconciledAndClearedOnRecovery covers the synced →
// forbidden → recovered arc (§ 0.3): a previously Synced CR must report
// Ready=False while an RBAC authority loss (Unreconciled=True/NamespaceNotBound)
// is active, and an authorized recovery must clear that condition rather than let
// it linger — otherwise authority failure looks healthy and recovery looks stuck.
func TestReadyBlockedByUnreconciledAndClearedOnRecovery(t *testing.T) {
	forbidActive := false
	interceptors := interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if s, ok := obj.(*corev1.Secret); ok && key.Name == testTarget && forbidActive {
				_ = s
				return apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, key.Name, context.DeadlineExceeded)
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}
	cr := makeCR("app")
	h := newHarness(t, interceptors,
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true),
		makeOptedInDeployment("web", testTarget), cr)

	// Reconcile 1: clean delivery → Synced/Ready True.
	h.stub.set(200, deliveryJSON(false, "v1:cur1", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile1: %v", err)
	}
	got := h.getCR("app")
	requireCond(t, got, hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonDelivered)
	requireCond(t, got, hikyov1.ConditionReady, metav1.ConditionTrue, hikyov1.ReasonReconciled)

	// Reconcile 2: RBAC authority is lost on the managed-Secret read. Unreconciled
	// goes True, and Ready must NOT stay stale-True from the prior sync.
	forbidActive = true
	if _, err := h.reconcile("app"); err == nil {
		t.Fatal("a Forbidden access should surface an error")
	}
	got = h.getCR("app")
	requireCond(t, got, hikyov1.ConditionUnreconciled, metav1.ConditionTrue, hikyov1.ReasonNamespaceNotBound)
	requireCond(t, got, hikyov1.ConditionReady, metav1.ConditionFalse, hikyov1.ReasonBlocked)
	if got.Status.Lifecycle != hikyov1.LifecycleUnreconciled {
		t.Fatalf("lifecycle = %q, want Unreconciled", got.Status.Lifecycle)
	}

	// Reconcile 3: authority is restored. The stale Unreconciled/NamespaceNotBound
	// must clear and Ready must return True — recovery must not leave a phantom
	// authority loss behind.
	forbidActive = false
	h.stub.set(200, deliveryJSON(false, "v1:cur2", "v1:t2", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile3: %v", err)
	}
	got = h.getCR("app")
	if _, _, ok := condStatus(got, hikyov1.ConditionUnreconciled); ok {
		t.Fatalf("recovery left a stale Unreconciled condition: %v", got.Status.Conditions)
	}
	requireCond(t, got, hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonDelivered)
	requireCond(t, got, hikyov1.ConditionReady, metav1.ConditionTrue, hikyov1.ReasonReconciled)
}

func TestScopeChangeForcesCursorless(t *testing.T) {
	cr := makeCR("app")
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	h.stub.set(200, deliveryJSON(false, "v1:cur1", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile1: %v", err)
	}
	// Move the scope (environment) — the binding tracks org/project/environment, so
	// the cursor must not survive the move.
	fresh := h.getCR("app")
	fresh.Spec.Scope.Environment = "staging"
	if err := h.cl.Update(context.Background(), fresh); err != nil {
		t.Fatalf("edit scope: %v", err)
	}
	h.stub.set(200, deliveryJSON(false, "v1:cur2", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile2: %v", err)
	}
	if h.stub.lastCursor != "" {
		t.Fatalf("a moved scope still presented a cursor: %q", h.stub.lastCursor)
	}
}

func TestInstanceUIDChangeForcesCursorless(t *testing.T) {
	cr := makeCR("app")
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	h.stub.set(200, deliveryJSON(false, "v1:cur1", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile1: %v", err)
	}
	// Rebuild the HikyoInstance under a new UID (deleted and re-declared). The
	// binding tracks inst.UID, so the cursor must not survive.
	var inst hikyov1.HikyoInstance
	if err := h.cl.Get(context.Background(), types.NamespacedName{Name: testInstance}, &inst); err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if err := h.cl.Delete(context.Background(), &inst); err != nil {
		t.Fatalf("delete instance: %v", err)
	}
	rebuilt := makeInstance("")
	rebuilt.UID = "inst-uid-2"
	if err := h.cl.Create(context.Background(), rebuilt); err != nil {
		t.Fatalf("recreate instance: %v", err)
	}
	h.stub.set(200, deliveryJSON(false, "v1:cur2", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile2: %v", err)
	}
	if h.stub.lastCursor != "" {
		t.Fatalf("a new instance UID still presented a cursor: %q", h.stub.lastCursor)
	}
}

func TestCredentialUIDChangeForcesCursorless(t *testing.T) {
	cr := makeCR("app")
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	h.stub.set(200, deliveryJSON(false, "v1:cur1", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile1: %v", err)
	}
	// Delete and recreate the bootstrap Secret under a new UID (same name and
	// designation) — a rebuild of the credential object, distinct from a data
	// rotation. The binding tracks the Secret UID, so the cursor must not survive.
	var boot corev1.Secret
	if err := h.cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: "boot"}, &boot); err != nil {
		t.Fatalf("get boot: %v", err)
	}
	if err := h.cl.Delete(context.Background(), &boot); err != nil {
		t.Fatalf("delete boot: %v", err)
	}
	rebuilt := makeBootstrapSecret("boot", testInstance, "tok", true)
	rebuilt.UID = "boot-uid-rebuilt"
	if err := h.cl.Create(context.Background(), rebuilt); err != nil {
		t.Fatalf("recreate boot: %v", err)
	}
	h.stub.set(200, deliveryJSON(false, "v1:cur2", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile2: %v", err)
	}
	if h.stub.lastCursor != "" {
		t.Fatalf("a rebuilt credential (new UID) still presented a cursor: %q", h.stub.lastCursor)
	}
}

func TestOwnedSecretWriteConflictClearsCursor(t *testing.T) {
	// § 0.5/decision 7: an owned-Secret Update that conflicts on a stale
	// resourceVersion is a failure before the cursor write — the cursor must not
	// advance and must be cleared, so the next reconcile is a cursor-less full fetch.
	conflictActive := false
	interceptors := interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if s, ok := obj.(*corev1.Secret); ok && s.Namespace == testNS && s.Name == testTarget && conflictActive {
				return apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, s.Name, context.DeadlineExceeded)
			}
			return c.Update(ctx, obj, opts...)
		},
	}
	cr := makeCR("app")
	h := newHarness(t, interceptors,
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)

	// Reconcile 1: create + establish a cursor.
	h.stub.set(200, deliveryJSON(false, "v1:cur1", "v1:t", []deliveredKey{secretVal("API_KEY", "v1")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile1: %v", err)
	}
	if got := h.getCR("app"); got.Status.Cursor != "v1:cur1" || got.Status.CursorBinding == "" {
		t.Fatalf("cursor not established: %+v", got.Status)
	}

	// Reconcile 2: new content forces an Update on the owned Secret, which conflicts.
	conflictActive = true
	h.stub.set(200, deliveryJSON(false, "v1:cur2", "v1:t2", []deliveredKey{secretVal("API_KEY", "v2")}, nil))
	if _, err := h.reconcile("app"); err == nil {
		t.Fatal("a conflicting Secret update should surface an error")
	}
	got := h.getCR("app")
	if got.Status.Cursor != "" || got.Status.CursorBinding != "" {
		t.Fatalf("write conflict did not clear the cursor: cursor=%q binding=%q", got.Status.Cursor, got.Status.CursorBinding)
	}
	requireCond(t, got, hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonFetchFailed)

	// Reconcile 3: the conflict clears → the next fetch must be cursor-less.
	conflictActive = false
	h.stub.set(200, deliveryJSON(false, "v1:cur3", "v1:t3", []deliveredKey{secretVal("API_KEY", "v3")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile3: %v", err)
	}
	if h.stub.lastCursor != "" {
		t.Fatalf("post-conflict reconcile presented cursor %q, want a cursor-less full fetch", h.stub.lastCursor)
	}
}

func TestReadAfterWriteVerificationFailure(t *testing.T) {
	// § 0.5 step 1's verify: the post-write re-read must confirm byte-exact data. A
	// racing actor that rewrites the managed Secret between write and verify yields
	// a data mismatch → the reconcile errors and never advances the cursor.
	wrote := false
	interceptors := interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if err := c.Create(ctx, obj, opts...); err != nil {
				return err
			}
			if s, ok := obj.(*corev1.Secret); ok && s.Namespace == testNS && s.Name == testTarget {
				wrote = true
			}
			return nil
		},
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := c.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			// Corrupt ONLY the post-write verify read of the managed Secret, leaving
			// its ownerRef/UID intact so the mismatch is purely in the data.
			if s, ok := obj.(*corev1.Secret); ok && wrote && key.Namespace == testNS && key.Name == testTarget {
				s.Data = map[string][]byte{"API_KEY": []byte("corrupted-by-a-racing-actor")}
			}
			return nil
		},
	}
	cr := makeCR("app")
	h := newHarness(t, interceptors,
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	h.stub.set(200, deliveryJSON(false, "v1:cur1", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err == nil {
		t.Fatal("a read-after-write data mismatch should surface an error")
	}
	got := h.getCR("app")
	if got.Status.Cursor != "" || got.Status.CursorBinding != "" {
		t.Fatalf("verification failure advanced the cursor: %q/%q", got.Status.Cursor, got.Status.CursorBinding)
	}
	requireCond(t, got, hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonFetchFailed)
}

// TestRefusalEventsEmitted asserts that every refusal/False condition in § 0.3
// emits a Kubernetes Event on the CR (§ 0.3: "Every False/refusal condition also
// emits a Kubernetes Event on the CR"). Table-driven over the reason set.
func TestRefusalEventsEmitted(t *testing.T) {
	full := func(keys ...deliveredKey) string {
		return deliveryJSON(false, "v1:c", "v1:t", keys, nil)
	}
	tests := []struct {
		reason string
		crName string
		setup  func(t *testing.T) *harness
	}{
		{
			reason: hikyov1.ReasonSecretNotDesignated, crName: "app",
			setup: func(t *testing.T) *harness {
				return newHarness(t, interceptor.Funcs{},
					makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", false), makeCR("app"))
			},
		},
		{
			reason: hikyov1.ReasonServiceAccountNotDesignated, crName: "app",
			setup: func(t *testing.T) *harness {
				return newHarness(t, interceptor.Funcs{},
					makeInstance("hikyo"), makeServiceAccount("worker", testInstance, false), makeCR("app", withSA("worker")))
			},
		},
		{
			reason: hikyov1.ReasonInstanceMismatch, crName: "app",
			setup: func(t *testing.T) *harness {
				return newHarness(t, interceptor.Funcs{},
					makeInstance(""), makeBootstrapSecret("boot", "other-instance", "tok", true), makeCR("app"))
			},
		},
		{
			reason: hikyov1.ReasonAudienceMissing, crName: "app",
			setup: func(t *testing.T) *harness {
				return newHarness(t, interceptor.Funcs{},
					makeInstance(""), makeServiceAccount("worker", testInstance, true), makeCR("app", withSA("worker")))
			},
		},
		{
			reason: hikyov1.ReasonTargetClaimed, crName: "loser",
			setup: func(t *testing.T) *harness {
				early := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
				late := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
				return newHarness(t, interceptor.Funcs{},
					makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true),
					makeCR("winner", withCreation(early, "uid-winner")), makeCR("loser", withCreation(late, "uid-loser")))
			},
		},
		{
			reason: hikyov1.ReasonManagedSecretNotOwned, crName: "app",
			setup: func(t *testing.T) *harness {
				unowned := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testTarget, UID: "foreign"},
					Data:       map[string][]byte{"existing": []byte("keep")},
				}
				return newHarness(t, interceptor.Funcs{},
					makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), unowned, makeCR("app"))
			},
		},
		{
			reason: hikyov1.ReasonUndeliveredSecrets, crName: "app",
			setup: func(t *testing.T) *harness {
				h := newHarness(t, interceptor.Funcs{},
					makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true),
					makeCR("app", withMapping([2]string{"API_KEY", "API_KEY"}, [2]string{"DB", "DB"})))
				h.stub.set(200, full(secretVal("API_KEY", "x"), secretPresenceOnly("DB")))
				return h
			},
		},
		{
			reason: hikyov1.ReasonKeysMissing, crName: "app",
			setup: func(t *testing.T) *harness {
				h := newHarness(t, interceptor.Funcs{},
					makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true),
					makeCR("app", withMapping([2]string{"API_KEY", "API_KEY"}, [2]string{"GONE", "GONE"})))
				h.stub.set(200, full(secretVal("API_KEY", "x")))
				return h
			},
		},
		{
			reason: hikyov1.ReasonLoaderControlUnacknowledged, crName: "app",
			setup: func(t *testing.T) *harness {
				h := newHarness(t, interceptor.Funcs{},
					makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true),
					makeCR("app", withMapping([2]string{"PATH", "PATH"})))
				h.stub.set(200, full(configVal("PATH", "/usr/bin")))
				return h
			},
		},
		{
			reason: hikyov1.ReasonEnvFromSkip, crName: "app",
			setup: func(t *testing.T) *harness {
				h := newHarness(t, interceptor.Funcs{},
					makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true),
					makeCR("app", withMapping([2]string{"API_KEY", "bad-key"})))
				h.stub.set(200, full(configVal("API_KEY", "v")))
				return h
			},
		},
		{
			reason: hikyov1.ReasonFetchFailed, crName: "app",
			setup: func(t *testing.T) *harness {
				h := newHarness(t, interceptor.Funcs{},
					makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), makeCR("app"))
				h.stub.set(401, "")
				return h
			},
		},
		{
			reason: hikyov1.ReasonNotMaterialized, crName: "app",
			setup: func(t *testing.T) *harness {
				h := newHarness(t, interceptor.Funcs{},
					makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), makeCR("app"))
				h.stub.set(409, "")
				return h
			},
		},
		{
			reason: hikyov1.ReasonAuthorizationWithdrawn, crName: "app",
			setup: func(t *testing.T) *harness {
				cr := makeCR("app")
				owned := makeOwnedSecret(t, testScheme(t), cr, map[string][]byte{"API_KEY": []byte("was-here")})
				h := newHarness(t, interceptor.Funcs{},
					makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), owned, cr)
				h.stub.set(404, "")
				return h
			},
		},
		{
			reason: hikyov1.ReasonStalled, crName: "app",
			setup: func(t *testing.T) *harness {
				faultPatch := interceptor.Funcs{
					Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						if _, ok := obj.(*appsv1.Deployment); ok {
							return context.DeadlineExceeded
						}
						return c.Patch(ctx, obj, patch, opts...)
					},
				}
				h := newHarness(t, faultPatch,
					makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true),
					makeOptedInDeployment("web", testTarget), makeCR("app"))
				h.stub.set(200, full(secretVal("API_KEY", "v")))
				return h
			},
		},
		{
			reason: hikyov1.ReasonExpiresSoon, crName: "app",
			setup: func(t *testing.T) *harness {
				h := newHarness(t, interceptor.Funcs{},
					makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), makeCR("app"))
				soon := testClock.Add(3 * 24 * time.Hour)
				h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, &soon))
				return h
			},
		},
		{
			reason: hikyov1.ReasonExpired, crName: "app",
			setup: func(t *testing.T) *harness {
				h := newHarness(t, interceptor.Funcs{},
					makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), makeCR("app"))
				past := testClock.Add(-time.Hour)
				h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, &past))
				return h
			},
		},
		{
			reason: hikyov1.ReasonNamespaceNotBound, crName: "app",
			setup: func(t *testing.T) *harness {
				forbid := interceptor.Funcs{
					Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
						if s, ok := obj.(*corev1.Secret); ok && key.Name == testTarget {
							_ = s
							return apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, key.Name, context.DeadlineExceeded)
						}
						return c.Get(ctx, key, obj, opts...)
					},
				}
				return newHarness(t, forbid,
					makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), makeCR("app"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.reason, func(t *testing.T) {
			h := tc.setup(t)
			// The event, not the error, is under test: several of these refusals
			// return an error for backoff.
			_, _ = h.reconcile(tc.crName)
			if !hasEventReason(h.drainEvents(), tc.reason) {
				t.Fatalf("refusal %q emitted no Kubernetes Event", tc.reason)
			}
		})
	}
}
