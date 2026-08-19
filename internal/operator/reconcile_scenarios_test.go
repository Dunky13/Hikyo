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

func Test409NotMaterialized(t *testing.T) {
	cr := makeCR("app")
	owned := makeOwnedSecret(t, testScheme(t), cr, map[string][]byte{"API_KEY": []byte("keep")})
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), owned, cr)
	h.stub.set(409, "")
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonNotMaterialized)
	if got := h.getCR("app"); got.Status.Lifecycle != hikyov1.LifecycleRetained {
		t.Fatalf("lifecycle = %q, want Retained", got.Status.Lifecycle)
	}
	if sec, _ := h.getSecret(testNS, testTarget); string(sec.Data["API_KEY"]) != "keep" {
		t.Fatal("409 changed the retained Secret")
	}
}

func TestEnvFromSkipWarnsButSyncs(t *testing.T) {
	// A secretKey that is not a valid env identifier is a documented Kubernetes
	// caveat: envFrom skips it. Delivery still succeeds (Synced True), with a
	// warning condition.
	cr := makeCR("app", withMapping([2]string{"API_KEY", "bad-key"}))
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{configVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := h.getCR("app")
	requireCond(t, got, hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonDelivered)
	requireCond(t, got, hikyov1.ConditionDelivery, metav1.ConditionTrue, hikyov1.ReasonEnvFromSkip)
	requireCond(t, got, hikyov1.ConditionReady, metav1.ConditionTrue, hikyov1.ReasonReconciled)
	if sec, _ := h.getSecret(testNS, testTarget); string(sec.Data["bad-key"]) != "v" {
		t.Fatal("delivered value not written under the invalid-identifier key")
	}
}

func TestCredentialExpiredCondition(t *testing.T) {
	cr := makeCR("app")
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	past := testClock.Add(-time.Hour)
	h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, &past))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionCredentialExpiry, metav1.ConditionTrue, hikyov1.ReasonExpired)
}

func TestNamespaceNotBoundOnForbidden(t *testing.T) {
	// A Forbidden on the managed-Secret read is the visible authority failure for
	// a CR in a namespace the operator's RBAC does not reach (§ 0.3).
	forbid := interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if s, ok := obj.(*corev1.Secret); ok && key.Name == testTarget {
				_ = s
				return apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, key.Name, context.DeadlineExceeded)
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}
	cr := makeCR("app")
	h := newHarness(t, forbid,
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	if _, err := h.reconcile("app"); err == nil {
		t.Fatal("a Forbidden access should surface an error")
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionUnreconciled, metav1.ConditionTrue, hikyov1.ReasonNamespaceNotBound)
	if !hasEventReason(h.drainEvents(), hikyov1.ReasonNamespaceNotBound) {
		t.Error("no NamespaceNotBound event")
	}
	if got := h.getCR("app"); got.Status.Lifecycle != hikyov1.LifecycleUnreconciled {
		t.Fatalf("lifecycle = %q, want Unreconciled", got.Status.Lifecycle)
	}
}

func TestFailedTokenRequestRetains(t *testing.T) {
	cr := makeCR("app", withSA("worker"))
	owned := makeOwnedSecret(t, testScheme(t), cr, map[string][]byte{"API_KEY": []byte("stale")})
	h := newHarness(t, interceptor.Funcs{},
		makeInstance("aud"), makeServiceAccount("worker", testInstance, true), owned, cr)
	h.minter.err = context.DeadlineExceeded
	if _, err := h.reconcile("app"); err == nil {
		t.Fatal("a failed TokenRequest should requeue with an error (retain)")
	}
	got := h.getCR("app")
	requireCond(t, got, hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonFetchFailed)
	if got.Status.Lifecycle != hikyov1.LifecycleRetained {
		t.Fatalf("lifecycle = %q, want Retained", got.Status.Lifecycle)
	}
	if sec, _ := h.getSecret(testNS, testTarget); string(sec.Data["API_KEY"]) != "stale" {
		t.Fatal("failed TokenRequest changed the retained Secret")
	}
	if h.stub.requests != 0 {
		t.Fatal("fetched despite a failed TokenRequest")
	}
}

func TestOwnerDeletionLeavesSecretToGC(t *testing.T) {
	// Owner policy: no finalizer, so deletion is handled by garbage collection via
	// the ownerRef — the operator does nothing on the delete path.
	cr := makeCR("app") // default Owner
	now := metav1.NewTime(testClock)
	cr.DeletionTimestamp = &now
	// A foreign finalizer keeps the object storable under deletion; the operator
	// must NOT own or strip anything (no orphan finalizer present).
	cr.Finalizers = []string{"example.com/keep"}
	owned := makeOwnedSecret(t, testScheme(t), cr, map[string][]byte{"API_KEY": []byte("v")})
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), owned, cr)
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("owner deletion reconcile should be a no-op, got %v", err)
	}
	// The operator did not strip the ownerRef (GC owns it).
	if sec, ok := h.getSecret(testNS, testTarget); !ok || controllerRefUID(sec.OwnerReferences) == "" {
		t.Fatal("owner-policy deletion should leave the ownerRef for GC")
	}
}

func TestDeletedManagedSecretForcesCursorlessFetch(t *testing.T) {
	cr := makeCR("app")
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	h.stub.set(200, deliveryJSON(false, "v1:cur1", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile1: %v", err)
	}
	// Delete the managed Secret out from under the CR.
	sec, _ := h.getSecret(testNS, testTarget)
	if err := h.cl.Delete(context.Background(), sec); err != nil {
		t.Fatalf("delete managed Secret: %v", err)
	}
	h.stub.set(200, deliveryJSON(false, "v1:cur2", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile2: %v", err)
	}
	// A deleted managed Secret is not "verifiably in effect" → cursor-less.
	if h.stub.lastCursor != "" {
		t.Fatalf("deleted managed Secret still presented a cursor: %q", h.stub.lastCursor)
	}
	if _, ok := h.getSecret(testNS, testTarget); !ok {
		t.Fatal("managed Secret not re-created on the full fetch")
	}
}

func TestCredentialRotationForcesCursorless(t *testing.T) {
	cr := makeCR("app")
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	h.stub.set(200, deliveryJSON(false, "v1:cur1", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile1: %v", err)
	}
	// Rotate the bootstrap Secret (a data edit bumps its resourceVersion).
	var boot corev1.Secret
	if err := h.cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: "boot"}, &boot); err != nil {
		t.Fatalf("get boot: %v", err)
	}
	boot.Data[hikyov1.BootstrapTokenKey] = []byte("tok-rotated")
	if err := h.cl.Update(context.Background(), &boot); err != nil {
		t.Fatalf("rotate boot: %v", err)
	}
	h.stub.set(200, deliveryJSON(false, "v1:cur2", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile2: %v", err)
	}
	if h.stub.lastCursor != "" {
		t.Fatalf("a rotated credential still presented a cursor: %q", h.stub.lastCursor)
	}
}

func TestProjectionChangeForcesCursorless(t *testing.T) {
	cr := makeCR("app")
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	h.stub.set(200, deliveryJSON(false, "v1:cur1", "v1:t", []deliveredKey{configVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile1: %v", err)
	}
	fresh := h.getCR("app")
	fresh.Spec.Projection = hikyov1.ProjectionConfigOnly
	if err := h.cl.Update(context.Background(), fresh); err != nil {
		t.Fatalf("edit projection: %v", err)
	}
	h.stub.set(200, deliveryJSON(false, "v1:cur2", "v1:t", []deliveredKey{configVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile2: %v", err)
	}
	if h.stub.lastCursor != "" {
		t.Fatalf("a changed projection still presented a cursor: %q", h.stub.lastCursor)
	}
	if h.stub.lastProjection != "config-only" {
		t.Fatalf("new projection not sent: %q", h.stub.lastProjection)
	}
}

func TestUnchangedContentFullFetchDoesNotPatch(t *testing.T) {
	// The rotate-token-key consequence (ADR § Write ordering): a cursor
	// invalidation forces a full fetch, but unchanged content yields the same
	// stamp → NO workload patch, no restart wave.
	patches := 0
	countPatch := interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if _, ok := obj.(*appsv1.Deployment); ok {
				patches++
			}
			return c.Patch(ctx, obj, patch, opts...)
		},
	}
	cr := makeCR("app")
	h := newHarness(t, countPatch,
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true),
		makeOptedInDeployment("web", testTarget), cr)
	h.stub.set(200, deliveryJSON(false, "v1:cur1", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile1: %v", err)
	}
	if patches != 1 {
		t.Fatalf("first delivery patched %d times, want 1", patches)
	}
	// Simulate server-side cursor invalidation (rotate-token-key): the next fetch
	// is cursor-less and returns the SAME content.
	fresh := h.getCR("app")
	fresh.Status.Cursor = ""
	fresh.Status.CursorBinding = ""
	if err := h.cl.Status().Update(context.Background(), fresh); err != nil {
		t.Fatalf("clear cursor: %v", err)
	}
	patches = 0
	h.stub.set(200, deliveryJSON(false, "v1:cur2", "v1:t2", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile2: %v", err)
	}
	if h.stub.lastCursor != "" {
		t.Fatalf("expected a cursor-less full fetch, presented %q", h.stub.lastCursor)
	}
	if patches != 0 {
		t.Fatalf("unchanged content still patched the workload %d time(s)", patches)
	}
}

func TestInvalidCABundleRetains(t *testing.T) {
	// A malformed base64 caBundle is an error before contacting Hikyo — retain,
	// never a silent fall-back to system roots.
	inst := makeInstance("")
	inst.Spec.CABundle = "!!!not-base64!!!"
	cr := makeCR("app")
	h := newHarness(t, interceptor.Funcs{}, inst, makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	if _, err := h.reconcile("app"); err == nil {
		t.Fatal("invalid caBundle should surface an error (retain)")
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonFetchFailed)
	if h.stub.requests != 0 {
		t.Fatal("fetched despite an undecodable caBundle")
	}
}

func TestInvalidResyncIntervalRefused(t *testing.T) {
	// "0s" passes the CRD duration pattern but is not a usable cadence — refused
	// loudly, never silently substituted with 5m.
	cr := makeCR("app")
	cr.Spec.ResyncInterval = "0s"
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	if _, err := h.reconcile("app"); err == nil {
		t.Fatal("a non-positive resyncInterval must fail loud")
	}
	if h.stub.requests != 0 {
		t.Fatal("fetched despite an invalid resyncInterval")
	}
}

func TestStalledObservedOnCurrentPath(t *testing.T) {
	cr := makeCR("app")
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true),
		makeOptedInDeployment("web", testTarget), cr)
	h.stub.set(200, deliveryJSON(false, "v1:cur1", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile1: %v", err)
	}
	// Mark the opted-in workload as not progressed (controller-reported).
	web := h.getDeployment("web")
	web.Generation = 2
	web.Status.ObservedGeneration = 1
	web.Status.UnavailableReplicas = 1
	if err := h.cl.Update(context.Background(), web); err != nil {
		t.Fatalf("update web status: %v", err)
	}
	// Reconcile 2: eligible cursor, server answers current; rollout is evaluated
	// read-only and the stall surfaces.
	h.stub.set(200, deliveryJSON(true, "v1:cur1", "v1:t", nil, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile2: %v", err)
	}
	got := h.getCR("app")
	requireCond(t, got, hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonCurrent)
	requireCond(t, got, hikyov1.ConditionRollout, metav1.ConditionFalse, hikyov1.ReasonStalled)
}
