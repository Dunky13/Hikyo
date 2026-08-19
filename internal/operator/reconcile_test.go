package operator

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	hikyov1 "github.com/Hikyo-Org/hikyo/internal/operator/api/v1alpha1"
)

func TestConvergeWritesSecretAndStampsOptedInOnly(t *testing.T) {
	cr := makeCR("app", withMapping([2]string{"API_KEY", "API_KEY"}, [2]string{"LOG_LEVEL", "LOG_LEVEL"}))
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""),
		makeBootstrapSecret("boot", testInstance, "tok", true),
		makeOptedInDeployment("web", testTarget),
		makeOptedInDeployment("db"), // not opted in
		cr,
	)
	h.stub.set(200, deliveryJSON(false, "v1:cur1", "v1:tok1",
		[]deliveredKey{secretVal("API_KEY", "s3cr3t"), configVal("LOG_LEVEL", "info")}, nil))

	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	sec, ok := h.getSecret(testNS, testTarget)
	if !ok {
		t.Fatal("managed Secret not created")
	}
	if string(sec.Data["API_KEY"]) != "s3cr3t" || string(sec.Data["LOG_LEVEL"]) != "info" {
		t.Fatalf("secret data = %v", sec.Data)
	}
	if !hasControllerRef(sec, cr) {
		t.Fatal("managed Secret missing this CR's controller ownerRef")
	}

	web := h.getDeployment("web")
	if stampAnnotation(web) == "" {
		t.Fatal("opted-in Deployment web not stamped")
	}
	db := h.getDeployment("db")
	if stampAnnotation(db) != "" {
		t.Fatal("non-opted-in Deployment db was stamped")
	}

	got := h.getCR("app")
	requireCond(t, got, hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonDelivered)
	requireCond(t, got, hikyov1.ConditionReady, metav1.ConditionTrue, hikyov1.ReasonReconciled)
	if got.Status.Cursor != "v1:cur1" {
		t.Fatalf("cursor = %q, want v1:cur1", got.Status.Cursor)
	}
	if got.Status.CursorBinding == "" || got.Status.Stamp == "" {
		t.Fatal("cursorBinding/stamp not persisted")
	}
	if got.Status.Lifecycle != hikyov1.LifecycleSynced {
		t.Fatalf("lifecycle = %q", got.Status.Lifecycle)
	}
	// First fetch is cursor-less.
	if h.stub.lastCursor != "" {
		t.Fatalf("first fetch presented a cursor: %q", h.stub.lastCursor)
	}
	// The declared projection reaches the server (§ 0.1 wire contract).
	if h.stub.lastProjection != "full" {
		t.Fatalf("projection sent = %q, want full", h.stub.lastProjection)
	}
}

func TestConfigOnlyProjectionSent(t *testing.T) {
	cr := makeCR("app", withProjection(hikyov1.ProjectionConfigOnly))
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{configVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if h.stub.lastProjection != "config-only" {
		t.Fatalf("projection sent = %q, want config-only", h.stub.lastProjection)
	}
}

func TestOrphanFinalizerAddedBeforeDelivery(t *testing.T) {
	// A fresh Orphan CR with no finalizer must gain it BEFORE any fetch, so a
	// crash between Secret-create and finalizer-add cannot orphan-capture.
	cr := makeCR("app", withPolicy(hikyov1.CreationPolicyOrphan))
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))

	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := h.getCR("app")
	found := false
	for _, f := range got.Finalizers {
		if f == hikyov1.OrphanFinalizer {
			found = true
		}
	}
	if !found {
		t.Fatal("orphan finalizer not added on first reconcile")
	}
	if h.stub.requests != 0 {
		t.Fatalf("fetched before the finalizer was installed (requests=%d)", h.stub.requests)
	}
}

func TestDesignationRefusals(t *testing.T) {
	t.Run("secret undesignated", func(t *testing.T) {
		cr := makeCR("app")
		h := newHarness(t, interceptor.Funcs{},
			makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", false), cr)
		if _, err := h.reconcile("app"); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		got := h.getCR("app")
		requireCond(t, got, hikyov1.ConditionDesignation, metav1.ConditionFalse, hikyov1.ReasonSecretNotDesignated)
		if _, ok := h.getSecret(testNS, testTarget); ok {
			t.Fatal("managed Secret written despite undesignated credential")
		}
		if !hasEventReason(h.drainEvents(), hikyov1.ReasonSecretNotDesignated) {
			t.Error("no SecretNotDesignated event")
		}
	})

	t.Run("service account undesignated", func(t *testing.T) {
		cr := makeCR("app", withSA("worker"))
		h := newHarness(t, interceptor.Funcs{},
			makeInstance("hikyo"), makeServiceAccount("worker", testInstance, false), cr)
		if _, err := h.reconcile("app"); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		requireCond(t, h.getCR("app"), hikyov1.ConditionDesignation, metav1.ConditionFalse, hikyov1.ReasonServiceAccountNotDesignated)
	})

	t.Run("wrong instance designation", func(t *testing.T) {
		cr := makeCR("app")
		h := newHarness(t, interceptor.Funcs{},
			makeInstance(""), makeBootstrapSecret("boot", "other-instance", "tok", true), cr)
		if _, err := h.reconcile("app"); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		requireCond(t, h.getCR("app"), hikyov1.ConditionDesignation, metav1.ConditionFalse, hikyov1.ReasonInstanceMismatch)
	})

	t.Run("SA path without audience", func(t *testing.T) {
		cr := makeCR("app", withSA("worker"))
		h := newHarness(t, interceptor.Funcs{},
			makeInstance(""), makeServiceAccount("worker", testInstance, true), cr)
		if _, err := h.reconcile("app"); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		requireCond(t, h.getCR("app"), hikyov1.ConditionDesignation, metav1.ConditionFalse, hikyov1.ReasonAudienceMissing)
	})
}

func TestFederationUsesMintedToken(t *testing.T) {
	cr := makeCR("app", withSA("worker"))
	h := newHarness(t, interceptor.Funcs{},
		makeInstance("hikyo-audience"), makeServiceAccount("worker", testInstance, true), cr)
	h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{configVal("API_KEY", "v")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if h.minter.last.audience != "hikyo-audience" || h.minter.last.sa != "worker" || h.minter.last.ns != testNS {
		t.Fatalf("minter called with %+v", h.minter.last)
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonDelivered)
}

func TestManagedSecretNotOwned(t *testing.T) {
	cr := makeCR("app")
	// A pre-existing Secret with no controller ownerRef — a takeover target.
	unowned := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testTarget, UID: "foreign"},
		Data:       map[string][]byte{"existing": []byte("keep-me")},
	}
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), unowned, cr)
	h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))

	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionConflict, metav1.ConditionTrue, hikyov1.ReasonManagedSecretNotOwned)
	sec, _ := h.getSecret(testNS, testTarget)
	if string(sec.Data["existing"]) != "keep-me" {
		t.Fatal("unowned Secret was mutated (adopted)")
	}
	if _, has := sec.Data["API_KEY"]; has {
		t.Fatal("delivery written into an unowned Secret")
	}
}

func TestTargetClaimedLoserRefused(t *testing.T) {
	early := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	winner := makeCR("winner", withCreation(early, "uid-winner"))
	loser := makeCR("loser", withCreation(late, "uid-loser"))
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), winner, loser)
	h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))

	if _, err := h.reconcile("loser"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	requireCond(t, h.getCR("loser"), hikyov1.ConditionConflict, metav1.ConditionTrue, hikyov1.ReasonTargetClaimed)
	if _, ok := h.getSecret(testNS, testTarget); ok {
		t.Fatal("loser wrote the managed Secret")
	}
}

func TestAllOrNothingRefusal(t *testing.T) {
	cr := makeCR("app", withMapping([2]string{"API_KEY", "API_KEY"}, [2]string{"DB_PASSWORD", "DB_PASSWORD"}))
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	// API_KEY delivered, DB_PASSWORD presence-only → no write at all.
	h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t",
		[]deliveredKey{secretVal("API_KEY", "s3cr3t"), secretPresenceOnly("DB_PASSWORD")}, nil))

	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionDelivery, metav1.ConditionFalse, hikyov1.ReasonUndeliveredSecrets)
	if _, ok := h.getSecret(testNS, testTarget); ok {
		t.Fatal("partial write despite all-or-nothing refusal")
	}
}

func TestKeysMissingConverges(t *testing.T) {
	cr := makeCR("app", withMapping([2]string{"API_KEY", "API_KEY"}, [2]string{"GONE", "GONE"}))
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	// Only API_KEY present; GONE absent from the manifest → drop it, converge.
	h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))

	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := h.getCR("app")
	requireCond(t, got, hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonDelivered)
	requireCond(t, got, hikyov1.ConditionDelivery, metav1.ConditionFalse, hikyov1.ReasonKeysMissing)
	sec, ok := h.getSecret(testNS, testTarget)
	if !ok || string(sec.Data["API_KEY"]) != "v" {
		t.Fatal("present key not converged")
	}
	if _, has := sec.Data["GONE"]; has {
		t.Fatal("missing key was written")
	}
	// KeysMissing is informational — Ready stays True.
	requireCond(t, got, hikyov1.ConditionReady, metav1.ConditionTrue, hikyov1.ReasonReconciled)
}

func TestLoaderControlRefusalThenAck(t *testing.T) {
	cr := makeCR("app", withMapping([2]string{"PATH", "PATH"}))
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{configVal("PATH", "/usr/bin")}, nil))

	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionDelivery, metav1.ConditionFalse, hikyov1.ReasonLoaderControlUnacknowledged)
	if _, ok := h.getSecret(testNS, testTarget); ok {
		t.Fatal("wrote despite loader-control refusal")
	}
	if h.stub.requests != 0 {
		t.Fatal("fetched despite a pre-fetch loader-control refusal")
	}

	// Acknowledge exactly PATH → converges, and the ack is sent to the server.
	fresh := h.getCR("app")
	fresh.Spec.AcknowledgedLoaderKeys = []string{"PATH"}
	if err := h.cl.Update(context.Background(), fresh); err != nil {
		t.Fatalf("update ack: %v", err)
	}
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile after ack: %v", err)
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonDelivered)
	if h.stub.lastAck != "PATH" {
		t.Fatalf("acknowledged_keys sent = %q, want PATH", h.stub.lastAck)
	}
}

func TestCursorPresentedOnlyWhenEligible(t *testing.T) {
	t.Run("tampered secret forces cursor-less", func(t *testing.T) {
		cr := makeCR("app")
		h := newHarness(t, interceptor.Funcs{},
			makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
		full := deliveryJSON(false, "v1:cur1", "v1:t", []deliveredKey{secretVal("API_KEY", "s3cr3t")}, nil)
		h.stub.set(200, full)
		if _, err := h.reconcile("app"); err != nil {
			t.Fatalf("reconcile1: %v", err)
		}

		// Reconcile 2: eligible → cursor presented; stub answers current.
		h.stub.set(200, deliveryJSON(true, "v1:cur1", "v1:t", nil, nil))
		if _, err := h.reconcile("app"); err != nil {
			t.Fatalf("reconcile2: %v", err)
		}
		if h.stub.lastCursor != "v1:cur1" {
			t.Fatalf("eligible reconcile presented cursor %q, want v1:cur1", h.stub.lastCursor)
		}
		requireCond(t, h.getCR("app"), hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonCurrent)

		// Tamper the managed Secret; reconcile 3 must go cursor-less.
		sec, _ := h.getSecret(testNS, testTarget)
		sec.Data["API_KEY"] = []byte("tampered")
		if err := h.cl.Update(context.Background(), sec); err != nil {
			t.Fatalf("tamper: %v", err)
		}
		h.stub.set(200, full)
		if _, err := h.reconcile("app"); err != nil {
			t.Fatalf("reconcile3: %v", err)
		}
		if h.stub.lastCursor != "" {
			t.Fatalf("tampered Secret still presented cursor %q", h.stub.lastCursor)
		}
	})

	t.Run("edited mapping forces cursor-less", func(t *testing.T) {
		cr := makeCR("app")
		h := newHarness(t, interceptor.Funcs{},
			makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
		h.stub.set(200, deliveryJSON(false, "v1:cur1", "v1:t", []deliveredKey{secretVal("API_KEY", "s3cr3t")}, nil))
		if _, err := h.reconcile("app"); err != nil {
			t.Fatalf("reconcile1: %v", err)
		}
		// Edit the mapping destination — delivery identity changes.
		fresh := h.getCR("app")
		fresh.Spec.Mapping = []hikyov1.Mapping{{Key: "API_KEY", SecretKey: "RENAMED"}}
		if err := h.cl.Update(context.Background(), fresh); err != nil {
			t.Fatalf("edit mapping: %v", err)
		}
		h.stub.set(200, deliveryJSON(false, "v1:cur2", "v1:t", []deliveredKey{secretVal("API_KEY", "s3cr3t")}, nil))
		if _, err := h.reconcile("app"); err != nil {
			t.Fatalf("reconcile2: %v", err)
		}
		if h.stub.lastCursor != "" {
			t.Fatalf("edited mapping still presented cursor %q", h.stub.lastCursor)
		}
	})
}

func TestWriteOrdering(t *testing.T) {
	var order []string
	rec := func(label string) { order = append(order, label) }
	interceptors := interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if s, ok := obj.(*corev1.Secret); ok && s.Namespace == testNS && s.Name == testTarget {
				rec("secret-write")
			}
			return c.Create(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if s, ok := obj.(*corev1.Secret); ok && s.Namespace == testNS && s.Name == testTarget {
				rec("secret-write")
			}
			return c.Update(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if _, ok := obj.(*appsv1.Deployment); ok {
				rec("workload-patch")
			}
			return c.Patch(ctx, obj, patch, opts...)
		},
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if _, ok := obj.(*hikyov1.HikyoSecret); ok {
				rec("status-update")
			}
			return c.Status().Update(ctx, obj, opts...)
		},
	}
	cr := makeCR("app")
	h := newHarness(t, interceptors,
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true),
		makeOptedInDeployment("web", testTarget), cr)
	h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))

	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	iSecret := indexOf(order, "secret-write")
	iPatch := indexOf(order, "workload-patch")
	iStatus := indexOf(order, "status-update")
	if iSecret < 0 || iPatch < 0 || iStatus < 0 {
		t.Fatalf("missing a write in %v", order)
	}
	if !(iSecret < iPatch && iPatch < iStatus) {
		t.Fatalf("write ordering wrong: %v", order)
	}
}

func TestFaultAfterSecretLeavesCursorEmpty(t *testing.T) {
	interceptors := interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if _, ok := obj.(*appsv1.Deployment); ok {
				return context.DeadlineExceeded // inject a workload-patch fault
			}
			return c.Patch(ctx, obj, patch, opts...)
		},
	}
	cr := makeCR("app")
	h := newHarness(t, interceptors,
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true),
		makeOptedInDeployment("web", testTarget), cr)
	h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))

	if _, err := h.reconcile("app"); err == nil {
		t.Fatal("expected the injected patch fault to surface as an error")
	}
	// Secret was written...
	sec, ok := h.getSecret(testNS, testTarget)
	if !ok || string(sec.Data["API_KEY"]) != "v" {
		t.Fatal("Secret not written before the fault")
	}
	// ...but the cursor was NOT advanced.
	if got := h.getCR("app"); got.Status.Cursor != "" {
		t.Fatalf("cursor advanced despite a post-Secret fault: %q", got.Status.Cursor)
	}
}

func Test401RetainsAndFetchFailed(t *testing.T) {
	cr := makeCR("app")
	owned := makeOwnedSecret(t, testScheme(t), cr, map[string][]byte{"API_KEY": []byte("stale-but-valid")})
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), owned, cr)
	h.stub.set(401, "")

	if _, err := h.reconcile("app"); err == nil {
		t.Fatal("401 should requeue with an error for backoff")
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonFetchFailed)
	sec, _ := h.getSecret(testNS, testTarget)
	if string(sec.Data["API_KEY"]) != "stale-but-valid" {
		t.Fatal("401 scrubbed/changed the retained Secret")
	}
	if got := h.getCR("app"); got.Status.Lifecycle != hikyov1.LifecycleRetained {
		t.Fatalf("lifecycle = %q, want Retained", got.Status.Lifecycle)
	}
}

func Test404Scrubs(t *testing.T) {
	cr := makeCR("app")
	owned := makeOwnedSecret(t, testScheme(t), cr, map[string][]byte{"API_KEY": []byte("was-here")})
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), owned, cr)
	h.stub.set(404, "")

	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionScrubbed, metav1.ConditionTrue, hikyov1.ReasonAuthorizationWithdrawn)
	sec, ok := h.getSecret(testNS, testTarget)
	if !ok {
		t.Fatal("scrub deleted the Secret instead of emptying it")
	}
	if len(sec.Data) != 0 {
		t.Fatalf("scrub left data: %v", sec.Data)
	}
	got := h.getCR("app")
	if got.Status.Cursor != "" {
		t.Fatal("scrub did not clear the cursor")
	}
	if got.Status.Lifecycle != hikyov1.LifecycleScrubbed {
		t.Fatalf("lifecycle = %q, want Scrubbed", got.Status.Lifecycle)
	}
}

func TestScrubPatchFailureRetriesWithBackoff(t *testing.T) {
	interceptors := interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if _, ok := obj.(*appsv1.Deployment); ok {
				return context.DeadlineExceeded
			}
			return c.Patch(ctx, obj, patch, opts...)
		},
	}
	cr := makeCR("app")
	owned := makeOwnedSecret(t, testScheme(t), cr, map[string][]byte{"API_KEY": []byte("was-here")})
	h := newHarness(t, interceptors,
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true),
		makeOptedInDeployment("web", testTarget), owned, cr)
	h.stub.set(404, "")

	// A scrub whose workload patch fails must surface an error (backoff), not a
	// quiet resync — the workload has not rolled into the scrubbed state.
	if _, err := h.reconcile("app"); err == nil {
		t.Fatal("scrub patch failure should return an error for backoff")
	}
	// The Secret is still converged to empty (values withdrawn regardless).
	sec, ok := h.getSecret(testNS, testTarget)
	if !ok || len(sec.Data) != 0 {
		t.Fatalf("scrub did not empty the Secret: %v", sec.Data)
	}
	got := h.getCR("app")
	requireCond(t, got, hikyov1.ConditionScrubbed, metav1.ConditionTrue, hikyov1.ReasonAuthorizationWithdrawn)
	requireCond(t, got, hikyov1.ConditionRollout, metav1.ConditionFalse, hikyov1.ReasonStalled)
}

func TestCurrentWritesNothing(t *testing.T) {
	cr := makeCR("app")
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	h.stub.set(200, deliveryJSON(true, "v1:cur", "v1:t", nil, nil))

	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonCurrent)
	if _, ok := h.getSecret(testNS, testTarget); ok {
		t.Fatal("current answer created a Secret")
	}
}

func TestCredentialExpiryCondition(t *testing.T) {
	cr := makeCR("app")
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	soon := testClock.Add(3 * 24 * time.Hour) // within the 7-day horizon
	h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, &soon))

	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := h.getCR("app")
	requireCond(t, got, hikyov1.ConditionCredentialExpiry, metav1.ConditionTrue, hikyov1.ReasonExpiresSoon)
	if got.Status.CredentialExpiresAt == nil {
		t.Fatal("status.credentialExpiresAt not set")
	}
}

func TestOrphanFinalizerStripsOwnerRef(t *testing.T) {
	cr := makeCR("app", withPolicy(hikyov1.CreationPolicyOrphan))
	cr.Finalizers = []string{hikyov1.OrphanFinalizer}
	now := metav1.NewTime(testClock)
	cr.DeletionTimestamp = &now
	owned := makeOwnedSecret(t, testScheme(t), cr, map[string][]byte{"API_KEY": []byte("keep")})
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), owned, cr)

	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// The CR is released (finalizer removed → GC'd by the fake client), and the
	// Secret survives unowned.
	sec, ok := h.getSecret(testNS, testTarget)
	if !ok {
		t.Fatal("orphaned Secret was deleted")
	}
	if controllerRefUID(sec.OwnerReferences) != "" {
		t.Fatalf("Secret still carries a controller ownerRef: %v", sec.OwnerReferences)
	}
	if string(sec.Data["API_KEY"]) != "keep" {
		t.Fatal("orphaned Secret data changed")
	}
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}
