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
	writes := &secretWrites{}
	h := newHarness(t, writes.interceptors(),
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), unowned, cr)
	h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))

	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionConflict, metav1.ConditionTrue, hikyov1.ReasonManagedSecretNotOwned)
	// Authority refusal is PRE-write and PRE-fetch: no Secret op, no fetch.
	if writes.n != 0 {
		t.Fatalf("takeover refusal still wrote the Secret %d time(s)", writes.n)
	}
	if h.stub.requests != 0 {
		t.Fatalf("fetched before refusing an unowned target (requests=%d)", h.stub.requests)
	}
	sec, _ := h.getSecret(testNS, testTarget)
	if string(sec.Data["existing"]) != "keep-me" || len(sec.Data) != 1 {
		t.Fatalf("foreign Secret not preserved byte-for-byte: %v", sec.Data)
	}
	if !hasEventReason(h.drainEvents(), hikyov1.ReasonManagedSecretNotOwned) {
		t.Error("no ManagedSecretNotOwned event")
	}
}

func TestTargetClaimedLoserRefused(t *testing.T) {
	t.Run("earlier creation wins", func(t *testing.T) {
		early := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
		late := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
		winner := makeCR("winner", withCreation(early, "uid-winner"))
		loser := makeCR("loser", withCreation(late, "uid-loser"))
		writes := &secretWrites{}
		h := newHarness(t, writes.interceptors(),
			makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), winner, loser)
		h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))

		if _, err := h.reconcile("loser"); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		requireCond(t, h.getCR("loser"), hikyov1.ConditionConflict, metav1.ConditionTrue, hikyov1.ReasonTargetClaimed)
		if !hasEventReason(h.drainEvents(), hikyov1.ReasonTargetClaimed) {
			t.Error("no TargetClaimed event")
		}
		if writes.n != 0 {
			t.Fatalf("loser wrote the managed Secret %d time(s)", writes.n)
		}
		if h.stub.requests != 0 {
			t.Fatalf("loser fetched before refusing (requests=%d)", h.stub.requests)
		}
		if _, ok := h.getSecret(testNS, testTarget); ok {
			t.Fatal("loser wrote the managed Secret")
		}
	})

	t.Run("equal creation, lower UID wins", func(t *testing.T) {
		ts := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
		// Same creationTimestamp → the lower UID is the deterministic winner. The
		// higher-UID CR is the loser.
		winner := makeCR("aaa", withCreation(ts, "uid-aaa"))
		loser := makeCR("zzz", withCreation(ts, "uid-zzz"))
		h := newHarness(t, interceptor.Funcs{},
			makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), winner, loser)
		h.stub.set(200, deliveryJSON(false, "v1:c", "v1:t", []deliveredKey{secretVal("API_KEY", "v")}, nil))
		if _, err := h.reconcile("zzz"); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		requireCond(t, h.getCR("zzz"), hikyov1.ConditionConflict, metav1.ConditionTrue, hikyov1.ReasonTargetClaimed)
	})
}

func TestAllOrNothingRefusal(t *testing.T) {
	cr := makeCR("app", withMapping([2]string{"API_KEY", "API_KEY"}, [2]string{"DB_PASSWORD", "DB_PASSWORD"}))
	// Seed an owned Secret with prior data so we can prove it is untouched — a
	// partial or metadata-only write would be invisible to a state check.
	cr.Status.Cursor = "v1:prev"
	owned := makeOwnedSecret(t, testScheme(t), cr, map[string][]byte{"API_KEY": []byte("prior")})
	writes := &secretWrites{}
	h := newHarness(t, writes.interceptors(),
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), owned, cr)
	// API_KEY delivered, DB_PASSWORD presence-only → no write at all.
	h.stub.set(200, deliveryJSON(false, "v1:new", "v1:t",
		[]deliveredKey{secretVal("API_KEY", "s3cr3t"), secretPresenceOnly("DB_PASSWORD")}, nil))

	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionDelivery, metav1.ConditionFalse, hikyov1.ReasonUndeliveredSecrets)
	if !hasEventReason(h.drainEvents(), hikyov1.ReasonUndeliveredSecrets) {
		t.Error("no UndeliveredSecrets event")
	}
	if writes.n != 0 {
		t.Fatalf("all-or-nothing refusal still wrote the Secret %d time(s)", writes.n)
	}
	sec, ok := h.getSecret(testNS, testTarget)
	if !ok || string(sec.Data["API_KEY"]) != "prior" || len(sec.Data) != 1 {
		t.Fatalf("existing Secret data not retained byte-for-byte: %v", sec.Data)
	}
	// The cursor is NOT advanced on a refusal.
	if got := h.getCR("app"); got.Status.Cursor != "v1:prev" {
		t.Fatalf("cursor advanced on a refusal: %q", got.Status.Cursor)
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
	if !hasEventReason(h.drainEvents(), hikyov1.ReasonLoaderControlUnacknowledged) {
		t.Error("no LoaderControlUnacknowledged event")
	}
	if _, ok := h.getSecret(testNS, testTarget); ok {
		t.Fatal("wrote despite loader-control refusal")
	}
	if h.stub.requests != 0 {
		t.Fatal("fetched despite a pre-fetch loader-control refusal")
	}

	// Acknowledge exactly PATH → converges, and the ack is sent to the server.
	fresh := h.getCR("app")
	fresh.Spec.AcknowledgedLoaderKeys = []hikyov1.KeyName{"PATH"}
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
	// The cursor-status write is only recorded when the status object being
	// persisted actually carries cursor + binding + stamp + managed-Secret RV —
	// proving §0.5 step 3 (the full cursor state) was persisted LAST, not merely
	// that some status update happened.
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
			if cr, ok := obj.(*hikyov1.HikyoSecret); ok &&
				cr.Status.Cursor != "" && cr.Status.CursorBinding != "" &&
				cr.Status.Stamp != "" && cr.Status.ManagedSecretResourceVersion != "" {
				rec("cursor-status-write")
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
	iStatus := indexOf(order, "cursor-status-write")
	if iSecret < 0 || iPatch < 0 || iStatus < 0 {
		t.Fatalf("missing a write in %v", order)
	}
	if !(iSecret < iPatch && iPatch < iStatus) {
		t.Fatalf("write ordering wrong: %v", order)
	}
}

func TestFaultAfterSecretLeavesCursorEmpty(t *testing.T) {
	// §0.5/decision 7: a failure after the Secret write and before the cursor
	// write must leave NO cursor — including clearing an OLD cursor from a prior
	// delivery, or the next reconcile could present it, receive "current", and
	// permanently skip the failed patch (finding #3). Establish an old cursor
	// first, then fault the patch on a subsequent full delivery.
	faultActive := false
	interceptors := interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if _, ok := obj.(*appsv1.Deployment); ok && faultActive {
				return context.DeadlineExceeded
			}
			return c.Patch(ctx, obj, patch, opts...)
		},
	}
	cr := makeCR("app")
	h := newHarness(t, interceptors,
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true),
		makeOptedInDeployment("web", testTarget), cr)

	// Reconcile 1: clean full delivery → cursor established.
	h.stub.set(200, deliveryJSON(false, "v1:cur1", "v1:t", []deliveredKey{secretVal("API_KEY", "v1")}, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile1: %v", err)
	}
	if got := h.getCR("app"); got.Status.Cursor != "v1:cur1" || got.Status.CursorBinding == "" {
		t.Fatalf("old cursor not established: %+v", got.Status)
	}

	// Reconcile 2: a NEW full delivery (content changed) whose workload patch
	// faults. The old cursor AND binding must be cleared.
	faultActive = true
	h.stub.set(200, deliveryJSON(false, "v1:cur2", "v1:t2", []deliveredKey{secretVal("API_KEY", "v2")}, nil))
	if _, err := h.reconcile("app"); err == nil {
		t.Fatal("expected the injected patch fault to surface as an error")
	}
	sec, ok := h.getSecret(testNS, testTarget)
	if !ok || string(sec.Data["API_KEY"]) != "v2" {
		t.Fatal("new Secret content not written before the fault")
	}
	got := h.getCR("app")
	if got.Status.Cursor != "" || got.Status.CursorBinding != "" {
		t.Fatalf("cursor/binding not cleared after a post-Secret fault: cursor=%q binding=%q", got.Status.Cursor, got.Status.CursorBinding)
	}
	requireCond(t, got, hikyov1.ConditionRollout, metav1.ConditionFalse, hikyov1.ReasonStalled)
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
	// Seed prior cursor/binding/stamp so we can prove they clear.
	cr.Status.Cursor = "v1:old"
	cr.Status.CursorBinding = "old-binding"
	cr.Status.Stamp = "v1:oldstamp"
	owned := makeOwnedSecret(t, testScheme(t), cr, map[string][]byte{"API_KEY": []byte("was-here")})
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), owned,
		makeOptedInDeployment("web", testTarget), // opted in
		makeOptedInDeployment("db"),              // not opted in
		cr)
	h.stub.set(404, "")

	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := h.getCR("app")
	requireCond(t, got, hikyov1.ConditionScrubbed, metav1.ConditionTrue, hikyov1.ReasonAuthorizationWithdrawn)
	// AuthorizationWithdrawn is a Scrubbed reason only — no Synced condition.
	if _, _, ok := condStatus(got, hikyov1.ConditionSynced); ok {
		t.Fatal("scrub left a Synced condition; AuthorizationWithdrawn belongs to Scrubbed only")
	}
	requireCond(t, got, hikyov1.ConditionReady, metav1.ConditionFalse, hikyov1.ReasonBlocked)
	sec, ok := h.getSecret(testNS, testTarget)
	if !ok {
		t.Fatal("scrub deleted the Secret instead of emptying it")
	}
	if len(sec.Data) != 0 {
		t.Fatalf("scrub left data: %v", sec.Data)
	}
	if got.Status.Cursor != "" || got.Status.CursorBinding != "" {
		t.Fatalf("scrub did not clear cursor/binding: %q/%q", got.Status.Cursor, got.Status.CursorBinding)
	}
	if got.Status.Lifecycle != hikyov1.LifecycleScrubbed {
		t.Fatalf("lifecycle = %q, want Scrubbed", got.Status.Lifecycle)
	}
	// Opted-in workload rolled into the scrubbed (empty-set) stamp; it must have
	// MOVED off the pre-scrub value and be non-empty.
	web := stampAnnotation(h.getDeployment("web"))
	if web == "" || web == "v1:oldstamp" {
		t.Fatalf("opted-in workload not stamped into the scrubbed state: %q", web)
	}
	if db := stampAnnotation(h.getDeployment("db")); db != "" {
		t.Fatalf("non-opted-in workload was stamped: %q", db)
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
	// §0.4/decision 6: a "current" answer is valid ONLY for an eligible presented
	// cursor. Establish one with a full delivery, then answer current and prove
	// nothing was written and the delivered data/stamp are unchanged.
	writes := &secretWrites{}
	cr := makeCR("app")
	h := newHarness(t, writes.interceptors(),
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true),
		makeOptedInDeployment("web", testTarget), cr)

	full := deliveryJSON(false, "v1:cur1", "v1:t", []deliveredKey{secretVal("API_KEY", "s3cr3t")}, nil)
	h.stub.set(200, full)
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile1 (full): %v", err)
	}
	afterFull := h.getCR("app")
	if afterFull.Status.Cursor != "v1:cur1" || afterFull.Status.Stamp == "" {
		t.Fatalf("full delivery did not establish a cursor/stamp: %+v", afterFull.Status)
	}
	sec1, _ := h.getSecret(testNS, testTarget)
	rv1, data1 := sec1.ResourceVersion, string(sec1.Data["API_KEY"])
	stamp1 := stampAnnotation(h.getDeployment("web"))
	writes.n = 0

	// Reconcile 2: eligible cursor presented, server answers current.
	h.stub.set(200, deliveryJSON(true, "v1:cur1", "v1:t", nil, nil))
	if _, err := h.reconcile("app"); err != nil {
		t.Fatalf("reconcile2 (current): %v", err)
	}
	if h.stub.lastCursor != "v1:cur1" {
		t.Fatalf("current reconcile presented cursor %q, want v1:cur1", h.stub.lastCursor)
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonCurrent)
	if writes.n != 0 {
		t.Fatalf("current answer wrote the managed Secret %d time(s)", writes.n)
	}
	sec2, _ := h.getSecret(testNS, testTarget)
	if sec2.ResourceVersion != rv1 || string(sec2.Data["API_KEY"]) != data1 {
		t.Fatalf("current answer changed the Secret: rv %s->%s data %q", rv1, sec2.ResourceVersion, sec2.Data["API_KEY"])
	}
	if got := stampAnnotation(h.getDeployment("web")); got != stamp1 {
		t.Fatalf("current answer moved the workload stamp: %q -> %q", stamp1, got)
	}
}

func TestCurrentToCursorlessIsFetchFailed(t *testing.T) {
	// A "current" answer to a cursor-LESS request is a protocol violation → retain
	// (decision 6). A fresh CR presents no cursor, so any current answer here is
	// FetchFailed, and the managed Secret is not created.
	cr := makeCR("app")
	h := newHarness(t, interceptor.Funcs{},
		makeInstance(""), makeBootstrapSecret("boot", testInstance, "tok", true), cr)
	h.stub.set(200, deliveryJSON(true, "v1:cur", "v1:t", nil, nil))

	if _, err := h.reconcile("app"); err == nil {
		t.Fatal("current-to-cursor-less should surface an error (retain/backoff)")
	}
	requireCond(t, h.getCR("app"), hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonFetchFailed)
	if _, ok := h.getSecret(testNS, testTarget); ok {
		t.Fatal("a protocol-violating current answer created a Secret")
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
