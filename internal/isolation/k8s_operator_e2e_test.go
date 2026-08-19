//go:build k8se2e

package isolation

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	hikyov1 "github.com/Hikyo-Org/hikyo/internal/operator/api/v1alpha1"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

// fedAudience is the per-instance TokenRequest audience for the federation leg.
// It is deliberately not the kind API server's default audience (which the
// issuer refuses).
const fedAudience = "hikyo-e2e-fed-aud"

// TestK8sOperator is the operator's kind end-to-end suite (§ 0.8). It applies
// the CRDs once, then runs each scenario against its own seeded DB, TLS server
// and namespace. Skips unless HIKYO_K8S_E2E_KUBECONFIG is set.
func TestK8sOperator(t *testing.T) {
	restCfg := restConfig(t) // skips when the kubeconfig env is unset
	sch := e2eScheme(t)

	bootstrap, err := client.New(restCfg, client.Options{Scheme: sch})
	must(t, err)
	applyCRDs(t, t.Context(), bootstrap)

	t.Run("converge", func(t *testing.T) { testConverge(t, restCfg, sch) })
	t.Run("rotate_token_key", func(t *testing.T) { testRotateTokenKey(t, restCfg, sch) })
	t.Run("designation_refusals", func(t *testing.T) { testDesignationRefusals(t, restCfg, sch) })
	t.Run("managed_secret_conflict", func(t *testing.T) { testManagedSecretConflict(t, restCfg, sch) })
	t.Run("lifecycle", func(t *testing.T) { testLifecycle(t, restCfg, sch) })
	t.Run("write_ordering", func(t *testing.T) { testWriteOrdering(t, restCfg, sch) })
	t.Run("federation", func(t *testing.T) { testFederation(t, restCfg, sch) })
}

// allFourMapping maps every catalogue key to a same-named data key.
func allFourMapping() [][2]string {
	return [][2]string{
		{cfgKeyOne, cfgKeyOne}, {cfgKeyTwo, cfgKeyTwo},
		{secKeyOne, secKeyOne}, {secKeyTwo, secKeyTwo},
	}
}

func configMapping() [][2]string {
	return [][2]string{{cfgKeyOne, cfgKeyOne}, {cfgKeyTwo, cfgKeyTwo}}
}

func assertSecretData(t *testing.T, sec *corev1.Secret, want map[string]string) {
	t.Helper()
	if len(sec.Data) != len(want) {
		t.Fatalf("secret has %d keys, want %d (%v)", len(sec.Data), len(want), keysOf(sec.Data))
	}
	for k, v := range want {
		if got := string(sec.Data[k]); got != v {
			t.Fatalf("secret[%q] = %q, want %q", k, got, v)
		}
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---- Scenario 1: converge ----

func testConverge(t *testing.T, restCfg *rest.Config, sch *runtime.Scheme) {
	e := newOpEnv(t, restCfg, sch, false)
	e.createInstance(instanceName, "")

	// Reveal-capable workload: read + reveal, so secret values cross.
	revealSA, revealCred := e.newWorkloadCredential("wl-reveal")
	grantMachineRead(t, e.db, revealSA.Principal, envA1)
	seedMachineReveal(t, e.db, "g_e2e_reveal", revealSA.Principal, domain.CapReveal, envA1)
	e.createBootstrapSecret("boot-reveal", revealCred.Value, instanceName, true)

	// Read-only workload: no reveal, so secret keys arrive presence-only.
	readSA, readCred := e.newWorkloadCredential("wl-read")
	grantMachineRead(t, e.db, readSA.Principal, envA1)
	e.createBootstrapSecret("boot-read", readCred.Value, instanceName, true)

	optedIn := e.createPauseDeployment("app", "app-secret")
	bystander := e.createPauseDeployment("bystander")
	e.waitDeploymentSettled("bystander")
	bystanderGen := e.getDeployment("bystander").Generation

	r := e.reconciler()

	// (1a) Reveal SA converges all four keys byte-exact.
	e.createCR(crSpec{name: "cr-reveal", target: "app-secret", secretRef: "boot-reveal", mapping: allFourMapping()})
	must(t, e.reconcile(r, "cr-reveal"))
	cr := e.getCR("cr-reveal")
	requireCondition(t, cr, hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonDelivered)
	requireCondition(t, cr, hikyov1.ConditionReady, metav1.ConditionTrue, hikyov1.ReasonReconciled)
	sec, ok := e.getSecret("app-secret")
	if !ok {
		t.Fatal("managed Secret app-secret absent after converge")
	}
	assertSecretData(t, sec, map[string]string{
		cfgKeyOne: cfgValOne, cfgKeyTwo: cfgValTwo, secKeyOne: secValOne, secKeyTwo: secValTwo,
	})
	if !metav1.IsControlledBy(sec, cr) {
		t.Fatal("managed Secret is not controlled by the CR")
	}

	// Opted-in Deployment carries the stamp; non-opted-in is untouched.
	if stampOf(e.getDeployment("app"), "app-secret") == "" {
		t.Fatal("opted-in Deployment did not receive the stamp annotation")
	}
	_ = optedIn
	if got := e.getDeployment("bystander"); stampOf(got, "app-secret") != "" || got.Generation != bystanderGen {
		t.Fatalf("non-opted-in Deployment was touched: stamp=%q generation %d→%d",
			stampOf(got, "app-secret"), bystanderGen, got.Generation)
	}
	_ = bystander

	// (1b) Read-only SA refuses: secret keys presence-only, nothing written.
	e.createCR(crSpec{name: "cr-read", target: "app-secret-ro", secretRef: "boot-read", mapping: allFourMapping()})
	must(t, e.reconcile(r, "cr-read"))
	cr = e.getCR("cr-read")
	requireCondition(t, cr, hikyov1.ConditionDelivery, metav1.ConditionFalse, hikyov1.ReasonUndeliveredSecrets)
	requireCondition(t, cr, hikyov1.ConditionReady, metav1.ConditionFalse, hikyov1.ReasonBlocked)
	if _, ok := e.getSecret("app-secret-ro"); ok {
		t.Fatal("read-only refusal still wrote a managed Secret")
	}

	// (1c) config-only projection converges only the two config keys.
	e.createCR(crSpec{name: "cr-cfg", target: "app-cfg", secretRef: "boot-read", mapping: configMapping(), projection: hikyov1.ProjectionConfigOnly})
	must(t, e.reconcile(r, "cr-cfg"))
	cr = e.getCR("cr-cfg")
	requireCondition(t, cr, hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonDelivered)
	sec, ok = e.getSecret("app-cfg")
	if !ok {
		t.Fatal("config-only managed Secret absent")
	}
	assertSecretData(t, sec, map[string]string{cfgKeyOne: cfgValOne, cfgKeyTwo: cfgValTwo})
}

// ---- Scenario 2: rotate-token-key without a restart wave ----

func testRotateTokenKey(t *testing.T, restCfg *rest.Config, sch *runtime.Scheme) {
	e := newOpEnv(t, restCfg, sch, false)
	e.createInstance(instanceName, "")

	sa, cred := e.newWorkloadCredential("wl-rot")
	grantMachineRead(t, e.db, sa.Principal, envA1)
	seedMachineReveal(t, e.db, "g_rot_reveal", sa.Principal, domain.CapReveal, envA1)
	e.createBootstrapSecret("boot-rot", cred.Value, instanceName, true)
	e.createPauseDeployment("rotapp", "rot-secret")

	r := e.reconciler()
	e.createCR(crSpec{name: "cr-rot", target: "rot-secret", secretRef: "boot-rot", mapping: allFourMapping()})

	// Reconcile #1: full delivery, cursor recorded, workload patched.
	must(t, e.reconcile(r, "cr-rot"))
	requireCondition(t, e.getCR("cr-rot"), hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonDelivered)
	e.waitDeploymentSettled("rotapp")

	baselineStamp := stampOf(e.getDeployment("rotapp"), "rot-secret")
	if baselineStamp == "" {
		t.Fatal("opted-in Deployment not stamped after first delivery")
	}
	baselineGen := e.getDeployment("rotapp").Generation
	baselineRS := e.replicaSetCount("rotapp")

	// Reconcile #2: cursor still valid, server answers current — no write.
	must(t, e.reconcile(r, "cr-rot"))
	requireCondition(t, e.getCR("cr-rot"), hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonCurrent)
	if got := e.countCurrentFetch(); got != 1 {
		t.Fatalf("current-disposition fetch count = %d, want 1", got)
	}

	// Rotate the token key as the instance operator: every outstanding cursor is
	// invalidated server-side.
	if _, err := revisionSvc(t, e.db).RotateTokenKey(e.ctx, service.LocalPrincipal(root)); err != nil {
		t.Fatalf("rotate token key: %v", err)
	}

	// Reconcile #3: the operator still presents its cursor, but the server now
	// answers a full delivery. Content is unchanged, so the stamp is identical
	// and no workload patch / ReplicaSet churn follows.
	must(t, e.reconcile(r, "cr-rot"))
	requireCondition(t, e.getCR("cr-rot"), hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonDelivered)
	if got := e.countFullFetchWithCursor(); got != 1 {
		t.Fatalf("full-disposition-with-cursor fetch count = %d, want exactly 1 (the post-rotate fetch)", got)
	}
	if got := stampOf(e.getDeployment("rotapp"), "rot-secret"); got != baselineStamp {
		t.Fatalf("stamp changed after rotate: %q → %q (a restart wave the ADR forbids)", baselineStamp, got)
	}
	if got := e.getDeployment("rotapp").Generation; got != baselineGen {
		t.Fatalf("Deployment generation moved after rotate: %d → %d", baselineGen, got)
	}
	if got := e.replicaSetCount("rotapp"); got != baselineRS {
		t.Fatalf("ReplicaSet count changed after rotate: %d → %d (a restart wave)", baselineRS, got)
	}
}

// replicaSetCount counts the ReplicaSets a Deployment owns.
func (e *opEnv) replicaSetCount(deployment string) int {
	e.t.Helper()
	var list appsv1.ReplicaSetList
	must(e.t, e.cl.List(e.ctx, &list, client.InNamespace(e.ns)))
	n := 0
	for i := range list.Items {
		for _, ref := range list.Items[i].OwnerReferences {
			if ref.Kind == "Deployment" && ref.Name == deployment {
				n++
			}
		}
	}
	return n
}

// ---- Scenario 3: credential-designation refusals ----

func testDesignationRefusals(t *testing.T, restCfg *rest.Config, sch *runtime.Scheme) {
	e := newOpEnv(t, restCfg, sch, false)
	e.createInstance(instanceName, fedAudience) // audience present so the SA path reaches designation

	_, cred := e.newWorkloadCredential("wl-des")

	// (3a) Bootstrap Secret without designation labels.
	e.createBootstrapSecret("boot-undes", cred.Value, "", false)
	r := e.reconciler()
	e.createCR(crSpec{name: "cr-undes", target: "t-undes", secretRef: "boot-undes", mapping: configMapping()})
	must(t, e.reconcile(r, "cr-undes"))
	requireCondition(t, e.getCR("cr-undes"), hikyov1.ConditionDesignation, metav1.ConditionFalse, hikyov1.ReasonSecretNotDesignated)
	if _, ok := e.getSecret("t-undes"); ok {
		t.Fatal("undesignated Secret still produced a managed Secret")
	}

	// (3b) ServiceAccount without designation labels.
	e.createServiceAccountObj("sa-undes", "", false)
	e.createCR(crSpec{name: "cr-sa-undes", target: "t-sa-undes", serviceAccount: "sa-undes", mapping: configMapping()})
	must(t, e.reconcile(r, "cr-sa-undes"))
	requireCondition(t, e.getCR("cr-sa-undes"), hikyov1.ConditionDesignation, metav1.ConditionFalse, hikyov1.ReasonServiceAccountNotDesignated)

	// (3c) Bootstrap Secret designated for a DIFFERENT instance name.
	e.createBootstrapSecret("boot-wrong", cred.Value, "some-other-instance", true)
	e.createCR(crSpec{name: "cr-wrong", target: "t-wrong", secretRef: "boot-wrong", mapping: configMapping()})
	must(t, e.reconcile(r, "cr-wrong"))
	requireCondition(t, e.getCR("cr-wrong"), hikyov1.ConditionDesignation, metav1.ConditionFalse, hikyov1.ReasonInstanceMismatch)
	if _, ok := e.getSecret("t-wrong"); ok {
		t.Fatal("wrong-instance designation still produced a managed Secret")
	}
}

// ---- Scenario 4: managed-Secret conflict refusals ----

func testManagedSecretConflict(t *testing.T, restCfg *rest.Config, sch *runtime.Scheme) {
	e := newOpEnv(t, restCfg, sch, false)
	e.createInstance(instanceName, "")

	sa, cred := e.newWorkloadCredential("wl-conf")
	grantMachineRead(t, e.db, sa.Principal, envA1)
	e.createBootstrapSecret("boot-conf", cred.Value, instanceName, true)

	// (4a) An unowned Secret already occupies the target name.
	unowned := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: e.ns, Name: "claimed"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"pre-existing": []byte("do-not-touch")},
	}
	must(t, e.cl.Create(e.ctx, unowned))
	r := e.reconciler()
	e.createCR(crSpec{name: "cr-claim", target: "claimed", secretRef: "boot-conf", mapping: configMapping()})
	must(t, e.reconcile(r, "cr-claim"))
	requireCondition(t, e.getCR("cr-claim"), hikyov1.ConditionConflict, metav1.ConditionTrue, hikyov1.ReasonManagedSecretNotOwned)
	got, _ := e.getSecret("claimed")
	assertSecretData(t, got, map[string]string{"pre-existing": "do-not-touch"})

	// (4b) Two CRs name the same target; the later one loses. creationTimestamp
	// has 1s granularity, so the sleep guarantees a deterministic winner.
	e.createCR(crSpec{name: "cr-dup-first", target: "dup", secretRef: "boot-conf", mapping: configMapping()})
	time.Sleep(1100 * time.Millisecond)
	e.createCR(crSpec{name: "cr-dup-second", target: "dup", secretRef: "boot-conf", mapping: configMapping()})
	must(t, e.reconcile(r, "cr-dup-second"))
	requireCondition(t, e.getCR("cr-dup-second"), hikyov1.ConditionConflict, metav1.ConditionTrue, hikyov1.ReasonTargetClaimed)
}

// ---- Scenario 5: orphan-vs-scrub lifecycle ----

func testLifecycle(t *testing.T, restCfg *rest.Config, sch *runtime.Scheme) {
	e := newOpEnv(t, restCfg, sch, false)
	e.createInstance(instanceName, "")

	// (5a) creationPolicy: Owner + delete → the managed Secret is GC'd.
	ownerSA, ownerCred := e.newWorkloadCredential("wl-owner")
	grantMachineRead(t, e.db, ownerSA.Principal, envA1)
	e.createBootstrapSecret("boot-owner", ownerCred.Value, instanceName, true)
	r := e.reconciler()
	crOwner := e.createCR(crSpec{name: "cr-owner", target: "sec-owner", secretRef: "boot-owner", mapping: configMapping(), policy: hikyov1.CreationPolicyOwner})
	must(t, e.reconcile(r, "cr-owner"))
	if _, ok := e.getSecret("sec-owner"); !ok {
		t.Fatal("Owner CR did not create its managed Secret")
	}
	must(t, e.cl.Delete(e.ctx, crOwner))
	poll(t, e.ctx, func(ctx context.Context) (bool, error) {
		var sec corev1.Secret
		err := e.cl.Get(ctx, types.NamespacedName{Namespace: e.ns, Name: "sec-owner"}, &sec)
		return apierrors.IsNotFound(err), nil
	})

	// (5b) creationPolicy: Orphan + delete → the Secret survives, unowned.
	orphanSA, orphanCred := e.newWorkloadCredential("wl-orphan")
	grantMachineRead(t, e.db, orphanSA.Principal, envA1)
	e.createBootstrapSecret("boot-orphan", orphanCred.Value, instanceName, true)
	crOrphan := e.createCR(crSpec{name: "cr-orphan", target: "sec-orphan", secretRef: "boot-orphan", mapping: configMapping(), policy: hikyov1.CreationPolicyOrphan})
	must(t, e.reconcile(r, "cr-orphan")) // adds the finalizer
	must(t, e.reconcile(r, "cr-orphan")) // delivers
	if _, ok := e.getSecret("sec-orphan"); !ok {
		t.Fatal("Orphan CR did not create its managed Secret")
	}
	must(t, e.cl.Delete(e.ctx, crOrphan))
	must(t, e.reconcile(r, "cr-orphan")) // finalize: strip ownerRef, drop finalizer
	poll(t, e.ctx, func(ctx context.Context) (bool, error) {
		var cr hikyov1.HikyoSecret
		err := e.cl.Get(ctx, types.NamespacedName{Namespace: e.ns, Name: "cr-orphan"}, &cr)
		return apierrors.IsNotFound(err), nil
	})
	sec, ok := e.getSecret("sec-orphan")
	if !ok {
		t.Fatal("Orphan Secret was GC'd; it must survive the CR")
	}
	if len(sec.OwnerReferences) != 0 {
		t.Fatalf("Orphan Secret still carries ownerReferences: %+v", sec.OwnerReferences)
	}

	// (5c) Revoke the credential while the Secret is synced → retain + FetchFailed.
	revSA, revCred := e.newWorkloadCredential("wl-revoke")
	grantMachineRead(t, e.db, revSA.Principal, envA1)
	e.createBootstrapSecret("boot-revoke", revCred.Value, instanceName, true)
	e.createCR(crSpec{name: "cr-revoke", target: "sec-revoke", secretRef: "boot-revoke", mapping: configMapping()})
	must(t, e.reconcile(r, "cr-revoke"))
	before, ok := e.getSecret("sec-revoke")
	if !ok {
		t.Fatal("cr-revoke did not create its Secret")
	}
	beforeData := map[string]string{cfgKeyOne: cfgValOne, cfgKeyTwo: cfgValTwo}
	assertSecretData(t, before, beforeData)
	if err := identitySvc(e.db).RevokeCredential(e.ctx, service.LocalPrincipal(identAdmin), prjScope(), revSA.ID, revCred.Credential.ID); err != nil {
		t.Fatalf("revoke credential: %v", err)
	}
	_ = e.drainEvents()
	must(t, e.reconcile(r, "cr-revoke"))
	cr := e.getCR("cr-revoke")
	requireCondition(t, cr, hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonFetchFailed)
	if cr.Status.Lifecycle != hikyov1.LifecycleRetained {
		t.Fatalf("lifecycle = %q, want Retained", cr.Status.Lifecycle)
	}
	after, _ := e.getSecret("sec-revoke")
	assertSecretData(t, after, beforeData) // retained unchanged
	if !eventsContain(e.drainEvents(), hikyov1.ReasonFetchFailed) {
		t.Fatal("no FetchFailed Event emitted on revoked credential")
	}

	// (5d) Remove `read` while the credential is alive → scrub to empty.
	scrubSA, scrubCred := e.newWorkloadCredential("wl-scrub")
	grantMachineRead(t, e.db, scrubSA.Principal, envA1)
	e.createBootstrapSecret("boot-scrub", scrubCred.Value, instanceName, true)
	e.createPauseDeployment("scrubapp", "sec-scrub")
	e.createCR(crSpec{name: "cr-scrub", target: "sec-scrub", secretRef: "boot-scrub", mapping: configMapping()})
	must(t, e.reconcile(r, "cr-scrub"))
	preScrubStamp := stampOf(e.getDeployment("scrubapp"), "sec-scrub")
	if preScrubStamp == "" {
		t.Fatal("scrubapp not stamped before scrub")
	}
	if err := grantSvcWithAuth(e.db).Revoke(e.ctx, service.LocalPrincipal(identAdmin),
		service.GrantSpec{Target: scrubSA.Principal, Capability: domain.CapRead, Scope: envScope(envA1)}); err != nil {
		t.Fatalf("revoke read grant: %v", err)
	}
	must(t, e.reconcile(r, "cr-scrub"))
	cr = e.getCR("cr-scrub")
	requireCondition(t, cr, hikyov1.ConditionScrubbed, metav1.ConditionTrue, hikyov1.ReasonAuthorizationWithdrawn)
	scrubbed, _ := e.getSecret("sec-scrub")
	if len(scrubbed.Data) != 0 {
		t.Fatalf("scrubbed Secret still holds data: %v", keysOf(scrubbed.Data))
	}
	if got := stampOf(e.getDeployment("scrubapp"), "sec-scrub"); got == preScrubStamp || got == "" {
		t.Fatalf("stamp did not change on scrub: %q → %q", preScrubStamp, got)
	}
}

// ---- Scenario 6: write ordering ----

func testWriteOrdering(t *testing.T, restCfg *rest.Config, sch *runtime.Scheme) {
	e := newOpEnv(t, restCfg, sch, false)
	e.createInstance(instanceName, "")

	sa, cred := e.newWorkloadCredential("wl-order")
	grantMachineRead(t, e.db, sa.Principal, envA1)
	e.createBootstrapSecret("boot-order", cred.Value, instanceName, true)

	// (6a) One clean delivery: Secret write < workload patch < status update.
	e.createPauseDeployment("orderapp", "sec-order")
	var ops []string
	rc := &recordingClient{Client: e.cl, ops: &ops}
	r := e.reconcilerWith(rc)
	e.createCR(crSpec{name: "cr-order", target: "sec-order", secretRef: "boot-order", mapping: configMapping()})
	must(t, e.reconcile(r, "cr-order"))
	assertOrder(t, ops, "secret", "workload", "status")

	// (6b) A fault after the Secret write leaves the cursor empty; the next
	// reconcile re-fetches full.
	e.createPauseDeployment("faultapp", "sec-fault")
	fail := true
	var faultOps []string
	frc := &recordingClient{Client: e.cl, ops: &faultOps, failWorkloadPatch: &fail}
	fr := e.reconcilerWith(frc)
	e.createCR(crSpec{name: "cr-fault", target: "sec-fault", secretRef: "boot-order", mapping: configMapping()})
	if err := e.reconcile(fr, "cr-fault"); err == nil {
		t.Fatal("expected the injected workload-patch fault to surface as a reconcile error")
	}
	cr := e.getCR("cr-fault")
	if cr.Status.Cursor != "" {
		t.Fatalf("cursor advanced despite the post-Secret fault: %q", cr.Status.Cursor)
	}
	if _, ok := e.getSecret("sec-fault"); !ok {
		t.Fatal("Secret was not written before the fault")
	}
	// Next reconcile (fault consumed) re-fetches full and advances the cursor.
	must(t, e.reconcile(fr, "cr-fault"))
	cr = e.getCR("cr-fault")
	requireCondition(t, cr, hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonDelivered)
	if cr.Status.Cursor == "" {
		t.Fatal("cursor still empty after the recovery reconcile")
	}
	// The recovery fetch was cursor-less (full): the pre-fault reconcile left no
	// cursor, so both fetches presented none.
	if got := e.countFullFetchWithCursor(); got != 0 {
		t.Fatalf("a cursor was presented despite the cleared cursor: %d full-with-cursor fetches", got)
	}
}

func assertOrder(t *testing.T, ops []string, first, second, third string) {
	t.Helper()
	idx := func(label string) int {
		for i, o := range ops {
			if o == label {
				return i
			}
		}
		return -1
	}
	a, b, c := idx(first), idx(second), idx(third)
	if a < 0 || b < 0 || c < 0 || !(a < b && b < c) {
		t.Fatalf("write ordering wrong: want %s < %s < %s, got sequence %v", first, second, third, ops)
	}
}

// recordingClient wraps a live client, recording the order of mutating calls and
// optionally injecting a one-shot workload-patch fault. It overrides Status() so
// the status write (the ordering's third event) is recorded too.
type recordingClient struct {
	client.Client
	mu                sync.Mutex
	ops               *[]string
	failWorkloadPatch *bool
}

func opLabel(obj client.Object) string {
	switch obj.(type) {
	case *corev1.Secret:
		return "secret"
	case *appsv1.Deployment, *appsv1.StatefulSet, *appsv1.DaemonSet:
		return "workload"
	default:
		return ""
	}
}

func (c *recordingClient) record(label string) {
	if label == "" {
		return
	}
	c.mu.Lock()
	*c.ops = append(*c.ops, label)
	c.mu.Unlock()
}

func (c *recordingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	c.record(opLabel(obj))
	return c.Client.Create(ctx, obj, opts...)
}

func (c *recordingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.record(opLabel(obj))
	return c.Client.Update(ctx, obj, opts...)
}

func (c *recordingClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if opLabel(obj) == "workload" && c.failWorkloadPatch != nil {
		c.mu.Lock()
		fire := *c.failWorkloadPatch
		*c.failWorkloadPatch = false
		c.mu.Unlock()
		if fire {
			return fmt.Errorf("injected workload-patch fault")
		}
	}
	c.record(opLabel(obj))
	return c.Client.Patch(ctx, obj, patch, opts...)
}

func (c *recordingClient) Status() client.SubResourceWriter {
	return &recordingStatus{inner: c.Client.Status(), rec: c}
}

type recordingStatus struct {
	inner client.SubResourceWriter
	rec   *recordingClient
}

func (s *recordingStatus) Create(ctx context.Context, obj client.Object, sub client.Object, opts ...client.SubResourceCreateOption) error {
	return s.inner.Create(ctx, obj, sub, opts...)
}

func (s *recordingStatus) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	s.rec.record("status")
	return s.inner.Update(ctx, obj, opts...)
}

func (s *recordingStatus) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	return s.inner.Patch(ctx, obj, patch, opts...)
}

// ---- Scenario 7: federation leg ----

func testFederation(t *testing.T, restCfg *rest.Config, sch *runtime.Scheme) {
	e := newOpEnv(t, restCfg, sch, true) // Federation wired into Delivery

	clusterIssuer := e.clusterIssuer()
	jwks := e.clusterJWKS()

	// A designated kind ServiceAccount whose real UID pins the binding.
	kindSA := e.createServiceAccountObj("wl-fed", instanceName, true)
	saUID := string(kindSA.UID)
	defaultAud := e.defaultAudience("wl-fed")

	e.createInstance(instanceName, fedAudience)

	// Register the cluster as a Kubernetes issuer with the cluster's own JWKS,
	// refusing the API-server default audience.
	if _, err := e.fed.CreateIssuer(e.ctx, service.LocalPrincipal(root), service.IssuerRequest{
		Issuer: clusterIssuer, Type: domain.IssuerKubernetes, Mode: domain.JWKSStatic,
		StaticJWKS: jwks, RefusedAudiences: []string{defaultAud},
	}); err != nil {
		t.Fatalf("configure kubernetes issuer: %v", err)
	}

	// A Hikyo service account, bound to the kind SA's (issuer, subject) and
	// pinned to its UID, granted read on env_a1.
	hsa, err := identitySvc(e.db).CreateServiceAccount(e.ctx, service.LocalPrincipal(identAdmin), prjScope(), "fed-hikyo-sa", domain.ClassWorkload)
	must(t, err)
	subject := fmt.Sprintf("system:serviceaccount:%s:%s", e.ns, "wl-fed")
	uidPin := saUID
	if _, err := e.fed.CreateBinding(e.ctx, service.LocalPrincipal(identAdmin), prjScope(), hsa.ID, service.BindingRequest{
		Issuer: clusterIssuer, Subject: subject, Audience: fedAudience,
		RequiredClaims: []service.ClaimPin{{Claim: "/kubernetes.io/serviceaccount/uid", String: &uidPin}},
	}); err != nil {
		t.Fatalf("create federated binding: %v", err)
	}
	grantMachineRead(t, e.db, hsa.Principal, envA1)

	r := e.reconciler()

	// Designated SA → the operator mints a TokenRequest, the server validates it
	// against the cluster JWKS, and delivery converges.
	e.createCR(crSpec{name: "cr-fed", target: "sec-fed", serviceAccount: "wl-fed", mapping: configMapping()})
	must(t, e.reconcile(r, "cr-fed"))
	requireCondition(t, e.getCR("cr-fed"), hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonDelivered)
	sec, ok := e.getSecret("sec-fed")
	if !ok {
		t.Fatal("federated delivery did not converge a managed Secret")
	}
	assertSecretData(t, sec, map[string]string{cfgKeyOne: cfgValOne, cfgKeyTwo: cfgValTwo})

	// The same SA without designation labels → refused before any token mint.
	e.createServiceAccountObj("wl-fed-undes", "", false)
	e.createCR(crSpec{name: "cr-fed-undes", target: "sec-fed-undes", serviceAccount: "wl-fed-undes", mapping: configMapping()})
	must(t, e.reconcile(r, "cr-fed-undes"))
	requireCondition(t, e.getCR("cr-fed-undes"), hikyov1.ConditionDesignation, metav1.ConditionFalse, hikyov1.ReasonServiceAccountNotDesignated)
}

// clusterIssuer reads the kind API server's SA issuer from its OIDC discovery
// document (§ 0.8: issuer = the cluster's SA issuer).
func (e *opEnv) clusterIssuer() string {
	raw, err := e.cs.CoreV1().RESTClient().Get().AbsPath("/.well-known/openid-configuration").DoRaw(e.ctx)
	must(e.t, err)
	var doc struct {
		Issuer string `json:"issuer"`
	}
	must(e.t, jsonUnmarshal(raw, &doc))
	if doc.Issuer == "" {
		e.t.Fatal("cluster discovery document carried no issuer")
	}
	return doc.Issuer
}

// clusterJWKS reads the kind API server's static JWKS document (§ 0.8).
func (e *opEnv) clusterJWKS() string {
	raw, err := e.cs.CoreV1().RESTClient().Get().AbsPath("/openid/v1/jwks").DoRaw(e.ctx)
	must(e.t, err)
	return string(raw)
}
