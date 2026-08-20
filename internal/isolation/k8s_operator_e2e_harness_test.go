//go:build k8se2e

// Package isolation's kind-cluster operator e2e harness (#64 WP-D, mvp-boundary
// M3). Built only under `-tags k8se2e` and skipped unless
// HIKYO_K8S_E2E_KUBECONFIG points at a kind cluster's kubeconfig.
//
// Shape (handoff § 0.8): the Hikyo server runs in-process on the host over TLS
// via httptest.NewTLSServer; CRDs are applied from chart/hikyo/crds; workloads
// use registry.k8s.io/pause; one namespace per scenario.
//
// Two harness modes coexist by design:
//   - The converge and federation scenarios run through the REAL manager
//     (operator.NewManager + SetupWithManager + mgr.Start), so the production
//     wiring — the uncached Reader, the TokenMinter, the workload Watches, the
//     rate limiter — is exercised end to end (R1 found manager-level wiring bugs
//     a direct-Reconcile harness cannot catch). Leader election is disabled via
//     the WithLeaderElection seam: one in-process manager needs no lease.
//   - The remaining scenarios (rotate, designation, conflict, lifecycle, write
//     ordering) drive r.Reconcile directly. The controller has no Secret
//     informer but the manager still requeues on workload/instance events and on
//     the 5m resync, which would make the exact audit-count and single-write
//     ordering assertions racy; synchronous driving keeps them exact.
//
// Scope ids are production-shaped prefixed UUIDv7s (the CRD's ScopeID grammar,
// `^[a-z]{2,8}_[0-9a-fA-F-]{36}$`), NOT the isolation suite's `org_a` shorthand
// — a HikyoSecret carrying `org_a` would be rejected at admission. The e2e seeds
// its own org/project/environment under those ids.
package isolation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/Hikyo-Org/hikyo/internal/admission"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/oidcfed"
	"github.com/Hikyo-Org/hikyo/internal/operator"
	hikyov1 "github.com/Hikyo-Org/hikyo/internal/operator/api/v1alpha1"
	"github.com/Hikyo-Org/hikyo/internal/server"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

const kubeconfigEnv = "HIKYO_K8S_E2E_KUBECONFIG"

// pauseImage is the workload image (§ 0.8): a do-nothing container.
const pauseImage = "registry.k8s.io/pause:3.10"

// instanceName is the single HikyoInstance every scenario references.
const instanceName = "hikyo-e2e-instance"

// Production-shaped scope ids (prefixed UUIDv7) satisfying the CRD ScopeID
// grammar. The e2e seeds its own hierarchy under them.
const (
	e2eOrg = "org_0192f000-0000-7000-8000-00000000000a"
	e2ePrj = "prj_0192f000-0000-7000-8000-00000000000b"
	e2eEnv = "env_0192f000-0000-7000-8000-00000000000c"
)

// Two config + two secret keys (§ 0.8 converge). Names obey the KeyName grammar.
const (
	cfgKeyOne = "CONFIG_ONE"
	cfgKeyTwo = "CONFIG_TWO"
	secKeyOne = "SECRET_ONE"
	secKeyTwo = "SECRET_TWO"

	cfgValOne = "cfg-one-value"
	cfgValTwo = "cfg-two-value"
	secValOne = "sec-one-value"
	secValTwo = "sec-two-value"
)

func e2eScopePrj() domain.Scope {
	return domain.Scope{Org: domain.OrgID(e2eOrg), Project: domain.ProjectID(e2ePrj)}
}

func e2eScopeEnv() domain.Scope {
	return domain.Scope{Org: domain.OrgID(e2eOrg), Project: domain.ProjectID(e2ePrj), Env: domain.EnvID(e2eEnv)}
}

// operatorReconciler aliases the reconciler under test. Its Client, Reader,
// Recorder, Config, Log and TokenMinter fields are exported; the TokenMinter
// field's interface type is unexported but satisfied structurally by e2eMinter's
// exported Mint method.
type operatorReconciler = operator.HikyoSecretReconciler

func reconcileRequest(ns, name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}
}

func e2eScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	sch := runtime.NewScheme()
	must(t, k8sscheme.AddToScheme(sch))
	must(t, apiextensionsv1.AddToScheme(sch))
	must(t, hikyov1.AddToScheme(sch))
	return sch
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func restConfig(t *testing.T) *rest.Config {
	t.Helper()
	path := os.Getenv(kubeconfigEnv)
	if path == "" {
		t.Skipf("%s not set; skipping kind operator e2e", kubeconfigEnv)
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	must(t, err)
	// Raise the default client-go throttle (5 QPS / 10 burst): the manager-driven
	// scenarios and the polling clients issue enough reads that the default would
	// throttle and flake the 60s condition waits.
	cfg.QPS = 50
	cfg.Burst = 100
	return cfg
}

// repoRoot walks up to the module root so chart/hikyo/crds resolves.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	must(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repo root (go.mod) above the test working directory")
		}
		dir = parent
	}
}

// applyCRDs applies both operator CRDs and waits until each reports Established.
func applyCRDs(t *testing.T, ctx context.Context, cl client.Client) {
	t.Helper()
	crdDir := filepath.Join(repoRoot(t), "chart", "hikyo", "crds")
	entries, err := os.ReadDir(crdDir)
	must(t, err)
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(crdDir, e.Name()))
		must(t, err)
		for _, doc := range strings.Split(string(raw), "\n---") {
			if strings.TrimSpace(doc) == "" {
				continue
			}
			var crd apiextensionsv1.CustomResourceDefinition
			must(t, yaml.Unmarshal([]byte(doc), &crd))
			if crd.Name == "" {
				continue
			}
			var existing apiextensionsv1.CustomResourceDefinition
			switch err := cl.Get(ctx, types.NamespacedName{Name: crd.Name}, &existing); {
			case apierrors.IsNotFound(err):
				must(t, cl.Create(ctx, &crd))
			case err != nil:
				t.Fatalf("get CRD %s: %v", crd.Name, err)
			default:
				crd.ResourceVersion = existing.ResourceVersion
				must(t, cl.Update(ctx, &crd))
			}
			names = append(names, crd.Name)
		}
	}
	for _, name := range names {
		waitCRDEstablished(t, ctx, cl, name)
	}
}

func waitCRDEstablished(t *testing.T, ctx context.Context, cl client.Client, name string) {
	t.Helper()
	poll(t, ctx, func(ctx context.Context) (bool, error) {
		var crd apiextensionsv1.CustomResourceDefinition
		if err := cl.Get(ctx, types.NamespacedName{Name: name}, &crd); err != nil {
			return false, err
		}
		for _, c := range crd.Status.Conditions {
			if c.Type == apiextensionsv1.Established && c.Status == apiextensionsv1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	})
}

// poll runs cond until true or the 60s bound (§ 0.8: ≤ 60s per assertion).
func poll(t *testing.T, ctx context.Context, cond func(context.Context) (bool, error)) {
	t.Helper()
	pctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := wait.PollUntilContextTimeout(pctx, 300*time.Millisecond, 60*time.Second, true, cond); err != nil {
		t.Fatalf("condition not met within 60s: %v", err)
	}
}

// opEnv is one scenario's world: a fresh sqlite DB, a fresh in-process TLS Hikyo
// server, a dedicated kind namespace and a live (uncached) client.
type opEnv struct {
	t        *testing.T
	ctx      context.Context
	restCfg  *rest.Config
	db       *store.DB
	server   *httptest.Server
	caPEM    []byte
	scheme   *runtime.Scheme
	cl       client.Client
	cs       *kubernetes.Clientset
	ns       string
	fed      *service.Federation
	recorder *record.FakeRecorder
}

// newOpEnv seeds the delivery hierarchy (two config + two secret keys published
// into the e2e environment), stands up the TLS server, creates a namespace, and
// pre-seeds the stamp root.
func newOpEnv(t *testing.T, restCfg *rest.Config, sch *runtime.Scheme, withFederation bool) *opEnv {
	t.Helper()
	ctx := t.Context()

	db := seededDB(t, openSQLite)
	identityFixtures(t, db)
	seedE2EScope(t, db)

	kr := probeKeyring(t, db)
	api := &server.API{
		Auth:         authService(t, db),
		Orgs:         &service.Orgs{DB: db},
		Projects:     &service.Projects{DB: db},
		Environments: &service.Environments{DB: db, Keyring: kr},
		Folders:      &service.Folders{DB: db},
		Grants:       &service.Grants{DB: db},
		Settings:     &service.ProjectSettings{DB: db, Auth: authService(t, db)},
		Delivery:     &service.Delivery{DB: db, Keyring: kr},
		Version:      "k8se2e",
	}
	e := &opEnv{t: t, ctx: ctx, restCfg: restCfg, db: db, scheme: sch, recorder: record.NewFakeRecorder(500)}
	if withFederation {
		e.fed = newE2EFederation(t, db)
		api.Delivery = &service.Delivery{DB: db, Keyring: kr, Federation: e.fed, Now: time.Now}
	}

	srv := httptest.NewTLSServer(server.New(&service.System{DB: db}, api, nil))
	t.Cleanup(srv.Close)
	e.server = srv
	e.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	cl, err := client.New(restCfg, client.Options{Scheme: sch})
	must(t, err)
	e.cl = cl
	cs, err := kubernetes.NewForConfig(restCfg)
	must(t, err)
	e.cs = cs

	e.ns = e.createNamespace()
	e.seedStampRoot()
	return e
}

func (e *opEnv) createNamespace() string {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "hikyo-e2e-"}}
	must(e.t, e.cl.Create(e.ctx, ns))
	e.t.Cleanup(func() {
		_ = e.cl.Delete(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns.Name}})
	})
	return ns.Name
}

// seedStampRoot pre-creates the operator's 32-byte stamp root in the scenario
// namespace (also the operator's OwnNamespace); its auto-creation is covered by
// the operator's own unit tests.
func (e *opEnv) seedStampRoot() {
	root := make([]byte, crypto.KeySize)
	for i := range root {
		root[i] = byte(i*7 + 1)
	}
	must(e.t, e.cl.Create(e.ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: e.ns, Name: hikyov1.StampRootSecretName},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{hikyov1.StampRootKey: root},
	}))
}

// managerConfig is the operator config for the manager-driven scenarios: bound
// to the scenario namespace, rollouts on, metrics/health servers disabled so
// sequential scenarios never fight over :8080/:8081.
func (e *opEnv) managerConfig() operator.Config {
	return operator.Config{
		Namespaces:      []string{e.ns},
		TriggerRollouts: true,
		OwnNamespace:    e.ns,
		MetricsAddr:     "0",
		HealthAddr:      "0",
	}
}

// startManager builds a real manager (leader election off), wires the production
// reconciler shape (cached Client, uncached Reader, TokenMinter, Watches), starts
// it in a goroutine and blocks until its cache has synced.
func (e *opEnv) startManager() {
	e.t.Helper()
	cfg := e.managerConfig()
	mgr, err := operator.NewManager(e.restCfg, cfg, operator.WithLeaderElection(false))
	must(e.t, err)
	r := &operatorReconciler{
		Client:                       mgr.GetClient(),
		Reader:                       mgr.GetAPIReader(),
		Scheme:                       mgr.GetScheme(),
		Recorder:                     mgr.GetEventRecorderFor("hikyo-operator-e2e"),
		Config:                       cfg,
		Log:                          discardLog(),
		TokenMinter:                  e2eMinter{cs: e.cs},
		SkipControllerNameValidation: true, // more than one manager per test process
	}
	must(e.t, r.SetupWithManager(mgr))

	ctx, cancel := context.WithCancel(context.Background())
	e.t.Cleanup(cancel)
	go func() { _ = mgr.Start(ctx) }()
	if !mgr.GetCache().WaitForCacheSync(mgrSyncCtx(e.t)) {
		e.t.Fatal("manager cache did not sync")
	}
}

func mgrSyncCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// reconciler builds a direct-drive reconciler bound to the live client. Reader is
// the same live (uncached) client. NewClientForURL is left nil: the default
// factory dials inst.Spec.URL with decodeCABundle(caBundle) — the TLS server URL
// + cert — and its result type is unexported, unsettable from outside operator.
func (e *opEnv) reconciler() *operatorReconciler {
	return e.reconcilerWith(e.cl)
}

func (e *opEnv) reconcilerWith(writer client.Client) *operatorReconciler {
	return &operatorReconciler{
		Client:      writer,
		Reader:      e.cl,
		Scheme:      e.scheme,
		Recorder:    e.recorder,
		Config:      operator.Config{OwnNamespace: e.ns, TriggerRollouts: true},
		Log:         discardLog(),
		TokenMinter: e2eMinter{cs: e.cs},
	}
}

func (e *opEnv) reconcile(r *operatorReconciler, name string) error {
	e.t.Helper()
	_, err := r.Reconcile(e.ctx, reconcileRequest(e.ns, name))
	return err
}

func (e *opEnv) drainEvents() []string {
	var out []string
	for {
		select {
		case ev := <-e.recorder.Events:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func eventsContain(events []string, reason string) bool {
	for _, ev := range events {
		if strings.Contains(ev, reason) {
			return true
		}
	}
	return false
}

// --- object builders ---

func (e *opEnv) createInstance(name, audience string) *hikyov1.HikyoInstance {
	inst := &hikyov1.HikyoInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       hikyov1.HikyoInstanceSpec{URL: e.server.URL, CABundle: e.caBundleB64(), Audience: audience},
	}
	must(e.t, e.cl.Create(e.ctx, inst))
	e.t.Cleanup(func() {
		_ = e.cl.Delete(context.Background(), &hikyov1.HikyoInstance{ObjectMeta: metav1.ObjectMeta{Name: name}})
	})
	return inst
}

func (e *opEnv) caBundleB64() string { return base64.StdEncoding.EncodeToString(e.caPEM) }

func (e *opEnv) createBootstrapSecret(name, token, instanceLabel string, designate bool) *corev1.Secret {
	labels := map[string]string{}
	if designate {
		labels[hikyov1.LabelDelivery] = hikyov1.LabelDeliveryValue
		labels[hikyov1.LabelInstance] = instanceLabel
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: e.ns, Name: name, Labels: labels},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{hikyov1.BootstrapTokenKey: []byte(token)},
	}
	must(e.t, e.cl.Create(e.ctx, sec))
	return sec
}

func (e *opEnv) createServiceAccountObj(name, instanceLabel string, designate bool) *corev1.ServiceAccount {
	labels := map[string]string{}
	if designate {
		labels[hikyov1.LabelDelivery] = hikyov1.LabelDeliveryValue
		labels[hikyov1.LabelInstance] = instanceLabel
	}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: e.ns, Name: name, Labels: labels}}
	must(e.t, e.cl.Create(e.ctx, sa))
	return sa
}

// newWorkloadCredential mints a workload SA bearer credential in the e2e project.
func (e *opEnv) newWorkloadCredential(name string) (service.ServiceAccountView, service.MintResult) {
	ident := identitySvc(e.db)
	sa, err := ident.CreateServiceAccount(e.ctx, service.LocalPrincipal(identAdmin), e2eScopePrj(), name, domain.ClassWorkload)
	must(e.t, err)
	minted, err := ident.MintCredential(e.ctx, service.LocalPrincipal(identAdmin), e2eScopePrj(), sa.ID, service.MintRequest{})
	must(e.t, err)
	return sa, minted
}

// crSpec is a compact description of a HikyoSecret.
type crSpec struct {
	name           string
	target         string
	secretRef      string
	serviceAccount string
	mapping        [][2]string // {sourceKey, secretKey}
	projection     hikyov1.Projection
	policy         hikyov1.CreationPolicy
}

func (e *opEnv) createCR(s crSpec) *hikyov1.HikyoSecret {
	cr := &hikyov1.HikyoSecret{
		ObjectMeta: metav1.ObjectMeta{Namespace: e.ns, Name: s.name},
		Spec: hikyov1.HikyoSecretSpec{
			InstanceRef: hikyov1.InstanceRef{Name: instanceName},
			Scope:       hikyov1.Scope{Org: e2eOrg, Project: e2ePrj, Environment: e2eEnv},
			Target:      hikyov1.Target{Name: s.target},
		},
	}
	if s.secretRef != "" {
		cr.Spec.Auth = hikyov1.AuthRef{SecretRef: &hikyov1.LocalObjectRef{Name: s.secretRef}}
	}
	if s.serviceAccount != "" {
		cr.Spec.Auth = hikyov1.AuthRef{ServiceAccountRef: &hikyov1.LocalObjectRef{Name: s.serviceAccount}}
	}
	for _, m := range s.mapping {
		cr.Spec.Mapping = append(cr.Spec.Mapping, hikyov1.Mapping{Key: hikyov1.KeyName(m[0]), SecretKey: m[1]})
	}
	if s.projection != "" {
		cr.Spec.Projection = s.projection
	}
	if s.policy != "" {
		cr.Spec.Target.CreationPolicy = s.policy
	}
	must(e.t, e.cl.Create(e.ctx, cr))
	return cr
}

func (e *opEnv) createPauseDeployment(name string, consumes ...string) *appsv1.Deployment {
	ann := map[string]string{}
	if len(consumes) > 0 {
		ann[hikyov1.AnnotationWorkloadSecrets] = strings.Join(consumes, ",")
	}
	one := int32(1)
	labels := map[string]string{"app": name}
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: e.ns, Name: name, Annotations: ann},
		Spec: appsv1.DeploymentSpec{
			Replicas: &one,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "pause", Image: pauseImage}}},
			},
		},
	}
	must(e.t, e.cl.Create(e.ctx, d))
	return d
}

// --- getters ---

func (e *opEnv) getCR(name string) *hikyov1.HikyoSecret {
	e.t.Helper()
	var cr hikyov1.HikyoSecret
	must(e.t, e.cl.Get(e.ctx, types.NamespacedName{Namespace: e.ns, Name: name}, &cr))
	return &cr
}

func (e *opEnv) getSecret(name string) (*corev1.Secret, bool) {
	e.t.Helper()
	var sec corev1.Secret
	err := e.cl.Get(e.ctx, types.NamespacedName{Namespace: e.ns, Name: name}, &sec)
	if apierrors.IsNotFound(err) {
		return nil, false
	}
	must(e.t, err)
	return &sec, true
}

func (e *opEnv) getDeployment(name string) *appsv1.Deployment {
	e.t.Helper()
	var d appsv1.Deployment
	must(e.t, e.cl.Get(e.ctx, types.NamespacedName{Namespace: e.ns, Name: name}, &d))
	return &d
}

func stampOf(d *appsv1.Deployment, target string) string {
	if d.Spec.Template.Annotations == nil {
		return ""
	}
	return d.Spec.Template.Annotations[hikyov1.StampAnnotationPrefix+target]
}

func (e *opEnv) waitDeploymentSettled(name string) {
	e.t.Helper()
	poll(e.t, e.ctx, func(ctx context.Context) (bool, error) {
		var d appsv1.Deployment
		if err := e.cl.Get(ctx, types.NamespacedName{Namespace: e.ns, Name: name}, &d); err != nil {
			return false, err
		}
		return d.Status.ObservedGeneration >= d.Generation, nil
	})
}

// waitCondition polls the CR until it carries the given condition type/status/
// reason — the manager-driven scenarios' assertion primitive.
func (e *opEnv) waitCondition(name, condType string, status metav1.ConditionStatus, reason string) *hikyov1.HikyoSecret {
	e.t.Helper()
	var last *hikyov1.HikyoSecret
	pctx, cancel := context.WithTimeout(e.ctx, 60*time.Second)
	defer cancel()
	err := wait.PollUntilContextTimeout(pctx, 300*time.Millisecond, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		var cr hikyov1.HikyoSecret
		if err := e.cl.Get(ctx, types.NamespacedName{Namespace: e.ns, Name: name}, &cr); err != nil {
			return false, client.IgnoreNotFound(err)
		}
		last = &cr
		for _, c := range cr.Status.Conditions {
			if c.Type == condType {
				return c.Status == status && c.Reason == reason, nil
			}
		}
		return false, nil
	})
	if err != nil {
		e.t.Fatalf("CR %q never reached %s=%s/%s within 60s: %v\n  observedGeneration=%d lifecycle=%q conditions=%s",
			name, condType, status, reason, err, obsGen(last), lifecycleOf(last), dumpConds(last))
	}
	return last
}

func obsGen(cr *hikyov1.HikyoSecret) int64 {
	if cr == nil {
		return -1
	}
	return cr.Status.ObservedGeneration
}

func lifecycleOf(cr *hikyov1.HikyoSecret) hikyov1.Lifecycle {
	if cr == nil {
		return ""
	}
	return cr.Status.Lifecycle
}

func dumpConds(cr *hikyov1.HikyoSecret) string {
	if cr == nil {
		return "<CR not found>"
	}
	var b strings.Builder
	for _, c := range cr.Status.Conditions {
		fmt.Fprintf(&b, "[%s=%s/%s: %s] ", c.Type, c.Status, c.Reason, c.Message)
	}
	if b.Len() == 0 {
		return "<no conditions>"
	}
	return b.String()
}

// --- condition assertions (by type + reason, never message substring) ---

func requireCondition(t *testing.T, cr *hikyov1.HikyoSecret, condType string, status metav1.ConditionStatus, reason string) {
	t.Helper()
	for _, c := range cr.Status.Conditions {
		if c.Type == condType {
			if c.Status != status || c.Reason != reason {
				t.Fatalf("condition %q = (%s/%s), want (%s/%s)", condType, c.Status, c.Reason, status, reason)
			}
			return
		}
	}
	t.Fatalf("condition %q absent; have %+v", condType, cr.Status.Conditions)
}

// --- audit helpers (payload is a JSON string column; match with LIKE) ---

func (e *opEnv) countFullFetchWithCursor() int64 {
	return queryInt(e.t, e.db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.delivery_fetched' `+
		`AND payload LIKE '%"disposition":"full"%' AND payload LIKE '%"cursor_presented":true%'`)
}

func (e *opEnv) countCurrentFetch() int64 {
	return queryInt(e.t, e.db, `SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.delivery_fetched' `+
		`AND payload LIKE '%"disposition":"current"%'`)
}

// --- e2e-scope seeding (production-shaped ids) ---

// seedE2EScope seeds the e2e org/project/environment, the four keys, the fixture
// admin's project grants, and publishes values for all four keys into the env.
func seedE2EScope(t *testing.T, db *store.DB) {
	t.Helper()
	stmts := []string{
		fmt.Sprintf(`INSERT INTO orgs (id, name, active, metadata, created_at) VALUES ('%s', 'e2e-org', TRUE, '{}', %s)`, e2eOrg, ts),
		fmt.Sprintf(`INSERT INTO projects (id, org_id, name, created_at) VALUES ('%s', '%s', 'e2e', %s)`, e2ePrj, e2eOrg, ts),
		fmt.Sprintf(`INSERT INTO project_schema_revisions (org_id, project_id, revision) VALUES ('%s', '%s', 0)`, e2eOrg, e2ePrj),
		fmt.Sprintf(`INSERT INTO environments (id, org_id, project_id, name, note, created_at, display_order) VALUES ('%s', '%s', '%s', 'dev', '', %s, 0)`, e2eEnv, e2eOrg, e2ePrj, ts),
	}
	keys := []struct{ id, name, class string }{
		{"key_e2e_cfg1", cfgKeyOne, "config"},
		{"key_e2e_cfg2", cfgKeyTwo, "config"},
		{"key_e2e_sec1", secKeyOne, "secret"},
		{"key_e2e_sec2", secKeyTwo, "secret"},
	}
	for _, k := range keys {
		stmts = append(stmts, fmt.Sprintf(
			`INSERT INTO keys (id, org_id, project_id, name, folder_path, classification, description, deprecated, deprecation_note, declaration, required_mode, forbidden_mode, group_id, created_at)
			 VALUES ('%s', '%s', '%s', '%s', '', '%s', '', FALSE, '', '{"rule":{"type":"string"}}', 'none', 'none', NULL, %s)`,
			k.id, e2eOrg, e2ePrj, k.name, k.class, ts))
	}
	// The fixture admin (usr_ident) gets the project authority the e2e drives:
	// identity management (create SA + mint + revoke), member management + read
	// (grant/revoke read), and edit/publish/definitions-edit (publish values).
	for i, capability := range []string{"manage-identities", "manage-members", "read", "edit", "publish", "definitions-edit"} {
		stmts = append(stmts, fmt.Sprintf(
			`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
			 VALUES ('g_e2e_%d', '%s', '%s', '%s', '%s', NULL, %s)`,
			i, identAdmin, capability, e2eOrg, e2ePrj, ts))
	}
	for _, s := range stmts {
		execRaw(t, db, s)
	}
	seedOrigins(t, db)
	publishE2EValues(t, db, map[string]string{
		cfgKeyOne: cfgValOne, cfgKeyTwo: cfgValTwo, secKeyOne: secValOne, secKeyTwo: secValTwo,
	})
}

// publishE2EValues stages then publishes a batch of values into the e2e env.
func publishE2EValues(t *testing.T, db *store.DB, values map[string]string) {
	t.Helper()
	actor := service.LocalPrincipal(identAdmin)
	scope := e2eScopeEnv()
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	versions := make([]string, 0, len(names))
	for _, name := range names {
		staged, err := valueSvc(t, db).Set(t.Context(), actor, scope, name, values[name], nil)
		if err != nil {
			t.Fatalf("stage %s: %v", name, err)
		}
		versions = append(versions, staged.VersionID)
	}
	revisions := revisionSvc(t, db)
	_, err := revisions.PublishPlanned(t.Context(), actor, scope, service.PublishRequest{VersionIDs: versions})
	if errors.Is(err, service.ErrProtectedDestination) {
		_, err = revisions.PublishPlanned(t.Context(), actor, scope, service.PublishRequest{
			VersionIDs: versions, ConfirmedProtectedEnvironments: []string{string(scope.Env)},
		})
	}
	if err != nil {
		t.Fatalf("publish %v: %v", names, err)
	}
}

// grantE2ERead grants a principal `read` on the e2e env through the real grant
// API (the widening gate a production grant passes).
func grantE2ERead(t *testing.T, db *store.DB, p domain.PrincipalID) {
	t.Helper()
	if _, err := grantSvcWithAuth(db).Create(t.Context(), service.LocalPrincipal(identAdmin),
		service.GrantSpec{Target: p, Capability: domain.CapRead, Scope: e2eScopeEnv()}); err != nil {
		t.Fatalf("grant read to %s: %v", p, err)
	}
}

// revokeE2ERead removes a principal's `read` on the e2e env.
func revokeE2ERead(t *testing.T, db *store.DB, p domain.PrincipalID) {
	t.Helper()
	if err := grantSvcWithAuth(db).Revoke(t.Context(), service.LocalPrincipal(identAdmin),
		service.GrantSpec{Target: p, Capability: domain.CapRead, Scope: e2eScopeEnv()}); err != nil {
		t.Fatalf("revoke read from %s: %v", p, err)
	}
}

// seedE2EReveal writes a machine `reveal` grant on the e2e env directly (the
// per-project machine-reveal opt-in API is out of scope; the isolation suite
// seeds the row the same way).
func seedE2EReveal(t *testing.T, db *store.DB, id string, p domain.PrincipalID, cap domain.Capability) {
	t.Helper()
	execRaw(t, db, fmt.Sprintf(
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', %s)`,
		id, p, cap, e2eOrg, e2ePrj, e2eEnv, ts))
	seedOrigins(t, db)
}

// newE2EFederation builds a Federation service backed by a real admission
// limiter and a real clock — the JWTs are minted by the kind API server, so
// their timestamps are real and the validator's clock must be too.
func newE2EFederation(t *testing.T, db *store.DB) *service.Federation {
	t.Helper()
	limiter, err := admission.New(admission.Config{ArgonMemoryKiB: crypto.PasswordFloor.MemoryKiB, Now: time.Now})
	must(t, err)
	cache := &oidcfed.Cache{Limiter: limiter, Nowf: time.Now, HTTP: http.DefaultClient}
	return &service.Federation{DB: db, Auth: authWithWindow(db), Cache: cache, Now: time.Now}
}

// --- token minting via the kind TokenRequest subresource ---

// e2eMinter mirrors the production clientsetMinter: a short-lived audience-bound
// ServiceAccount token via the kind TokenRequest API. It satisfies the
// reconciler's unexported tokenMinter interface structurally.
type e2eMinter struct{ cs *kubernetes.Clientset }

func (m e2eMinter) Mint(ctx context.Context, namespace, serviceAccount, audience string) (string, error) {
	exp := int64(600)
	tr := &authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{Audiences: []string{audience}, ExpirationSeconds: &exp}}
	out, err := m.cs.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, serviceAccount, tr, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("mint token for %s/%s: %w", namespace, serviceAccount, err)
	}
	return out.Status.Token, nil
}

// defaultAudience mints a token with no requested audience so the kind API server
// stamps its default, then reads it back — the value the issuer refuses.
func (e *opEnv) defaultAudience(serviceAccount string) string {
	out, err := e.cs.CoreV1().ServiceAccounts(e.ns).CreateToken(e.ctx, serviceAccount, &authnv1.TokenRequest{}, metav1.CreateOptions{})
	must(e.t, err)
	aud := jwtAudience(e.t, out.Status.Token)
	if aud == "" {
		e.t.Fatal("kind default token carried no audience")
	}
	return aud
}

func jwtAudience(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWT: %d segments", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	must(t, err)
	var claims struct {
		Aud json.RawMessage `json:"aud"`
	}
	must(t, json.Unmarshal(payload, &claims))
	var single string
	if err := json.Unmarshal(claims.Aud, &single); err == nil {
		return single
	}
	var many []string
	must(t, json.Unmarshal(claims.Aud, &many))
	if len(many) == 0 {
		return ""
	}
	return many[0]
}

// discardLog silences the operator by default; set HIKYO_E2E_LOG to route it to
// stderr for diagnosis (the manager scenarios reconcile asynchronously, so their
// failures are otherwise invisible).
func discardLog() *slog.Logger {
	if os.Getenv("HIKYO_E2E_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
