//go:build k8se2e

// Package isolation's kind-cluster operator e2e harness (#64 WP-D, mvp-boundary
// M3). Built only under `-tags k8se2e` and skipped unless
// HIKYO_K8S_E2E_KUBECONFIG points at a kind cluster's kubeconfig.
//
// Shape (handoff § 0.8): the Hikyo server runs in-process on the host over TLS
// via httptest.NewTLSServer; the operator's reconciler runs in-process against
// the kind API server through a live (uncached) controller-runtime client;
// CRDs are applied from chart/hikyo/crds. Reconciliation is driven SYNCHRONOUSLY
// (r.Reconcile called directly) rather than through a running manager: the
// controller Owns the managed Secret, so a running manager would requeue on
// every Secret write and make the audit-count assertions (a "full" fetch after
// rotate; exactly-once ordering) racy by construction. Driving Reconcile keeps
// every per-reconcile assertion exact. This is the one deliberate divergence
// from "manager in-process"; the reconciler, its client and the API server are
// all real.
package isolation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// instanceName is the single HikyoInstance every scenario references.
const instanceName = "hikyo-e2e-instance"

// operatorReconciler aliases the reconciler under test so scenario code reads
// cleanly. Its Client, Recorder, Config, Log and TokenMinter fields are exported;
// the TokenMinter field's interface type is unexported but satisfied
// structurally by e2eMinter's exported Mint method.
type operatorReconciler = operator.HikyoSecretReconciler

func newReconciler(cl client.Client, sch *runtime.Scheme, rec record.EventRecorder, ownNS string) *operatorReconciler {
	return &operatorReconciler{
		Client:   cl,
		Scheme:   sch,
		Recorder: rec,
		Config:   operator.Config{OwnNamespace: ownNS, TriggerRollouts: true},
		Log:      discardLog(),
	}
}

func reconcileRequest(ns, name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}
}

// kubeconfigEnv gates the whole suite: absent → skip (handoff § 0.8).
const kubeconfigEnv = "HIKYO_K8S_E2E_KUBECONFIG"

// pauseImage is the workload image (§ 0.8): a do-nothing container, so the
// Deployment/pods schedule on kind without pulling anything heavy.
const pauseImage = "registry.k8s.io/pause:3.10"

// e2eScheme is the runtime scheme for the live client: core + apps + auth +
// apiextensions (to apply CRDs) + the hikyo.dev types.
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

// restConfig builds the kind REST config from the gating kubeconfig, or skips.
func restConfig(t *testing.T) *rest.Config {
	t.Helper()
	path := os.Getenv(kubeconfigEnv)
	if path == "" {
		t.Skipf("%s not set; skipping kind operator e2e", kubeconfigEnv)
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	must(t, err)
	return cfg
}

// repoRoot walks up from the test's working directory to the module root (the
// directory holding go.mod), so chart/hikyo/crds resolves regardless of cwd.
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

// applyCRDs applies both operator CRDs from chart/hikyo/crds and waits until
// each reports Established, so the first CR create does not race admission.
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
			existing := &apiextensionsv1.CustomResourceDefinition{}
			switch err := cl.Get(ctx, types.NamespacedName{Name: crd.Name}, existing); {
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

// poll runs cond until true or the 60s bound (handoff § 0.8: ≤ 60s per scenario
// assertion). A cond error aborts immediately.
func poll(t *testing.T, ctx context.Context, cond func(context.Context) (bool, error)) {
	t.Helper()
	pctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := wait.PollUntilContextTimeout(pctx, 300*time.Millisecond, 60*time.Second, true, cond); err != nil {
		t.Fatalf("condition not met within 60s: %v", err)
	}
}

// opEnv is one scenario's world: a fresh sqlite DB, a fresh in-process TLS
// Hikyo server, a dedicated kind namespace, and a live client. Fresh per
// scenario because rotate-token-key (scenario 2) invalidates every cursor and
// the audit COUNT(*) assertions must run against a private trail.
type opEnv struct {
	t       *testing.T
	ctx     context.Context
	db      *store.DB
	server  *httptest.Server
	caPEM   []byte
	scheme  *runtime.Scheme
	cl      client.Client
	cs      *kubernetes.Clientset
	ns      string // scenario namespace (also the operator's own namespace)
	fed     *service.Federation
	recorder *record.FakeRecorder
}

// newOpEnv seeds the delivery catalogue (two config + two secret keys published
// into env_a1), stands up the TLS server, creates a namespace, and pre-seeds the
// stamp root so write-ordering assertions never see it created mid-flow.
func newOpEnv(t *testing.T, restCfg *rest.Config, sch *runtime.Scheme, withFederation bool) *opEnv {
	t.Helper()
	ctx := t.Context()

	db := seededDB(t, openSQLite)
	identityFixtures(t, db)
	seedFourKeyCatalogue(t, db)

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
	e := &opEnv{t: t, ctx: ctx, db: db, scheme: sch, recorder: record.NewFakeRecorder(500)}
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

// createNamespace makes a uniquely named namespace via GenerateName (the API
// server assigns the suffix, so parallel subtests never collide) and registers
// its deletion.
func (e *opEnv) createNamespace() string {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "hikyo-e2e-"}}
	must(e.t, e.cl.Create(e.ctx, ns))
	e.t.Cleanup(func() {
		_ = e.cl.Delete(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns.Name}})
	})
	return ns.Name
}

// seedStampRoot pre-creates the operator's 32-byte stamp root in the scenario
// namespace (which is also the reconciler's OwnNamespace), matching the operator
// unit harness: its auto-creation is covered by the operator's own tests, and
// pre-seeding keeps write-ordering assertions free of an extra Secret create.
func (e *opEnv) seedStampRoot() {
	root := make([]byte, crypto.KeySize)
	for i := range root {
		root[i] = byte(i * 7)
	}
	must(e.t, e.cl.Create(e.ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: e.ns, Name: hikyov1.StampRootSecretName},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{hikyov1.StampRootKey: root},
	}))
}

// bearerToken mints a workload service-account bearer credential and returns the
// plaintext token (delivered once). read/reveal grants are seeded by the caller.
func (e *opEnv) newWorkloadCredential(name string) (service.ServiceAccountView, service.MintResult) {
	ident := identitySvc(e.db)
	sa, err := ident.CreateServiceAccount(e.ctx, service.LocalPrincipal(identAdmin), prjScope(), name, domain.ClassWorkload)
	must(e.t, err)
	minted, err := ident.MintCredential(e.ctx, service.LocalPrincipal(identAdmin), prjScope(), sa.ID, service.MintRequest{})
	must(e.t, err)
	return sa, minted
}

// instanceURL is the TLS server origin the HikyoInstance points at.
func (e *opEnv) instanceURL() string { return e.server.URL }

// caBundleB64 is the server certificate as base64 PEM for HikyoInstance.caBundle.
func (e *opEnv) caBundleB64() string { return base64.StdEncoding.EncodeToString(e.caPEM) }

// reconciler builds a reconciler bound to the live client, wired with a real
// TokenMinter (kind TokenRequest) for the federation path. NewClientForURL is
// left nil: the default factory dials inst.Spec.URL with decodeCABundle(caBundle)
// — exactly the TLS server URL + cert — and its result type is unexported, so it
// cannot be set from outside package operator anyway.
func (e *opEnv) reconciler() *operatorReconciler {
	return e.reconcilerWith(e.cl)
}

func (e *opEnv) reconcilerWith(cl client.Client) *operatorReconciler {
	r := newReconciler(cl, e.scheme, e.recorder, e.ns)
	r.TokenMinter = e2eMinter{cs: e.cs}
	return r
}

// reconcile drives one synchronous reconcile of the named CR in the scenario
// namespace and returns its result/error.
func (e *opEnv) reconcile(r *operatorReconciler, name string) error {
	e.t.Helper()
	_, err := r.Reconcile(e.ctx, reconcileRequest(e.ns, name))
	return err
}

// drainEvents returns the FakeRecorder reasons emitted so far without blocking.
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

// --- object builders on the live cluster ---

func (e *opEnv) createInstance(name, audience string) *hikyov1.HikyoInstance {
	inst := &hikyov1.HikyoInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: hikyov1.HikyoInstanceSpec{
			URL:      e.instanceURL(),
			CABundle: e.caBundleB64(),
			Audience: audience,
		},
	}
	must(e.t, e.cl.Create(e.ctx, inst))
	e.t.Cleanup(func() {
		_ = e.cl.Delete(context.Background(), &hikyov1.HikyoInstance{ObjectMeta: metav1.ObjectMeta{Name: name}})
	})
	return inst
}

// createBootstrapSecret writes a designated (or not) bootstrap Secret holding a
// bearer token. When designate is true it carries both designation labels for
// instanceLabel.
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

// createServiceAccountObj creates a kind ServiceAccount (optionally designated),
// returning it with its server-assigned UID populated.
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

// crSpec is a compact description of a HikyoSecret to create.
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
			Scope:       hikyov1.Scope{Org: string(orgA), Project: string(prjA1), Environment: string(envA1)},
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
		cr.Spec.Mapping = append(cr.Spec.Mapping, hikyov1.Mapping{Key: m[0], SecretKey: m[1]})
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

// createPauseDeployment creates a replicas=1 pause Deployment, opted-in to the
// named targets when any are given.
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

// stampOf returns the pod-template stamp annotation for target on a Deployment.
func stampOf(d *appsv1.Deployment, target string) string {
	if d.Spec.Template.Annotations == nil {
		return ""
	}
	return d.Spec.Template.Annotations[hikyov1.StampAnnotationPrefix+target]
}

// waitDeploymentSettled blocks until the Deployment's controller has observed
// its latest generation (so a later resourceVersion/generation comparison is not
// racing the built-in controller's status writes).
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

func conditionAbsent(t *testing.T, cr *hikyov1.HikyoSecret, condType string) {
	t.Helper()
	for _, c := range cr.Status.Conditions {
		if c.Type == condType {
			t.Fatalf("condition %q present but should be absent: (%s/%s)", condType, c.Status, c.Reason)
		}
	}
}

// --- audit helpers (payload is a JSON string column; match with LIKE) ---

func (e *opEnv) auditCount(query string) int64 {
	return queryInt(e.t, e.db, query)
}

// deliveryFetchedFull counts full-disposition fetch records that presented a
// cursor.
func (e *opEnv) countFullFetchWithCursor() int64 {
	return e.auditCount(`SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.delivery_fetched' ` +
		`AND payload LIKE '%"disposition":"full"%' AND payload LIKE '%"cursor_presented":true%'`)
}

func (e *opEnv) countCurrentFetch() int64 {
	return e.auditCount(`SELECT COUNT(*) FROM audit_tenant_events WHERE type = 'identity.delivery_fetched' ` +
		`AND payload LIKE '%"disposition":"current"%'`)
}

// --- token minting via the kind TokenRequest subresource ---

// e2eMinter mirrors the production clientsetMinter: it mints a short-lived,
// audience-bound ServiceAccount token via the kind TokenRequest API. It
// satisfies the reconciler's (unexported) tokenMinter interface structurally
// through the exported Mint method.
type e2eMinter struct{ cs *kubernetes.Clientset }

func (m e2eMinter) Mint(ctx context.Context, namespace, serviceAccount, audience string) (string, error) {
	exp := int64(600)
	tr := &authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{
		Audiences:         []string{audience},
		ExpirationSeconds: &exp,
	}}
	out, err := m.cs.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, serviceAccount, tr, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("mint token for %s/%s: %w", namespace, serviceAccount, err)
	}
	return out.Status.Token, nil
}

// defaultAudience mints a token with no requested audience so the kind API
// server stamps its default audience, then reads it back from the token's `aud`
// claim — the value that must go in the issuer's RefusedAudiences.
func (e *opEnv) defaultAudience(serviceAccount string) string {
	tr := &authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{}}
	out, err := e.cs.CoreV1().ServiceAccounts(e.ns).CreateToken(e.ctx, serviceAccount, tr, metav1.CreateOptions{})
	must(e.t, err)
	aud := jwtAudience(e.t, out.Status.Token)
	if aud == "" {
		e.t.Fatal("kind default token carried no audience")
	}
	return aud
}

// jwtAudience decodes a compact JWT's payload and returns the first audience.
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
	// aud is either a string or an array of strings.
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

// discardLog is the operator log sink for tests.
func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// The scenario key set: two config keys and two secret keys (§ 0.8 converge).
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

// seedFourKeyCatalogue declares two config + two secret keys on prj_a1, grants
// the fixture admin the edit/publish/definitions-edit it needs, and publishes
// values for all four into env_a1 (delivery fails closed on an unmaterialized
// environment, so the publish is what makes a fetch answer). Same shape as the
// federation suite's seedDeliveryCatalogue, widened to four keys.
func seedFourKeyCatalogue(t *testing.T, db *store.DB) {
	t.Helper()
	keys := []struct{ id, name, class string }{
		{"key_e2e_cfg1", cfgKeyOne, "config"},
		{"key_e2e_cfg2", cfgKeyTwo, "config"},
		{"key_e2e_sec1", secKeyOne, "secret"},
		{"key_e2e_sec2", secKeyTwo, "secret"},
	}
	for _, k := range keys {
		execRaw(t, db, fmt.Sprintf(
			`INSERT INTO keys (id, org_id, project_id, name, folder_path, classification, description, deprecated, deprecation_note, declaration, required_mode, forbidden_mode, group_id, created_at)
			 VALUES ('%s', 'org_a', 'prj_a1', '%s', '', '%s', '', FALSE, '', '{"rule":{"type":"string"}}', 'none', 'none', NULL, %s)`,
			k.id, k.name, k.class, ts))
	}
	for i, capability := range []string{"edit", "publish", "definitions-edit"} {
		execRaw(t, db, fmt.Sprintf(
			`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
			 VALUES ('g_e2e_%d', '%s', '%s', 'org_a', 'prj_a1', NULL, %s)`,
			i, identAdmin, capability, ts))
	}
	publishDeliveryValues(t, db, envA1, map[string]string{
		cfgKeyOne: cfgValOne, cfgKeyTwo: cfgValTwo,
		secKeyOne: secValOne, secKeyTwo: secValTwo,
	})
}

// newE2EFederation builds a Federation service backed by a real admission
// limiter and a real clock — the federation JWTs are minted by the kind API
// server, so their timestamps are real and the validator's clock must be too.
func newE2EFederation(t *testing.T, db *store.DB) *service.Federation {
	t.Helper()
	limiter, err := admission.New(admission.Config{ArgonMemoryKiB: crypto.PasswordFloor.MemoryKiB, Now: time.Now})
	must(t, err)
	cache := &oidcfed.Cache{Limiter: limiter, Nowf: time.Now, HTTP: http.DefaultClient}
	return &service.Federation{DB: db, Auth: authWithWindow(db), Cache: cache, Now: time.Now}
}
