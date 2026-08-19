package operator

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	hikyov1 "github.com/Hikyo-Org/hikyo/internal/operator/api/v1alpha1"
	opclient "github.com/Hikyo-Org/hikyo/internal/operator/client"
)

const (
	testNS       = "team-a"
	testOwnNS    = "hikyo-system"
	testInstance = "prod"
	testTarget   = "app-secret"
)

var testClock = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

// deliveryStub is a programmable Hikyo delivery server. Tests set status/json
// before each reconcile and read back the query params the operator sent.
type deliveryStub struct {
	mu             sync.Mutex
	status         int
	json           string
	lastCursor     string
	lastAck        string
	lastProjection string
	requests       int
}

func (s *deliveryStub) set(status int, json string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.json = status, json
}

func (s *deliveryStub) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	q := r.URL.Query()
	s.lastCursor = q.Get("cursor")
	s.lastAck = q.Get("acknowledged_keys")
	s.lastProjection = q.Get("projection")
	status := s.status
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status == http.StatusOK {
		_, _ = io.WriteString(w, s.json)
	}
}

func serverCAPEM(t *testing.T, srv *httptest.Server) []byte {
	t.Helper()
	c := srv.Certificate()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// stubMinter returns a fixed federation token; the fake client cannot serve the
// token subresource, so the reconciler's TokenMinter is injected in tests.
type stubMinter struct {
	token string
	err   error
	last  struct{ ns, sa, audience string }
}

func (m *stubMinter) Mint(_ context.Context, ns, sa, audience string) (string, error) {
	m.last.ns, m.last.sa, m.last.audience = ns, sa, audience
	if m.err != nil {
		return "", m.err
	}
	return m.token, nil
}

// harness wires a fake client, a reconciler, and a delivery stub.
type harness struct {
	t        *testing.T
	scheme   *runtime.Scheme
	cl       client.Client
	r        *HikyoSecretReconciler
	stub     *deliveryStub
	server   *httptest.Server
	recorder *record.FakeRecorder
	events   chan string
	minter   *stubMinter
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	sch := runtime.NewScheme()
	if err := scheme.AddToScheme(sch); err != nil {
		t.Fatal(err)
	}
	if err := hikyov1.AddToScheme(sch); err != nil {
		t.Fatal(err)
	}
	return sch
}

// newHarness builds the fixture. objs are seeded into the fake client;
// interceptors are optional (write-ordering / fault-injection tests).
func newHarness(t *testing.T, interceptors interceptor.Funcs, objs ...client.Object) *harness {
	t.Helper()
	sch := testScheme(t)
	stub := &deliveryStub{}
	srv := httptest.NewTLSServer(http.HandlerFunc(stub.handler))
	t.Cleanup(srv.Close)
	ca := serverCAPEM(t, srv)

	// Seed the operator stamp-root so reconciles do not create it mid-flow (keeps
	// write-ordering assertions clean). Its auto-creation is covered separately.
	objs = append(objs, makeStampRoot())

	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithObjects(objs...).
		WithStatusSubresource(&hikyov1.HikyoSecret{}).
		WithInterceptorFuncs(interceptors).
		Build()

	rec := record.NewFakeRecorder(200)
	minter := &stubMinter{token: "fed-token-abc"}
	r := &HikyoSecretReconciler{
		Client: cl,
		// The fake client serves both cached and uncached reads; wiring it as the
		// Reader mirrors production's mgr.GetAPIReader() so Secret/SA reads work.
		Reader:   cl,
		Scheme:   sch,
		Recorder: rec,
		Config:   Config{OwnNamespace: testOwnNS, TriggerRollouts: true},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		NewClientForURL: func(rawURL string, _ []byte) (deliveryClient, error) {
			return opclient.NewClient(srv.URL, ca, "hikyo-operator/test")
		},
		TokenMinter: minter,
		now:         func() time.Time { return testClock },
	}
	return &harness{t: t, scheme: sch, cl: cl, r: r, stub: stub, server: srv, recorder: rec, events: rec.Events, minter: minter}
}

func (h *harness) reconcile(name string) (ctrl.Result, error) {
	h.t.Helper()
	return h.r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: testNS, Name: name},
	})
}

func (h *harness) getCR(name string) *hikyov1.HikyoSecret {
	h.t.Helper()
	var cr hikyov1.HikyoSecret
	if err := h.cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: name}, &cr); err != nil {
		h.t.Fatalf("get CR %q: %v", name, err)
	}
	return &cr
}

func (h *harness) getSecret(ns, name string) (*corev1.Secret, bool) {
	h.t.Helper()
	var sec corev1.Secret
	err := h.cl.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &sec)
	if apierrors.IsNotFound(err) {
		return nil, false
	}
	if err != nil {
		h.t.Fatalf("get secret %s/%s: %v", ns, name, err)
	}
	return &sec, true
}

func (h *harness) getDeployment(name string) *appsv1.Deployment {
	h.t.Helper()
	var d appsv1.Deployment
	if err := h.cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: name}, &d); err != nil {
		h.t.Fatalf("get deployment %q: %v", name, err)
	}
	return &d
}

// drainEvents collects the reasons emitted so far without blocking.
func (h *harness) drainEvents() []string {
	var out []string
	for {
		select {
		case e := <-h.events:
			out = append(out, e)
		default:
			return out
		}
	}
}

func hasEventReason(events []string, reason string) bool {
	for _, e := range events {
		if strings.Contains(e, reason) {
			return true
		}
	}
	return false
}

// ---- object builders ----

func makeInstance(audience string) *hikyov1.HikyoInstance {
	return &hikyov1.HikyoInstance{
		ObjectMeta: metav1.ObjectMeta{Name: testInstance, UID: "inst-uid-1"},
		Spec:       hikyov1.HikyoInstanceSpec{URL: "https://placeholder.invalid", Audience: audience},
	}
}

type crOpt func(*hikyov1.HikyoSecret)

func withMapping(pairs ...[2]string) crOpt {
	return func(cr *hikyov1.HikyoSecret) {
		cr.Spec.Mapping = nil
		for _, p := range pairs {
			cr.Spec.Mapping = append(cr.Spec.Mapping, hikyov1.Mapping{Key: hikyov1.KeyName(p[0]), SecretKey: p[1]})
		}
	}
}

func withSA(name string) crOpt {
	return func(cr *hikyov1.HikyoSecret) {
		cr.Spec.Auth = hikyov1.AuthRef{ServiceAccountRef: &hikyov1.LocalObjectRef{Name: name}}
	}
}

func withProjection(p hikyov1.Projection) crOpt {
	return func(cr *hikyov1.HikyoSecret) { cr.Spec.Projection = p }
}

func withPolicy(p hikyov1.CreationPolicy) crOpt {
	return func(cr *hikyov1.HikyoSecret) { cr.Spec.Target.CreationPolicy = p }
}

func withCreation(ts time.Time, uid string) crOpt {
	return func(cr *hikyov1.HikyoSecret) {
		cr.CreationTimestamp = metav1.NewTime(ts)
		cr.UID = types.UID(uid)
	}
}

func makeCR(name string, opts ...crOpt) *hikyov1.HikyoSecret {
	cr := &hikyov1.HikyoSecret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNS, Name: name, UID: types.UID("cr-uid-" + name),
			CreationTimestamp: metav1.NewTime(testClock),
		},
		Spec: hikyov1.HikyoSecretSpec{
			InstanceRef: hikyov1.InstanceRef{Name: testInstance},
			Auth:        hikyov1.AuthRef{SecretRef: &hikyov1.LocalObjectRef{Name: "boot"}},
			Scope:       hikyov1.Scope{Org: "acme", Project: "web", Environment: "prod"},
			Mapping:     []hikyov1.Mapping{{Key: "API_KEY", SecretKey: "API_KEY"}},
			Target:      hikyov1.Target{Name: testTarget, CreationPolicy: hikyov1.CreationPolicyOwner},
			Projection:  hikyov1.ProjectionFull,
		},
	}
	for _, o := range opts {
		o(cr)
	}
	return cr
}

// makeBootstrapSecret builds a designated (or not) bootstrap Secret.
func makeBootstrapSecret(name, instanceLabel, token string, designate bool) *corev1.Secret {
	labels := map[string]string{}
	if designate {
		labels[hikyov1.LabelDelivery] = hikyov1.LabelDeliveryValue
		labels[hikyov1.LabelInstance] = instanceLabel
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: name, UID: types.UID("boot-uid-" + name), Labels: labels},
		Data:       map[string][]byte{hikyov1.BootstrapTokenKey: []byte(token)},
	}
}

func makeStampRoot() *corev1.Secret {
	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(i + 1)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: testOwnNS, Name: hikyov1.StampRootSecretName, UID: "stamp-root-uid"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{hikyov1.StampRootKey: root},
	}
}

func makeServiceAccount(name, instanceLabel string, designate bool) *corev1.ServiceAccount {
	labels := map[string]string{}
	if designate {
		labels[hikyov1.LabelDelivery] = hikyov1.LabelDeliveryValue
		labels[hikyov1.LabelInstance] = instanceLabel
	}
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: name, UID: types.UID("sa-uid-" + name), Labels: labels},
	}
}

// makeOwnedSecret builds a managed Secret already controlled by cr, with data.
func makeOwnedSecret(t *testing.T, sch *runtime.Scheme, cr *hikyov1.HikyoSecret, data map[string][]byte) *corev1.Secret {
	t.Helper()
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: cr.Spec.Target.Name, UID: "managed-uid-1"},
		Type:       corev1.SecretTypeOpaque,
		Data:       data,
	}
	if err := ctrl.SetControllerReference(cr, sec, sch); err != nil {
		t.Fatalf("set controller ref: %v", err)
	}
	return sec
}

// makeOptedInDeployment builds a Deployment consuming the target (opt-in).
func makeOptedInDeployment(name string, consumesTargets ...string) *appsv1.Deployment {
	ann := map[string]string{}
	if len(consumesTargets) > 0 {
		ann[hikyov1.AnnotationWorkloadSecrets] = strings.Join(consumesTargets, ",")
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: name, Annotations: ann},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{}},
		},
	}
}

// deliveryJSON builds a 200 response body.
func deliveryJSON(current bool, cursor, changeToken string, keys []deliveredKey, credExpiresAt *time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, `{"current":%t,"cursor":%q,"change_token":%q,"schema_revision":3,"pin_expired":false`, current, cursor, changeToken)
	if credExpiresAt != nil {
		fmt.Fprintf(&b, `,"credential_expires_at":%q`, credExpiresAt.Format(time.RFC3339))
	}
	b.WriteString(`,"keys":[`)
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"name":%q,"classification":%q,"presence":"set"`, k.name, k.classification)
		if k.hasValue {
			fmt.Fprintf(&b, `,"value":%q`, k.value)
		}
		b.WriteString("}")
	}
	b.WriteString("]}")
	return b.String()
}

type deliveredKey struct {
	name           string
	classification string
	value          string
	hasValue       bool
}

func configVal(name, value string) deliveredKey {
	return deliveredKey{name: name, classification: "config", value: value, hasValue: true}
}
func secretVal(name, value string) deliveredKey {
	return deliveredKey{name: name, classification: "secret", value: value, hasValue: true}
}
func secretPresenceOnly(name string) deliveredKey {
	return deliveredKey{name: name, classification: "secret", hasValue: false}
}

func condStatus(cr *hikyov1.HikyoSecret, condType string) (metav1.ConditionStatus, string, bool) {
	for _, c := range cr.Status.Conditions {
		if c.Type == condType {
			return c.Status, c.Reason, true
		}
	}
	return "", "", false
}

func requireCond(t *testing.T, cr *hikyov1.HikyoSecret, condType string, status metav1.ConditionStatus, reason string) {
	t.Helper()
	s, r, ok := condStatus(cr, condType)
	if !ok {
		t.Fatalf("condition %q absent; conditions=%v", condType, cr.Status.Conditions)
	}
	if s != status || r != reason {
		t.Fatalf("condition %q = (%s/%s), want (%s/%s)", condType, s, r, status, reason)
	}
}

func hasControllerRef(sec *corev1.Secret, cr *hikyov1.HikyoSecret) bool {
	return metav1.IsControlledBy(sec, cr)
}

func stampAnnotation(d *appsv1.Deployment) string {
	if d.Spec.Template.Annotations == nil {
		return ""
	}
	return d.Spec.Template.Annotations[hikyov1.StampAnnotationPrefix+testTarget]
}

// secretWrites counts Create/Update/Patch calls against the managed target
// Secret, so a test can assert "no write at all" rather than inferring it from
// final state (a metadata-only write or a failed attempt is invisible to a
// state check).
type secretWrites struct{ n int }

func (w *secretWrites) interceptors() interceptor.Funcs {
	hit := func(obj client.Object) {
		if s, ok := obj.(*corev1.Secret); ok && s.Namespace == testNS && s.Name == testTarget {
			w.n++
		}
	}
	return interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			hit(obj)
			return c.Create(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			hit(obj)
			return c.Update(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			hit(obj)
			return c.Patch(ctx, obj, patch, opts...)
		},
	}
}

// statusFields captures the status object written on each SubResourceUpdate, so
// write-ordering can require the cursor/binding/stamp/RV were all present on the
// LAST status write rather than accepting any status update.
type statusField struct {
	cursor, binding, stamp, rv string
}

func recordStatusWrites(dst *[]statusField) interceptor.Funcs {
	return interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if cr, ok := obj.(*hikyov1.HikyoSecret); ok {
				*dst = append(*dst, statusField{
					cursor:  cr.Status.Cursor,
					binding: cr.Status.CursorBinding,
					stamp:   cr.Status.Stamp,
					rv:      cr.Status.ManagedSecretResourceVersion,
				})
			}
			return c.Status().Update(ctx, obj, opts...)
		},
	}
}
