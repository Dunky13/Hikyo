package operator

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/delivery"
	hikyov1 "github.com/Hikyo-Org/hikyo/internal/operator/api/v1alpha1"
	opclient "github.com/Hikyo-Org/hikyo/internal/operator/client"
)

// credentialExpiryHorizon is the ahead-of-time credential-expiry warning window
// (§ 0.9: 7 days, this ticket's value).
const credentialExpiryHorizon = 7 * 24 * time.Hour

// envIdentifier matches a valid environment-variable name. A mapped secretKey
// failing it is silently skipped by `envFrom` at pod start (a Kubernetes caveat
// past Hikyo's guarantee), so delivery warns rather than owns it (§ 0.3
// EnvFromSkip).
var envIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// HikyoSecretReconciler converges one managed Secret per HikyoSecret CR under the
// identity the CR names — the operator holds none of its own.
type HikyoSecretReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	Config   Config
	Log      *slog.Logger

	// NewClientForURL builds the delivery client for an instance; nil defaults to
	// the real HTTPS client. Tests inject a stub.
	NewClientForURL func(rawURL string, caBundlePEM []byte) (deliveryClient, error)
	// TokenMinter mints federation tokens; nil is a hard error on the SA path.
	TokenMinter tokenMinter

	// now is injected in tests for deterministic expiry conditions.
	now func() time.Time
}

func (r *HikyoSecretReconciler) clientFactory() func(string, []byte) (deliveryClient, error) {
	if r.NewClientForURL != nil {
		return r.NewClientForURL
	}
	return defaultClientFactory
}

func (r *HikyoSecretReconciler) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// Reconcile drives one CR toward its converged state per § 0.4/§ 0.5.
func (r *HikyoSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cr hikyov1.HikyoSecret
	if err := r.Get(ctx, req.NamespacedName, &cr); err != nil {
		// NotFound: the CR is gone and its managed Secret was GC'd (Owner) or
		// finalizer-handled (Orphan). Nothing to do.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Deletion / finalizer handling first — an Orphan CR must strip the ownerRef
	// before it is released so the Secret survives unowned (§ 0.2).
	if !cr.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &cr)
	}
	if res, done, err := r.ensureFinalizer(ctx, &cr); done {
		return res, err
	}

	return r.reconcileActive(ctx, &cr)
}

// reconcileActive is the non-deletion path.
func (r *HikyoSecretReconciler) reconcileActive(ctx context.Context, cr *hikyov1.HikyoSecret) (ctrl.Result, error) {
	// Resolve the cluster-scoped instance.
	var inst hikyov1.HikyoInstance
	if err := r.Get(ctx, types.NamespacedName{Name: cr.Spec.InstanceRef.Name}, &inst); err != nil {
		if apierrors.IsNotFound(err) {
			r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonBlocked,
				"HikyoInstance %q not found", cr.Spec.InstanceRef.Name)
			r.setCond(cr, hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonFetchFailed,
				fmt.Sprintf("HikyoInstance %q not found", cr.Spec.InstanceRef.Name))
			cr.Status.Lifecycle = hikyov1.LifecycleRetained
			return r.done(ctx, cr, ctrl.Result{}, fmt.Errorf("instance %q not found", cr.Spec.InstanceRef.Name))
		}
		return ctrl.Result{}, err
	}

	// Designation + credential acquisition.
	cred, res, done, err := r.acquireCredential(ctx, cr, &inst)
	if done {
		return res, err
	}

	// Target-claim conflict (deterministic: earliest creationTimestamp, then
	// lowest UID, wins) — refuse the loser before any write.
	if conflicted, winner, err := r.targetClaimed(ctx, cr); err != nil {
		return ctrl.Result{}, err
	} else if conflicted {
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonTargetClaimed,
			"target %q already claimed by HikyoSecret %q", cr.Spec.Target.Name, winner)
		r.setCond(cr, hikyov1.ConditionConflict, metav1.ConditionTrue, hikyov1.ReasonTargetClaimed,
			fmt.Sprintf("target %q is claimed by earlier HikyoSecret %q", cr.Spec.Target.Name, winner))
		cr.Status.Lifecycle = hikyov1.LifecycleRefused
		return r.done(ctx, cr, r.resyncResult(cr), nil)
	}
	// No active conflict — clear a stale Conflict condition.
	meta.RemoveStatusCondition(&cr.Status.Conditions, hikyov1.ConditionConflict)

	// Managed-Secret ownership pre-check: an existing target not controlled by
	// this CR is a takeover attempt, refused (never adopted).
	existing, existed, err := r.getManagedSecret(ctx, cr)
	if err != nil {
		return ctrl.Result{}, err
	}
	if existed && !metav1.IsControlledBy(existing, cr) {
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonManagedSecretNotOwned,
			"Secret %q exists without this CR's controller ownerRef", cr.Spec.Target.Name)
		r.setCond(cr, hikyov1.ConditionConflict, metav1.ConditionTrue, hikyov1.ReasonManagedSecretNotOwned,
			fmt.Sprintf("Secret %q exists and is not controlled by this HikyoSecret; refusing to adopt", cr.Spec.Target.Name))
		cr.Status.Lifecycle = hikyov1.LifecycleRefused
		return r.done(ctx, cr, r.resyncResult(cr), nil)
	}

	// Loader-control refusal against the mapping (§ 0.6) — before the fetch, no
	// write. The acknowledged list is still sent on the accepted path so the
	// server records it.
	mappedKeys := make([]string, 0, len(cr.Spec.Mapping))
	for _, m := range cr.Spec.Mapping {
		mappedKeys = append(mappedKeys, m.EffectiveSecretKey())
	}
	if refused, extra := delivery.Unacknowledged(mappedKeys, cr.Spec.AcknowledgedLoaderKeys); len(refused) > 0 || len(extra) > 0 {
		msg := loaderControlMessage(refused, extra)
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonLoaderControlUnacknowledged, "%s", msg)
		r.setCond(cr, hikyov1.ConditionDelivery, metav1.ConditionFalse, hikyov1.ReasonLoaderControlUnacknowledged, msg)
		cr.Status.Lifecycle = hikyov1.LifecycleRefused
		return r.done(ctx, cr, r.resyncResult(cr), nil)
	}

	// Cursor eligibility (§ 0.5) — present only when the recorded delivery is
	// verifiably still in effect and the binding is unchanged.
	fetchCursor := r.eligibleCursor(ctx, cr, &inst, cred, existing, existed)

	// Fetch.
	dc, err := r.clientFactory()(inst.Spec.URL, decodeCABundle(inst.Spec.CABundle))
	if err != nil {
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonFetchFailed, "build delivery client: %v", err)
		r.setCond(cr, hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonFetchFailed, err.Error())
		cr.Status.Lifecycle = hikyov1.LifecycleRetained
		return r.done(ctx, cr, ctrl.Result{}, err)
	}
	resp, outcome, fetchErr := dc.Fetch(ctx, opclient.FetchRequest{
		Org: cr.Spec.Scope.Org, Project: cr.Spec.Scope.Project, Environment: cr.Spec.Scope.Environment,
		Cursor:           fetchCursor,
		Projection:       string(effectiveProjection(cr)),
		AcknowledgedKeys: cr.Spec.AcknowledgedLoaderKeys,
		Bearer:           cred.token,
	})

	now := metav1.NewTime(r.clock())
	cr.Status.LastFetch = &now

	switch outcome {
	case opclient.OutcomeFetchFailed:
		// Retain last-synced Secret unchanged, backoff. Cursor never advanced.
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonFetchFailed, "%v", fetchErr)
		r.setCond(cr, hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonFetchFailed, fetchErr.Error())
		cr.Status.Lifecycle = hikyov1.LifecycleRetained
		return r.done(ctx, cr, ctrl.Result{}, fetchErr)
	case opclient.OutcomeNotMaterialized:
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonNotMaterialized, "%v", fetchErr)
		r.setCond(cr, hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonNotMaterialized, fetchErr.Error())
		cr.Status.Lifecycle = hikyov1.LifecycleRetained
		return r.done(ctx, cr, r.resyncResult(cr), nil)
	case opclient.OutcomeScrub:
		return r.scrub(ctx, cr, fetchErr)
	case opclient.OutcomeOK:
		return r.deliver(ctx, cr, &inst, cred, resp, existing, existed)
	default:
		return ctrl.Result{}, fmt.Errorf("operator: unhandled fetch outcome %v", outcome)
	}
}

// deliver handles a 200 response: either "current" (nothing written) or a full
// delivery (§ 0.4 normal, § 0.5 write ordering).
func (r *HikyoSecretReconciler) deliver(
	ctx context.Context, cr *hikyov1.HikyoSecret, inst *hikyov1.HikyoInstance, cred credential,
	resp *opclient.DeliveryResponse, existing *corev1.Secret, existed bool,
) (ctrl.Result, error) {
	r.applyCredentialExpiry(cr, resp.CredentialExpiresAt)

	if resp.Current {
		// Cursor answered current: no plaintext, no write. Its eligibility was
		// already proven (a "current" answer is only served for an eligible
		// cursor), so the recorded cursor/stamp stand.
		r.setCond(cr, hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonCurrent,
			"conditional fetch answered current; managed Secret unchanged")
		cr.Status.Lifecycle = hikyov1.LifecycleSynced
		return r.done(ctx, cr, r.resyncResult(cr), nil)
	}

	// Index the manifest by key name.
	byName := make(map[string]opclient.DeliveredKey, len(resp.Keys))
	for _, k := range resp.Keys {
		byName[k.Name] = k
	}

	var missing, presenceOnly, envSkip []string
	data := map[string][]byte{}
	pairs := make([]crypto.StampPair, 0, len(cr.Spec.Mapping))
	for _, m := range cr.Spec.Mapping {
		k, ok := byName[m.Key]
		if !ok {
			missing = append(missing, m.Key)
			continue
		}
		if k.Value == nil {
			// Presence-only: a mapped secret the principal cannot reveal (or any
			// mapped key delivered value-free). All-or-nothing turns on this.
			presenceOnly = append(presenceOnly, m.Key)
			continue
		}
		dest := m.EffectiveSecretKey()
		data[dest] = []byte(*k.Value)
		pairs = append(pairs, crypto.StampPair{SecretKey: dest, Value: *k.Value})
		if !envIdentifier.MatchString(dest) {
			envSkip = append(envSkip, dest)
		}
	}

	// All-or-nothing: any mapped key arriving presence-only refuses the whole
	// sync — no partial write (§ 0.4 refusal). Retain the existing Secret.
	if len(presenceOnly) > 0 {
		sort.Strings(presenceOnly)
		msg := fmt.Sprintf("undelivered (presence-only) mapped keys: %s. Grant the machine principal `reveal` on the project (the per-project machine-reveal opt-in) to deliver their values",
			strings.Join(presenceOnly, ", "))
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonUndeliveredSecrets, "%s", msg)
		r.setCond(cr, hikyov1.ConditionDelivery, metav1.ConditionFalse, hikyov1.ReasonUndeliveredSecrets, msg)
		cr.Status.Lifecycle = hikyov1.LifecycleRefused
		return r.done(ctx, cr, r.resyncResult(cr), nil)
	}

	// KeysMissing is informational: converge with what is present, drop the rest.
	if len(missing) > 0 {
		sort.Strings(missing)
		msg := fmt.Sprintf("mapped source keys absent from the manifest (dropped): %s", strings.Join(missing, ", "))
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonKeysMissing, "%s", msg)
		r.setCond(cr, hikyov1.ConditionDelivery, metav1.ConditionFalse, hikyov1.ReasonKeysMissing, msg)
	} else if len(envSkip) > 0 {
		sort.Strings(envSkip)
		msg := fmt.Sprintf("delivered, but these data keys are not valid env identifiers and envFrom will skip them: %s", strings.Join(envSkip, ", "))
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonEnvFromSkip, "%s", msg)
		// Warning, Synced still True — a delivered caveat, not a refusal.
		r.setCond(cr, hikyov1.ConditionDelivery, metav1.ConditionTrue, hikyov1.ReasonEnvFromSkip, msg)
	} else {
		meta.RemoveStatusCondition(&cr.Status.Conditions, hikyov1.ConditionDelivery)
	}

	// Compute the per-target stamp over the delivered pairs.
	stamp, err := r.computeStamp(ctx, inst, cr, pairs)
	if err != nil {
		return ctrl.Result{}, err
	}

	// § 0.5 step 1: write the managed Secret (create-only-if-absent with the
	// controller ownerRef; update only if controlled, with a resourceVersion
	// precondition; re-Get and verify).
	written, err := r.writeManagedSecret(ctx, cr, data, existing, existed)
	if err != nil {
		// A write failure before the cursor is persisted leaves no cursor: the
		// next reconcile is a full fetch (idempotent).
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonFetchFailed, "managed Secret write failed: %v", err)
		r.setCond(cr, hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonFetchFailed, err.Error())
		cr.Status.Lifecycle = hikyov1.LifecycleRetained
		return r.done(ctx, cr, ctrl.Result{}, err)
	}

	// § 0.5 step 2: workload patches (gated by TRIGGER_ROLLOUTS). A patch FAILURE
	// does not roll back the Secret but DOES block the cursor advance, so the
	// next reconcile re-attempts. A patched-but-not-progressed workload
	// (Rollout=False/Stalled) is informational and does NOT block the cursor —
	// delivery succeeded.
	stalled, rolloutErr := r.patchWorkloads(ctx, cr, stamp)
	if rolloutErr != nil {
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonStalled, "workload patch: %v", rolloutErr)
		r.setCond(cr, hikyov1.ConditionRollout, metav1.ConditionFalse, hikyov1.ReasonStalled, rolloutErr.Error())
		// Secret written but rollout patch failed: retain the delivered Secret,
		// do not advance the cursor, requeue with backoff.
		cr.Status.Lifecycle = hikyov1.LifecycleSynced
		cr.Status.Stamp = stamp
		cr.Status.ManagedSecretUID = string(written.UID)
		cr.Status.ManagedSecretResourceVersion = written.ResourceVersion
		r.setCond(cr, hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonDelivered,
			"values delivered to the managed Secret")
		return r.done(ctx, cr, ctrl.Result{}, rolloutErr)
	}
	if len(stalled) > 0 {
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonStalled, "opted-in workloads not progressed: %s", strings.Join(stalled, ", "))
		r.setCond(cr, hikyov1.ConditionRollout, metav1.ConditionFalse, hikyov1.ReasonStalled,
			fmt.Sprintf("opted-in workloads not progressed after the stamp patch: %s", strings.Join(stalled, ", ")))
	} else {
		meta.RemoveStatusCondition(&cr.Status.Conditions, hikyov1.ConditionRollout)
	}
	meta.RemoveStatusCondition(&cr.Status.Conditions, hikyov1.ConditionScrubbed)

	// § 0.5 step 3: persist cursor + binding + stamp + managedSecretResourceVersion
	// LAST, only after 1 and 2 succeeded.
	deliveredAt := metav1.NewTime(r.clock())
	cr.Status.Cursor = resp.Cursor
	cr.Status.CursorBinding = bindingDigest(bindingInputFor(cr, inst, cred))
	cr.Status.Stamp = stamp
	cr.Status.ManagedSecretUID = string(written.UID)
	cr.Status.ManagedSecretResourceVersion = written.ResourceVersion
	cr.Status.LastDelivery = &deliveredAt
	cr.Status.Lifecycle = hikyov1.LifecycleSynced
	r.setCond(cr, hikyov1.ConditionSynced, metav1.ConditionTrue, hikyov1.ReasonDelivered,
		"values delivered to the managed Secret")
	return r.done(ctx, cr, r.resyncResult(cr), nil)
}

func loaderControlMessage(refused, extra []string) string {
	var b strings.Builder
	b.WriteString("loader-control keys require exact acknowledgement in spec.acknowledgedLoaderKeys")
	if len(refused) > 0 {
		fmt.Fprintf(&b, "; unacknowledged mapped keys: %s", strings.Join(refused, ", "))
	}
	if len(extra) > 0 {
		fmt.Fprintf(&b, "; acknowledged but not mapped: %s", strings.Join(extra, ", "))
	}
	return b.String()
}

// effectiveProjection returns the CR's projection, defaulting to full.
func effectiveProjection(cr *hikyov1.HikyoSecret) hikyov1.Projection {
	if cr.Spec.Projection == "" {
		return hikyov1.ProjectionFull
	}
	return cr.Spec.Projection
}
