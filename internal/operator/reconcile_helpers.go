package operator

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	hikyov1 "github.com/Hikyo-Org/hikyo/internal/operator/api/v1alpha1"
)

// credential is the acquired fetch credential plus the identity the cursor
// binding tracks: the referenced Secret/SA UID + resourceVersion, so any edit to
// the credential object (even a relabel) moves the binding and forces a
// cursor-less full fetch (§ 0.5).
type credential struct {
	token           string
	uid             string
	resourceVersion string
}

// acquireCredential runs the designation checks (§ 0.2) and obtains the fetch
// credential. done=true means the caller returns (res, err) directly — a
// designation refusal writes its own status.
func (r *HikyoSecretReconciler) acquireCredential(
	ctx context.Context, cr *hikyov1.HikyoSecret, inst *hikyov1.HikyoInstance,
) (cred credential, res ctrl.Result, done bool, err error) {
	switch {
	case cr.Spec.Auth.SecretRef != nil:
		return r.acquireBootstrap(ctx, cr)
	case cr.Spec.Auth.ServiceAccountRef != nil:
		return r.acquireFederation(ctx, cr, inst)
	default:
		// CEL guarantees exactly-one-of, so this is unreachable in a valid CR;
		// fail loud rather than fetch without a credential.
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonSecretNotDesignated, "auth sets neither secretRef nor serviceAccountRef")
		r.setCond(cr, hikyov1.ConditionDesignation, metav1.ConditionFalse, hikyov1.ReasonSecretNotDesignated, "auth sets neither credential ref")
		cr.Status.Lifecycle = hikyov1.LifecycleRefused
		res, err = r.done(ctx, cr, r.resyncResult(cr), nil)
		return credential{}, res, true, err
	}
}

func (r *HikyoSecretReconciler) acquireBootstrap(
	ctx context.Context, cr *hikyov1.HikyoSecret,
) (credential, ctrl.Result, bool, error) {
	var sec corev1.Secret
	name := cr.Spec.Auth.SecretRef.Name
	// Uncached: the operator holds no list/watch on Secrets, and the credential
	// object's identity must be read fresh (its UID+resourceVersion binds the
	// cursor).
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: cr.Namespace, Name: name}, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			return r.designationRefusal(ctx, cr, hikyov1.ReasonSecretNotDesignated,
				fmt.Sprintf("bootstrap Secret %q not found", name))
		}
		if res, derr, handled := r.accessError(ctx, cr, err, "bootstrap Secret"); handled {
			return credential{}, res, true, derr
		}
		return credential{}, ctrl.Result{}, true, err
	}
	if !designated(sec.Labels, cr.Spec.InstanceRef.Name) {
		reason := hikyov1.ReasonSecretNotDesignated
		if mismatchedInstance(sec.Labels, cr.Spec.InstanceRef.Name) {
			reason = hikyov1.ReasonInstanceMismatch
		}
		return r.designationRefusal(ctx, cr, reason,
			fmt.Sprintf("bootstrap Secret %q lacks the required designation labels (%s=true, %s=%s)",
				name, hikyov1.LabelDelivery, hikyov1.LabelInstance, cr.Spec.InstanceRef.Name))
	}
	token, err := bootstrapToken(&sec)
	if err != nil {
		return r.designationRefusal(ctx, cr, hikyov1.ReasonSecretNotDesignated, err.Error())
	}
	r.clearDesignation(cr)
	return credential{token: token, uid: string(sec.UID), resourceVersion: sec.ResourceVersion}, ctrl.Result{}, false, nil
}

func (r *HikyoSecretReconciler) acquireFederation(
	ctx context.Context, cr *hikyov1.HikyoSecret, inst *hikyov1.HikyoInstance,
) (credential, ctrl.Result, bool, error) {
	var sa corev1.ServiceAccount
	name := cr.Spec.Auth.ServiceAccountRef.Name
	// Uncached: RBAC grants only `get` on ServiceAccounts (no list/watch), so a
	// cached read could never start its informer.
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: cr.Namespace, Name: name}, &sa); err != nil {
		if apierrors.IsNotFound(err) {
			return r.designationRefusal(ctx, cr, hikyov1.ReasonServiceAccountNotDesignated,
				fmt.Sprintf("ServiceAccount %q not found", name))
		}
		if res, derr, handled := r.accessError(ctx, cr, err, "ServiceAccount"); handled {
			return credential{}, res, true, derr
		}
		return credential{}, ctrl.Result{}, true, err
	}
	if !designated(sa.Labels, cr.Spec.InstanceRef.Name) {
		reason := hikyov1.ReasonServiceAccountNotDesignated
		if mismatchedInstance(sa.Labels, cr.Spec.InstanceRef.Name) {
			reason = hikyov1.ReasonInstanceMismatch
		}
		return r.designationRefusal(ctx, cr, reason,
			fmt.Sprintf("ServiceAccount %q lacks the required designation labels (%s=true, %s=%s)",
				name, hikyov1.LabelDelivery, hikyov1.LabelInstance, cr.Spec.InstanceRef.Name))
	}
	if inst.Spec.Audience == "" {
		// Federation needs the mandatory, non-default per-instance audience.
		return r.designationRefusal(ctx, cr, hikyov1.ReasonAudienceMissing,
			fmt.Sprintf("HikyoInstance %q declares no audience; the ServiceAccount federation path requires one", inst.Name))
	}
	if r.TokenMinter == nil {
		return credential{}, ctrl.Result{}, true, fmt.Errorf("operator: no token minter configured for the federation path")
	}
	token, err := r.TokenMinter.Mint(ctx, cr.Namespace, name, inst.Spec.Audience)
	if err != nil {
		// A failed TokenRequest is ADR case 2 — retain, backoff.
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonFetchFailed, "TokenRequest failed: %v", err)
		r.setCond(cr, hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonFetchFailed, err.Error())
		cr.Status.Lifecycle = hikyov1.LifecycleRetained
		res, derr := r.done(ctx, cr, ctrl.Result{}, err)
		return credential{}, res, true, derr
	}
	r.clearDesignation(cr)
	return credential{token: token, uid: string(sa.UID), resourceVersion: sa.ResourceVersion}, ctrl.Result{}, false, nil
}

func (r *HikyoSecretReconciler) designationRefusal(
	ctx context.Context, cr *hikyov1.HikyoSecret, reason, msg string,
) (credential, ctrl.Result, bool, error) {
	r.event(cr, corev1.EventTypeWarning, reason, "%s", msg)
	r.setCond(cr, hikyov1.ConditionDesignation, metav1.ConditionFalse, reason, msg)
	cr.Status.Lifecycle = hikyov1.LifecycleRefused
	res, err := r.done(ctx, cr, r.resyncResult(cr), nil)
	return credential{}, res, true, err
}

func (r *HikyoSecretReconciler) clearDesignation(cr *hikyov1.HikyoSecret) {
	meta.RemoveStatusCondition(&cr.Status.Conditions, hikyov1.ConditionDesignation)
}

// designated reports whether an object carries BOTH required designation labels
// with the delivery flag true and the instance label naming this CR's instance
// (§ 0.2). Naming a credential is not authority to use it.
func designated(labels map[string]string, instanceName string) bool {
	return labels[hikyov1.LabelDelivery] == hikyov1.LabelDeliveryValue &&
		labels[hikyov1.LabelInstance] == instanceName
}

// mismatchedInstance distinguishes "designated for a DIFFERENT instance" from
// "not designated at all", so the condition can name InstanceMismatch — the hole
// where a Secret designated for instance A would ship A's token to instance B.
func mismatchedInstance(labels map[string]string, instanceName string) bool {
	got, ok := labels[hikyov1.LabelInstance]
	return labels[hikyov1.LabelDelivery] == hikyov1.LabelDeliveryValue && ok && got != instanceName
}

// eligibleCursor returns the cursor to present, or "" for a full fetch. All of
// § 0.5's conditions must hold: recorded cursor non-empty; managed Secret exists,
// is controlled by this CR, and stamp(current data) == status.stamp; and the
// binding digest is unchanged.
func (r *HikyoSecretReconciler) eligibleCursor(
	ctx context.Context, cr *hikyov1.HikyoSecret, inst *hikyov1.HikyoInstance,
	cred credential, existing *corev1.Secret, existed bool, root []byte,
) string {
	if cr.Status.Cursor == "" || !existed || !metav1.IsControlledBy(existing, cr) {
		return ""
	}
	// stamp(current Secret data) must equal the recorded stamp — a tampered or
	// externally-edited Secret discards the cursor. root is the pre-validated
	// stamp root read once for this reconcile.
	pairs := stampPairsFromData(existing.Data)
	stamp, err := r.computeStamp(inst, cr, pairs, root)
	if err != nil || stamp != cr.Status.Stamp {
		return ""
	}
	if bindingDigest(bindingInputFor(cr, inst, cred)) != cr.Status.CursorBinding {
		return ""
	}
	return cr.Status.Cursor
}

func bindingInputFor(cr *hikyov1.HikyoSecret, inst *hikyov1.HikyoInstance, cred credential) bindingInput {
	return bindingInput{
		credentialUID:             cred.uid,
		credentialResourceVersion: cred.resourceVersion,
		org:                       string(cr.Spec.Scope.Org),
		project:                   string(cr.Spec.Scope.Project),
		environment:               string(cr.Spec.Scope.Environment),
		projection:                string(effectiveProjection(cr)),
		mapping:                   cr.Spec.Mapping,
		targetName:                cr.Spec.Target.Name,
		instanceUID:               string(inst.UID),
	}
}

// targetClaimed resolves the deterministic winner among all HikyoSecrets in the
// namespace naming the same target (earliest creationTimestamp, then lowest UID).
// If this CR is not the winner it is the loser and must not write.
func (r *HikyoSecretReconciler) targetClaimed(ctx context.Context, cr *hikyov1.HikyoSecret) (bool, string, error) {
	var list hikyov1.HikyoSecretList
	// Authoritative UNCACHED list (decision 9): the claimant is decided from the
	// live API, not a cache that could let two CRs each believe they won.
	if err := r.Reader.List(ctx, &list, client.InNamespace(cr.Namespace)); err != nil {
		return false, "", err
	}
	claimants := make([]*hikyov1.HikyoSecret, 0, 2)
	for i := range list.Items {
		if list.Items[i].Spec.Target.Name == cr.Spec.Target.Name {
			claimants = append(claimants, &list.Items[i])
		}
	}
	if len(claimants) <= 1 {
		return false, "", nil
	}
	sort.Slice(claimants, func(i, j int) bool {
		ti, tj := claimants[i].CreationTimestamp, claimants[j].CreationTimestamp
		if !ti.Equal(&tj) {
			return ti.Before(&tj)
		}
		return string(claimants[i].UID) < string(claimants[j].UID)
	})
	winner := claimants[0]
	if winner.UID == cr.UID {
		return false, "", nil
	}
	return true, winner.Name, nil
}

// getManagedSecret fetches the target Secret; existed=false on NotFound.
func (r *HikyoSecretReconciler) getManagedSecret(ctx context.Context, cr *hikyov1.HikyoSecret) (*corev1.Secret, bool, error) {
	var sec corev1.Secret
	// Uncached read-after-write: controller-ownership/UID is the authority test,
	// and a cache could lag a delete/recreate/re-own.
	err := r.Reader.Get(ctx, types.NamespacedName{Namespace: cr.Namespace, Name: cr.Spec.Target.Name}, &sec)
	if apierrors.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &sec, true, nil
}

// applyCredentialExpiry surfaces credential_expires_at ahead of time (§ 0.3
// CredentialExpiry). Absent expiry clears the condition.
func (r *HikyoSecretReconciler) applyCredentialExpiry(cr *hikyov1.HikyoSecret, expiresAt *time.Time) {
	if expiresAt == nil {
		cr.Status.CredentialExpiresAt = nil
		meta.RemoveStatusCondition(&cr.Status.Conditions, hikyov1.ConditionCredentialExpiry)
		return
	}
	t := metav1.NewTime(*expiresAt)
	cr.Status.CredentialExpiresAt = &t
	now := r.clock()
	switch {
	case !now.Before(*expiresAt):
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonExpired, "presenting credential expired at %s", expiresAt.Format(time.RFC3339))
		r.setCond(cr, hikyov1.ConditionCredentialExpiry, metav1.ConditionTrue, hikyov1.ReasonExpired,
			fmt.Sprintf("presenting credential expired at %s", expiresAt.Format(time.RFC3339)))
	case expiresAt.Sub(now) <= credentialExpiryHorizon:
		r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonExpiresSoon, "presenting credential expires at %s", expiresAt.Format(time.RFC3339))
		r.setCond(cr, hikyov1.ConditionCredentialExpiry, metav1.ConditionTrue, hikyov1.ReasonExpiresSoon,
			fmt.Sprintf("presenting credential expires at %s (within %s)", expiresAt.Format(time.RFC3339), credentialExpiryHorizon))
	default:
		meta.RemoveStatusCondition(&cr.Status.Conditions, hikyov1.ConditionCredentialExpiry)
	}
}

// setCond sets a status condition with the CR's generation as observedGeneration.
func (r *HikyoSecretReconciler) setCond(cr *hikyov1.HikyoSecret, condType string, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&cr.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: cr.Generation,
	})
}

func (r *HikyoSecretReconciler) event(cr *hikyov1.HikyoSecret, etype, reason, format string, args ...any) {
	if r.Recorder != nil {
		r.Recorder.Eventf(cr, etype, reason, format, args...)
	}
}

// done finalizes the Ready summary, sets observedGeneration, and writes the
// status subresource LAST. A status-write failure is JOINED with the reconcile
// error rather than discarded — losing the condition/cursor write is itself a
// fault that must surface (finding: fail-loud handling).
func (r *HikyoSecretReconciler) done(ctx context.Context, cr *hikyov1.HikyoSecret, res ctrl.Result, err error) (ctrl.Result, error) {
	// Clear a stale Unreconciled/NamespaceNotBound on every outcome except the
	// RBAC-forbidden one (the only path that sets LifecycleUnreconciled) — otherwise
	// a recovered CR keeps reporting an authority loss that no longer holds (§ 0.3).
	// The two pre-credential exits that never touched a namespaced object (invalid
	// resyncInterval, HikyoInstance NotFound) also clear here; that is accepted —
	// they set Ready=False via FetchFailed regardless, and the next reconcile that
	// reaches the forbidden read re-detects and re-asserts Unreconciled.
	if cr.Status.Lifecycle != hikyov1.LifecycleUnreconciled {
		meta.RemoveStatusCondition(&cr.Status.Conditions, hikyov1.ConditionUnreconciled)
	}
	r.setReady(cr)
	cr.Status.ObservedGeneration = cr.Generation
	if uerr := r.Status().Update(ctx, cr); uerr != nil {
		err = errors.Join(err, uerr)
	}
	return res, err
}

// setReady computes the Ready summary: True only when Synced is True and no
// blocking refusal (Designation=False, Conflict=True, Scrubbed=True,
// Unreconciled=True, or a blocking Delivery refusal) is active. KeysMissing and
// EnvFromSkip are informational and do not block Ready (delivery happened).
func (r *HikyoSecretReconciler) setReady(cr *hikyov1.HikyoSecret) {
	ready := meta.IsStatusConditionTrue(cr.Status.Conditions, hikyov1.ConditionSynced)
	blockingReason := ""
	for _, c := range cr.Status.Conditions {
		switch c.Type {
		case hikyov1.ConditionDesignation:
			if c.Status == metav1.ConditionFalse {
				ready, blockingReason = false, c.Reason
			}
		case hikyov1.ConditionConflict, hikyov1.ConditionScrubbed, hikyov1.ConditionUnreconciled:
			// Unreconciled=True is an active RBAC authority loss (§ 0.3
			// NamespaceNotBound): a previously synced CR must not report Ready while
			// its namespace is unbound.
			if c.Status == metav1.ConditionTrue {
				ready, blockingReason = false, c.Reason
			}
		case hikyov1.ConditionDelivery:
			if c.Status == metav1.ConditionFalse &&
				(c.Reason == hikyov1.ReasonUndeliveredSecrets || c.Reason == hikyov1.ReasonLoaderControlUnacknowledged) {
				ready, blockingReason = false, c.Reason
			}
		case hikyov1.ConditionSynced:
			if c.Status == metav1.ConditionFalse {
				ready, blockingReason = false, c.Reason
			}
		}
	}
	if ready {
		r.setCond(cr, hikyov1.ConditionReady, metav1.ConditionTrue, hikyov1.ReasonReconciled, "managed Secret is synced")
		return
	}
	if blockingReason == "" {
		blockingReason = hikyov1.ReasonBlocked
	}
	r.setCond(cr, hikyov1.ConditionReady, metav1.ConditionFalse, hikyov1.ReasonBlocked,
		fmt.Sprintf("not ready: %s", blockingReason))
}

// validateResyncInterval parses spec.resyncInterval and refuses a non-positive
// or otherwise unusable value LOUDLY (§ 0.7). The CRD pattern rejects malformed
// syntax at admission; this catches the values the pattern still admits ("0s",
// "0h") that cannot be a requeue cadence. Empty is fine (the 5m default applies).
func validateResyncInterval(cr *hikyov1.HikyoSecret) error {
	if cr.Spec.ResyncInterval == "" {
		return nil
	}
	d, err := time.ParseDuration(cr.Spec.ResyncInterval)
	if err != nil {
		return fmt.Errorf("%q: %w", cr.Spec.ResyncInterval, err)
	}
	if d <= 0 {
		return fmt.Errorf("%q is not a positive duration", cr.Spec.ResyncInterval)
	}
	return nil
}

// resyncResult is the success-path requeue at spec.resyncInterval (default 5m).
// The value was already validated by validateResyncInterval at the top of the
// reconcile, so a parse failure here is unreachable; the 5m fallback covers only
// the empty (defaulted) case.
func (r *HikyoSecretReconciler) resyncResult(cr *hikyov1.HikyoSecret) ctrl.Result {
	d := 5 * time.Minute
	if cr.Spec.ResyncInterval != "" {
		if parsed, err := time.ParseDuration(cr.Spec.ResyncInterval); err == nil && parsed > 0 {
			d = parsed
		}
	}
	return ctrl.Result{RequeueAfter: d}
}

// accessError classifies an RBAC access failure. On apierrors.IsForbidden it
// sets Unreconciled=True/NamespaceNotBound — the ADR § Scoping visible authority
// failure for a CR in a namespace the operator's RBAC does not reach — emits an
// event, persists status where the status RBAC permits, and returns handled=true
// so the caller returns (res, err). Any other error is the caller's to return
// raw (handled=false, so the switch falls through).
func (r *HikyoSecretReconciler) accessError(ctx context.Context, cr *hikyov1.HikyoSecret, err error, what string) (ctrl.Result, error, bool) {
	if !apierrors.IsForbidden(err) {
		return ctrl.Result{}, nil, false
	}
	msg := fmt.Sprintf("forbidden accessing %s (namespace not bound to operator authority): %v", what, err)
	r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonNamespaceNotBound, "%s", msg)
	r.setCond(cr, hikyov1.ConditionUnreconciled, metav1.ConditionTrue, hikyov1.ReasonNamespaceNotBound, msg)
	cr.Status.Lifecycle = hikyov1.LifecycleUnreconciled
	res, derr := r.done(ctx, cr, ctrl.Result{}, err)
	return res, derr, true
}

// ensureFinalizer keeps the orphan finalizer present iff creationPolicy=Orphan.
// done=true means the caller returns after the mutation requeues.
func (r *HikyoSecretReconciler) ensureFinalizer(ctx context.Context, cr *hikyov1.HikyoSecret) (ctrl.Result, bool, error) {
	wantFinalizer := cr.Spec.Target.CreationPolicy == hikyov1.CreationPolicyOrphan
	has := controllerutil.ContainsFinalizer(cr, hikyov1.OrphanFinalizer)
	switch {
	case wantFinalizer && !has:
		return ctrl.Result{}, true, r.patchFinalizers(ctx, cr, controllerutil.AddFinalizer)
	case !wantFinalizer && has:
		// Owner policy needs no finalizer (§ 0.2); drop a stale one.
		return ctrl.Result{}, true, r.patchFinalizers(ctx, cr, controllerutil.RemoveFinalizer)
	default:
		return ctrl.Result{}, false, nil
	}
}

// patchFinalizers mutates only metadata.finalizers via a JSON MERGE patch — the
// operator's `hikyosecrets` RBAC carries `patch` for exactly this bookkeeping
// (decision 2), never `update` of the whole object. mutate is
// controllerutil.AddFinalizer or RemoveFinalizer.
func (r *HikyoSecretReconciler) patchFinalizers(ctx context.Context, cr *hikyov1.HikyoSecret, mutate func(client.Object, string) bool) error {
	base := cr.DeepCopy()
	mutate(cr, hikyov1.OrphanFinalizer)
	return r.Patch(ctx, cr, client.MergeFrom(base))
}

// finalize handles CR deletion: an Orphan CR strips the managed Secret's
// controller ownerRef before the CR is released, so the Secret survives unowned.
func (r *HikyoSecretReconciler) finalize(ctx context.Context, cr *hikyov1.HikyoSecret) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(cr, hikyov1.OrphanFinalizer) {
		// Owner policy (or already finalized): garbage collection handles the
		// Secret via the ownerRef. Nothing to do.
		return ctrl.Result{}, nil
	}
	if err := r.stripOwnerRef(ctx, cr); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.patchFinalizers(ctx, cr, controllerutil.RemoveFinalizer); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// stripOwnerRef removes this CR's controller ownerReference from the managed
// Secret, leaving it unowned (the Orphan handover). It reads uncached, updates
// with the resourceVersion precondition from that read (so a concurrent GC race
// fails the Update rather than clobbering), then RE-READS uncached and verifies
// the ownerRef is gone before the caller removes the finalizer — an
// unverified strip that left the ownerRef would let garbage collection delete
// the Secret the moment the finalizer is dropped (§ 0.2 Orphan ordering).
func (r *HikyoSecretReconciler) stripOwnerRef(ctx context.Context, cr *hikyov1.HikyoSecret) error {
	sec, existed, err := r.getManagedSecret(ctx, cr)
	if err != nil || !existed {
		return err
	}
	if !metav1.IsControlledBy(sec, cr) {
		return nil
	}
	kept := make([]metav1.OwnerReference, 0, len(sec.OwnerReferences))
	for _, ref := range sec.OwnerReferences {
		if ref.UID != cr.UID {
			kept = append(kept, ref)
		}
	}
	sec.OwnerReferences = kept
	// Carries the resourceVersion from the uncached read → optimistic precondition.
	if err := r.Update(ctx, sec); err != nil {
		return fmt.Errorf("operator: strip ownerRef: %w", err)
	}
	// Re-read uncached and prove the strip landed before releasing the CR.
	var again corev1.Secret
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: cr.Namespace, Name: cr.Spec.Target.Name}, &again); err != nil {
		return fmt.Errorf("operator: re-read after ownerRef strip: %w", err)
	}
	if metav1.IsControlledBy(&again, cr) {
		return fmt.Errorf("operator: managed Secret %q still controlled by this CR after strip; refusing to release", cr.Spec.Target.Name)
	}
	return nil
}

// decodeCABundle base64-decodes the instance CA bundle. Empty → nil (system
// roots). A malformed value is a hard ERROR — never reinterpreted as raw PEM,
// which would silently change the locked base64-PEM wire shape and could fail
// open to a weaker trust posture (parse, don't cast).
func decodeCABundle(b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("caBundle is not valid base64 (the CRD documents base64-encoded PEM): %w", err)
	}
	return raw, nil
}
