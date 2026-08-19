package operator

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
	hikyov1 "github.com/Hikyo-Org/hikyo/internal/operator/api/v1alpha1"
)

// stampPairsFromData renders a managed Secret's data as stamp pairs so the
// recorded stamp can be recomputed over what is actually stored (cursor
// eligibility § 0.5). Stamp sorts internally; order here is immaterial.
func stampPairsFromData(data map[string][]byte) []crypto.StampPair {
	pairs := make([]crypto.StampPair, 0, len(data))
	for k, v := range data {
		pairs = append(pairs, crypto.StampPair{SecretKey: k, Value: string(v)})
	}
	return pairs
}

// computeStamp derives the per-target stamp key from the operator's local root
// and computes the stamp. The key is zeroed after use.
func (r *HikyoSecretReconciler) computeStamp(
	ctx context.Context, inst *hikyov1.HikyoInstance, cr *hikyov1.HikyoSecret, pairs []crypto.StampPair,
) (string, error) {
	root, err := r.stampRoot(ctx)
	if err != nil {
		return "", err
	}
	defer crypto.Zero(root)
	key, err := crypto.StampKey(root, string(inst.UID), string(cr.UID), cr.Spec.Target.Name)
	if err != nil {
		return "", err
	}
	defer crypto.Zero(key)
	return crypto.Stamp(key, pairs), nil
}

// stampRoot reads (or, on first need, creates) the operator's 32-byte random
// stamp root from the Secret in its own namespace (§ 0.2). It is a client-side
// key outside the server hierarchy; compromise is a comparison-oracle incident,
// not plaintext disclosure.
func (r *HikyoSecretReconciler) stampRoot(ctx context.Context) ([]byte, error) {
	key := types.NamespacedName{Namespace: r.Config.OwnNamespace, Name: hikyov1.StampRootSecretName}
	var sec corev1.Secret
	err := r.Get(ctx, key, &sec)
	if err == nil {
		root := sec.Data[hikyov1.StampRootKey]
		if len(root) != crypto.KeySize {
			return nil, fmt.Errorf("operator: stamp root %s/%s data key %q is %d bytes, want %d",
				key.Namespace, key.Name, hikyov1.StampRootKey, len(root), crypto.KeySize)
		}
		out := make([]byte, len(root))
		copy(out, root)
		return out, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("operator: read stamp root: %w", err)
	}

	// Create it. A concurrent creator (a second replica losing leader election
	// briefly, or a racing reconcile) is handled by re-reading on AlreadyExists.
	root := make([]byte, crypto.KeySize)
	if _, err := rand.Read(root); err != nil {
		return nil, fmt.Errorf("operator: generate stamp root: %w", err)
	}
	create := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{hikyov1.StampRootKey: root},
	}
	if err := r.Create(ctx, create); err != nil {
		if apierrors.IsAlreadyExists(err) {
			var again corev1.Secret
			if gerr := r.Get(ctx, key, &again); gerr != nil {
				return nil, fmt.Errorf("operator: re-read stamp root after race: %w", gerr)
			}
			existing := again.Data[hikyov1.StampRootKey]
			if len(existing) != crypto.KeySize {
				return nil, fmt.Errorf("operator: raced stamp root has %d bytes, want %d", len(existing), crypto.KeySize)
			}
			out := make([]byte, len(existing))
			copy(out, existing)
			return out, nil
		}
		return nil, fmt.Errorf("operator: create stamp root: %w", err)
	}
	return root, nil
}

// writeManagedSecret applies § 0.5 step 1: create only if absent (always with
// this CR's controller ownerRef), otherwise Update only when controlled by this
// CR — never adopt — with the resourceVersion precondition from the read, then
// re-Get and verify the data matches byte-exact.
func (r *HikyoSecretReconciler) writeManagedSecret(
	ctx context.Context, cr *hikyov1.HikyoSecret, data map[string][]byte, existing *corev1.Secret, existed bool,
) (*corev1.Secret, error) {
	if !existed {
		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: cr.Namespace, Name: cr.Spec.Target.Name},
			Type:       corev1.SecretTypeOpaque,
			Data:       data,
		}
		if err := ctrl.SetControllerReference(cr, sec, r.Scheme); err != nil {
			return nil, fmt.Errorf("operator: set controller ref: %w", err)
		}
		if err := r.Create(ctx, sec); err != nil {
			return nil, fmt.Errorf("operator: create managed Secret: %w", err)
		}
		return r.verifyManagedSecret(ctx, cr, data)
	}

	// Defensive re-check: the ownership was verified in reconcileActive, but the
	// controller-UID check is the authority test and must gate every write.
	if !metav1.IsControlledBy(existing, cr) {
		return nil, fmt.Errorf("operator: refusing to update Secret %q not controlled by this CR", cr.Spec.Target.Name)
	}
	existing.Data = data
	existing.Type = corev1.SecretTypeOpaque
	// existing carries the resourceVersion from the read, so Update fails on a
	// concurrent modification rather than clobbering it.
	if err := r.Update(ctx, existing); err != nil {
		return nil, fmt.Errorf("operator: update managed Secret: %w", err)
	}
	return r.verifyManagedSecret(ctx, cr, data)
}

// verifyManagedSecret re-Gets the managed Secret and confirms its data is
// byte-exact what was written (§ 0.5 step 1's verify).
func (r *HikyoSecretReconciler) verifyManagedSecret(ctx context.Context, cr *hikyov1.HikyoSecret, want map[string][]byte) (*corev1.Secret, error) {
	var got corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: cr.Namespace, Name: cr.Spec.Target.Name}, &got); err != nil {
		return nil, fmt.Errorf("operator: re-read managed Secret: %w", err)
	}
	if !dataEqual(got.Data, want) {
		return nil, fmt.Errorf("operator: managed Secret data did not match what was written")
	}
	return &got, nil
}

func dataEqual(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !bytes.Equal(v, b[k]) {
			return false
		}
	}
	return true
}

// scrub converges the managed Secret to empty under a 404 (authoritative
// refusal, § 0.4 case 3): data → empty, stamp recomputed over the empty set and
// patched into opted-in workloads, cursor cleared, Scrubbed=True. It follows the
// same write ordering as a delivery — the empty state IS a delivery.
func (r *HikyoSecretReconciler) scrub(ctx context.Context, cr *hikyov1.HikyoSecret, cause error) (ctrl.Result, error) {
	inst := &hikyov1.HikyoInstance{}
	if err := r.Get(ctx, types.NamespacedName{Name: cr.Spec.InstanceRef.Name}, inst); err != nil {
		return ctrl.Result{}, err
	}
	existing, existed, err := r.getManagedSecret(ctx, cr)
	if err != nil {
		return ctrl.Result{}, err
	}
	// Only converge a Secret we own; an unowned target is never touched.
	if existed && !metav1.IsControlledBy(existing, cr) {
		r.setCond(cr, hikyov1.ConditionConflict, metav1.ConditionTrue, hikyov1.ReasonManagedSecretNotOwned,
			fmt.Sprintf("Secret %q is not controlled by this CR; not scrubbing", cr.Spec.Target.Name))
		cr.Status.Lifecycle = hikyov1.LifecycleRefused
		return r.done(ctx, cr, r.resyncResult(cr), nil)
	}

	empty := map[string][]byte{}
	stamp, err := r.computeStamp(ctx, inst, cr, nil)
	if err != nil {
		return ctrl.Result{}, err
	}

	written, err := r.writeManagedSecret(ctx, cr, empty, existing, existed)
	if err != nil {
		r.setCond(cr, hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonFetchFailed, err.Error())
		cr.Status.Lifecycle = hikyov1.LifecycleRetained
		return r.done(ctx, cr, ctrl.Result{}, err)
	}

	// The Secret is now empty (values withdrawn). Record the scrubbed state.
	r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonAuthorizationWithdrawn, "authorization withdrawn (404): %v", cause)
	r.setCond(cr, hikyov1.ConditionScrubbed, metav1.ConditionTrue, hikyov1.ReasonAuthorizationWithdrawn,
		"authorization withdrawn; managed Secret converged to empty")
	r.setCond(cr, hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonAuthorizationWithdrawn,
		"managed Secret scrubbed")
	// Cursor cleared — never advanced on a refusal.
	cr.Status.Cursor = ""
	cr.Status.CursorBinding = ""
	cr.Status.Stamp = stamp
	cr.Status.ManagedSecretUID = string(written.UID)
	cr.Status.ManagedSecretResourceVersion = written.ResourceVersion
	cr.Status.Lifecycle = hikyov1.LifecycleScrubbed

	// Roll opted-in workloads into the scrubbed state. A patch FAILURE is handled
	// exactly as on the delivery path (§ 0.5): surface Rollout=False and return
	// the error for backoff so the next reconcile re-attempts the roll — the
	// Secret stays scrubbed, the workload is retried, never silently left
	// referencing the pre-scrub stamp.
	if _, patchErr := r.patchWorkloads(ctx, cr, stamp); patchErr != nil {
		r.setCond(cr, hikyov1.ConditionRollout, metav1.ConditionFalse, hikyov1.ReasonStalled, patchErr.Error())
		return r.done(ctx, cr, ctrl.Result{}, patchErr)
	}
	meta.RemoveStatusCondition(&cr.Status.Conditions, hikyov1.ConditionRollout)
	return r.done(ctx, cr, r.resyncResult(cr), nil)
}
