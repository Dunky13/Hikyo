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
// (read and validated ONCE per reconcile by the caller, held in root) and
// computes the stamp. The derived key is zeroed after use; the root's lifetime
// is the caller's.
func (r *HikyoSecretReconciler) computeStamp(
	inst *hikyov1.HikyoInstance, cr *hikyov1.HikyoSecret, pairs []crypto.StampPair, root []byte,
) (string, error) {
	key, err := crypto.StampKey(root, string(inst.UID), string(cr.UID), cr.Spec.Target.Name)
	if err != nil {
		return "", err
	}
	defer crypto.Zero(key)
	return crypto.Stamp(key, pairs)
}

// stampRoot reads (or, on first need, creates) the operator's 32-byte random
// stamp root from the Secret in its own namespace (§ 0.2). It is a client-side
// key outside the server hierarchy; compromise is a comparison-oracle incident,
// not plaintext disclosure.
func (r *HikyoSecretReconciler) stampRoot(ctx context.Context) ([]byte, error) {
	key := types.NamespacedName{Namespace: r.Config.OwnNamespace, Name: hikyov1.StampRootSecretName}
	var sec corev1.Secret
	// Uncached: the operator's own namespace is deliberately outside the watch
	// set (§ Scoping), so this Secret is only reachable through the APIReader.
	err := r.Reader.Get(ctx, key, &sec)
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
			if gerr := r.Reader.Get(ctx, key, &again); gerr != nil {
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
		return r.verifyManagedSecret(ctx, cr, data, sec.UID)
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
	return r.verifyManagedSecret(ctx, cr, data, existing.UID)
}

// verifyManagedSecret re-Gets the managed Secret and confirms it is byte-exact
// what was written (§ 0.5 step 1's verify): the object still carries this CR's
// controller ownerRef, its UID matches the object we just wrote, and its data is
// byte-exact. The UID check closes the delete/recreate-and-re-own window that
// IsControlledBy alone misses — a racing actor that deletes our Secret and
// recreates an identically-controlled one gets a fresh UID, so a mismatch means
// the bytes we verified are not the bytes we wrote.
func (r *HikyoSecretReconciler) verifyManagedSecret(ctx context.Context, cr *hikyov1.HikyoSecret, want map[string][]byte, wantUID types.UID) (*corev1.Secret, error) {
	// Uncached read-after-write: proves the write actually landed AND that the
	// object we own is still ours. A cached read could return a pre-write copy,
	// or miss a concurrent delete/recreate/re-own between write and verify.
	var got corev1.Secret
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: cr.Namespace, Name: cr.Spec.Target.Name}, &got); err != nil {
		return nil, fmt.Errorf("operator: re-read managed Secret: %w", err)
	}
	if !metav1.IsControlledBy(&got, cr) {
		return nil, fmt.Errorf("operator: managed Secret %q is not controlled by this CR after write (deleted/recreated/re-owned)", cr.Spec.Target.Name)
	}
	if got.UID != wantUID {
		return nil, fmt.Errorf("operator: managed Secret %q UID %q after write does not match the written UID %q (deleted/recreated between write and verify)", cr.Spec.Target.Name, got.UID, wantUID)
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
func (r *HikyoSecretReconciler) scrub(ctx context.Context, cr *hikyov1.HikyoSecret, cause error, root []byte) (ctrl.Result, error) {
	inst := &hikyov1.HikyoInstance{}
	if err := r.Get(ctx, types.NamespacedName{Name: cr.Spec.InstanceRef.Name}, inst); err != nil {
		return ctrl.Result{}, err
	}
	existing, existed, err := r.getManagedSecret(ctx, cr)
	if err != nil {
		if res, derr, handled := r.accessError(ctx, cr, err, "managed Secret"); handled {
			return res, derr
		}
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
	stamp, err := r.computeStamp(inst, cr, nil, root)
	if err != nil {
		return ctrl.Result{}, err
	}

	written, err := r.writeManagedSecret(ctx, cr, empty, existing, existed)
	if err != nil {
		// Failure before the cursor write leaves no cursor (decision 7); clear it
		// before persisting status (accessError persists via done()).
		cr.Status.Cursor = ""
		cr.Status.CursorBinding = ""
		if res, derr, handled := r.accessError(ctx, cr, err, "managed Secret write"); handled {
			return res, derr
		}
		r.setCond(cr, hikyov1.ConditionSynced, metav1.ConditionFalse, hikyov1.ReasonFetchFailed, err.Error())
		cr.Status.Lifecycle = hikyov1.LifecycleRetained
		return r.done(ctx, cr, ctrl.Result{}, err)
	}

	// The Secret is now empty (values withdrawn). Record the scrubbed state.
	// AuthorizationWithdrawn belongs to Scrubbed=True ONLY (§ 0.3's closed table);
	// Synced is NOT given this reason — Ready derives False from Scrubbed=True.
	// Remove any stale Synced condition rather than leaving a Delivered=True.
	r.event(cr, corev1.EventTypeWarning, hikyov1.ReasonAuthorizationWithdrawn, "authorization withdrawn (404): %v", cause)
	r.setCond(cr, hikyov1.ConditionScrubbed, metav1.ConditionTrue, hikyov1.ReasonAuthorizationWithdrawn,
		"authorization withdrawn; managed Secret converged to empty")
	meta.RemoveStatusCondition(&cr.Status.Conditions, hikyov1.ConditionSynced)
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
		if res, derr, handled := r.accessError(ctx, cr, patchErr, "workload patch"); handled {
			return res, derr
		}
		r.setCond(cr, hikyov1.ConditionRollout, metav1.ConditionFalse, hikyov1.ReasonStalled, patchErr.Error())
		return r.done(ctx, cr, ctrl.Result{}, patchErr)
	}
	meta.RemoveStatusCondition(&cr.Status.Conditions, hikyov1.ConditionRollout)
	return r.done(ctx, cr, r.resyncResult(cr), nil)
}
