package v1alpha1

// Condition types and their closed reason set (§ 0.3). One reason per ADR-named
// state; a reason outside this set is a defect, not a value. Conditions are set
// on HikyoSecret.status via meta.SetStatusCondition.

// Condition types.
const (
	// ConditionReady is the summary — True only when Synced is True and no
	// refusal condition is active.
	ConditionReady = "Ready"
	// ConditionSynced reports whether the last fetch delivered or answered
	// current.
	ConditionSynced = "Synced"
	// ConditionDesignation reports whether the referenced credential object
	// carries a valid designation for this instance.
	ConditionDesignation = "Designation"
	// ConditionConflict reports an ownership or target conflict.
	ConditionConflict = "Conflict"
	// ConditionDelivery reports a delivery-content refusal or caveat.
	ConditionDelivery = "Delivery"
	// ConditionScrubbed reports the managed Secret was converged to empty under
	// an authoritative refusal.
	ConditionScrubbed = "Scrubbed"
	// ConditionRollout reports whether opted-in workloads progressed after a
	// stamp patch.
	ConditionRollout = "Rollout"
	// ConditionCredentialExpiry surfaces credential_expires_at ahead of time.
	ConditionCredentialExpiry = "CredentialExpiry"
	// ConditionUnreconciled reports a cluster-wide install seeing a CR in a
	// namespace excluded from authority.
	ConditionUnreconciled = "Unreconciled"
)

// Reasons — the closed set. Each maps to exactly one ADR-named state.
const (
	// Synced.
	ReasonDelivered       = "Delivered"       // full delivery written
	ReasonCurrent         = "Current"         // cursor answered current
	ReasonFetchFailed     = "FetchFailed"     // network error, 5xx, 429, 401 — retain, backoff
	ReasonNotMaterialized = "NotMaterialized" // 409, no published revision — retain/empty

	// Designation.
	ReasonSecretNotDesignated         = "SecretNotDesignated"
	ReasonServiceAccountNotDesignated = "ServiceAccountNotDesignated"
	ReasonInstanceMismatch            = "InstanceMismatch"
	ReasonAudienceMissing             = "AudienceMissing" // SA path, instance lacks audience

	// Conflict.
	ReasonManagedSecretNotOwned = "ManagedSecretNotOwned" // target exists without this CR's controller ownerRef
	ReasonTargetClaimed         = "TargetClaimed"         // another HikyoSecret (earlier) names the same target

	// Delivery.
	ReasonUndeliveredSecrets          = "UndeliveredSecrets"          // all-or-nothing: secret keys arrived presence-only
	ReasonKeysMissing                 = "KeysMissing"                 // mapped source keys absent from the manifest
	ReasonLoaderControlUnacknowledged = "LoaderControlUnacknowledged" // mapped secretKey on baseline, not acknowledged
	ReasonEnvFromSkip                 = "EnvFromSkip"                 // secretKey is not a valid env identifier (warning)

	// Scrubbed.
	ReasonAuthorizationWithdrawn = "AuthorizationWithdrawn" // 404 under an authenticating credential

	// Rollout.
	ReasonStalled = "Stalled" // opted-in workload not progressed after the stamp patch

	// CredentialExpiry.
	ReasonExpiresSoon = "ExpiresSoon" // within 7 days
	ReasonExpired     = "Expired"     // passed

	// Unreconciled.
	ReasonNamespaceNotBound = "NamespaceNotBound" // cluster-wide install, namespace excluded from authority

	// Ready summary.
	ReasonReconciled = "Reconciled" // Ready=True: Synced and no refusal active
	ReasonBlocked    = "Blocked"    // Ready=False: a refusal or failure is active
)

// OrphanFinalizer strips the managed Secret's controller ownerRef on CR deletion
// under creationPolicy: Orphan, so the Secret survives unowned (§ 0.2).
const OrphanFinalizer = "hikyo.dev/orphan"

// Designation labels — both required on the bootstrap Secret and on the
// ServiceAccount (§ 0.2). The instance label must equal the CR's
// instanceRef.name. Naming a credential is not authority to use it.
const (
	LabelDelivery = "hikyo.dev/delivery" // must equal "true"
	LabelInstance = "hikyo.dev/instance" // must equal the HikyoInstance name

	// LabelDeliveryValue is the required value of LabelDelivery.
	LabelDeliveryValue = "true"
)

// AnnotationWorkloadSecrets is the workload opt-in: a comma-separated list of
// managed Secret names the Deployment/StatefulSet/DaemonSet consumes and
// consents to be rolled for (§ 0.2). Consent lives on the workload.
const AnnotationWorkloadSecrets = "hikyo.dev/secrets"

// StampAnnotationPrefix + target name is the pod-template annotation the
// operator patches with the per-target stamp (`stamp.hikyo.dev/<target>`). The
// key-name part is ≤ 63 chars, which is why target.name is bounded there.
const StampAnnotationPrefix = "stamp.hikyo.dev/"

// BootstrapTokenKey is the data key in a bootstrap Secret holding the bearer
// credential (§ 0.2).
const BootstrapTokenKey = "hikyo-token"

// StampRootSecretName is the operator-namespace Secret holding the 32-byte
// random stamp root; StampRootKey is its data key (§ 0.2).
const (
	StampRootSecretName = "hikyo-operator-stamp-root"
	StampRootKey        = "root"
)
