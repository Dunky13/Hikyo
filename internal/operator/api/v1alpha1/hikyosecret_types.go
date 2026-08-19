package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Projection is the delivery projection — a server-side authorized term, never a
// client-side filter (ADR § Loader-control keys). config-only receives the
// config projection as its authorized manifest and is bound into the cursor.
//
// +kubebuilder:validation:Enum=full;config-only
type Projection string

const (
	ProjectionFull       Projection = "full"
	ProjectionConfigOnly Projection = "config-only"
)

// CreationPolicy governs the managed Secret's fate on CR deletion.
//
// +kubebuilder:validation:Enum=Owner;Orphan
type CreationPolicy string

const (
	// CreationPolicyOwner (default) garbage-collects the managed Secret with
	// its CR via the ownerReference.
	CreationPolicyOwner CreationPolicy = "Owner"
	// CreationPolicyOrphan keeps the controller ownerRef during the CR's life
	// (so the authority test stays one rule) and a finalizer strips it on
	// deletion — the Secret survives, unowned. The explicit opt-in for GitOps
	// handover.
	CreationPolicyOrphan CreationPolicy = "Orphan"
)

// InstanceRef names the cluster-scoped HikyoInstance this CR fetches against.
// The name is immutable: retargeting the endpoint is delete-and-recreate, so a
// mutated ref cannot silently redirect a live credential to another server.
//
// +kubebuilder:validation:XValidation:rule="self.name == oldSelf.name",message="instanceRef.name is immutable"
type InstanceRef struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// LocalObjectRef names an object in the CR's OWN namespace (there is never a
// namespace field — same-namespace confinement stops cross-namespace theft, ADR
// § Identity).
type LocalObjectRef struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// AuthRef is exactly one of a bootstrap-Secret credential or a ServiceAccount
// for federation (ADR § Identity: two credential kinds). The referenced object
// must additionally carry the designation labels — naming a credential is not
// authority to use it.
//
// +kubebuilder:validation:XValidation:rule="[has(self.secretRef), has(self.serviceAccountRef)].filter(x, x).size() == 1",message="auth must set exactly one of secretRef or serviceAccountRef"
type AuthRef struct {
	// SecretRef names a bootstrap Secret in the CR's namespace whose data key
	// `hikyo-token` holds a bearer credential.
	//
	// +optional
	SecretRef *LocalObjectRef `json:"secretRef,omitempty"`

	// ServiceAccountRef names a ServiceAccount in the CR's namespace; the
	// operator mints a short-lived audience-bound token via TokenRequest and
	// presents it under the oidc-federation kind. The instance must declare an
	// audience.
	//
	// +optional
	ServiceAccountRef *LocalObjectRef `json:"serviceAccountRef,omitempty"`
}

// Scope is the Hikyo (org, project, environment) selector, as the API takes
// them in the request path.
type Scope struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Org string `json:"org"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Project string `json:"project"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Environment string `json:"environment"`
}

// Mapping is one delivered key routed to one managed-Secret data key. The source
// `key` is the Hikyo key name; `secretKey` is the destination data key,
// defaulting to `key`. A renamed destination changes delivery without changing
// the source set, which is why the mapping digest binds both (cursor eligibility
// § 0.5).
type Mapping struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Key string `json:"key"`

	// SecretKey is the managed Secret's data key. Defaults to Key; the operator
	// applies the default, not the API server, because it also validates it
	// against the loader-control baseline (§ 0.6). Kubernetes Secret data keys
	// obey `[-._a-zA-Z0-9]+`.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	SecretKey string `json:"secretKey,omitempty"`
}

// EffectiveSecretKey is the destination data key: SecretKey when set, else Key.
func (m Mapping) EffectiveSecretKey() string {
	if m.SecretKey != "" {
		return m.SecretKey
	}
	return m.Key
}

// Target is the managed Secret this CR owns. The name is immutable and ≤ 63
// chars: retargeting is delete-and-recreate (so a retarget cannot
// orphan-then-capture), and the 63-char bound is the pod-template stamp
// annotation's key-name limit (`stamp.hikyo.dev/<target.name>`, § 0.2).
//
// +kubebuilder:validation:XValidation:rule="self.name == oldSelf.name",message="target.name is immutable"
type Target struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// +optional
	// +kubebuilder:default=Owner
	CreationPolicy CreationPolicy `json:"creationPolicy,omitempty"`
}

// HikyoSecretSpec carries everything with authority or effect (ADR § The API
// objects): the auth ref, the instance ref, the scope, the mapping, the managed
// Secret target and policy, the projection and the loader-control
// acknowledgement.
type HikyoSecretSpec struct {
	InstanceRef InstanceRef `json:"instanceRef"`
	Auth        AuthRef     `json:"auth"`
	Scope       Scope       `json:"scope"`

	// Mapping is non-empty and its effective secretKeys are unique. The
	// uniqueness rule uses the effective key (secretKey when set, else key) so
	// two sources cannot silently collide on one destination.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:XValidation:rule="self.all(m1, self.exists_one(m2, (has(m2.secretKey) ? m2.secretKey : m2.key) == (has(m1.secretKey) ? m1.secretKey : m1.key)))",message="mapping secretKeys (effective) must be unique"
	Mapping []Mapping `json:"mapping"`

	Target Target `json:"target"`

	// +optional
	// +kubebuilder:default=full
	Projection Projection `json:"projection,omitempty"`

	// AcknowledgedLoaderKeys lists exactly the mapped destination keys on the
	// loader-control baseline that the CR author consents to deliver (§ 0.6).
	// Sent verbatim as `acknowledged_keys` on every fetch so the server records
	// it. Extra names not among the mapped keys are themselves a refusal.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=64
	AcknowledgedLoaderKeys []string `json:"acknowledgedLoaderKeys,omitempty"`

	// ResyncInterval is the success-path requeue cadence (ops-spec default 5m).
	// A Go duration string; the operator parses it.
	//
	// +optional
	// +kubebuilder:default="5m"
	// +kubebuilder:validation:Pattern=`^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$`
	ResyncInterval string `json:"resyncInterval,omitempty"`
}

// Lifecycle is the coarse managed-Secret state, distinct from the fine-grained
// conditions.
//
// +kubebuilder:validation:Enum=Synced;Retained;Scrubbed;Refused;Unreconciled
type Lifecycle string

const (
	LifecycleSynced       Lifecycle = "Synced"
	LifecycleRetained     Lifecycle = "Retained"
	LifecycleScrubbed     Lifecycle = "Scrubbed"
	LifecycleRefused      Lifecycle = "Refused"
	LifecycleUnreconciled Lifecycle = "Unreconciled"
)

// HikyoSecretStatus is the reconciler's durable record. The cursor fields are
// written LAST (§ 0.5) and never advanced after a failed or refused sync.
type HikyoSecretStatus struct {
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Cursor is the opaque server cursor for the last successfully delivered
	// state — non-secret by construction. Empty forces a full authorized fetch.
	//
	// +optional
	Cursor string `json:"cursor,omitempty"`

	// CursorBinding is the hex digest of the local binding tuple (§ 0.5). The
	// cursor is presented only while this still matches the CR's current
	// referenced-credential identity, scope, projection, mapping and target.
	//
	// +optional
	CursorBinding string `json:"cursorBinding,omitempty"`

	// Stamp is the last delivered per-target stamp (`v1:<hex>`), recomputed and
	// compared to the managed Secret's content to prove the recorded delivery is
	// still in effect before the cursor may be presented.
	//
	// +optional
	Stamp string `json:"stamp,omitempty"`

	// +optional
	ManagedSecretUID string `json:"managedSecretUID,omitempty"`

	// +optional
	ManagedSecretResourceVersion string `json:"managedSecretResourceVersion,omitempty"`

	// +optional
	Lifecycle Lifecycle `json:"lifecycle,omitempty"`

	// CredentialExpiresAt mirrors the delivery response's credential_expires_at
	// when finite; surfaced ahead of time as the CredentialExpiry condition.
	//
	// +optional
	CredentialExpiresAt *metav1.Time `json:"credentialExpiresAt,omitempty"`

	// +optional
	LastFetch *metav1.Time `json:"lastFetch,omitempty"`

	// +optional
	LastDelivery *metav1.Time `json:"lastDelivery,omitempty"`
}

// HikyoSecret is a namespaced delivery request: it fetches under the identity it
// names (the operator holds none) and writes the result into a native Secret it
// owns.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=hksec
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Instance",type=string,JSONPath=`.spec.instanceRef.name`
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.target.name`
// +kubebuilder:printcolumn:name="Lifecycle",type=string,JSONPath=`.status.lifecycle`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
type HikyoSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HikyoSecretSpec   `json:"spec"`
	Status HikyoSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type HikyoSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HikyoSecret `json:"items"`
}
