package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HikyoInstanceSpec is non-secret connection configuration only: where the
// Hikyo server is and how to trust it. It NEVER carries a credential, and there
// is deliberately no field that could hold one (ADR § The API objects). The
// whole spec is immutable — changing the URL or CA means creating a new
// HikyoInstance, so "where do credentials and trust point" has an audit-visible
// identity and a mutated object cannot silently redirect every referencing CR.
//
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="HikyoInstance spec is immutable; create a new HikyoInstance to change the endpoint or trust anchors"
type HikyoInstanceSpec struct {
	// URL is the Hikyo server origin. HTTPS is mandatory and unconditional —
	// there is no insecure-skip-verify field and never will be (ADR § The API
	// objects). Server certificate verification against caBundle (or system
	// roots) is unconditional.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:XValidation:rule="self.startsWith('https://')",message="url must be an https:// origin"
	URL string `json:"url"`

	// CABundle is an optional base64-encoded PEM bundle of trust anchors. Absent
	// means the operator verifies against the host's system roots.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=1048576
	CABundle string `json:"caBundle,omitempty"`

	// Audience is the per-instance TokenRequest audience for the federation
	// path — required whenever a referencing HikyoSecret uses a
	// serviceAccountRef. It is never the API-server default audience (ADR §
	// Identity: mandatory, non-default audience). Absent is valid only for
	// instances used exclusively via bootstrap-Secret credentials.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=512
	Audience string `json:"audience,omitempty"`
}

// HikyoInstanceStatus is intentionally minimal: HikyoInstance has an immutable
// spec and no reconciler, so there is no derived state to report beyond what
// controller-runtime records for object identity.
type HikyoInstanceStatus struct {
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// HikyoInstance is a cluster-scoped connection target. Creation is RBAC-gated to
// the cluster admin; a namespace tenant cannot bring their own instance without
// one being created (ADR § The API objects, accepted consequence).
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=hkinst
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.url`
type HikyoInstance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HikyoInstanceSpec   `json:"spec"`
	Status HikyoInstanceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type HikyoInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HikyoInstance `json:"items"`
}
