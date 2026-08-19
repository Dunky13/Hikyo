// Package v1alpha1 defines the Hikyo operator's CustomResourceDefinition Go
// types: HikyoInstance (cluster-scoped connection configuration) and HikyoSecret
// (namespaced delivery request). The API group and every field spelling are
// fixed by the #64 handoff § 0.2, which the k8s-integration ADR delegates to
// #25. The CRD YAML under chart/hikyo/crds/ is generated from these markers by
// `controller-gen` and drift-checked by a Go test in this package.
//
// The authority split is the ADR's central security decision, encoded here: a
// cluster-scoped Hikyo object may never carry authority, so HikyoInstance has no
// credential-shaped field and its whole spec is immutable; everything with
// authority or effect lives on the namespaced HikyoSecret.
// +kubebuilder:object:generate=true
// +groupName=hikyo.dev
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// GroupVersion is hikyo.dev/v1alpha1 (§ 0.2).
var GroupVersion = schema.GroupVersion{Group: "hikyo.dev", Version: "v1alpha1"}

// SchemeBuilder registers the operator's types with a runtime scheme.
var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

// AddToScheme adds the operator's types to a scheme. The manager wiring and the
// tests both call it.
var AddToScheme = SchemeBuilder.AddToScheme

func init() {
	SchemeBuilder.Register(&HikyoInstance{}, &HikyoInstanceList{}, &HikyoSecret{}, &HikyoSecretList{})
}
