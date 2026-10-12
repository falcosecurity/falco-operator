// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MaxNodeArtifacts is the maximum number of artifacts a single ArtifactNode can list, in its spec
// and in its status alike. It bounds the object size, since every update rewrites and re-sends the
// whole object.
const MaxNodeArtifacts = 100

// NodeArtifactRef identifies one artifact assigned to a node. The artifact lives in the namespace of
// the ArtifactNode that lists it.
type NodeArtifactRef struct {
	// Kind is the kind of the assigned artifact.
	// +kubebuilder:validation:Required
	Kind ArtifactKind `json:"kind"`
	// Name is the name of the assigned artifact.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// UID is the UID of the artifact object the assignment was made for. It tells a deleted and
	// recreated artifact of the same name apart from its predecessor.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	UID string `json:"uid"`
}

// ArtifactNodeSpec defines the artifacts assigned to a node.
type ArtifactNodeSpec struct {
	// NodeName is the name of the node the artifacts are assigned to.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="nodeName is immutable"
	NodeName string `json:"nodeName"`
	// Artifacts is the set of artifacts assigned to the node. Entries are unique by kind and name.
	// +optional
	// +listType=map
	// +listMapKey=kind
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=100
	Artifacts []NodeArtifactRef `json:"artifacts,omitempty"`
}

// NodeArtifactStatus is the state of one assigned artifact on the node, as reported by the artifact
// operator running there.
type NodeArtifactStatus struct {
	// Kind is the kind of the artifact this entry reports on.
	// +kubebuilder:validation:Required
	Kind ArtifactKind `json:"kind"`
	// Name is the name of the artifact this entry reports on.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// UID is the UID of the artifact object this entry reports on. An entry whose UID differs from
	// the assignment's describes a previous incarnation of the artifact and must be ignored.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	UID string `json:"uid"`
	// Conditions represent the latest available observations of the artifact's state on this node.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=16
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// InstalledArtifacts tracks the artifact files currently written to disk for this artifact.
	// Each entry corresponds to one source medium (oci, inline, configmap).
	// +optional
	// +listType=map
	// +listMapKey=medium
	// +kubebuilder:validation:MaxItems=3
	InstalledArtifacts []InstalledArtifact `json:"installedArtifacts,omitempty"`
}

// ArtifactNodeStatus defines the observed state of the artifacts assigned to a node.
type ArtifactNodeStatus struct {
	// Artifacts is the per-artifact state, written exclusively by the artifact operator on the node.
	// +optional
	// +listType=map
	// +listMapKey=kind
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=100
	Artifacts []NodeArtifactStatus `json:"artifacts,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=artifactnodes,categories=artifacts
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".spec.nodeName"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ArtifactNode records the artifacts (Rulesfile, Plugin and Config) assigned to one node of a
// namespace and their per-node state. One ArtifactNode exists per namespace and node that runs a
// Falco pod. Its spec is written by the instance operator and its status by the artifact operator
// running on that node.
type ArtifactNode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is required, so the apiserver also enforces NodeName's own required constraint within it.
	// +kubebuilder:validation:Required
	Spec ArtifactNodeSpec `json:"spec"`

	Status ArtifactNodeStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ArtifactNodeList contains a list of ArtifactNode.
type ArtifactNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ArtifactNode `json:"items"`
}
