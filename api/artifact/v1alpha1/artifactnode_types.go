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

// ArtifactNodeSpec defines the node assignment for an ArtifactNode.
type ArtifactNodeSpec struct {
	// NodeName is the name of the node to which this artifact is assigned.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="nodeName is immutable"
	NodeName string `json:"nodeName"`
}

// ArtifactNodeStatus defines the per-node observed state of an artifact.
type ArtifactNodeStatus struct {
	// Conditions represent the latest available observations of this node's artifact state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
	// InstalledArtifacts tracks the artifact files currently written to disk by this node's operator.
	// Each entry corresponds to one source medium (oci, inline, configmap).
	// +optional
	// +listType=map
	// +listMapKey=medium
	InstalledArtifacts []InstalledArtifact `json:"installedArtifacts,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=artifactnodes,categories=artifacts
// +kubebuilder:printcolumn:name="Kind",type="string",JSONPath=".metadata.labels['artifact\\.falcosecurity\\.dev/kind']"
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".spec.nodeName"
// +kubebuilder:printcolumn:name="Programmed",type="string",JSONPath=".status.conditions[?(@.type=='Programmed')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ArtifactNode tracks the per-node state of an artifact (Plugin, Rulesfile, or Config).
// One ArtifactNode is created per cluster node that matches the parent artifact selector.
// It is written exclusively by the artifact operator running on that node.
// The artifact kind is stored in the label artifact.falcosecurity.dev/kind.
type ArtifactNode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is required, so the apiserver also enforces NodeName's own required constraint within it.
	// +kubebuilder:validation:Required
	Spec ArtifactNodeSpec `json:"spec"`

	// +kubebuilder:default={conditions: {{type: "Programmed", status: "Unknown", reason:"Pending", message:"Waiting for controller", lastTransitionTime: "1970-01-01T00:00:00Z"}}}
	Status ArtifactNodeStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ArtifactNodeList contains a list of ArtifactNode.
type ArtifactNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ArtifactNode `json:"items"`
}
