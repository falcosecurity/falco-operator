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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MetacollectorSpec defines the desired state of Metacollector.
type MetacollectorSpec struct {
	// Version specifies the version of k8s-metacollector to deploy.
	// If omitted, the operator will default to the version bundled with the operator.
	// +optional
	Version string `json:"version,omitempty"`

	// Replicas defines the number of replicas for the Deployment.
	// Default is 1.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// PodTemplateSpec contains the pod template specification for the Metacollector instance.
	// Users can customize metadata, containers, volumes, tolerations, etc.
	// +optional
	PodTemplateSpec *corev1.PodTemplateSpec `json:"podTemplateSpec,omitempty"`

	// Strategy specifies the deployment strategy for the Deployment.
	// +optional
	Strategy *appsv1.DeploymentStrategy `json:"strategy,omitempty"`
}

// MetacollectorStatus defines the observed state of Metacollector.
type MetacollectorStatus struct {
	// Desired number of instances for the Metacollector deployment.
	// +optional
	DesiredReplicas int32 `json:"desiredReplicas,omitempty" protobuf:"varint,1,opt,name=desiredReplicas"`
	// Total number of available pods (ready for at least minReadySeconds) targeted by the deployment.
	// +optional
	AvailableReplicas int32 `json:"availableReplicas" protobuf:"varint,2,opt,name=availableReplicas"`
	// Total number of unavailable pods targeted by the deployment.
	// +optional
	UnavailableReplicas int32 `json:"unavailableReplicas,omitempty" protobuf:"varint,3,opt,name=unavailableReplicas"`

	// Conditions represent the latest available observations of the Metacollector instance's state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:printcolumn:name="Version",type="string",JSONPath=".spec.version",description="The version of k8s-metacollector"
// +kubebuilder:printcolumn:name="Desired",type="integer",JSONPath=".status.desiredReplicas",description="The desired number of replicas"
// +kubebuilder:printcolumn:name="Ready",type="integer",JSONPath=".status.availableReplicas",description="The number of ready replicas"
// +kubebuilder:printcolumn:name="Reconciled",type="string",JSONPath=".status.conditions[?(@.type == 'Reconciled')].status"
// +kubebuilder:printcolumn:name="Available",type="string",JSONPath=".status.conditions[?(@.type == 'Available')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=metacollectors

// Metacollector is the Schema for the metacollectors API.
type Metacollector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MetacollectorSpec   `json:"spec,omitempty"`
	Status MetacollectorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MetacollectorList contains a list of Metacollector.
type MetacollectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Metacollector `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Metacollector{}, &MetacollectorList{})
}
