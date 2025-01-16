// Copyright (C) 2025 The Falco Authors
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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// FalcoSpec defines the desired state of Falco.
type FalcoSpec struct {
	// Type specifies the type of Kubernetes resource to deploy Falco.
	// Allowed values: "daemonset" or "deployment".
	// +kubebuilder:validation:Enum=daemonset;deployment
	Type string `json:"type"`

	// Replicas defines the number of replicas for the Deployment.
	// Required only when 'type' is "deployment".
	// Default is 1.
	// +kubebuilder:validation:Minimum=1
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// PodTemplateSpec contains the pod template specification for the Falco instance.
	// Users can customize metadata, initContainers, containers, volumes, tolerations, etc.
	// +optional
	PodTemplateSpec *corev1.PodTemplateSpec `json:"podTemplate,omitempty"`
}

// FalcoStatus defines the observed state of Falco.
type FalcoStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=falcos

// Falco is the Schema for the falcos API.
type Falco struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FalcoSpec   `json:"spec,omitempty"`
	Status FalcoStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FalcoList contains a list of Falco.
type FalcoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Falco `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Falco{}, &FalcoList{})
}
