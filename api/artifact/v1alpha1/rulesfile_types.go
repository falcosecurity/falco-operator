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

// Package controller defines controllers' logic.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commonv1alpha1 "github.com/alacuku/falco-operator/api/common/v1alpha1"
)

// RulesfileSpec defines the desired state of Rulesfile.
type RulesfileSpec struct {
	// OCIArtifact specifies the reference to an OCI artifact.
	OCIArtifact *commonv1alpha1.OCIArtifact `json:"ociArtifact,omitempty"`
	// RulesString specifies the rules as a string.
	RulesString string `json:"rulesString,omitempty"`
}

// RulesfileStatus defines the observed state of Rulesfile.
type RulesfileStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Rulesfile is the Schema for the rulesfiles API.
type Rulesfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RulesfileSpec   `json:"spec,omitempty"`
	Status RulesfileStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RulesfileList contains a list of Rulesfile.
type RulesfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Rulesfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Rulesfile{}, &RulesfileList{})
}
