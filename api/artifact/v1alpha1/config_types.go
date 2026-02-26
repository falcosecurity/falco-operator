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

// ConfigSpec defines the desired state of Config.
type ConfigSpec struct {
	// Config is the configuration for Falco deployment.
	// +kubebuilder:validation:Required
	Config string `json:"config,omitempty"`
	// Priority specifies the priority of the rulesfile.\
	// The higher the value, the higher the priority.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=99
	// +kubebuilder:default=50
	Priority int32 `json:"priority,omitempty"`
	// Selector is used to select the nodes where the config should be applied.
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// ConfigStatus defines the observed state of Config.
type ConfigStatus struct {
	// Conditions represent the latest available observations of the Config's state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Priority",type="integer",JSONPath=".spec.priority",description="The priority of the config"
// +kubebuilder:printcolumn:name="Reconciled",type="string",JSONPath=".status.conditions[?(@.type == 'Reconciled')].status"
// +kubebuilder:printcolumn:name="InlineContent",type="string",JSONPath=".status.conditions[?(@.type == 'InlineContent')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// Config is the Schema for the configs API.
type Config struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ConfigSpec   `json:"spec,omitempty"`
	Status ConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConfigList contains a list of Config.
type ConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Config `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Config{}, &ConfigList{})
}
