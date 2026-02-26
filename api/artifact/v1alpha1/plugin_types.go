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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

// PluginSpec defines the desired state of Plugin.
type PluginSpec struct {
	// OCIArtifact specifies the reference to an OCI artifact.
	OCIArtifact *commonv1alpha1.OCIArtifact `json:"ociArtifact,omitempty"`
	// Config specifies the configuration for the plugin.
	Config *PluginConfig `json:"config,omitempty"`
	// Selector is used to select the nodes where the plugin should be applied.
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// PluginConfig defines the configuration for the plugin.
type PluginConfig struct {
	// Name is the name of the plugin.
	// If omitted, the name of the CRD will be used.
	Name string `json:"name,omitempty"`
	// LibraryPath is the path to the plugin library, e.g., /usr/share/falco/plugins/myplugin.so.
	// If omitted, it is set to /usr/share/falco/plugins/plugin-name.so.
	LibraryPath string `json:"libraryPath,omitempty"`
	// InitConfig is the initialization configuration for the plugin.
	InitConfig *apiextensionsv1.JSON `json:"initConfig,omitempty"`
	// OpenParams is the open parameters for the plugin.
	OpenParams string `json:"openParams,omitempty"`
}

// PluginStatus defines the observed state of Plugin.
type PluginStatus struct {
	// Conditions represent the latest available observations of the Plugin's state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=plugins
// +kubebuilder:printcolumn:name="Reconciled",type="string",JSONPath=".status.conditions[?(@.type == 'Reconciled')].status"
// +kubebuilder:printcolumn:name="OCIArtifact",type="string",JSONPath=".status.conditions[?(@.type == 'OCIArtifact')].status"
// +kubebuilder:printcolumn:name="InlineContent",type="string",JSONPath=".status.conditions[?(@.type == 'InlineContent')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// Plugin is the Schema for the plugin API.
type Plugin struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PluginSpec   `json:"spec,omitempty"`
	Status PluginStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PluginList contains a list of Plugin.
type PluginList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Plugin `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Plugin{}, &PluginList{})
}
