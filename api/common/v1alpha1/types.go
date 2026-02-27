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

// Package v1alpha1 contains common types used across apis.
package v1alpha1

// ConditionType represents a Falco condition type.
// +kubebuilder:validation:MinLength=1
type ConditionType string

const (
	// ConditionAvailable indicates whether enough pods are ready to provide the
	// service.
	// The possible status values for this condition type are:
	// - True: all pods are running and ready, the service is fully available.
	// - Degraded: some pods aren't ready, the service is partially available.
	// - False: no pods are running, the service is totally unavailable.
	// - Unknown: the operator couldn't determine the condition status.
	ConditionAvailable ConditionType = "Available"
	// ConditionReconciled indicates whether the operator has reconciled the state of
	// the underlying resources with the object's spec.
	// The possible status values for this condition type are:
	// - True: the reconciliation was successful.
	// - False: the reconciliation failed.
	// - Unknown: the operator couldn't determine the condition status.
	ConditionReconciled ConditionType = "Reconciled"
	// ConditionResolvedRef indicates whether the references have been successfully resolved.
	// The possible status values for this condition type are:
	// - True: all references were resolved successfully.
	// - False: one or more references could not be resolved.
	ConditionResolvedRef ConditionType = "ResolvedRef"
	// ConditionOCIArtifact indicates whether the OCI artifact has been successfully
	// pulled and stored.
	// The possible status values for this condition type are:
	// - True: the OCI artifact was pulled and stored successfully.
	// - False: the OCI artifact could not be pulled or stored.
	ConditionOCIArtifact ConditionType = "OCIArtifact"
	// ConditionInlineContent indicates whether inline content has been successfully stored.
	// The possible status values for this condition type are:
	// - True: the inline content was stored successfully.
	// - False: the inline content could not be stored.
	ConditionInlineContent ConditionType = "InlineContent"
)

// String returns the string representation of the condition type.
func (c ConditionType) String() string {
	return string(c)
}

const (
	// ConfigMapRulesKey is the standard key used for rules data in ConfigMaps.
	ConfigMapRulesKey = "rules.yaml"
)

// OCIArtifact defines the structure for specifying an OCI artifact reference.
// +kubebuilder:object:generate=true
type OCIArtifact struct {
	// Reference is the OCI artifact reference.
	// +kubebuilder:validation:Required
	Reference string `json:"reference,omitempty"`

	// PullSecret contains authentication details used to pull the OCI artifact.
	PullSecret *OCIPullSecret `json:"pullSecret,omitempty"`
}

// OCIPullSecret defines the structure for specifying authentication details for an OCI artifact.
// +kubebuilder:object:generate=true
type OCIPullSecret struct {
	// SecretName is the name of the secret containing credentials.
	// +kubebuilder:validation:Required
	SecretName string `json:"secretName,omitempty"`

	// UsernameKey is the key in the secret that contains the username.
	// +kubebuilder:default=username
	UsernameKey string `json:"usernameKey,omitempty"`

	// PasswordKey is the key in the secret that contains the password.
	// +kubebuilder:default=password
	PasswordKey string `json:"passwordKey,omitempty"`
}

// ConfigMapRef defines the structure for referencing a ConfigMap and a specific key within it.
// +kubebuilder:object:generate=true
type ConfigMapRef struct {
	// Name is the name of the ConfigMap.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}
