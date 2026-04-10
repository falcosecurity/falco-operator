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
	// - False (reason: Degraded): some pods aren't ready, the service is partially available.
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
	// ConditionResolvedRefs indicates whether the references have been successfully resolved.
	// The possible status values for this condition type are:
	// - True: all references were resolved successfully.
	// - False: one or more references could not be resolved.
	ConditionResolvedRefs ConditionType = "ResolvedRefs"
	// ConditionProgrammed indicates whether the artifact has been successfully programmed into falco.
	// The possible status values for this condition type are:
	// - True: the artifact was programmed successfully.
	// - False: the artifact could not be programmed.
	ConditionProgrammed ConditionType = "Programmed"
	// ConditionDependenciesSatisfied indicates whether the plugin dependencies are present.
	// The possible status values for this condition type are:
	// - True: all required dependencies are satisfied.
	// - False: one or more required dependencies are missing.
	// - Unknown: the operator couldn't determine dependency status.
	ConditionDependenciesSatisfied ConditionType = "DependenciesSatisfied"
)

// String returns the string representation of the condition type.
func (c ConditionType) String() string {
	return string(c)
}

const (
	// ConfigMapRulesKey is the standard key used for rules data in ConfigMaps.
	ConfigMapRulesKey = "rules.yaml"

	// ConfigMapConfigKey is the standard key used for Falco configuration data in ConfigMaps.
	ConfigMapConfigKey = "config.yaml"

	// SecretUsernameKey is the key used for the username in authentication Secrets.
	SecretUsernameKey = "username"

	// SecretPasswordKey is the key used for the password (or token) in authentication Secrets.
	SecretPasswordKey = "password"
)

// OCIArtifact defines the structure for specifying an OCI artifact reference.
// +kubebuilder:object:generate=true
type OCIArtifact struct {
	// Image specifies the OCI image coordinates.
	// +kubebuilder:validation:Required
	Image ImageSpec `json:"image"`

	// Registry contains inline registry configuration for authentication, TLS, and hostname.
	// +optional
	Registry *RegistryConfig `json:"registry,omitempty"`
}

// ImageSpec specifies the OCI image coordinates.
// +kubebuilder:object:generate=true
type ImageSpec struct {
	// Repository is the OCI repository path (e.g. "falcosecurity/rules/falco-rules").
	// +kubebuilder:validation:Required
	Repository string `json:"repository"`
	// Tag is the image tag or digest (e.g. "latest" or "sha256:abc...").
	// +kubebuilder:default=latest
	Tag string `json:"tag,omitempty"`
}

// SecretRef defines a reference to a Secret containing registry credentials.
// The referenced Secret must contain the keys "username" and "password".
// The "password" field can also hold an access token.
// +kubebuilder:object:generate=true
type SecretRef struct {
	// Name is the name of the Secret containing credentials.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// TLSConfig defines TLS transport options for OCI registry communication.
// +kubebuilder:object:generate=true
type TLSConfig struct {
	// InsecureSkipVerify disables TLS certificate verification.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// RegistryAuth defines authentication configuration for an OCI registry.
// +kubebuilder:object:generate=true
type RegistryAuth struct {
	// SecretRef references a Secret containing registry credentials.
	// +optional
	SecretRef *SecretRef `json:"secretRef,omitempty"`
}

// RegistryConfig defines inline registry configuration for an OCI artifact.
// +kubebuilder:object:generate=true
// +kubebuilder:validation:XValidation:rule="!(has(self.plainHTTP) && self.plainHTTP && has(self.tls))",message="plainHTTP and tls are mutually exclusive"
type RegistryConfig struct {
	// Name is the registry hostname (e.g. "ghcr.io").
	// +optional
	Name string `json:"name,omitempty"`

	// Auth contains authentication configuration.
	// +optional
	Auth *RegistryAuth `json:"auth,omitempty"`

	// PlainHTTP allows connections to registries over plain HTTP (no TLS).
	// Mutually exclusive with tls.
	// +optional
	PlainHTTP *bool `json:"plainHTTP,omitempty"`

	// TLS contains TLS transport configuration.
	// Mutually exclusive with plainHTTP.
	// +optional
	TLS *TLSConfig `json:"tls,omitempty"`
}

// ConfigMapRef defines the structure for referencing a ConfigMap and a specific key within it.
// +kubebuilder:object:generate=true
type ConfigMapRef struct {
	// Name is the name of the ConfigMap.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}
