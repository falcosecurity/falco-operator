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
	// ConditionDependenciesSatisfied indicates whether the plugin's declared requirements are met by the
	// running Falco instance.
	// The possible status values for this condition type are:
	// - True: all plugin requirements are satisfied; the plugin may be installed.
	// - False: one or more requirements are not satisfied; the plugin will not be installed.
	// - Unknown: the Falco API was unreachable; the check will be retried on the next reconcile.
	ConditionDependenciesSatisfied ConditionType = "DependenciesSatisfied"
	// ConditionOCIArtifactProgrammed indicates whether the OCI-sourced artifact has been successfully
	// stored on the local filesystem. Used by plugin (binary) and rulesfile (OCI rules).
	// The possible status values for this condition type are:
	// - True: the artifact was fetched and stored (or verified unchanged on disk).
	// - False: fetching or storing the artifact failed.
	ConditionOCIArtifactProgrammed ConditionType = "OCIArtifactProgrammed"
	// ConditionInlineArtifactProgrammed indicates whether the inline-sourced artifact has been
	// successfully stored on the local filesystem. Used by rulesfile and config.
	// The possible status values for this condition type are:
	// - True: the artifact was stored (or verified unchanged on disk).
	// - False: storing the artifact failed.
	ConditionInlineArtifactProgrammed ConditionType = "InlineArtifactProgrammed"
	// ConditionConfigMapArtifactProgrammed indicates whether the ConfigMap-sourced artifact has been
	// successfully stored on the local filesystem. Used by rulesfile and config.
	// The possible status values for this condition type are:
	// - True: the artifact was stored (or verified unchanged on disk).
	// - False: storing the artifact failed.
	ConditionConfigMapArtifactProgrammed ConditionType = "ConfigMapArtifactProgrammed"
	// ConditionConfigProgrammed indicates whether the shared plugin configuration file
	// (plugins-config-inline.yaml) has been written for this plugin. Owned exclusively by ensurePluginConfig.
	// The possible status values for this condition type are:
	// - True: the config entry was written (or verified unchanged on disk).
	// - False: writing the config entry failed.
	ConditionConfigProgrammed ConditionType = "ConfigProgrammed"
	// ConditionDeletionBlocked indicates whether removal of this node's artifact is being
	// withheld because another artifact on the same node (e.g. a Rulesfile) still structurally
	// depends on it. Set only by per-node artifact operators on the ArtifactNode they own; the
	// instance-level aggregator surfaces it onto the parent artifact like any other condition.
	// The possible status values for this condition type are:
	// - True: removal is blocked; the message names the blocking dependent(s).
	// - Absent: not blocked. This condition is only ever set while a removal is actually being
	//   withheld; there is no corresponding False state to clear.
	ConditionDeletionBlocked ConditionType = "DeletionBlocked"
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

// ArtifactMeta holds the parsed metadata for an artifact (requirements and dependencies
// extracted from all sources). Written by the instance operator; read by per-node artifact
// operators to check requirements without hitting the registry or re-parsing content.
// +kubebuilder:object:generate=true
type ArtifactMeta struct {
	// Digest is the resolved OCI manifest digest of the currently observed artifact.
	// +optional
	Digest string `json:"digest,omitempty"`
	// SpecHash is a SHA-256 hash of the OCIArtifact spec. When it changes the cached
	// Digest, Requirements, and Dependencies are invalidated and re-fetched.
	// +optional
	SpecHash string `json:"specHash,omitempty"`
	// Requirements lists the engine/capability requirements declared by the artifact.
	// +optional
	Requirements []ArtifactMetaRequirement `json:"requirements,omitempty"`
	// Dependencies lists the plugin dependencies declared by the artifact.
	// +optional
	Dependencies []ArtifactMetaDependency `json:"dependencies,omitempty"`
}

// ArtifactMetaRequirement is a single engine or capability requirement declared by an artifact.
// +kubebuilder:object:generate=true
type ArtifactMetaRequirement struct {
	// Name is the capability name (e.g. "engine_version_semver", "falco").
	Name string `json:"name"`
	// Version is the minimum required version string.
	Version string `json:"version"`
}

// ArtifactMetaDependency is a plugin dependency declared by an artifact.
// +kubebuilder:object:generate=true
type ArtifactMetaDependency struct {
	// Name is the plugin name.
	Name string `json:"name"`
	// Version is the minimum required plugin version.
	Version string `json:"version"`
	// Alternatives lists optional substitute plugins that can satisfy this dependency.
	// +optional
	Alternatives []ArtifactMetaDependencyVariant `json:"alternatives,omitempty"`
}

// ArtifactMetaDependencyVariant is an alternative plugin that can satisfy a dependency.
// It is a flat (non-recursive) form of ArtifactMetaDependency so that CRD schemas
// can express a concrete array-item type.
// +kubebuilder:object:generate=true
type ArtifactMetaDependencyVariant struct {
	// Name is the plugin name.
	Name string `json:"name"`
	// Version is the minimum required plugin version.
	Version string `json:"version"`
}
