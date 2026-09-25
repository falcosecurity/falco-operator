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

import (
	corev1 "k8s.io/api/core/v1"
)

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

	// AzureClientSecretKey is the key used for the client secret in Secrets referenced by
	// AzureAuth.ClientSecretRef.
	AzureClientSecretKey = "clientSecret"

	// AzureClientCertificateKey is the key used for the client certificate (PEM or PKCS#12) in
	// Secrets referenced by AzureAuth.ClientCertificateRef.
	AzureClientCertificateKey = "certificate"

	// AzureClientCertificatePasswordKey is the key used for the client certificate's password, if
	// any, in Secrets referenced by AzureAuth.ClientCertificateRef.
	AzureClientCertificatePasswordKey = "password"
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

// RegistryAuth defines authentication configuration for an OCI registry. If both SecretRef and
// Azure are set, Azure takes precedence and SecretRef is ignored entirely -- not merged, not
// used as a fallback. Set only one.
// +kubebuilder:object:generate=true
type RegistryAuth struct {
	// SecretRef references a Secret containing registry credentials. Ignored when Azure is also
	// set.
	// +optional
	SecretRef *SecretRef `json:"secretRef,omitempty"`

	// Azure authenticates using an Azure identity instead of a static Secret. See AzureAuth's
	// own godoc for the four supported methods and what each requires. Takes precedence over
	// SecretRef when both are set.
	// +optional
	Azure *AzureAuth `json:"azure,omitempty"`
}

const (
	// AzureMethodClientSecret authenticates as a Microsoft Entra app registration using a
	// client secret (AzureAuth.ClientSecretRef).
	AzureMethodClientSecret = "clientSecret"
	// AzureMethodClientCertificate authenticates as a Microsoft Entra app registration using a
	// client certificate (AzureAuth.ClientCertificateRef).
	AzureMethodClientCertificate = "clientCertificate"
	// AzureMethodManagedIdentity authenticates via the Azure Instance Metadata Service (IMDS)
	// using the node's system-assigned identity, or a user-assigned identity when
	// AzureAuth.ClientID is set.
	AzureMethodManagedIdentity = "managedIdentity"
	// AzureMethodWorkloadIdentity authenticates using a Kubernetes ServiceAccount token
	// (AzureAuth.ServiceAccountRef), federated to an Entra app or managed identity via OIDC
	// trust.
	AzureMethodWorkloadIdentity = "workloadIdentity"
)

// AzureAuth configures registry authentication via an Azure identity. Exactly one method is
// used, selected by Method; the other method-specific fields are ignored.
//
// Every field below except Method and ServiceAccountRef is optional in the CR and falls back to
// the matching AZURE_* environment variable (read from this process's own environment -- the
// falco-operator Deployment's) when left empty; an explicit CR value always wins when both are
// set. This lets one cluster-wide default identity be configured once via the operator's
// Deployment env, with individual AzureAuth resources overriding only what differs. The one
// field with no environment equivalent is ServiceAccountRef: it identifies which ServiceAccount
// to federate, not a credential value, so there is nothing meaningful to source from the
// operator's own environment -- see its own godoc.
// +kubebuilder:object:generate=true
// +kubebuilder:validation:XValidation:rule="self.method != 'workloadIdentity' || (has(self.serviceAccountRef) && self.serviceAccountRef.name.size() > 0)",message="serviceAccountRef.name is required when method is workloadIdentity"
type AzureAuth struct {
	// Method selects how the Azure identity is obtained.
	// - clientSecret: a Microsoft Entra app registration authenticated with a client secret.
	// - clientCertificate: the same, authenticated with a certificate instead.
	// - managedIdentity: the node's system-assigned identity, or a user-assigned identity when
	//   clientId is set. Authenticates via the Azure Instance Metadata Service (IMDS) -- there is
	//   no per-namespace or per-artifact isolation with this method, every AzureAuth using it
	//   resolves to whichever identity is attached to the node the operator pod is scheduled on.
	// - workloadIdentity: a Kubernetes ServiceAccount token (serviceAccountRef), federated to an
	//   Entra app or managed identity via OIDC trust.
	// +kubebuilder:validation:Enum=clientSecret;clientCertificate;managedIdentity;workloadIdentity
	// +kubebuilder:validation:Required
	Method string `json:"method"`

	// TenantID is the Microsoft Entra tenant ID. Required (from this field or AZURE_TENANT_ID)
	// for clientSecret, clientCertificate, and workloadIdentity; unused for managedIdentity
	// (IMDS resolves the tenant from the attached identity).
	// +optional
	TenantID string `json:"tenantId,omitempty"`

	// ClientID is the application (client) ID to authenticate as. Required (from this field or
	// AZURE_CLIENT_ID) for clientSecret, clientCertificate, and workloadIdentity. For
	// managedIdentity, its presence selects a user-assigned identity by client ID; its absence
	// selects the node's system-assigned identity.
	//
	// Warning for managedIdentity: "its presence" includes the AZURE_CLIENT_ID environment
	// fallback, not just this field. If the operator Deployment sets AZURE_CLIENT_ID as a
	// cluster-wide default for clientSecret/clientCertificate/workloadIdentity resources (an
	// Entra app registration's client ID), every managedIdentity resource that leaves this field
	// empty inherits that same value and silently stops being system-assigned -- it attempts a
	// user-assigned IMDS lookup with an Entra app ID instead of a managed identity's client ID,
	// which fails. A managedIdentity resource that wants the node's system-assigned identity
	// while AZURE_CLIENT_ID is set for other methods must not rely on leaving this field empty;
	// there is no way to explicitly override it back to "unset" once the environment provides a
	// value, since an empty string here is indistinguishable from "not set, check the
	// environment".
	// +optional
	ClientID string `json:"clientId,omitempty"`

	// ClientSecretRef references a Secret containing the app registration's client secret, under
	// the key "clientSecret". Used when method is clientSecret; falls back to the
	// AZURE_CLIENT_SECRET environment variable when unset.
	// +optional
	ClientSecretRef *SecretRef `json:"clientSecretRef,omitempty"`

	// ClientCertificateRef references a Secret containing the client certificate (PEM or PKCS#12,
	// under the key "certificate") and, if the certificate is password-protected, the password
	// under the key "password". Used when method is clientCertificate; falls back to reading a
	// certificate file at the path named by the AZURE_CLIENT_CERTIFICATE_PATH environment
	// variable (plus AZURE_CLIENT_CERTIFICATE_PASSWORD) when unset.
	// +optional
	ClientCertificateRef *SecretRef `json:"clientCertificateRef,omitempty"`

	// SendCertificateChain controls whether the certificate's public chain is sent in the x5c
	// header of each token request, as required for Subject Name/Issuer (SNI) authentication --
	// needed when the Microsoft Entra app registration trusts this certificate by subject
	// name/issuer rather than by exact thumbprint (e.g. because the certificate is reissued
	// periodically by an intermediate CA without updating the app registration each time). Only
	// used when method is clientCertificate. A pointer, not a bare bool: nil means "not set,
	// fall back to the AZURE_CLIENT_SEND_CERTIFICATE_CHAIN environment variable" (itself
	// defaulting to false), distinct from an explicit false in the CR. Matches azidentity's own
	// ClientCertificateCredentialOptions.SendCertificateChain default when nothing is set
	// anywhere.
	// +optional
	SendCertificateChain *bool `json:"sendCertificateChain,omitempty"`

	// ServiceAccountRef names the ServiceAccount, in the same namespace as this resource, whose
	// federated identity is used. Required when method is workloadIdentity -- unlike every other
	// field on AzureAuth, it has no environment variable fallback, deliberately: it names which
	// ServiceAccount to federate, not a credential value, so there is nothing meaningful to
	// source from the operator's own environment (that would collapse every workloadIdentity
	// AzureAuth cluster-wide onto a single identity, defeating the point of this method). The
	// Azure-side federated identity credential must trust the subject
	// system:serviceaccount:<this resource's namespace>:<name>.
	//
	// This ServiceAccount does not need the azure.workload.identity/use pod label or the
	// Azure Workload Identity mutating webhook installed: the operator mints its token itself,
	// per resolution, via the Kubernetes TokenRequest API, rather than relying on a
	// webhook-projected token file tied to one pod's one identity. Those are only relevant to
	// azidentity's own file-based WorkloadIdentityCredential, which this does not use.
	//
	// Security note: minting a token for a ServiceAccount is a materially different privilege
	// than referencing a Secret (as ClientSecretRef/ClientCertificateRef do). A Secret reference
	// only exposes whatever credential that Secret already contains; naming a ServiceAccount
	// here actively mints a *fresh* identity assertion for it, and the underlying
	// serviceaccounts/token permission is granted to the operator as a cluster-wide ClusterRole
	// (Kubernetes has no finer-grained way to scope it to "only ServiceAccounts referenced by a
	// resource in their own namespace"). Without a further check, that would let anyone able to
	// create a Rulesfile/Plugin/Config resource in a namespace get a token minted for *any*
	// ServiceAccount in it -- including one some unrelated workload already has federated to an
	// Azure identity, not just one meant for their own resource.
	//
	// To narrow that: the named ServiceAccount must separately carry the annotation
	// azure.falcosecurity.dev/client-id, set to exactly this AzureAuth's ClientID, before the
	// operator will mint a token for it. Setting that annotation is a deliberate act by whoever
	// administers ServiceAccounts in the namespace -- not implied by merely being nameable here.
	// This narrows the trust to "any artifact author can use any ServiceAccount that has opted
	// in to their specific client ID", still namespace-local and still not a full authorization
	// system (someone who can both create artifact resources *and* edit ServiceAccounts in the
	// same namespace can self-authorize) but a real reduction from "any ServiceAccount already
	// federated to anything, for any reason". See the Reconcile doc comment in
	// controllers/instance/falco/controller.go for the full reasoning.
	// +optional
	ServiceAccountRef *corev1.LocalObjectReference `json:"serviceAccountRef,omitempty"`
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
