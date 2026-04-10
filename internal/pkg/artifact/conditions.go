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

package artifact

// Condition reasons.
const (
	// ReasonArtifactRemoveFailed indicates the artifact failed to be removed.
	ReasonArtifactRemoveFailed = "ArtifactRemoveFailed"
	// ReasonPluginArtifactsRemoved indicates all plugin artifacts (OCI files and config) were removed successfully.
	ReasonPluginArtifactsRemoved = "PluginArtifactsRemoved"
	// ReasonReferenceResolved indicates the reference was resolved successfully.
	ReasonReferenceResolved = "ReferenceResolved"
	// ReasonReferenceResolutionFailed indicates the reference failed to resolve.
	ReasonReferenceResolutionFailed = "ReferenceResolutionFailed"
	// ReasonOCIArtifactStored indicates the OCI artifact was stored successfully.
	ReasonOCIArtifactStored = "OCIArtifactStored"
	// ReasonOCIArtifactUpdated indicates the OCI artifact was updated successfully.
	ReasonOCIArtifactUpdated = "OCIArtifactUpdated"
	// ReasonOCIArtifactRemoved indicates the OCI artifact was removed from the filesystem.
	ReasonOCIArtifactRemoved = "OCIArtifactRemoved"
	// ReasonOCIArtifactPriorityChanged indicates the OCI artifact priority changed and the file was renamed.
	ReasonOCIArtifactPriorityChanged = "OCIArtifactPriorityChanged"
	// ReasonOCIArtifactStoreFailed indicates the OCI artifact failed to store.
	ReasonOCIArtifactStoreFailed = "OCIArtifactStoreFailed"
	// ReasonInlineArtifactStored indicates an inline artifact was stored successfully.
	ReasonInlineArtifactStored = "InlineArtifactStored"
	// ReasonInlineArtifactUpdated indicates an inline artifact was updated successfully.
	ReasonInlineArtifactUpdated = "InlineArtifactUpdated"
	// ReasonInlineArtifactRemoved indicates an inline artifact was removed from the filesystem.
	ReasonInlineArtifactRemoved = "InlineArtifactRemoved"
	// ReasonInlineArtifactPriorityChanged indicates an inline artifact priority changed and the file was renamed.
	ReasonInlineArtifactPriorityChanged = "InlineArtifactPriorityChanged"
	// ReasonInlineRulesStoreFailed indicates inline rules failed to store.
	ReasonInlineRulesStoreFailed = "InlineRulesStoreFailed"
	// ReasonConfigMapArtifactStored indicates a ConfigMap artifact was stored successfully.
	ReasonConfigMapArtifactStored = "ConfigMapArtifactStored"
	// ReasonConfigMapArtifactUpdated indicates a ConfigMap artifact was updated successfully.
	ReasonConfigMapArtifactUpdated = "ConfigMapArtifactUpdated"
	// ReasonConfigMapArtifactRemoved indicates a ConfigMap artifact was removed from the filesystem.
	ReasonConfigMapArtifactRemoved = "ConfigMapArtifactRemoved"
	// ReasonConfigMapArtifactPriorityChanged indicates a ConfigMap artifact priority changed and the file was renamed.
	ReasonConfigMapArtifactPriorityChanged = "ConfigMapArtifactPriorityChanged"
	// ReasonConfigMapRulesStoreFailed indicates rules from a ConfigMap failed to store.
	ReasonConfigMapRulesStoreFailed = "ConfigMapRulesStoreFailed"
	// ReasonInlineConfigStoreFailed indicates inline configuration failed to store.
	ReasonInlineConfigStoreFailed = "InlineConfigStoreFailed"
	// ReasonConfigMapConfigStoreFailed indicates configuration from a ConfigMap failed to store.
	ReasonConfigMapConfigStoreFailed = "ConfigMapConfigStoreFailed"
	// ReasonInlinePluginConfigStoreFailed indicates the plugin configuration failed to store.
	ReasonInlinePluginConfigStoreFailed = "InlinePluginConfigStoreFailed"
	// ReasonReconciled indicates the artifact was reconciled successfully.
	ReasonReconciled = "Reconciled"
	// ReasonReconcileFailed indicates the artifact failed to reconcile.
	ReasonReconcileFailed = "ReconcileFailed"
	// ReasonProgrammed indicates the artifact was programmed successfully.
	ReasonProgrammed = "Programmed"
	// ReasonProgramFailed indicates the artifact failed to program.
	ReasonProgramFailed = "ProgramFailed"
	// ReasonDependenciesSatisfied indicates all plugin dependencies are satisfied.
	ReasonDependenciesSatisfied = "DependenciesSatisfied"
	// ReasonMissingDependencies indicates one or more plugin dependencies are missing.
	ReasonMissingDependencies = "MissingDependencies"
)

// Condition messages.
const (
	// MessageOCIArtifactPriorityChanged is the message when an OCI artifact priority changed and the file was renamed.
	MessageOCIArtifactPriorityChanged = "OCI artifact priority changed, file renamed"
	// MessageInlineArtifactPriorityChanged is the message when an inline artifact priority changed and the file was renamed.
	MessageInlineArtifactPriorityChanged = "Inline artifact priority changed, file renamed"
	// MessageConfigMapArtifactPriorityChanged is the message when a ConfigMap artifact priority changed and the file was renamed.
	MessageConfigMapArtifactPriorityChanged = "ConfigMap artifact priority changed, file renamed"
	// MessageConfigReconciled is the message when config is reconciled successfully.
	MessageConfigReconciled = "Config reconciled successfully"
	// MessagePluginReconciled is the message when plugin is reconciled successfully.
	MessagePluginReconciled = "Plugin reconciled successfully"
	// MessageRulesfileReconciled is the message when rulesfile is reconciled successfully.
	MessageRulesfileReconciled = "Rulesfile reconciled successfully"
	// MessagePluginArtifactsRemoved is the message when plugin artifacts are removed.
	MessagePluginArtifactsRemoved = "Plugin artifacts removed successfully"
	// MessageOCIArtifactStored is the message when OCI artifact is stored successfully.
	MessageOCIArtifactStored = "OCI artifact stored successfully"
	// MessageOCIArtifactUpdated is the message when OCI artifact is updated successfully.
	MessageOCIArtifactUpdated = "OCI artifact updated successfully"
	// MessageOCIArtifactRemoved is the message when OCI artifact is removed from the filesystem.
	MessageOCIArtifactRemoved = "OCI artifact removed from filesystem"
	// MessageInlineArtifactStored is the message when an inline artifact is stored successfully.
	MessageInlineArtifactStored = "Inline artifact stored successfully"
	// MessageInlineArtifactUpdated is the message when an inline artifact is updated successfully.
	MessageInlineArtifactUpdated = "Inline artifact updated successfully"
	// MessageInlineArtifactRemoved is the message when an inline artifact is removed from the filesystem.
	MessageInlineArtifactRemoved = "Inline artifact removed from filesystem"
	// MessageConfigMapArtifactStored is the message when a ConfigMap artifact is stored successfully.
	MessageConfigMapArtifactStored = "ConfigMap artifact stored successfully"
	// MessageConfigMapArtifactUpdated is the message when a ConfigMap artifact is updated successfully.
	MessageConfigMapArtifactUpdated = "ConfigMap artifact updated successfully"
	// MessageConfigMapArtifactRemoved is the message when a ConfigMap artifact is removed from the filesystem.
	MessageConfigMapArtifactRemoved = "ConfigMap artifact removed from filesystem"
	// MessageProgrammed is the message when the artifact is programmed successfully.
	MessageProgrammed = "All artifacts sources were programmed successfully"
	// MessageReferencesResolved is the message when all references are resolved successfully.
	MessageReferencesResolved = "All references were resolved successfully"
	// MessageDependenciesSatisfied is the message when plugin dependencies are satisfied.
	MessageDependenciesSatisfied = "All dependencies are satisfied"
)

// Condition message formats (for use with fmt.Sprintf).
const (
	// MessageFormatConfigStoreFailed is the format for config store failure message.
	MessageFormatConfigStoreFailed = "Failed to store config: %s"
	// MessageFormatOCIArtifactStoreFailed is the format for OCI artifact store failure message.
	MessageFormatOCIArtifactStoreFailed = "Failed to store OCI artifact: %s"
	// MessageFormatPluginArtifactsRemoveFailed is the format for plugin artifacts remove failure message.
	MessageFormatPluginArtifactsRemoveFailed = "Failed to remove plugin artifacts: %s"
	// MessageFormatConfigMapRulesStoreFailed is the format for ConfigMap rules store failure message.
	MessageFormatConfigMapRulesStoreFailed = "Failed to store ConfigMap rules: %s"
	// MessageFormatConfigMapConfigStoreFailed is the format for ConfigMap config store failure message.
	MessageFormatConfigMapConfigStoreFailed = "Failed to store ConfigMap config: %s"
	// MessageFormatInlineRulesStoreFailed is the format for inline rules store failure message.
	MessageFormatInlineRulesStoreFailed = "Failed to store inline rules: %s"
	// MessageFormatReferenceResolutionFailed is the format for Reference resolution failure message.
	MessageFormatReferenceResolutionFailed = "Failed to resolve Reference: %s"
	// MessageFormatReferenceResolved is the format for Reference resolved message.
	MessageFormatReferenceResolved = "Reference %q resolved successfully"
	// MessageFormatInlinePluginConfigStoreFailed is the format for inline plugin config store failure message.
	MessageFormatInlinePluginConfigStoreFailed = "Failed to store inline plugin config: %v"
	// MessageFormatDependenciesNotFound is the format for missing dependency message.
	MessageFormatDependenciesNotFound = "Dependencies not found: %s"
)
