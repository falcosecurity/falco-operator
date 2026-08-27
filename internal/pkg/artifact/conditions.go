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
	// ReasonOCIArtifactProgrammed indicates the OCI-sourced artifact was stored successfully.
	ReasonOCIArtifactProgrammed = "OCIArtifactProgrammed"
	// ReasonOCIArtifactProgramFailed indicates the OCI-sourced artifact failed to store.
	ReasonOCIArtifactProgramFailed = "OCIArtifactProgramFailed"
	// ReasonInlineArtifactProgrammed indicates the inline-sourced artifact was stored successfully.
	ReasonInlineArtifactProgrammed = "InlineArtifactProgrammed"
	// ReasonInlineArtifactProgramFailed indicates the inline-sourced artifact failed to store.
	ReasonInlineArtifactProgramFailed = "InlineArtifactProgramFailed"
	// ReasonConfigMapArtifactProgrammed indicates the ConfigMap-sourced artifact was stored successfully.
	ReasonConfigMapArtifactProgrammed = "ConfigMapArtifactProgrammed"
	// ReasonConfigMapArtifactProgramFailed indicates the ConfigMap-sourced artifact failed to store.
	ReasonConfigMapArtifactProgramFailed = "ConfigMapArtifactProgramFailed"
	// ReasonConfigProgrammed indicates the plugin config entry was written successfully.
	ReasonConfigProgrammed = "ConfigProgrammed"
	// ReasonConfigProgramFailed indicates the plugin config entry failed to write.
	ReasonConfigProgramFailed = "ConfigProgramFailed"
	// ReasonDependenciesSatisfied indicates all plugin requirements are met by the running Falco instance.
	ReasonDependenciesSatisfied = "DependenciesSatisfied"
	// ReasonDependenciesNotSatisfied indicates one or more plugin requirements are not met.
	ReasonDependenciesNotSatisfied = "DependenciesNotSatisfied"
	// ReasonDependenciesUnknown indicates the Falco API was unreachable and requirements could not be checked.
	ReasonDependenciesUnknown = "DependenciesUnknown"
	// ReasonDependenciesNotSatisfiedInstalledAnyway indicates one or more requirements are not
	// met but the artifact was installed anyway because requirement enforcement is disabled.
	ReasonDependenciesNotSatisfiedInstalledAnyway = "DependenciesNotSatisfiedInstalledAnyway"
	// ReasonDependenciesNotSatisfiedUpdateRejected indicates an update's requirements are not
	// met and the update was rejected, while a previously installed artifact remains in place.
	ReasonDependenciesNotSatisfiedUpdateRejected = "DependenciesNotSatisfiedUpdateRejected"
	// ReasonPluginConfigStillRequired indicates a plugin's on-disk config/binary removal is
	// being withheld because a Rulesfile on this node still structurally depends on it.
	ReasonPluginConfigStillRequired = "PluginConfigStillRequired"
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
	// MessageOCIArtifactProgrammed is the message when the OCI-sourced artifact is stored successfully.
	MessageOCIArtifactProgrammed = "OCI artifact stored successfully"
	// MessageInlineArtifactProgrammed is the message when the inline-sourced artifact is stored successfully.
	MessageInlineArtifactProgrammed = "Inline artifact stored successfully"
	// MessageConfigMapArtifactProgrammed is the message when the ConfigMap-sourced artifact is stored successfully.
	MessageConfigMapArtifactProgrammed = "ConfigMap artifact stored successfully"
	// MessageConfigProgrammed is the message when the plugin config entry is written successfully.
	MessageConfigProgrammed = "Plugin configuration stored successfully"
	// MessageProgramFailed is the message when not all conditions are satisfied.
	MessageProgramFailed = "Not all conditions are satisfied"
	// MessageReferencesResolved is the message when all references are resolved successfully.
	MessageReferencesResolved = "All references were resolved successfully"
	// MessageDependenciesSatisfied is the message when all plugin requirements are met.
	MessageDependenciesSatisfied = "All plugin requirements are satisfied"
	// MessageDependenciesUnknown is the message when the Falco API is unreachable.
	MessageDependenciesUnknown = "Falco API unreachable; plugin requirements could not be verified"
	// MessageSuffixInstalledAnyway is appended to a not-satisfied message when the artifact is
	// installed anyway because requirement enforcement is disabled.
	MessageSuffixInstalledAnyway = "; installed anyway because requirement enforcement is disabled (--enforce-requirements=false)"
	// MessageSuffixUpdateRejected is appended to a not-satisfied message when an update is
	// rejected and the previously installed artifact is kept in place.
	MessageSuffixUpdateRejected = "; rejecting this update and keeping the previously installed version"
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
	// MessageFormatDependenciesNotSatisfied is the format for unmet plugin requirement messages.
	MessageFormatDependenciesNotSatisfied = "Plugin requires %s >= %s but Falco reports %s"
	// MessageFormatPluginAPIMajorMismatch is the format when plugin_api_version major versions differ.
	MessageFormatPluginAPIMajorMismatch = "Plugin requires plugin_api_version %s but Falco reports %s: major versions are incompatible"
	// MessageFormatDependenciesCapabilityMissing is the format when Falco does not advertise a required capability.
	MessageFormatDependenciesCapabilityMissing = "Plugin requires %s >= %s but Falco does not advertise this capability"
	// MessageFormatDependenciesMetadataFetchFailed is the format when OCI metadata cannot be fetched.
	MessageFormatDependenciesMetadataFetchFailed = "Failed to fetch plugin metadata: %s"
	// MessageFormatFalcoVersionsFetchFailed is the format when the Falco /versions endpoint cannot be reached.
	MessageFormatFalcoVersionsFetchFailed = "Failed to fetch Falco versions: %s"
	// MessageFormatRequirementNotSatisfied is the format when a Falco engine requirement version is not met.
	MessageFormatRequirementNotSatisfied = "requires %s >= %s but Falco reports %s"
	// MessageFormatRequirementAPIMajorMismatch is the format when a plugin_api_version major version differs.
	MessageFormatRequirementAPIMajorMismatch = "requires plugin_api_version %s but Falco reports %s: major versions are incompatible"
	// MessageFormatRequirementMissing is the format when a Falco engine requirement is not in the /versions response.
	MessageFormatRequirementMissing = "requires %s >= %s but Falco does not report this capability"
	// MessageFormatDependencyNotSatisfiedWithAlternatives is the format when a plugin dependency and all its
	// alternatives are not satisfied. The alternatives argument is a comma-separated list of "name >= version".
	MessageFormatDependencyNotSatisfiedWithAlternatives = "%s >= %s not satisfied (checked alternatives: %s)"
	// MessageFormatDependencyNotSatisfied is the format when a plugin dependency (no alternatives) is not satisfied.
	MessageFormatDependencyNotSatisfied = "%s >= %s is not satisfied by Falco"
)
