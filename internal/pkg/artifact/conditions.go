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
	// ReasonArtifactRemoved indicates the artifact was successfully removed.
	ReasonArtifactRemoved = "ArtifactRemoved"
	// ReasonArtifactRemoveFailed indicates the artifact failed to be removed.
	ReasonArtifactRemoveFailed = "ArtifactRemoveFailed"
	// ReasonConfigMapResolved indicates the ConfigMap reference was resolved successfully.
	ReasonConfigMapResolved = "ConfigMapResolved"
	// ReasonConfigMapResolutionFailed indicates the ConfigMap reference failed to resolve.
	ReasonConfigMapResolutionFailed = "ConfigMapResolutionFailed"
	// ReasonOCIArtifactStored indicates the OCI artifact was stored successfully.
	ReasonOCIArtifactStored = "OCIArtifactStored"
	// ReasonOCIArtifactStoreFailed indicates the OCI artifact failed to store.
	ReasonOCIArtifactStoreFailed = "OCIArtifactStoreFailed"
	// ReasonInlineRulesStored indicates inline rules were stored successfully.
	ReasonInlineRulesStored = "InlineRulesStored"
	// ReasonInlineRulesStoreFailed indicates inline rules failed to store.
	ReasonInlineRulesStoreFailed = "InlineRulesStoreFailed"
	// ReasonInlineConfigStored indicates inline configuration was stored successfully.
	ReasonInlineConfigStored = "InlineConfigStored"
	// ReasonInlineConfigStoreFailed indicates inline configuration failed to store.
	ReasonInlineConfigStoreFailed = "InlineConfigStoreFailed"
	// ReasonInlinePluginConfigStored indicates the plugin configuration was stored successfully.
	ReasonInlinePluginConfigStored = "InlinePluginConfigStored"
	// ReasonInlinePluginConfigStoreFailed indicates the plugin configuration failed to store.
	ReasonInlinePluginConfigStoreFailed = "InlinePluginConfigStoreFailed"
	// ReasonReconciled indicates the artifact was reconciled successfully.
	ReasonReconciled = "Reconciled"
	// ReasonReconcileFailed indicates the artifact failed to reconcile.
	ReasonReconcileFailed = "ReconcileFailed"
)

// Condition messages.
const (
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
	// MessageInlineRulesStored is the message when inline rules are stored successfully.
	MessageInlineRulesStored = "Inline rules stored successfully"
	// MessageInlineConfigStored is the message when inline configuration is stored successfully.
	MessageInlineConfigStored = "Inline configuration stored successfully"
	// MessageInlinePluginConfigStored is the message when inline plugin configuration is stored successfully.
	MessageInlinePluginConfigStored = "Inline plugin configuration stored successfully"
)

// Condition message formats (for use with fmt.Sprintf).
const (
	// MessageFormatConfigStoreFailed is the format for config store failure message.
	MessageFormatConfigStoreFailed = "Failed to store config: %v"
	// MessageFormatOCIArtifactStoreFailed is the format for OCI artifact store failure message.
	MessageFormatOCIArtifactStoreFailed = "Failed to store OCI artifact: %v"
	// MessageFormatPluginArtifactsRemoveFailed is the format for plugin artifacts remove failure message.
	MessageFormatPluginArtifactsRemoveFailed = "Failed to remove plugin artifacts: %v"
	// MessageFormatInlineRulesStoreFailed is the format for inline rules store failure message.
	MessageFormatInlineRulesStoreFailed = "Failed to store inline rules: %v"
	// MessageFormatConfigMapResolutionFailed is the format for ConfigMap resolution failure message.
	MessageFormatConfigMapResolutionFailed = "Failed to resolve ConfigMap: %v"
	// MessageFormatConfigMapResolved is the format for ConfigMap resolved message.
	MessageFormatConfigMapResolved = "ConfigMap %q resolved successfully"
	// MessageFormatInlinePluginConfigStoreFailed is the format for inline plugin config store failure message.
	MessageFormatInlinePluginConfigStoreFailed = "Failed to store inline plugin config: %v"
)
