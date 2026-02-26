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

package falco

// Reconciled condition reasons.
const (
	// ReasonApplyConfigurationError indicates an error generating the apply configuration.
	ReasonApplyConfigurationError = "ApplyConfigurationError"
	// ReasonMarshalConfigurationError indicates an error marshaling the configuration.
	ReasonMarshalConfigurationError = "MarshalConfigurationError"
	// ReasonOwnerReferenceError indicates an error setting the owner reference.
	ReasonOwnerReferenceError = "OwnerReferenceError"
	// ReasonExistingResourceError indicates an error fetching existing resource.
	ReasonExistingResourceError = "ExistingResourceError"
	// ReasonApplyPatchErrorOnCreate indicates an error applying patch during creation.
	ReasonApplyPatchErrorOnCreate = "ApplyPatchErrorOnCreate"
	// ReasonApplyPatchErrorOnUpdate indicates an error applying patch during update.
	ReasonApplyPatchErrorOnUpdate = "ApplyPatchErrorOnUpdate"
	// ReasonResourceCreated indicates the resource was created successfully.
	ReasonResourceCreated = "ResourceCreated"
	// ReasonResourceUpdated indicates the resource was updated successfully.
	ReasonResourceUpdated = "ResourceUpdated"
	// ReasonResourceUpToDate indicates the resource is already up to date.
	ReasonResourceUpToDate = "ResourceUpToDate"
	// ReasonResourceComparisonError indicates an error comparing resources.
	ReasonResourceComparisonError = "ResourceComparisonError"
)

// Sub-resource event reasons.
const (
	// ReasonResourceGenerateError indicates an error generating a sub-resource.
	ReasonResourceGenerateError = "ResourceGenerateError"
	// ReasonResourceApplyError indicates an error applying a sub-resource.
	ReasonResourceApplyError = "ResourceApplyError"
	// ReasonSubResourceCreated indicates a sub-resource was created successfully.
	ReasonSubResourceCreated = "SubResourceCreated"
	// ReasonSubResourceUpdated indicates a sub-resource was updated successfully.
	ReasonSubResourceUpdated = "SubResourceUpdated"
)

// Deletion event reasons.
const (
	// ReasonDeletionError indicates an error during deletion cleanup.
	ReasonDeletionError = "DeletionError"
	// ReasonInstanceDeleted indicates the Falco instance was deleted successfully.
	ReasonInstanceDeleted = "InstanceDeleted"
)

// Available condition reasons.
const (
	// ReasonDeploymentNotFound indicates the deployment was not found.
	ReasonDeploymentNotFound = "DeploymentNotFound"
	// ReasonDeploymentAvailable indicates the deployment is available.
	ReasonDeploymentAvailable = "DeploymentAvailable"
	// ReasonDeploymentUnavailable indicates the deployment is unavailable.
	ReasonDeploymentUnavailable = "DeploymentUnavailable"
	// ReasonDeploymentFetchError indicates an error fetching the deployment status.
	ReasonDeploymentFetchError = "DeploymentFetchError"
	// ReasonDaemonSetNotFound indicates the daemonset was not found.
	ReasonDaemonSetNotFound = "DaemonSetNotFound"
	// ReasonDaemonSetAvailable indicates the daemonset is available.
	ReasonDaemonSetAvailable = "DaemonSetAvailable"
	// ReasonDaemonSetUnavailable indicates the daemonset is unavailable.
	ReasonDaemonSetUnavailable = "DaemonSetUnavailable"
	// ReasonDaemonSetFetchError indicates an error fetching the daemonset status.
	ReasonDaemonSetFetchError = "DaemonSetFetchError"
)

// Condition messages.
const (
	// MessageDeploymentNotFound is the message when deployment is not found.
	MessageDeploymentNotFound = "Deployment has not been created or has been deleted"
	// MessageDeploymentAvailable is the message when deployment is available.
	MessageDeploymentAvailable = "Deployment is available"
	// MessageDeploymentUnavailable is the message when deployment is unavailable.
	MessageDeploymentUnavailable = "Deployment is unavailable"
	// MessageDaemonSetNotFound is the message when daemonset is not found.
	MessageDaemonSetNotFound = "DaemonSet has not been created or has been deleted"
	// MessageDaemonSetAvailable is the message when daemonset is available.
	MessageDaemonSetAvailable = "DaemonSet is available"
	// MessageDaemonSetUnavailable is the message when daemonset is unavailable.
	MessageDaemonSetUnavailable = "DaemonSet is unavailable"
	// MessageResourceCreated is the message when resource is created.
	MessageResourceCreated = "Resource created successfully"
	// MessageResourceUpdated is the message when resource is updated.
	MessageResourceUpdated = "Resource updated successfully"
	// MessageResourceUpToDate is the message when resource is up to date.
	MessageResourceUpToDate = "Resource is up to date"
	// MessageInstanceDeleted is the message when a Falco instance is deleted.
	MessageInstanceDeleted = "Falco instance deleted successfully"
)

// Available condition message formats (for use with fmt.Sprintf).
const (
	// MessageFormatDeploymentFetchError is the format for deployment fetch error message.
	MessageFormatDeploymentFetchError = "Unable to fetch deployment for status: %s"
	// MessageFormatDaemonSetFetchError is the format for daemonset fetch error message.
	MessageFormatDaemonSetFetchError = "Unable to fetch daemonset for status: %s"
)

// Condition message formats (for use with fmt.Sprintf).
const (
	// MessageFormatApplyConfigurationError is the format for apply configuration error message.
	MessageFormatApplyConfigurationError = "Unable to generate apply configuration: %s"
	// MessageFormatMarshalConfigurationError is the format for marshal configuration error message.
	MessageFormatMarshalConfigurationError = "Unable to marshal apply configuration: %s"
	// MessageFormatOwnerReferenceError is the format for owner reference error message.
	MessageFormatOwnerReferenceError = "Unable to set owner reference: %s"
	// MessageFormatExistingResourceError is the format for existing resource error message.
	MessageFormatExistingResourceError = "Unable to fetch existing resource: %s"
	// MessageFormatApplyPatchErrorOnCreate is the format for apply patch error on create message.
	MessageFormatApplyPatchErrorOnCreate = "Unable to create resource by patch: %s"
	// MessageFormatApplyPatchErrorOnUpdate is the format for apply patch error on update message.
	MessageFormatApplyPatchErrorOnUpdate = "Unable to update resource by patch: %s"
	// MessageFormatResourceComparisonError is the format for resource comparison error message.
	MessageFormatResourceComparisonError = "Unable to compare existing and desired resources: %s"
	// MessageFormatResourceGenerateError is the format for resource generation error message.
	MessageFormatResourceGenerateError = "Unable to generate desired resource: %s"
	// MessageFormatResourceApplyError is the format for resource apply error message.
	MessageFormatResourceApplyError = "Unable to apply %s: %s"
	// MessageFormatSubResourceCreated is the format for sub-resource created message.
	MessageFormatSubResourceCreated = "%s %s created successfully"
	// MessageFormatSubResourceUpdated is the format for sub-resource updated message.
	MessageFormatSubResourceUpdated = "%s %s updated successfully"
	// MessageFormatDeletionError is the format for deletion error message.
	MessageFormatDeletionError = "Unable to delete %s during cleanup: %s"
)
