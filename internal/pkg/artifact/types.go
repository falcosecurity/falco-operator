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

// Medium represents how the artifact is distributed.
type Medium string

const (
	// MediumInline represents an inline artifact.
	MediumInline Medium = "inline"
	// MediumOCI represents an OCI artifact.
	MediumOCI Medium = "oci"
	// MediumConfigMap represents an artifact from a ConfigMap.
	MediumConfigMap Medium = "configmap"
)

// StoreAction represents the operation performed by a Store method.
type StoreAction string

const (
	// StoreActionNone means the input was absent and no existing artifact was found; no filesystem change occurred.
	StoreActionNone StoreAction = "None"
	// StoreActionRemoved means a previously stored artifact was removed from the filesystem.
	StoreActionRemoved StoreAction = "Removed"
	// StoreActionAdded means a new artifact was written to the filesystem for the first time.
	StoreActionAdded StoreAction = "Added"
	// StoreActionUpdated means an existing artifact was replaced because its content changed.
	StoreActionUpdated StoreAction = "Updated"
	// StoreActionUnchanged means the artifact already existed and was up-to-date; nothing was written.
	StoreActionUnchanged StoreAction = "Unchanged"
	// StoreActionPriorityChanged means the artifact content is unchanged but the priority changed;
	// the file was moved/renamed to reflect the new load order.
	StoreActionPriorityChanged StoreAction = "PriorityChanged"
)

// File represents a tracked file for any artifact type.
type File struct {
	Path     string // Full Path on filesystem
	Medium   Medium // How the artifact is stored/distributed
	Priority int32  // Priority when created
}
