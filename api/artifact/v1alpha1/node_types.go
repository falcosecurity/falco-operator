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

package v1alpha1

// InstalledArtifactConfig tracks a generated configuration file derived from an installed artifact.
// Currently used for Plugin artifacts to record the plugins-config-inline.yaml entry that Falco
// needs to discover and load the plugin. Binary and config are one lifecycle unit: the config is
// always created and removed alongside the binary.
type InstalledArtifactConfig struct {
	// Path is the absolute on-disk path of the generated config file.
	// +kubebuilder:validation:Required
	Path string `json:"path"`
}

// InstalledArtifact describes a single artifact file currently on disk.
// The medium field is the list map key: at most one entry per medium exists.
type InstalledArtifact struct {
	// Path is the absolute on-disk path of the installed file.
	// +kubebuilder:validation:Required
	Path string `json:"path"`
	// Medium identifies the source: "oci", "inline", or "configmap".
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=oci;inline;configmap
	Medium string `json:"medium"`
	// Priority is the load-order value encoded in the filename.
	// +kubebuilder:validation:Required
	Priority int32 `json:"priority"`
	// ContentHash is the SHA-256 hex digest of the bytes written to disk.
	// A mismatch between this value and the current source signals that the file must be re-written.
	// +kubebuilder:validation:Required
	ContentHash string `json:"contentHash"`
	// SpecHash is the SHA-256 hash of the parent artifact's OCIArtifact spec at the time this
	// artifact was installed. Populated only for MediumOCI. A mismatch with the parent
	// artifact's current ArtifactMeta.SpecHash means the remote blob may have changed and the
	// artifact must be re-fetched regardless of disk integrity.
	// +optional
	SpecHash string `json:"specHash,omitempty"`
	// Config tracks the generated configuration file derived from this artifact.
	// Populated only for Plugin artifacts (the plugins-config-inline.yaml shared config file).
	// Binary and config share the same lifecycle: no binary means no config, and vice versa.
	// +optional
	Config *InstalledArtifactConfig `json:"config,omitempty"`
}
