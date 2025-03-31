// Copyright (C) 2025 The Falco Authors
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

package puller

import (
	"errors"
)

// ArtifactType represents a rules file or a plugin. Used to select the right mediaType when interacting with the registry.
type ArtifactType string

const (
	// Rulesfile represents a rules file artifact.
	Rulesfile ArtifactType = "rulesfile"
	// Plugin represents a plugin artifact.
	Plugin ArtifactType = "plugin"
	// Asset represents an artifact consumed by another plugin.
	Asset ArtifactType = "asset"

	// FalcoRulesfileConfigMediaType is the MediaType for rule's config layer.
	FalcoRulesfileConfigMediaType = "application/vnd.cncf.falco.rulesfile.config.v1+json"

	// FalcoRulesfileLayerMediaType is the MediaType for rules.
	FalcoRulesfileLayerMediaType = "application/vnd.cncf.falco.rulesfile.layer.v1+tar.gz"

	// FalcoPluginConfigMediaType is the MediaType for plugin's config layer.
	FalcoPluginConfigMediaType = "application/vnd.cncf.falco.plugin.config.v1+json"

	// FalcoPluginLayerMediaType is the MediaType for plugins.
	FalcoPluginLayerMediaType = "application/vnd.cncf.falco.plugin.layer.v1+tar.gz"

	// FalcoAssetConfigMediaType is the MediaType for asset's config layer.
	FalcoAssetConfigMediaType = "application/vnd.cncf.falco.asset.config.v1+json"

	// FalcoAssetLayerMediaType is the MediaType for assets.
	FalcoAssetLayerMediaType = "application/vnd.cncf.falco.asset.layer.v1+tar.gz"

	// DefaultTag is the default tag reference to be used when none is provided.
	DefaultTag = "latest"
)

// The following functions are necessary to use ArtifactType with Cobra.

// String returns a string representation of ArtifactType.
func (e ArtifactType) String() string {
	return string(e)
}

// Set an ArtifactType.
func (e *ArtifactType) Set(v string) error {
	switch v {
	case "rulesfile", "plugin", "asset":
		*e = ArtifactType(v)
		return nil
	default:
		return errors.New(`must be one of "rulesfile", "plugin", "asset"`)
	}
}

// Type returns a string representing this type.
func (e *ArtifactType) Type() string {
	return "ArtifactType"
}

// RegistryResult represents a generic result that is generated when
// interacting with a remote OCI registry.
type RegistryResult struct {
	RootDigest string
	Digest     string
	Config     ArtifactConfig
	Type       ArtifactType
	Filename   string
}

// ArtifactConfig is the struct stored in the config layer of rulesfile and plugin artifacts. Each type fills only the fields of interest.
type ArtifactConfig struct {
	// It's the unique name used by the index
	Name         string                `json:"name,omitempty"`
	Version      string                `json:"version,omitempty"`
	Dependencies []ArtifactDependency  `json:"dependencies,omitempty"`
	Requirements []ArtifactRequirement `json:"requirements,omitempty"`
}

// ArtifactRequirement represents the artifact's requirement to be stored in the config.
type ArtifactRequirement struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Dependency represent a dependency with its own name and version.
type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ArtifactDependency represents the artifact's depedendency to be stored in the config.
type ArtifactDependency struct {
	Name         string       `json:"name"`
	Version      string       `json:"version"`
	Alternatives []Dependency `json:"alternatives,omitempty"`
}
