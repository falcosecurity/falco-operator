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

package compat

import (
	"fmt"
	"strconv"

	semver "github.com/blang/semver/v4"
	"gopkg.in/yaml.v3"

	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

// CapabilityPluginAPIVersion is the Falco capability name for the plugin API version.
// It uses major-compatibility semantics: the major version must match exactly.
const CapabilityPluginAPIVersion = "plugin_api_version"

// SemverAtLeast reports whether available >= required according to semantic-version
// precedence. Tolerant parsing accepts common forms such as "v1.2.3" and shortened
// versions such as "19" (interpreted as "19.0.0").
func SemverAtLeast(available, required string) (bool, error) {
	availableVersion, err := parseSemver(available, "available")
	if err != nil {
		return false, err
	}
	requiredVersion, err := parseSemver(required, "required")
	if err != nil {
		return false, err
	}
	return availableVersion.GTE(requiredVersion), nil
}

// SemverMajorCompatible reports whether available and required share the same major version
// AND available >= required. Used for plugin_api_version, where a higher major version
// (e.g. framework 3.x) is not compatible with a plugin requiring 2.x.
func SemverMajorCompatible(available, required string) (bool, error) {
	availableVersion, err := parseSemver(available, "available")
	if err != nil {
		return false, err
	}
	requiredVersion, err := parseSemver(required, "required")
	if err != nil {
		return false, err
	}
	return availableVersion.Major == requiredVersion.Major && availableVersion.GTE(requiredVersion), nil
}

func parseSemver(value, role string) (semver.Version, error) {
	version, err := semver.ParseTolerant(value)
	if err != nil {
		return semver.Version{}, fmt.Errorf("parse %s version %q: %w", role, value, err)
	}
	return version, nil
}

// PluginVersionCompatible follows Falco's sinsp_version: three numeric components,
// equal majors, and an available version at least as recent as the required version.
// Suffixes do not participate in Falco's comparison; abbreviated or v-prefixed versions
// are invalid. This is deliberately separate from the tolerant capability comparison.
func PluginVersionCompatible(available, required string) (bool, error) {
	av, err := parsePluginVersion(available)
	if err != nil {
		return false, fmt.Errorf("parse available plugin version: %w", err)
	}
	rv, err := parsePluginVersion(required)
	if err != nil {
		return false, fmt.Errorf("parse required plugin version: %w", err)
	}
	return av[0] == rv[0] && (av[1] > rv[1] || av[1] == rv[1] && av[2] >= rv[2]), nil
}

func parsePluginVersion(value string) ([3]uint32, error) {
	var version [3]uint32
	// Like Falco's sscanf, read major.minor.patch and ignore any trailing suffix.
	if _, err := fmt.Sscanf(value, "%d.%d.%d", &version[0], &version[1], &version[2]); err != nil {
		return version, fmt.Errorf("invalid plugin version %q: %w", value, err)
	}
	return version, nil
}

// ValidatePluginDependency checks every candidate before selecting a loaded plugin,
// including unused alternatives. Falco rejects missing names/versions and repeated
// names within a dependency group, even when the first candidate is compatible.
func ValidatePluginDependency(candidates []puller.Dependency) error {
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate.Name == "" {
			return fmt.Errorf("plugin dependency name must not be empty")
		}
		if _, err := parsePluginVersion(candidate.Version); err != nil {
			return fmt.Errorf("plugin dependency %q: %w", candidate.Name, err)
		}
		if _, exists := seen[candidate.Name]; exists {
			return fmt.Errorf("duplicate plugin dependency %q in the same alternative group", candidate.Name)
		}
		seen[candidate.Name] = struct{}{}
	}
	return nil
}

// RulesRequirements holds requirements extracted from a Falco rules YAML document.
type RulesRequirements struct {
	// EngineVersion is the value of the required_engine_version directive, empty if absent.
	EngineVersion string
	// EngineVersionIsInt is true when required_engine_version was written as a bare integer
	// (e.g. "15") rather than a semver string (e.g. "0.57.0"). The two forms must be compared
	// against different Falco capabilities: integers against "engine_version" (raw), semver
	// strings against "engine_version_semver".
	EngineVersionIsInt bool
	// PluginVersions holds all required_plugin_versions entries.
	PluginVersions []RulesPluginRequirement
}

// RulesPluginRequirement mirrors one entry in required_plugin_versions, including alternatives.
type RulesPluginRequirement struct {
	Name         string
	Version      string
	Alternatives []puller.Dependency
}

// ParseRulesRequirements scans a Falco rules YAML document for required_engine_version
// and required_plugin_versions directives. It skips unknown top-level items (rules, macros,
// lists, etc.) without error. Returns empty requirements when data is nil or empty.
func ParseRulesRequirements(data []byte) (*RulesRequirements, error) {
	if len(data) == 0 {
		return &RulesRequirements{}, nil
	}

	type altVersion struct {
		Name    string `yaml:"name"`
		Version string `yaml:"version"`
	}
	type pluginVersion struct {
		Name         string       `yaml:"name"`
		Version      string       `yaml:"version"`
		Alternatives []altVersion `yaml:"alternatives"`
	}
	type rulesItem struct {
		// any handles both string ("0.57.0") and integer (26) YAML values.
		RequiredEngineVersion  any             `yaml:"required_engine_version"`
		RequiredPluginVersions []pluginVersion `yaml:"required_plugin_versions"`
	}

	var items []rulesItem
	if err := yaml.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("parse rules YAML: %w", err)
	}

	var result RulesRequirements
	for _, item := range items {
		if item.RequiredEngineVersion != nil {
			// gopkg.in/yaml.v3 decodes bare integers (e.g. "15") as int,
			// and semver strings (e.g. "0.57.0") as string.
			switch v := item.RequiredEngineVersion.(type) {
			case int:
				result.EngineVersion = strconv.Itoa(v)
				result.EngineVersionIsInt = true
			case string:
				result.EngineVersion = v
			default:
				result.EngineVersion = fmt.Sprintf("%v", v)
			}
		}
		for _, pv := range item.RequiredPluginVersions {
			req := RulesPluginRequirement{Name: pv.Name, Version: pv.Version}
			for _, alt := range pv.Alternatives {
				req.Alternatives = append(req.Alternatives, puller.Dependency(alt))
			}
			candidates := append([]puller.Dependency{{Name: req.Name, Version: req.Version}}, req.Alternatives...)
			if err := ValidatePluginDependency(candidates); err != nil {
				return nil, err
			}
			result.PluginVersions = append(result.PluginVersions, req)
		}
	}
	return &result, nil
}
