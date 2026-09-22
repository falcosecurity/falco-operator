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
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	semver "github.com/blang/semver/v4"
	"gopkg.in/yaml.v3"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
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
func ValidatePluginDependency(dependency commonv1alpha1.ArtifactMetaDependency) error {
	candidates := append([]commonv1alpha1.ArtifactMetaDependencyVariant{{Name: dependency.Name, Version: dependency.Version}}, dependency.Alternatives...)
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

// RulesRequirements holds requirements extracted from all documents in a Falco rules YAML stream.
type RulesRequirements struct {
	// EngineVersions preserves every directive with its capability: legacy integers use
	// engine_version, while semver strings use engine_version_semver.
	EngineVersions []commonv1alpha1.ArtifactMetaRequirement
	// PluginVersions holds all required_plugin_versions entries.
	PluginVersions []commonv1alpha1.ArtifactMetaDependency
}

// ParseRulesRequirements scans every document in a Falco rules YAML stream for required_engine_version
// and required_plugin_versions directives. It skips unknown top-level items (rules, macros,
// lists, etc.) without error. Returns empty requirements when data is nil or empty.
func ParseRulesRequirements(data []byte) (*RulesRequirements, error) {
	if len(data) == 0 {
		return &RulesRequirements{}, nil
	}

	type rulesItem struct {
		// any handles both string ("0.57.0") and integer (26) YAML values.
		RequiredEngineVersion  any                                     `yaml:"required_engine_version"`
		RequiredPluginVersions []commonv1alpha1.ArtifactMetaDependency `yaml:"required_plugin_versions"`
	}

	var result RulesRequirements
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var items []rulesItem
		if err := decoder.Decode(&items); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("parse rules YAML: %w", err)
		}
		for _, item := range items {
			if item.RequiredEngineVersion != nil {
				const legacyCapability = "engine_version"
				requirement := commonv1alpha1.ArtifactMetaRequirement{
					Name: "engine_version_semver", Version: fmt.Sprint(item.RequiredEngineVersion),
				}
				// YAML normalizes bare integers; Falco also accepts quoted legacy integers.
				switch value := item.RequiredEngineVersion.(type) {
				case int:
					requirement.Name = legacyCapability
				case string:
					if version, err := parseLegacyEngineVersion(value); err == nil {
						requirement.Name = legacyCapability
						requirement.Version = strconv.FormatUint(version, 10)
					}
				}
				if requirement.Version != "" {
					result.EngineVersions = append(result.EngineVersions, requirement)
				}
			}
			for _, dependency := range item.RequiredPluginVersions {
				if err := ValidatePluginDependency(dependency); err != nil {
					return nil, err
				}
				result.PluginVersions = append(result.PluginVersions, dependency)
			}
		}
	}
	return &result, nil
}

// parseLegacyEngineVersion follows yaml-cpp's unsigned integer conversion for quoted scalars.
func parseLegacyEngineVersion(value string) (uint64, error) {
	value = strings.TrimPrefix(strings.TrimRight(value, " \t\n\r\v\f"), "+")
	base := 10
	switch {
	case strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X"):
		base, value = 16, value[2:]
	case strings.HasPrefix(value, "0"):
		base = 8
	}
	return strconv.ParseUint(value, base, 32)
}
