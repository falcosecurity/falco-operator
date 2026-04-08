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

package depresolver

import (
	"errors"
	"fmt"

	"github.com/blang/semver/v4"

	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

type artifactMetadataResolver func(ref string) (*puller.RegistryResult, error)
type dependencyRefResolver func(parentRef, dependencyRef string) (string, error)

// ArtifactMap maps artifact names to their resolved metadata.
type ArtifactMap map[string]*ArtifactInfo

var (
	// ErrCannotSatisfyDependencies is returned when two dependency requirements are semver-incompatible.
	ErrCannotSatisfyDependencies = errors.New("cannot satisfy dependencies")
)

// ArtifactInfo contains metadata about a resolved artifact.
type ArtifactInfo struct {
	Ref    string
	Config *puller.ArtifactConfig
	Type   puller.ArtifactType
	Ver    *semver.Version
	ok     bool
}

func copyArtifactMap(in ArtifactMap) (out ArtifactMap) {
	out = make(ArtifactMap, len(in))
	for k, v := range in {
		out[k] = v
	}
	return
}

// Resolve resolves transitive dependencies to a single semver-compatible artifact map.
// It mirrors falcoctl's dependency conflict semantics while delegating reference resolution to callers.
func Resolve(configResolver artifactMetadataResolver, resolver dependencyRefResolver, inRefs ...string) (ArtifactMap, error) {
	depMap := make(ArtifactMap)

	upsertMap := func(ref string) error {
		resolved, err := configResolver(ref)
		if err != nil {
			return err
		}
		if resolved == nil {
			return fmt.Errorf("received nil metadata for ref %q", ref)
		}
		if resolved.Config.Name == "" {
			return fmt.Errorf("empty artifact name for ref %q: config may be corrupted", ref)
		}
		if resolved.Config.Version == "" {
			return fmt.Errorf("empty version for ref %q: config may be corrupted", ref)
		}

		ver, err := semver.ParseTolerant(resolved.Config.Version)
		if err != nil {
			return fmt.Errorf("unable to parse version %q for ref %q: %w", resolved.Config.Version, ref, err)
		}

		cfg := resolved.Config
		depMap[cfg.Name] = &ArtifactInfo{
			Ref:    ref,
			Config: &cfg,
			Type:   resolved.Type,
			Ver:    &ver,
		}
		return nil
	}

	for _, ref := range inRefs {
		if err := upsertMap(ref); err != nil {
			return nil, err
		}
	}

	for {
		allOk := true

		for name, info := range copyArtifactMap(depMap) {
			if info.ok {
				continue
			}

			for _, required := range info.Config.Dependencies {
				if existing, ok := depMap[required.Name]; ok {
					requiredVer, err := semver.ParseTolerant(required.Version)
					if err != nil {
						return nil, fmt.Errorf(`invalid artifact config: version %q is not semver compatible`, required.Version)
					}

					if existing.Ver.Major != requiredVer.Major {
						return nil, fmt.Errorf(
							`%w: %s depends on %s:%s but an incompatible version %s:%s is required by other artifacts`,
							ErrCannotSatisfyDependencies, name, required.Name, required.Version, required.Name, existing.Ver.String(),
						)
					}

					// Required version is not higher than what is already selected.
					if requiredVer.Compare(*existing.Ver) <= 0 {
						continue
					}
				}

				foundAlternative := false
				for _, alternative := range required.Alternatives {
					existing, ok := depMap[alternative.Name]
					if !ok {
						continue
					}

					foundAlternative = true

					alternativeVer, err := semver.ParseTolerant(alternative.Version)
					if err != nil {
						return nil, fmt.Errorf(`invalid artifact config: version %q is not semver compatible`, alternative.Version)
					}

					if existing.Ver.Major != alternativeVer.Major {
						return nil, fmt.Errorf(
							`%w: %s depends on %s:%s but an incompatible version %s:%s is required by other artifacts`,
							ErrCannotSatisfyDependencies, name, required.Name, required.Version, alternative.Name, existing.Ver.String(),
						)
					}

					// Need to bump the selected alternative.
					if alternativeVer.Compare(*existing.Ver) > 0 {
						ref, err := resolver(info.Ref, alternative.Name+":"+alternative.Version)
						if err != nil {
							return nil, fmt.Errorf("unable to resolve reference for alternative dependency %q required by %q: %w", alternative.Name, name, err)
						}

						if err := upsertMap(ref); err != nil {
							return nil, err
						}
						allOk = false
					}

					break
				}
				if foundAlternative {
					continue
				}

				ref, err := resolver(info.Ref, required.Name+":"+required.Version)
				if err != nil {
					return nil, fmt.Errorf("unable to resolve reference for dependency %q required by %q: %w", required.Name, name, err)
				}

				if err := upsertMap(ref); err != nil {
					return nil, err
				}
				allOk = false
			}

			info.ok = true
		}

		if allOk {
			return depMap, nil
		}
	}
}
