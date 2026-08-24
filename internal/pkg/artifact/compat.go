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

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

// ComputeOCIArtifactSpecHash returns the SHA-256 hex digest of the JSON-marshaled OCIArtifact spec.
// A change in the hash signals that the spec changed and any cached config must be re-fetched.
func ComputeOCIArtifactSpecHash(ociArtifact *commonv1alpha1.OCIArtifact) (string, error) {
	data, err := json.Marshal(ociArtifact)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// DeduplicateArtifactMeta removes semantically redundant requirements and dependency groups.
// Monotonic requirements with the same name are collapsed to the strictest version, while
// incompatible plugin API majors and unparsable versions are preserved for the compatibility
// checker to reject. Dependency alternatives are OR-ed within a group, while distinct groups
// are AND-ed by Falco, so only identical dependency groups can be safely removed.
func DeduplicateArtifactMeta(meta *commonv1alpha1.ArtifactMeta) {
	meta.Requirements = deduplicateRequirements(meta.Requirements)
	meta.Dependencies = deduplicateDependencies(meta.Dependencies)
}

func deduplicateRequirements(reqs []commonv1alpha1.ArtifactMetaRequirement) []commonv1alpha1.ArtifactMetaRequirement {
	if len(reqs) <= 1 {
		return reqs
	}
	result := make([]commonv1alpha1.ArtifactMetaRequirement, 0, len(reqs))
	for _, req := range reqs {
		merged := false
		for i := range result {
			current := result[i]
			if current.Name != req.Name {
				continue
			}
			if current.Version == req.Version {
				merged = true
				break
			}

			if req.Name == compat.CapabilityPluginAPIVersion {
				newAtLeast, newErr := compat.SemverMajorCompatible(req.Version, current.Version)
				currentAtLeast, currentErr := compat.SemverMajorCompatible(current.Version, req.Version)
				switch {
				case newErr != nil || currentErr != nil:
					// Preserve invalid versions so the compatibility checker can report them.
					continue
				case newAtLeast:
					result[i] = req
					merged = true
				case currentAtLeast:
					merged = true
				default:
					// Different plugin API majors are incompatible, not ordered.
					continue
				}
				if merged {
					break
				}
				continue
			}

			if atLeast, err := compat.SemverAtLeast(req.Version, current.Version); err == nil {
				if atLeast {
					result[i] = req
				}
				merged = true
				break
			}
		}
		if !merged {
			result = append(result, req)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		return result[i].Version < result[j].Version
	})
	return result
}

// ArtifactMetaCacheHit reports whether cached is still valid for the given specHash.
// The check is purely in-memory: a hit requires cached to be non-nil and its SpecHash to
// equal specHash. The registry is never consulted; to pick up a new image pushed to the
// same tag, users must change the OCIArtifact spec (e.g. pin a new digest or bump the tag),
// which bumps Generation and invalidates the spec hash.
func ArtifactMetaCacheHit(cached *commonv1alpha1.ArtifactMeta, specHash string) bool {
	return cached != nil && cached.SpecHash == specHash
}

// AppendConfigLayerRequirements converts an OCI config layer's parsed requirements and
// dependencies (as returned by Manager.FetchConfig) into meta's Requirements/Dependencies,
// appending to whatever meta already has. fetched may be nil, in which case it is a no-op.
func AppendConfigLayerRequirements(meta *commonv1alpha1.ArtifactMeta, fetched *puller.ArtifactConfig) {
	if fetched == nil {
		return
	}
	for _, req := range fetched.Requirements {
		meta.Requirements = append(meta.Requirements, commonv1alpha1.ArtifactMetaRequirement{
			Name: req.Name, Version: req.Version,
		})
	}
	for _, dep := range fetched.Dependencies {
		d := commonv1alpha1.ArtifactMetaDependency{Name: dep.Name, Version: dep.Version}
		for _, alt := range dep.Alternatives {
			d.Alternatives = append(d.Alternatives, commonv1alpha1.ArtifactMetaDependencyVariant{
				Name: alt.Name, Version: alt.Version,
			})
		}
		meta.Dependencies = append(meta.Dependencies, d)
	}
}

func deduplicateDependencies(deps []commonv1alpha1.ArtifactMetaDependency) []commonv1alpha1.ArtifactMetaDependency {
	if len(deps) == 0 {
		return deps
	}
	result := make([]commonv1alpha1.ArtifactMetaDependency, 0, len(deps))
	for _, dep := range deps {
		dep = canonicalizeDependency(dep)
		duplicate := false
		for _, current := range result {
			if dep.Name == current.Name && dep.Version == current.Version &&
				slices.Equal(dep.Alternatives, current.Alternatives) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, dep)
		}
	}
	sort.Slice(result, func(i, j int) bool { return dependencyLess(result[i], result[j]) })
	return result
}

func canonicalizeDependency(dep commonv1alpha1.ArtifactMetaDependency) commonv1alpha1.ArtifactMetaDependency {
	if len(dep.Alternatives) == 0 {
		dep.Alternatives = nil
		return dep
	}

	alternatives := append([]commonv1alpha1.ArtifactMetaDependencyVariant(nil), dep.Alternatives...)
	sort.Slice(alternatives, func(i, j int) bool {
		if alternatives[i].Name != alternatives[j].Name {
			return alternatives[i].Name < alternatives[j].Name
		}
		return alternatives[i].Version < alternatives[j].Version
	})
	dep.Alternatives = alternatives[:0]
	for _, alternative := range alternatives {
		if len(dep.Alternatives) == 0 || dep.Alternatives[len(dep.Alternatives)-1] != alternative {
			dep.Alternatives = append(dep.Alternatives, alternative)
		}
	}
	return dep
}

func dependencyLess(a, b commonv1alpha1.ArtifactMetaDependency) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	for i := range min(len(a.Alternatives), len(b.Alternatives)) {
		if a.Alternatives[i].Name != b.Alternatives[i].Name {
			return a.Alternatives[i].Name < b.Alternatives[i].Name
		}
		if a.Alternatives[i].Version != b.Alternatives[i].Version {
			return a.Alternatives[i].Version < b.Alternatives[i].Version
		}
	}
	return len(a.Alternatives) < len(b.Alternatives)
}
