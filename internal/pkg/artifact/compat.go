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

// DeduplicateArtifactMeta removes duplicate requirements and dependencies by name,
// keeping the most restrictive (highest) version when the same name appears more than once.
// Results are sorted by name.
func DeduplicateArtifactMeta(meta *commonv1alpha1.ArtifactMeta) {
	meta.Requirements = deduplicateRequirements(meta.Requirements)
	meta.Dependencies = deduplicateDependencies(meta.Dependencies)
}

func deduplicateRequirements(reqs []commonv1alpha1.ArtifactMetaRequirement) []commonv1alpha1.ArtifactMetaRequirement {
	if len(reqs) <= 1 {
		return reqs
	}
	byName := make(map[string]string, len(reqs)) // name -> strictest version seen
	for _, req := range reqs {
		current, exists := byName[req.Name]
		if !exists {
			byName[req.Name] = req.Version
			continue
		}
		// Replace if the new version is strictly higher; on parse error keep existing.
		if atLeast, err := compat.SemverAtLeast(req.Version, current); err == nil && atLeast {
			byName[req.Name] = req.Version
		}
	}
	result := make([]commonv1alpha1.ArtifactMetaRequirement, 0, len(byName))
	for name, version := range byName {
		result = append(result, commonv1alpha1.ArtifactMetaRequirement{Name: name, Version: version})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
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
	if len(deps) <= 1 {
		return deps
	}
	byName := make(map[string]commonv1alpha1.ArtifactMetaDependency, len(deps))
	for _, dep := range deps {
		current, exists := byName[dep.Name]
		if !exists {
			byName[dep.Name] = dep
			continue
		}
		// Replace if the new primary version is strictly higher; alternatives travel with it.
		if atLeast, err := compat.SemverAtLeast(dep.Version, current.Version); err == nil && atLeast {
			byName[dep.Name] = dep
		}
	}
	result := make([]commonv1alpha1.ArtifactMetaDependency, 0, len(byName))
	for _, dep := range byName {
		result = append(result, dep)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}
