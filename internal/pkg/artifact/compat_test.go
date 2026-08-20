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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

func req(name, version string) commonv1alpha1.ArtifactMetaRequirement {
	return commonv1alpha1.ArtifactMetaRequirement{Name: name, Version: version}
}

func dep(name, version string, alts ...commonv1alpha1.ArtifactMetaDependencyVariant) commonv1alpha1.ArtifactMetaDependency {
	return commonv1alpha1.ArtifactMetaDependency{Name: name, Version: version, Alternatives: alts}
}

func TestDeduplicateArtifactMeta(t *testing.T) {
	tests := []struct {
		name     string
		input    commonv1alpha1.ArtifactMeta
		wantReqs []commonv1alpha1.ArtifactMetaRequirement
		wantDeps []commonv1alpha1.ArtifactMetaDependency
	}{
		{
			name:     "empty meta stays empty",
			input:    commonv1alpha1.ArtifactMeta{},
			wantReqs: nil,
			wantDeps: nil,
		},
		{
			name:     "single requirement unchanged",
			input:    commonv1alpha1.ArtifactMeta{Requirements: []commonv1alpha1.ArtifactMetaRequirement{req("engine_version_semver", "0.57.0")}},
			wantReqs: []commonv1alpha1.ArtifactMetaRequirement{req("engine_version_semver", "0.57.0")},
			wantDeps: nil,
		},
		{
			name: "duplicate requirement keeps strictest (higher) version",
			input: commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					req("engine_version_semver", "0.57.0"),
					req("engine_version_semver", "0.62.0"),
					req("engine_version_semver", "0.55.0"),
				},
			},
			wantReqs: []commonv1alpha1.ArtifactMetaRequirement{req("engine_version_semver", "0.62.0")},
			wantDeps: nil,
		},
		{
			name: "different requirement names both kept and sorted",
			input: commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					req("plugin_api_version", "3.0.0"),
					req("engine_version_semver", "0.57.0"),
				},
			},
			wantReqs: []commonv1alpha1.ArtifactMetaRequirement{
				req("engine_version_semver", "0.57.0"),
				req("plugin_api_version", "3.0.0"),
			},
			wantDeps: nil,
		},
		{
			name:     "single dependency unchanged",
			input:    commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{dep("json", "0.7.0")}},
			wantReqs: nil,
			wantDeps: []commonv1alpha1.ArtifactMetaDependency{dep("json", "0.7.0")},
		},
		{
			name: "duplicate dependency keeps strictest (higher) version with its alternatives",
			input: commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{
					dep("json", "0.7.0"),
					dep("json", "0.9.0", commonv1alpha1.ArtifactMetaDependencyVariant{Name: "alt", Version: "1.0.0"}),
					dep("json", "0.8.0"),
				},
			},
			wantDeps: []commonv1alpha1.ArtifactMetaDependency{
				dep("json", "0.9.0", commonv1alpha1.ArtifactMetaDependencyVariant{Name: "alt", Version: "1.0.0"}),
			},
		},
		{
			name: "different dependency names both kept and sorted",
			input: commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{
					dep("k8saudit", "0.8.0"),
					dep("json", "0.7.0"),
				},
			},
			wantDeps: []commonv1alpha1.ArtifactMetaDependency{
				dep("json", "0.7.0"),
				dep("k8saudit", "0.8.0"),
			},
		},
		{
			name: "requirements and dependencies deduped independently",
			input: commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					req("engine_version_semver", "0.57.0"),
					req("engine_version_semver", "0.62.0"),
				},
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{
					dep("json", "0.7.0"),
					dep("json", "0.9.0"),
				},
			},
			wantReqs: []commonv1alpha1.ArtifactMetaRequirement{req("engine_version_semver", "0.62.0")},
			wantDeps: []commonv1alpha1.ArtifactMetaDependency{dep("json", "0.9.0")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := tt.input
			DeduplicateArtifactMeta(&meta)
			assert.Equal(t, tt.wantReqs, meta.Requirements)
			assert.Equal(t, tt.wantDeps, meta.Dependencies)
		})
	}
}

func TestAppendConfigLayerRequirements(t *testing.T) {
	t.Run("nil fetched is a no-op", func(t *testing.T) {
		meta := &commonv1alpha1.ArtifactMeta{}
		AppendConfigLayerRequirements(meta, nil)
		assert.Empty(t, meta.Requirements)
		assert.Empty(t, meta.Dependencies)
	})

	t.Run("converts requirements and dependencies with alternatives", func(t *testing.T) {
		meta := &commonv1alpha1.ArtifactMeta{}
		fetched := &puller.ArtifactConfig{
			Requirements: []puller.ArtifactRequirement{
				{Name: "plugin_api_version", Version: "3.0.0"},
			},
			Dependencies: []puller.ArtifactDependency{
				{
					Name: "container", Version: "0.4.0",
					Alternatives: []puller.Dependency{{Name: "k8smeta", Version: "0.1.0"}},
				},
			},
		}
		AppendConfigLayerRequirements(meta, fetched)

		require.Len(t, meta.Requirements, 1)
		assert.Equal(t, req("plugin_api_version", "3.0.0"), meta.Requirements[0])
		require.Len(t, meta.Dependencies, 1)
		assert.Equal(t, dep("container", "0.4.0", commonv1alpha1.ArtifactMetaDependencyVariant{Name: "k8smeta", Version: "0.1.0"}), meta.Dependencies[0])
	})

	t.Run("appends to existing meta rather than replacing it", func(t *testing.T) {
		meta := &commonv1alpha1.ArtifactMeta{
			Requirements: []commonv1alpha1.ArtifactMetaRequirement{req("engine_version_semver", "0.57.0")},
		}
		fetched := &puller.ArtifactConfig{
			Requirements: []puller.ArtifactRequirement{{Name: "plugin_api_version", Version: "3.0.0"}},
		}
		AppendConfigLayerRequirements(meta, fetched)

		require.Len(t, meta.Requirements, 2)
		assert.Equal(t, req("engine_version_semver", "0.57.0"), meta.Requirements[0])
		assert.Equal(t, req("plugin_api_version", "3.0.0"), meta.Requirements[1])
	})
}

func TestArtifactMetaCacheHit(t *testing.T) {
	t.Run("nil cached is a miss", func(t *testing.T) {
		assert.False(t, ArtifactMetaCacheHit(nil, "hash-1"))
	})

	t.Run("spec hash mismatch is a miss", func(t *testing.T) {
		cached := &commonv1alpha1.ArtifactMeta{SpecHash: "hash-old", Digest: "sha256:current"}
		assert.False(t, ArtifactMetaCacheHit(cached, "hash-new"))
	})

	t.Run("spec hash matches is a hit regardless of stored digest", func(t *testing.T) {
		cached := &commonv1alpha1.ArtifactMeta{SpecHash: "hash-1", Digest: "sha256:old"}
		assert.True(t, ArtifactMetaCacheHit(cached, "hash-1"))
	})
}
