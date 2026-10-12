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

package node

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
)

func TestAssess_EngineRequirement(t *testing.T) {
	tests := []struct {
		name                string
		capability          string
		falcoCaps           map[string]string
		requiredVersion     string
		enforceRequirements bool
		preInstalled        bool
		wantSkip            bool
		wantSatisfied       bool
		wantErr             bool
	}{
		{
			name:            "capability found and version satisfied",
			capability:      "engine_version_semver",
			falcoCaps:       map[string]string{"engine_version_semver": "0.57.0"},
			requiredVersion: "0.57.0",
			wantSkip:        false,
			wantSatisfied:   true,
		},
		{
			name:                "capability found but version too low",
			capability:          "engine_version_semver",
			falcoCaps:           map[string]string{"engine_version_semver": "0.50.0"},
			requiredVersion:     "0.57.0",
			enforceRequirements: true,
			wantSkip:            true,
			wantSatisfied:       false,
		},
		{
			name:                "capability not found in Falco versions",
			capability:          "engine_version_semver",
			falcoCaps:           map[string]string{},
			requiredVersion:     "0.57.0",
			enforceRequirements: true,
			wantSkip:            true,
			wantSatisfied:       false,
		},
		{
			name:            "invalid provided version string returns error",
			capability:      "engine_version_semver",
			falcoCaps:       map[string]string{"engine_version_semver": "invalid"},
			requiredVersion: "0.57.0",
			wantSkip:        false,
			wantSatisfied:   false,
			wantErr:         true,
		},
		{
			name:                "advise mode installs anyway when capability too low",
			capability:          "engine_version_semver",
			falcoCaps:           map[string]string{"engine_version_semver": "0.50.0"},
			requiredVersion:     "0.57.0",
			enforceRequirements: false,
			wantSkip:            false,
			wantSatisfied:       false,
		},
		{
			name:                "enforce mode rejects update but keeps previous install",
			capability:          "engine_version_semver",
			falcoCaps:           map[string]string{"engine_version_semver": "0.50.0"},
			requiredVersion:     "0.57.0",
			enforceRequirements: true,
			preInstalled:        true,
			wantSkip:            true,
			wantSatisfied:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := newJudgeTestNode(t, tt.enforceRequirements)
			key := artifact.Ref{Kind: artifact.KindRulesfile, Name: judgeTestRulesfileName}
			// AlreadyInstalled is read from the node's own record, never from a status object,
			// so "rejects an update" has to start from a node that actually holds the artifact.
			if tt.preInstalled {
				n.SeedInstalled(key, []artifactv1alpha1.InstalledArtifact{
					{Path: "/etc/falco/rules.d/test.yaml", Medium: string(artifact.MediumOCI)},
				})
			}
			if tt.falcoCaps != nil {
				n.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(tt.falcoCaps).Result)
			}

			got, err := n.assess(key, &commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: tt.capability, Version: tt.requiredVersion},
				},
			}, tt.enforceRequirements)

			assert.Equal(t, tt.wantSkip, got.Blocked)
			assert.Equal(t, tt.wantSatisfied, err == nil && len(got.Unmet) == 0)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAssess_DependencyCompareError(t *testing.T) {
	n := newJudgeTestNode(t, false)
	n.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"container": "not-a-version"}).Result)
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: judgeTestRulesfileName}

	_, err := n.assess(key, &commonv1alpha1.ArtifactMeta{
		Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "0.4.0"}},
	}, false)

	require.Error(t, err)
	compareErr, ok := errors.AsType[*compareError](err)
	require.True(t, ok, "an uncomparable dependency version must surface as a compareError")
	assert.Empty(t, compareErr.Requirement, "an empty Requirement is what tells the caller it was a plugin dependency")
	assert.NotEmpty(t, compareErr.Error())
	assert.Error(t, errors.Unwrap(compareErr), "the underlying compat error must stay reachable")
}
