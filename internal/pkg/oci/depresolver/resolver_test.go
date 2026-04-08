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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

func TestResolve(t *testing.T) {
	tests := []struct {
		name            string
		inRefs          []string
		metadataByRef   map[string]*puller.RegistryResult
		resolvedDeps    map[string]string
		wantErrContains string
		wantNames       []string
	}{
		{
			name:   "resolves transitive dependencies",
			inRefs: []string{"root:1.0.0"},
			metadataByRef: map[string]*puller.RegistryResult{
				"root:1.0.0": {
					Config: puller.ArtifactConfig{
						Name:    "root",
						Version: "1.0.0",
						Dependencies: []puller.ArtifactDependency{
							{Name: "dep-a", Version: "1.0.0"},
						},
					},
					Type: puller.Plugin,
				},
				"dep-a:1.0.0": {
					Config: puller.ArtifactConfig{
						Name:    "dep-a",
						Version: "1.0.0",
						Dependencies: []puller.ArtifactDependency{
							{Name: "dep-b", Version: "2.2.0"},
						},
					},
					Type: puller.Plugin,
				},
				"dep-b:2.2.0": {
					Config: puller.ArtifactConfig{
						Name:    "dep-b",
						Version: "2.2.0",
					},
					Type: puller.Rulesfile,
				},
			},
			resolvedDeps: map[string]string{
				"dep-a:1.0.0": "dep-a:1.0.0",
				"dep-b:2.2.0": "dep-b:2.2.0",
			},
			wantNames: []string{"root", "dep-a", "dep-b"},
		},
		{
			name:   "bumps to highest compatible version",
			inRefs: []string{"root:1.0.0", "dep-a:1.0.0"},
			metadataByRef: map[string]*puller.RegistryResult{
				"root:1.0.0": {
					Config: puller.ArtifactConfig{
						Name:    "root",
						Version: "1.0.0",
						Dependencies: []puller.ArtifactDependency{
							{Name: "dep-a", Version: "1.2.0"},
						},
					},
					Type: puller.Plugin,
				},
				"dep-a:1.0.0": {
					Config: puller.ArtifactConfig{
						Name:    "dep-a",
						Version: "1.0.0",
					},
					Type: puller.Plugin,
				},
				"dep-a:1.2.0": {
					Config: puller.ArtifactConfig{
						Name:    "dep-a",
						Version: "1.2.0",
					},
					Type: puller.Plugin,
				},
			},
			resolvedDeps: map[string]string{
				"dep-a:1.2.0": "dep-a:1.2.0",
			},
			wantNames: []string{"root", "dep-a"},
		},
		{
			name:   "fails on incompatible major versions",
			inRefs: []string{"root:1.0.0", "dep-a:1.0.0"},
			metadataByRef: map[string]*puller.RegistryResult{
				"root:1.0.0": {
					Config: puller.ArtifactConfig{
						Name:    "root",
						Version: "1.0.0",
						Dependencies: []puller.ArtifactDependency{
							{Name: "dep-a", Version: "2.0.0"},
						},
					},
					Type: puller.Plugin,
				},
				"dep-a:1.0.0": {
					Config: puller.ArtifactConfig{
						Name:    "dep-a",
						Version: "1.0.0",
					},
					Type: puller.Plugin,
				},
			},
			wantErrContains: ErrCannotSatisfyDependencies.Error(),
		},
		{
			name:   "uses compatible alternative already in graph",
			inRefs: []string{"root:1.0.0", "alt:1.3.0"},
			metadataByRef: map[string]*puller.RegistryResult{
				"root:1.0.0": {
					Config: puller.ArtifactConfig{
						Name:    "root",
						Version: "1.0.0",
						Dependencies: []puller.ArtifactDependency{
							{
								Name:    "dep-a",
								Version: "1.0.0",
								Alternatives: []puller.Dependency{
									{Name: "alt", Version: "1.2.0"},
								},
							},
						},
					},
					Type: puller.Plugin,
				},
				"alt:1.3.0": {
					Config: puller.ArtifactConfig{
						Name:    "alt",
						Version: "1.3.0",
					},
					Type: puller.Plugin,
				},
			},
			wantNames: []string{"root", "alt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configResolver := func(ref string) (*puller.RegistryResult, error) {
				res, ok := tt.metadataByRef[ref]
				if !ok {
					return nil, fmt.Errorf("missing metadata for %s", ref)
				}
				return res, nil
			}
			depResolver := func(parentRef, depRef string) (string, error) {
				res, ok := tt.resolvedDeps[depRef]
				if !ok {
					return "", fmt.Errorf("unable to resolve %s from %s", depRef, parentRef)
				}
				return res, nil
			}

			got, err := Resolve(configResolver, depResolver, tt.inRefs...)
			if tt.wantErrContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContains)
				return
			}

			require.NoError(t, err)
			for _, name := range tt.wantNames {
				_, ok := got[name]
				assert.True(t, ok, "expected %q in resolved set", name)
			}
		})
	}
}
