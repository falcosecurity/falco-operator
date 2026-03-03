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
)

func TestResolveReference(t *testing.T) {
	tests := []struct {
		name     string
		artifact *commonv1alpha1.OCIArtifact
		want     string
	}{
		{
			name: "repository only defaults to ghcr.io and latest",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{
					Repository: "falcosecurity/rules/falco-rules",
				},
			},
			want: "ghcr.io/falcosecurity/rules/falco-rules:latest",
		},
		{
			name: "repository with tag",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{
					Repository: "falcosecurity/rules/falco-rules",
					Tag:        "v1.0.0",
				},
			},
			want: "ghcr.io/falcosecurity/rules/falco-rules:v1.0.0",
		},
		{
			name: "repository with digest",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{
					Repository: "falcosecurity/rules/falco-rules",
					Tag:        "sha256:abc123",
				},
			},
			want: "ghcr.io/falcosecurity/rules/falco-rules@sha256:abc123",
		},
		{
			name: "custom registry with repository and tag",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{
					Repository: "falcosecurity/rules/falco-rules",
					Tag:        "latest",
				},
				Registry: &commonv1alpha1.RegistryConfig{
					Name: "custom.io",
				},
			},
			want: "custom.io/falcosecurity/rules/falco-rules:latest",
		},
		{
			name: "custom registry with repository and digest",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{
					Repository: "falcosecurity/rules/falco-rules",
					Tag:        "sha256:abc123",
				},
				Registry: &commonv1alpha1.RegistryConfig{
					Name: "custom.io",
				},
			},
			want: "custom.io/falcosecurity/rules/falco-rules@sha256:abc123",
		},
		{
			name: "custom registry with repository no tag defaults to latest",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{
					Repository: "falcosecurity/rules/falco-rules",
				},
				Registry: &commonv1alpha1.RegistryConfig{
					Name: "custom.io",
				},
			},
			want: "custom.io/falcosecurity/rules/falco-rules:latest",
		},
		{
			name: "empty tag without registry defaults to ghcr.io and latest",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{
					Repository: "falcosecurity/rules/falco-rules",
					Tag:        "",
				},
			},
			want: "ghcr.io/falcosecurity/rules/falco-rules:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveReference(tt.artifact)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveRegistryOptions(t *testing.T) {
	tests := []struct {
		name          string
		artifact      *commonv1alpha1.OCIArtifact
		wantNil       bool
		wantPlainHTTP bool
		wantInsecure  bool
	}{
		{
			name:     "nil artifact returns nil",
			artifact: nil,
			wantNil:  true,
		},
		{
			name: "nil registry returns nil",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "test", Tag: "latest"},
			},
			wantNil: true,
		},
		{
			name: "nil TLS returns nil",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "test", Tag: "latest"},
				Registry: &commonv1alpha1.RegistryConfig{
					Auth: &commonv1alpha1.RegistryAuth{},
				},
			},
			wantNil: true,
		},
		{
			name: "plainHTTP only",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "test", Tag: "latest"},
				Registry: &commonv1alpha1.RegistryConfig{
					PlainHTTP: boolPtr(true),
				},
			},
			wantPlainHTTP: true,
		},
		{
			name: "insecureSkipVerify only",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "test", Tag: "latest"},
				Registry: &commonv1alpha1.RegistryConfig{
					TLS: &commonv1alpha1.TLSConfig{
						InsecureSkipVerify: true,
					},
				},
			},
			wantInsecure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := ResolveRegistryOptions(tt.artifact)

			if tt.wantNil {
				assert.Nil(t, opts)
				return
			}

			require.NotNil(t, opts)
			assert.Equal(t, tt.wantPlainHTTP, opts.PlainHTTP)
			assert.Equal(t, tt.wantInsecure, opts.InsecureSkipVerify)
		})
	}
}
