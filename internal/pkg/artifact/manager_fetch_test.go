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
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

func TestManager_FetchConfig(t *testing.T) {
	const testNamespace = "test-namespace"

	tests := []struct {
		name         string
		configResult *puller.ArtifactConfig
		configDigest string
		fetchErr     error
		wantErr      bool
	}{
		{
			name:         "fetches config successfully",
			configResult: &puller.ArtifactConfig{Name: "myplugin", Version: "1.0.0"},
			configDigest: "sha256:abc",
		},
		{
			name:     "puller error propagates",
			fetchErr: fmt.Errorf("registry unreachable"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			mockPuller := &puller.MockOCIPuller{
				ConfigResult:   tt.configResult,
				ConfigDigest:   tt.configDigest,
				FetchConfigErr: tt.fetchErr,
			}
			manager := NewManagerWithOptions(fakeClient, testNamespace, WithOCIPuller(mockPuller))

			cfg, digest, err := manager.FetchConfig(context.Background(), &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "example.com/myplugin", Tag: "latest"},
			})

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.configResult, cfg)
			assert.Equal(t, tt.configDigest, digest)
			require.Len(t, mockPuller.FetchConfigCalls, 1)
		})
	}
}

func TestManager_FetchContent(t *testing.T) {
	const testNamespace = "test-namespace"

	tests := []struct {
		name        string
		content     []byte
		fetchErr    error
		wantErr     bool
		wantContent []byte
	}{
		{
			name:        "fetches content successfully",
			content:     []byte("- rule: sample\n"),
			wantContent: []byte("- rule: sample\n"),
		},
		{
			name:     "puller error propagates",
			fetchErr: fmt.Errorf("registry unreachable"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			mockPuller := &puller.MockOCIPuller{
				ContentResult:   tt.content,
				FetchContentErr: tt.fetchErr,
			}
			manager := NewManagerWithOptions(fakeClient, testNamespace, WithOCIPuller(mockPuller))

			content, err := manager.FetchContent(context.Background(), &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "example.com/myrules", Tag: "latest"},
			})

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantContent, content)
			require.Len(t, mockPuller.FetchContentCalls, 1)
		})
	}
}
