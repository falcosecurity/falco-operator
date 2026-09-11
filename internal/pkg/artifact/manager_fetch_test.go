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
	pullerfake "github.com/falcosecurity/falco-operator/internal/pkg/oci/puller/fake"
)

func TestManager_FetchConfig(t *testing.T) {
	const testNamespace = "test-namespace"
	const tagRef = "ghcr.io/example.com/myplugin:latest"
	const pinnedRef = "ghcr.io/example.com/myplugin@" + testDigest

	tests := []struct {
		name         string
		knownDigest  string
		configResult *puller.ArtifactConfig
		configDigest string
		fetchErr     error
		wantRef      string
		wantErr      string
	}{
		{
			name:         "fetches config successfully",
			configResult: &puller.ArtifactConfig{Name: "myplugin", Version: "1.0.0"},
			configDigest: testDigest,
			wantRef:      tagRef,
		},
		{
			name:     "puller error propagates",
			fetchErr: fmt.Errorf("registry unreachable"),
			wantRef:  tagRef,
			wantErr:  "registry unreachable",
		},
		{
			name:         "reads the known digest instead of the mutable tag",
			knownDigest:  testDigest,
			configResult: &puller.ArtifactConfig{Name: "myplugin", Version: "1.0.0"},
			configDigest: testDigest,
			wantRef:      pinnedRef,
		},
		{
			name:         "rejects a different root digest",
			knownDigest:  testDigest,
			configResult: &puller.ArtifactConfig{Name: "wrong-revision"},
			configDigest: testOtherDigest,
			wantRef:      pinnedRef,
			wantErr:      "does not match expected digest",
		},
		{
			name:        "rejects a missing root digest",
			knownDigest: testDigest,
			wantRef:     pinnedRef,
			wantErr:     "does not match expected digest",
		},
		{
			name:        "rejects an invalid known digest before fetching",
			knownDigest: "sha256:short",
			wantErr:     "pin OCI reference",
		},
		{
			name:        "does not fall back to the tag when the pinned revision is unavailable",
			knownDigest: testDigest,
			fetchErr:    fmt.Errorf("manifest unavailable"),
			wantRef:     pinnedRef,
			wantErr:     "manifest unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			mockPuller := &pullerfake.MockOCIPuller{
				ConfigResult:   tt.configResult,
				ConfigDigest:   tt.configDigest,
				FetchConfigErr: tt.fetchErr,
			}
			manager := NewManagerWithOptions(fakeClient, testNamespace, WithOCIPuller(mockPuller))

			ociArtifact := &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "example.com/myplugin", Tag: "latest"},
			}
			original := ociArtifact.DeepCopy()
			cfg, digest, err := manager.FetchConfig(context.Background(), ociArtifact, tt.knownDigest)
			assert.Equal(t, original, ociArtifact)
			if tt.wantRef == "" {
				assert.Empty(t, mockPuller.FetchConfigCalls)
			} else {
				assert.Equal(t, []string{tt.wantRef}, mockPuller.FetchConfigCalls)
			}

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, cfg)
				assert.Empty(t, digest)
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

			mockPuller := &pullerfake.MockOCIPuller{
				ContentResult:   tt.content,
				FetchContentErr: tt.fetchErr,
			}
			manager := NewManagerWithOptions(fakeClient, testNamespace, WithOCIPuller(mockPuller))

			content, err := manager.FetchContent(context.Background(), &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "example.com/myrules", Tag: "latest"},
			}, testDigest)
			assert.Equal(t, []string{"ghcr.io/example.com/myrules@" + testDigest}, mockPuller.FetchContentCalls)

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

func TestManager_FetchContent_RejectsInvalidDigest(t *testing.T) {
	for _, digest := range []string{"", "latest", "sha256:short"} {
		t.Run(digest, func(t *testing.T) {
			mockPuller := &pullerfake.MockOCIPuller{}
			manager := NewManagerWithOptions(
				fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build(),
				"test-namespace", WithOCIPuller(mockPuller),
			)
			content, err := manager.FetchContent(context.Background(), &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "test/rules", Tag: "latest"},
			}, digest)
			require.ErrorContains(t, err, "pin OCI reference")
			assert.Nil(t, content)
			assert.Empty(t, mockPuller.FetchContentCalls)
		})
	}
}
