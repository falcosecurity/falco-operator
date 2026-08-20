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
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

func newTestCache(t *testing.T) *artifactcache.Cache {
	t.Helper()
	c := artifactcache.NewCache(t.TempDir())
	require.NoError(t, c.Load())
	return c
}

func TestManager_EnsureBlob(t *testing.T) {
	const testNamespace = "test-namespace"

	layer, err := puller.MakeTarGz("plugin.so", []byte("binary content"))
	require.NoError(t, err)

	tests := []struct {
		name         string
		resolveErr   error
		pullResult   *puller.RegistryResult
		pullErr      error
		layerContent []byte
		knownDigest  string
		wantErr      bool
		wantPullCall bool
	}{
		{
			name:         "cache miss pulls and stores the blob",
			pullResult:   &puller.RegistryResult{Type: puller.Plugin},
			layerContent: layer,
			knownDigest:  "sha256:abc",
			wantPullCall: true,
		},
		{
			name:       "resolve digest error propagates when knownDigest is empty",
			resolveErr: fmt.Errorf("registry unreachable"),
			wantErr:    true,
		},
		{
			name:         "pull error propagates",
			knownDigest:  "sha256:abc",
			pullErr:      fmt.Errorf("pull failed"),
			wantErr:      true,
			wantPullCall: true,
		},
		{
			name:         "unexpected artifact type is rejected",
			knownDigest:  "sha256:abc",
			pullResult:   &puller.RegistryResult{Type: puller.Rulesfile},
			layerContent: layer,
			wantErr:      true,
			wantPullCall: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
			cache := newTestCache(t)

			mockPuller := &puller.MockOCIPuller{
				ResolveDigestResult: "sha256:resolved",
				ResolveDigestErr:    tt.resolveErr,
				Result:              tt.pullResult,
				PullErr:             tt.pullErr,
				LayerContent:        tt.layerContent,
			}
			manager := NewManagerWithOptions(fakeClient, testNamespace, WithOCIPuller(mockPuller))

			blobPath, err := manager.EnsureBlob(context.Background(),
				&commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "example.com/myplugin", Tag: "latest"}},
				TypePlugin, "linux", "amd64", cache, tt.knownDigest)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, blobPath)
				assert.FileExists(t, blobPath, "EnsureBlob must write the blob to disk")
			}
			assert.Equal(t, tt.wantPullCall, len(mockPuller.PullCalls) == 1)
		})
	}
}

func TestManager_EnsureBlob_CacheHitSkipsPull(t *testing.T) {
	const testNamespace = "test-namespace"

	scheme := createTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	cache := newTestCache(t)

	ociArt := &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "example.com/myplugin", Tag: "latest"}}
	blobPath := artifactcache.BlobPath(cache.Dir(), string(TypePlugin), ResolveReference(ociArt), "sha256:abc", "linux", "amd64")
	require.NoError(t, artifactcache.Store(blobPath, []byte("cached content"), 0o755))
	require.NoError(t, cache.Set(string(TypePlugin), testNamespace, "myplugin", "linux-amd64", blobPath))

	mockPuller := &puller.MockOCIPuller{}
	manager := NewManagerWithOptions(fakeClient, testNamespace, WithOCIPuller(mockPuller))

	got, err := manager.EnsureBlob(context.Background(), ociArt, TypePlugin, "linux", "amd64", cache, "sha256:abc")
	require.NoError(t, err)
	assert.Equal(t, blobPath, got)
	assert.Empty(t, mockPuller.PullCalls, "cache hit must not trigger a pull")
}
