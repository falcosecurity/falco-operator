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
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
	pullerfake "github.com/falcosecurity/falco-operator/internal/pkg/oci/puller/fake"
)

const (
	testDigest         = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testResolvedDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testOtherDigest    = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestManager_EnsureBlob_PinsDigest(t *testing.T) {
	layer, err := pullerfake.MakeTarGz("plugin.so", []byte("binary content"))
	require.NoError(t, err)

	tests := []struct {
		name           string
		knownDigest    string
		resolvedDigest string
		rootDigest     string
		manifestDigest string
		pullErr        error
		wantErr        string
		wantPull       bool
	}{
		{
			name:        "uses the known digest without resolving the tag again",
			knownDigest: testDigest,
			rootDigest:  testDigest,
			wantPull:    true,
		},
		{
			name:           "resolves once then pulls by digest",
			resolvedDigest: testResolvedDigest,
			rootDigest:     testResolvedDigest,
			wantPull:       true,
		},
		{
			name:           "accepts a platform manifest within the pinned index",
			knownDigest:    testDigest,
			rootDigest:     testDigest,
			manifestDigest: testOtherDigest,
			wantPull:       true,
		},
		{
			name:        "rejects a different root digest before storing content",
			knownDigest: testDigest,
			rootDigest:  testOtherDigest,
			wantErr:     "does not match expected digest",
			wantPull:    true,
		},
		{
			name:        "reports the pinned reference when the pull fails",
			knownDigest: testDigest,
			pullErr:     errors.New("registry unavailable"),
			wantErr:     "pull \"ghcr.io/test/plugin@" + testDigest + "\" (linux/arm64): registry unavailable",
			wantPull:    true,
		},
		{
			name:        "rejects a missing root digest before storing content",
			knownDigest: testDigest,
			wantErr:     "does not match expected digest",
			wantPull:    true,
		},
		{
			name:        "rejects an invalid known digest before pulling",
			knownDigest: "not-a-digest",
			wantErr:     "pin OCI reference",
		},
		{
			name:           "rejects an invalid resolved digest before pulling",
			resolvedDigest: "sha256:short",
			wantErr:        "pin OCI reference",
		},
		{
			name:    "rejects an empty resolved digest before pulling",
			wantErr: "pin OCI reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := artifactcache.NewCache(t.TempDir())
			mockPuller := &pullerfake.MockOCIPuller{
				PullErr:             tt.pullErr,
				ResolveDigestResult: tt.resolvedDigest,
				Result: &puller.RegistryResult{
					RootDigest: tt.rootDigest,
					Digest:     tt.manifestDigest,
					Type:       puller.Plugin,
				},
				LayerContent: layer,
			}
			manager := NewManagerWithOptions(
				fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build(),
				"test-namespace", WithOCIPuller(mockPuller),
			)
			ociArt := &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "test/plugin", Tag: "latest"},
			}
			original := ociArt.DeepCopy()
			digest := tt.knownDigest
			if digest == "" {
				digest = tt.resolvedDigest
			}
			wantPath := artifactcache.BlobPath(cache.Dir(), string(TypePlugin), ResolveReference(ociArt), digest, "linux", "arm64")

			path, err := manager.EnsureBlob(context.Background(), ociArt, TypePlugin, "linux", "arm64", cache, tt.knownDigest)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.Empty(t, path)
				assert.NoFileExists(t, wantPath)
			} else {
				require.NoError(t, err)
				assert.Equal(t, wantPath, path)
				content, err := os.ReadFile(path)
				require.NoError(t, err)
				assert.Equal(t, "binary content", string(content))
			}
			if tt.wantPull {
				require.Len(t, mockPuller.PullCalls, 1)
				assert.Equal(t, "ghcr.io/test/plugin@"+digest, mockPuller.PullCalls[0].Ref)
				assert.Equal(t, "linux", mockPuller.PullCalls[0].OS)
				assert.Equal(t, "arm64", mockPuller.PullCalls[0].Arch)
			} else {
				assert.Empty(t, mockPuller.PullCalls)
			}
			if tt.knownDigest == "" {
				assert.Equal(t, []string{ResolveReference(ociArt)}, mockPuller.ResolveDigestCalls)
			} else {
				assert.Empty(t, mockPuller.ResolveDigestCalls)
			}
			assert.Equal(t, original, ociArt, "pinning must not modify the artifact spec")
		})
	}
}

func TestManager_EnsureBlob_PinnedPlatformsAndCacheHits(t *testing.T) {
	cache := artifactcache.NewCache(t.TempDir())
	mockPuller := &pullerfake.MockOCIPuller{}
	manager := NewManagerWithOptions(
		fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build(),
		"test-namespace", WithOCIPuller(mockPuller),
	)
	ociArt := &commonv1alpha1.OCIArtifact{
		Image: commonv1alpha1.ImageSpec{Repository: "test/artifact", Tag: "latest"},
	}
	tests := []struct {
		name         string
		artifactType Type
		ociType      puller.ArtifactType
		os, arch     string
		pullOS       string
		pullArch     string
	}{
		{"amd64 plugin", TypePlugin, puller.Plugin, "linux", "amd64", "linux", "amd64"},
		{"arm64 plugin", TypePlugin, puller.Plugin, "linux", "arm64", "linux", "arm64"},
		{"platform-agnostic rulesfile", TypeRulesfile, puller.Rulesfile, "", "", runtime.GOOS, runtime.GOARCH},
	}
	paths := make(map[string]bool)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			mockPuller.LayerContent, err = pullerfake.MakeTarGz("artifact", []byte(tt.name))
			require.NoError(t, err)
			mockPuller.Result = &puller.RegistryResult{RootDigest: testDigest, Digest: testOtherDigest, Type: tt.ociType}
			mockPuller.PullCalls = nil

			path, err := manager.EnsureBlob(context.Background(), ociArt, tt.artifactType, tt.os, tt.arch, cache, testDigest)
			require.NoError(t, err)
			assert.Equal(t, artifactcache.BlobPath(cache.Dir(), string(tt.artifactType), ResolveReference(ociArt), testDigest, tt.os, tt.arch), path)
			assert.False(t, paths[path], "each platform needs a separate cached file")
			paths[path] = true
			content, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, tt.name, string(content))
			platformKey := ""
			if tt.os != "" && tt.arch != "" {
				platformKey = tt.os + "-" + tt.arch
			}
			require.NoError(t, cache.Set(string(tt.artifactType), "test-namespace", "test-artifact", platformKey, path))

			cached, err := manager.EnsureBlob(context.Background(), ociArt, tt.artifactType, tt.os, tt.arch, cache, testDigest)
			require.NoError(t, err)
			assert.Equal(t, path, cached)
			require.Len(t, mockPuller.PullCalls, 1, "a cache hit must not download the artifact again")
			assert.Equal(t, "ghcr.io/test/artifact@"+testDigest, mockPuller.PullCalls[0].Ref)
			assert.Equal(t, tt.pullOS, mockPuller.PullCalls[0].OS)
			assert.Equal(t, tt.pullArch, mockPuller.PullCalls[0].Arch)
			assert.Empty(t, mockPuller.ResolveDigestCalls)
		})
	}
}
