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
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
	pullerfake "github.com/falcosecurity/falco-operator/internal/pkg/oci/puller/fake"
)

func TestNewManager(t *testing.T) {
	t.Run("creates manager with namespace", func(t *testing.T) {
		scheme := createTestScheme(t)
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		manager := NewManager(fakeClient, "test-namespace")
		require.NotNil(t, manager)
		assert.Equal(t, "test-namespace", manager.namespace)
		assert.NotNil(t, manager.client)
		assert.NotNil(t, manager.ociPuller)
	})

	t.Run("WithOCIPuller sets custom puller", func(t *testing.T) {
		scheme := createTestScheme(t)
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		mockPuller := &pullerfake.MockOCIPuller{}
		manager := NewManagerWithOptions(fakeClient, "ns", WithOCIPuller(mockPuller))
		require.NotNil(t, manager)
		assert.Equal(t, mockPuller, manager.ociPuller)
	})
}

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
			wantPath := artifactcache.BlobPath(cache.Dir(), string(KindPlugin), ResolveReference(ociArt), digest, "linux", "arm64")

			path, err := manager.EnsureBlob(context.Background(), "test-artifact", ociArt, KindPlugin, "linux", "arm64", cache, tt.knownDigest)
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
		name     string
		kind     Kind
		ociType  puller.ArtifactType
		os, arch string
		pullOS   string
		pullArch string
	}{
		{"amd64 plugin", KindPlugin, puller.Plugin, "linux", "amd64", "linux", "amd64"},
		{"arm64 plugin", KindPlugin, puller.Plugin, "linux", "arm64", "linux", "arm64"},
		{"platform-agnostic rulesfile", KindRulesfile, puller.Rulesfile, "", "", runtime.GOOS, runtime.GOARCH},
	}
	paths := make(map[string]bool)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			mockPuller.LayerContent, err = pullerfake.MakeTarGz("artifact", []byte(tt.name))
			require.NoError(t, err)
			mockPuller.Result = &puller.RegistryResult{RootDigest: testDigest, Digest: testOtherDigest, Type: tt.ociType}
			mockPuller.PullCalls = nil

			path, err := manager.EnsureBlob(context.Background(), "test-artifact", ociArt, tt.kind, tt.os, tt.arch, cache, testDigest)
			require.NoError(t, err)
			assert.Equal(t, artifactcache.BlobPath(cache.Dir(), string(tt.kind), ResolveReference(ociArt), testDigest, tt.os, tt.arch), path)
			assert.False(t, paths[path], "each platform needs a separate cached file")
			paths[path] = true
			content, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, tt.name, string(content))
			platformKey := ""
			if tt.os != "" && tt.arch != "" {
				platformKey = tt.os + "-" + tt.arch
			}
			indexed, ok := cache.Lookup(string(tt.kind), "test-namespace", "test-artifact", platformKey)
			require.True(t, ok, "EnsureBlob must register the reference before returning")
			require.Equal(t, path, indexed)

			cached, err := manager.EnsureBlob(context.Background(), "test-artifact", ociArt, tt.kind, tt.os, tt.arch, cache, testDigest)
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

func TestManager_EnsureBlob_ReacquiresBeforeSweep(t *testing.T) {
	cache := artifactcache.NewCache(t.TempDir(), artifactcache.WithEvictionGracePeriod(time.Nanosecond))
	require.NoError(t, cache.Load())
	ociArt := &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "test/plugin", Tag: "latest"}}
	path := artifactcache.BlobPath(cache.Dir(), string(KindPlugin), ResolveReference(ociArt), testDigest, "linux", "arm64")
	require.NoError(t, cache.Store(path, []byte("cached plugin"), 0o755))
	require.NoError(t, cache.Set(string(KindPlugin), "test-namespace", "old", "linux-arm64", path))
	require.NoError(t, cache.RemoveAll(string(KindPlugin), "test-namespace", "old"))
	mockPuller := &pullerfake.MockOCIPuller{}
	manager := NewManagerWithOptions(fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build(), "test-namespace", WithOCIPuller(mockPuller))
	reused, err := manager.EnsureBlob(t.Context(), "new", ociArt, KindPlugin, "linux", "arm64", cache, testDigest)
	require.NoError(t, err)
	require.Equal(t, path, reused)
	removed, err := cache.Sweep(t.Context())
	require.NoError(t, err)
	require.Zero(t, removed)
	indexed, ok := cache.Lookup(string(KindPlugin), "test-namespace", "new", "linux-arm64")
	require.True(t, ok)
	require.FileExists(t, indexed)
	require.Empty(t, mockPuller.PullCalls)
	require.Empty(t, mockPuller.ResolveDigestCalls)
}

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
