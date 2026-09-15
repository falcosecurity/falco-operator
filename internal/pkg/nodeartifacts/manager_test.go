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

package nodeartifacts_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

func newTestManager() *nodeartifacts.Manager {
	return newTestManagerWithFetcher(compatfake.NewMockVersionsFetcher(nil))
}

func newTestManagerWithFetcher(fetcher compat.VersionsFetcher) *nodeartifacts.Manager {
	store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	return nodeartifacts.NewManager(store, fetcher)
}

func TestManager_ScanAllPassesThroughToUnderlyingStore(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}
	_, _, err := m.StoreConfig(context.Background(), "", "myfile", 50, artifact.MediumInline, result)
	require.NoError(t, err)

	found, err := m.ScanAll(context.Background(), artifact.TypeConfig)

	require.NoError(t, err)
	require.Len(t, found["myfile"], 1)
	assert.Equal(t, string(artifact.MediumInline), found["myfile"][0].Medium)
}

func TestManager_RemovePassesThroughToUnderlyingStore(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}
	key := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Name: "myfile"}
	_, file, err := m.StoreConfig(context.Background(), "", "myfile", 50, artifact.MediumInline, result)
	require.NoError(t, err)

	err = m.Remove(context.Background(), key)
	require.NoError(t, err)

	ok, err := m.Verify(context.Background(), file)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestManager_FindInstalled_ReturnsWhatStoreWrote(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}
	key := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Name: "myfile"}

	assert.Nil(t, m.FindInstalled(key, artifact.MediumInline), "nothing stored yet")

	_, file, err := m.StoreConfig(context.Background(), "", "myfile", 50, artifact.MediumInline, result)
	require.NoError(t, err)

	found := m.FindInstalled(key, artifact.MediumInline)
	require.NotNil(t, found)
	assert.Equal(t, file.Path, found.Path)
	assert.Equal(t, file.ContentHash, found.ContentHash)
}

func TestManager_Remove_RemovesEveryInstalledMedium(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}
	key := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Name: "myfile"}
	_, file, err := m.StoreConfig(context.Background(), "", "myfile", 50, artifact.MediumInline, result)
	require.NoError(t, err)
	_, otherFile, err := m.StoreConfig(context.Background(), "", "myfile", 50, artifact.MediumConfigMap, result)
	require.NoError(t, err)

	require.NoError(t, m.Remove(context.Background(), key))
	for _, removedFile := range []*artifact.File{file, otherFile} {
		intact, err := m.Verify(context.Background(), removedFile)
		require.NoError(t, err)
		assert.False(t, intact)
	}

	assert.Empty(t, m.GetInstalled(key))
}

func TestManager_RemoveIfInstalled_NoOpWhenNothingInstalled(t *testing.T) {
	m := newTestManager()
	key := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Name: "myfile"}

	path, removed, err := m.RemoveIfInstalled(context.Background(), key, artifact.MediumInline)

	require.NoError(t, err)
	assert.False(t, removed)
	assert.Empty(t, path)
}

func TestManager_RemoveIfInstalled_RemovesWhenInstalled(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}
	key := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Name: "myfile"}
	_, file, err := m.StoreConfig(context.Background(), "", "myfile", 50, artifact.MediumInline, result)
	require.NoError(t, err)

	path, removed, err := m.RemoveIfInstalled(context.Background(), key, artifact.MediumInline)

	require.NoError(t, err)
	assert.True(t, removed)
	assert.Equal(t, file.Path, path)
	assert.Nil(t, m.FindInstalled(key, artifact.MediumInline), "cache entry must be cleared")
	ok, err := m.Verify(context.Background(), file)
	require.NoError(t, err)
	assert.False(t, ok, "file must be removed from the underlying store")
}

func TestManager_SeedInstalled_ThenFindInstalled(t *testing.T) {
	m := newTestManager()
	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rules"}

	m.SeedInstalled(key, []artifactv1alpha1.InstalledArtifact{
		{Path: "/x", Medium: "oci", Priority: 50, ContentHash: "h1", SpecHash: "s1"},
	})

	found := m.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, found)
	assert.Equal(t, "/x", found.Path)
	assert.Equal(t, "s1", found.SpecHash)
}

func TestManager_UpdateInstalledSpecHash_SetsSpecHashOnCachedEntry(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}
	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rules"}
	_, _, err := m.StoreRulesfile(context.Background(), "", "my-rules", 50, artifact.MediumOCI, result, &commonv1alpha1.ArtifactMeta{}, true)
	require.NoError(t, err)

	m.UpdateInstalledSpecHash(key, artifact.MediumOCI, "spec-hash-v1")

	found := m.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, found)
	assert.Equal(t, "spec-hash-v1", found.SpecHash)
}

// TestManager_SyncInstalledStatus_MirrorsCacheEvenWhenStatusStartsEmpty covers a reconcile that
// takes the "already verified on disk, skip re-fetch" shortcut (or hits StoreActionUnchanged): a
// status write gated on the StoreAction actually having changed something would leave
// status.InstalledArtifacts permanently missing an entry the cache (seeded by WarmSync, or
// surviving a status patch that lost an SSA conflict) already considers installed.
// SyncInstalledStatus must mirror the cache unconditionally, regardless of any StoreAction.
func TestManager_SyncInstalledStatus_MirrorsCacheEvenWhenStatusStartsEmpty(t *testing.T) {
	m := newTestManager()
	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "my-rules"}
	m.SeedInstalled(key, []artifactv1alpha1.InstalledArtifact{
		{Path: "/x", Medium: "oci", Priority: 50, ContentHash: "h1", SpecHash: "s1"},
	})
	var status []artifactv1alpha1.InstalledArtifact

	m.SyncInstalledStatus(key, artifact.MediumOCI, &status)

	entry := artifact.FindInstalled(status, artifact.MediumOCI)
	require.NotNil(t, entry, "status must be populated from the cache even though no Store call happened on this status object")
	assert.Equal(t, "/x", entry.Path)
	assert.Equal(t, "s1", entry.SpecHash)
}

// TestManager_SyncInstalledStatus_ClearsStatusWhenCacheHasNoEntry covers the removal direction:
// if the cache no longer has an entry for medium, status must not keep a stale one either.
func TestManager_SyncInstalledStatus_ClearsStatusWhenCacheHasNoEntry(t *testing.T) {
	m := newTestManager()
	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "my-rules"}
	status := []artifactv1alpha1.InstalledArtifact{{Path: "/stale", Medium: "oci"}}

	m.SyncInstalledStatus(key, artifact.MediumOCI, &status)

	assert.Nil(t, artifact.FindInstalled(status, artifact.MediumOCI))
}

// TestManager_SyncAllInstalledStatus_SyncsEveryMediumGiven covers SyncAllInstalledStatus, the
// helper each controller's Reconcile defer uses to resync every medium of its artifact type from
// the cache before patching status: every medium passed in must be synced, whether that means
// upserting an entry or clearing a stale one.
func TestManager_SyncAllInstalledStatus_SyncsEveryMediumGiven(t *testing.T) {
	m := newTestManager()
	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "my-rules"}
	m.SeedInstalled(key, []artifactv1alpha1.InstalledArtifact{
		{Path: "/oci", Medium: "oci", Priority: 50, ContentHash: "h-oci"},
		{Path: "/inline", Medium: "inline", Priority: 90, ContentHash: "h-inline"},
	})
	status := []artifactv1alpha1.InstalledArtifact{{Path: "/stale", Medium: "configmap"}}

	m.SyncAllInstalledStatus(key, []artifact.Medium{artifact.MediumOCI, artifact.MediumInline, artifact.MediumConfigMap}, &status)

	ociEntry := artifact.FindInstalled(status, artifact.MediumOCI)
	require.NotNil(t, ociEntry)
	assert.Equal(t, "/oci", ociEntry.Path)
	inlineEntry := artifact.FindInstalled(status, artifact.MediumInline)
	require.NotNil(t, inlineEntry)
	assert.Equal(t, "/inline", inlineEntry.Path)
	assert.Nil(t, artifact.FindInstalled(status, artifact.MediumConfigMap),
		"a medium the cache has no entry for must be cleared, not left stale")
}

// TestKeyFromObj covers building a Key from the parent CR object (Plugin, Rulesfile, or Config)
// that owns it.
func TestKeyFromObj(t *testing.T) {
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "my-plugin", Namespace: "ns"}}

	key := nodeartifacts.KeyFromObj(nodeartifacts.KindPlugin, plugin)

	assert.Equal(t, nodeartifacts.Key{Kind: nodeartifacts.KindPlugin, Namespace: "ns", Name: "my-plugin"}, key)
}

func TestManager_GetInstalled_ReturnsIndependentCopy(t *testing.T) {
	m := newTestManager()
	key := nodeartifacts.Key{Kind: nodeartifacts.KindPlugin, Name: "my-plugin"}
	m.SeedInstalled(key, []artifactv1alpha1.InstalledArtifact{{
		Path: "/x", Medium: "oci", Config: &artifactv1alpha1.InstalledArtifactConfig{Path: "/config"},
	}})

	got := m.GetInstalled(key)
	got[0].Path = "/mutated"
	got[0].Config.Path = "/mutated-config"

	assert.Equal(t, "/x", m.FindInstalled(key, artifact.MediumOCI).Path, "caller mutation must not affect the cache")
	assert.Equal(t, "/config", m.GetInstalled(key)[0].Config.Path, "nested config must not alias the cache")
}
