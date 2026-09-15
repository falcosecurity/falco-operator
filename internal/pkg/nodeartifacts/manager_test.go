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
	"errors"
	"fmt"
	"maps"
	"testing"

	"github.com/opencontainers/go-digest"
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

const (
	writeFailure         = "write"
	mutatedMetadataValue = "mutated"
)

func newTestManager() *nodeartifacts.Manager {
	return newTestManagerWithFetcher(compatfake.NewMockVersionsFetcher(nil))
}

func newTestManagerWithFetcher(fetcher compat.VersionsFetcher) *nodeartifacts.Manager {
	store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	return nodeartifacts.NewManager(store, fetcher)
}

func installTestRulesfile(t *testing.T, m *nodeartifacts.Manager, key nodeartifacts.Key,
	dependencies []commonv1alpha1.ArtifactMetaDependency,
) {
	t.Helper()
	content, err := (&artifact.Fetcher{}).FetchInline(t.Context(), []byte("test rules"))
	require.NoError(t, err)
	_, _, err = m.StoreRulesfile(t.Context(), key.Namespace, key.Name, 50, artifact.MediumOCI, content,
		&commonv1alpha1.ArtifactMeta{Dependencies: dependencies}, false)
	require.NoError(t, err)
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

func TestManager_StoreConfig_PartialPriorityMoveTracksInstalledFileAndRetries(t *testing.T) {
	ctx := t.Context()
	fs := fsfake.NewMockFileSystem()
	dirs := artifact.DefaultArtifactDirs()
	m := nodeartifacts.NewManager(&artifact.LocalStore{FS: fs, Dirs: dirs}, compatfake.NewMockVersionsFetcher(nil))
	fetcher := &artifact.Fetcher{}
	key := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Namespace: "ns", Name: "myfile"}
	oldContent, err := fetcher.FetchInline(ctx, []byte("old config"))
	require.NoError(t, err)
	updatedContent, err := fetcher.FetchInline(ctx, []byte("updated config"))
	require.NoError(t, err)
	_, original, err := m.StoreConfig(ctx, key.Namespace, key.Name, 50, artifact.MediumInline, oldContent)
	require.NoError(t, err)
	require.NotNil(t, original)
	newPath := artifact.ArtifactPath(dirs, key.Name, 20, artifact.MediumInline, artifact.TypeConfig)
	replaceErr := errors.New("cannot replace moved config")
	fs.RenameErrFor = map[string]error{newPath + ".tmp": replaceErr}

	action, relocated, err := m.StoreConfig(ctx, key.Namespace, key.Name, 20, artifact.MediumInline, updatedContent)

	require.ErrorIs(t, err, replaceErr)
	assert.Equal(t, artifact.StoreActionPriorityChanged, action)
	require.NotNil(t, relocated)
	assert.Equal(t, newPath, relocated.Path)
	assert.Equal(t, int32(20), relocated.Priority)
	assert.Equal(t, oldContent.ContentHash, relocated.ContentHash)
	assert.Equal(t, relocated, m.FindInstalled(key, artifact.MediumInline))
	assert.Equal(t, oldContent.Content, fs.Files[newPath])
	assert.NotContains(t, fs.Files, original.Path)
	assert.NotContains(t, fs.Files, newPath+".tmp")
	intact, err := m.Verify(ctx, relocated)
	require.NoError(t, err)
	assert.True(t, intact)

	delete(fs.RenameErrFor, newPath+".tmp")
	action, installed, err := m.StoreConfig(ctx, key.Namespace, key.Name, 20, artifact.MediumInline, updatedContent)

	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUpdated, action)
	require.NotNil(t, installed)
	assert.Equal(t, newPath, installed.Path)
	assert.Equal(t, int32(20), installed.Priority)
	assert.Equal(t, updatedContent.ContentHash, installed.ContentHash)
	assert.Equal(t, installed, m.FindInstalled(key, artifact.MediumInline))
	assert.Equal(t, updatedContent.Content, fs.Files[newPath])
	assert.NotContains(t, fs.Files, original.Path)
	assert.NotContains(t, fs.Files, newPath+".tmp")
	intact, err = m.Verify(ctx, installed)
	require.NoError(t, err)
	assert.True(t, intact)

	action, _, err = m.StoreConfig(ctx, key.Namespace, key.Name, 20, artifact.MediumInline, updatedContent)
	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUnchanged, action)
}

func TestManager_StoreConfigPassesThroughToUnderlyingStore(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}

	action, file, err := m.StoreConfig(context.Background(), "", "myfile", 50, artifact.MediumInline, result)

	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionAdded, action)
	require.NotNil(t, file)

	ok, err := m.Verify(context.Background(), file)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestManager_StoreConfig_OnlyWritesConfig(t *testing.T) {
	for _, medium := range []artifact.Medium{artifact.MediumInline, artifact.MediumConfigMap} {
		t.Run(string(medium), func(t *testing.T) {
			m := newTestManager()
			content, err := (&artifact.Fetcher{}).FetchInline(t.Context(), []byte("test artifact"))
			require.NoError(t, err)
			key := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Namespace: "ns", Name: "artifact"}

			action, file, err := m.StoreConfig(t.Context(), key.Namespace, key.Name, 50, medium, content)

			require.NoError(t, err)
			assert.Equal(t, artifact.StoreActionAdded, action)
			require.NotNil(t, file)
			assert.Equal(t, artifact.ArtifactPath(artifact.DefaultArtifactDirs(), key.Name, 50, medium, artifact.TypeConfig), file.Path)
			assert.Equal(t, file, m.FindInstalled(key, medium))
			for _, kind := range []nodeartifacts.Kind{nodeartifacts.KindRulesfile, nodeartifacts.KindPlugin} {
				assert.Empty(t, m.GetInstalled(nodeartifacts.Key{Kind: kind, Namespace: key.Namespace, Name: key.Name}))
			}
			for _, artifactType := range []artifact.Type{artifact.TypeRulesfile, artifact.TypePlugin} {
				disk, err := m.ScanAll(t.Context(), artifactType)
				require.NoError(t, err)
				assert.Empty(t, disk)
			}
		})
	}
}

func TestManager_StoreConfig_ProtectsSharedPluginConfigPath(t *testing.T) {
	for _, tc := range []struct {
		name     string
		priority int32
		medium   artifact.Medium
		wantErr  bool
	}{
		{name: "reserved path", priority: 99, medium: artifact.MediumInline, wantErr: true},
		{name: "different priority", priority: 50, medium: artifact.MediumInline},
		{name: "configmap medium", priority: 99, medium: artifact.MediumConfigMap},
		{name: "oci medium", priority: 99, medium: artifact.MediumOCI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			m := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))
			fetcher := &artifact.Fetcher{}
			_, shared, err := m.AddPluginConfig(ctx, testPlugin("container"), fetcher)
			require.NoError(t, err)
			before, err := store.Read(ctx, shared.Path)
			require.NoError(t, err)
			writes := len(fs.WriteCalls)
			content, err := fetcher.FetchInline(ctx, []byte("log_level: debug"))
			require.NoError(t, err)

			action, file, err := m.StoreConfig(ctx, "ns", nodeartifacts.PluginConfigKey.Name, tc.priority, tc.medium, content)

			if tc.wantErr {
				require.Error(t, err)
				assert.Equal(t, artifact.StoreActionNone, action)
				assert.Nil(t, file)
				assert.Len(t, fs.WriteCalls, writes)
			} else {
				require.NoError(t, err)
				require.NotNil(t, file)
				assert.NotEqual(t, shared.Path, file.Path)
				assert.Equal(t, content.Content, fs.Files[file.Path])
			}
			intact, err := m.Verify(ctx, shared)
			require.NoError(t, err)
			assert.True(t, intact)
			after, err := store.Read(ctx, shared.Path)
			require.NoError(t, err)
			assert.Equal(t, before, after)
		})
	}
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

func TestManager_StoreConfig_UsesCacheForCurrent_SecondIdenticalStoreIsUnchanged(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}

	action1, _, err := m.StoreConfig(context.Background(), "", "myfile", 50, artifact.MediumInline, result)
	require.NoError(t, err)
	require.Equal(t, artifact.StoreActionAdded, action1)

	// No caller-supplied "current": Manager must derive it from its own cache, not from any
	// status object, to recognize the second call as a no-op.
	action2, _, err := m.StoreConfig(context.Background(), "", "myfile", 50, artifact.MediumInline, result)
	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUnchanged, action2)
}

// TestManager_StoreConfig_IsolatesByNamespace proves that two artifacts with the same Kind and Name
// but different Namespace are tracked as distinct cache entries, not merged into one.
func TestManager_StoreConfig_IsolatesByNamespace(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}

	_, _, err := m.StoreConfig(context.Background(), "ns-a", "myfile", 50, artifact.MediumInline, result)
	require.NoError(t, err)

	keyA := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Namespace: "ns-a", Name: "myfile"}
	keyB := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Namespace: "ns-b", Name: "myfile"}

	assert.NotNil(t, m.FindInstalled(keyA, artifact.MediumInline), "ns-a's artifact must be tracked under its own namespace")
	assert.Nil(t, m.FindInstalled(keyB, artifact.MediumInline), "ns-b must not see ns-a's artifact of the same kind+name")
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

func testPlugin(name string) *artifactv1alpha1.Plugin {
	return &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func TestManager_StorePlugin_ProtectsInstalledOwnership(t *testing.T) {
	const (
		configCollision    = "config name collision"
		recreatedOwner     = "recreated owner"
		differentNamespace = "different namespace"
		blockedRename      = "blocked rename"
	)
	for _, scenario := range []string{configCollision, recreatedOwner, differentNamespace, blockedRename} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			m := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))
			fetcher := &artifact.Fetcher{}
			plugin := testPlugin("plugin-cr")
			plugin.Namespace, plugin.UID = "ns", "original-uid"
			plugin.Spec.Config = &artifactv1alpha1.PluginConfig{Name: "container"}
			oldContent, err := fetcher.FetchInline(ctx, []byte("installed binary"))
			require.NoError(t, err)
			oldContent.Perm = artifact.PermFor(artifact.TypePlugin)
			_, binary, err := m.StorePlugin(ctx, plugin, oldContent)
			require.NoError(t, err)
			_, config, err := m.AddPluginConfig(ctx, plugin, fetcher)
			require.NoError(t, err)
			candidate := plugin.DeepCopy()
			switch scenario {
			case configCollision:
				candidate.Name, candidate.UID = "another-cr", "another-uid"
			case recreatedOwner:
				candidate.UID = "replacement-uid"
				candidate.Spec.Config.Name = "replacement-name"
			case differentNamespace:
				candidate.Namespace = "another-ns"
			case blockedRename:
				candidate.Spec.Config.Name = "renamed"
				m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
				installTestRulesfile(t, m, nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: plugin.Namespace, Name: "rules"},
					[]commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}})
			}
			before, err := store.Read(ctx, config.Path)
			require.NoError(t, err)
			writes := len(fs.WriteCalls)
			newContent, err := fetcher.FetchInline(ctx, []byte("candidate binary"))
			require.NoError(t, err)
			newContent.Perm = artifact.PermFor(artifact.TypePlugin)

			action, installed, err := m.StorePlugin(ctx, candidate, newContent)

			require.Error(t, err)
			assert.Equal(t, artifact.StoreActionNone, action)
			assert.Nil(t, installed)
			if scenario == blockedRename {
				var blocked *nodeartifacts.BlockedError
				require.ErrorAs(t, err, &blocked)
			}
			_, _, err = m.AddPluginConfig(ctx, candidate, fetcher)
			require.Error(t, err, "the aggregate must reject the same ownership conflict")
			if scenario != blockedRename {
				require.NoError(t, m.RemovePluginConfig(ctx, fetcher, candidate), "a different owner cannot remove the installed entry")
			}
			assert.Len(t, fs.WriteCalls, writes, "rejected ownership must not write a binary or config")
			after, err := store.Read(ctx, config.Path)
			require.NoError(t, err)
			assert.Equal(t, before, after)
			for _, file := range []*artifact.File{binary, config} {
				intact, verifyErr := m.Verify(ctx, file)
				require.NoError(t, verifyErr)
				assert.True(t, intact, "installed bytes must survive the rejected update")
			}
			if scenario == configCollision {
				assert.Nil(t, m.FindInstalled(nodeartifacts.KeyFromObj(nodeartifacts.KindPlugin, candidate), artifact.MediumOCI))
				require.NoError(t, m.RemovePluginConfig(ctx, fetcher, plugin))
				_, _, err = m.StorePlugin(ctx, candidate, newContent)
				require.NoError(t, err)
				_, _, err = m.AddPluginConfig(ctx, candidate, fetcher)
				require.NoError(t, err, "an explicitly removed config name is not reserved forever")
			}
		})
	}
}

// TestManager_AddPluginConfig_DedupsFromItsOwnCacheNotTheCaller proves AddPluginConfig's dedup
// decision comes from the manager's own installed-artifact cache rather than the current the
// caller happens to pass: two calls with an identical plugin config, both passing nil, still
// dedup on the second (a caller with no tracked state of its own, e.g. right after a restart,
// gets the same correct behavior as one that tracked it).
func TestManager_AddPluginConfig_DedupsFromItsOwnCacheNotTheCaller(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}

	action1, file, err := m.AddPluginConfig(context.Background(), testPlugin("container"), fetcher)
	require.NoError(t, err)
	require.NotNil(t, file)
	assert.Equal(t, artifact.StoreActionAdded, action1)

	action2, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), fetcher)
	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUnchanged, action2)
}

func TestManager_RemovePluginConfig_AllowedWhenNothingRequiresIt(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), fetcher)
	require.NoError(t, err)

	err = m.RemovePluginConfig(context.Background(), fetcher, testPlugin("container"))
	require.NoError(t, err)
}

func TestManager_RemovePluginConfig_BlockedWhenSoleProvider(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), fetcher)
	require.NoError(t, err)

	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}
	installTestRulesfile(t, m, rfKey, []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}})

	err = m.RemovePluginConfig(context.Background(), fetcher, testPlugin("container"))

	require.Error(t, err)
	var blocked *nodeartifacts.BlockedError
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, "container", blocked.Name)
	assert.Contains(t, blocked.BlockedBy, rfKey)
}

func TestManager_RemovePluginConfig_AllowedWhenAlternativeCoversTheGroup(t *testing.T) {
	m := newTestManagerWithFetcher(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{
		"container": "1.0.0", "container-alt": "1.0.0",
	}))
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), fetcher)
	require.NoError(t, err)
	_, _, err = m.AddPluginConfig(context.Background(), testPlugin("container-alt"), fetcher)
	require.NoError(t, err)

	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}
	installTestRulesfile(t, m, rfKey, []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0", Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container-alt", Version: "1.0.0"}}}})

	err = m.RemovePluginConfig(context.Background(), fetcher, testPlugin("container"))

	require.NoError(t, err, "container-alt still satisfies the group, so removing container must be allowed")
}

func TestManager_RemovePluginConfig_ClearsProvidesOnSuccess(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), fetcher)
	require.NoError(t, err)
	require.NoError(t, m.RemovePluginConfig(context.Background(), fetcher, testPlugin("container")))

	// container must have been cleared from provides by the removal above; container-alt is now
	// the sole remaining provider, so removing it next must be blocked.
	_, _, err = m.AddPluginConfig(context.Background(), testPlugin("container-alt"), fetcher)
	require.NoError(t, err)
	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}
	installTestRulesfile(t, m, rfKey, []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0", Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container-alt", Version: "1.0.0"}}}})

	err = m.RemovePluginConfig(context.Background(), fetcher, testPlugin("container-alt"))
	require.Error(t, err, "container was already cleared from provides, so container-alt is the sole remaining provider and its removal must be blocked")
}

func TestManager_AddPluginConfig_RenameBlockedWhenOldNameStillRequired(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	pl := testPlugin("container")
	_, _, err := m.AddPluginConfig(context.Background(), pl, fetcher)
	require.NoError(t, err)

	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}
	installTestRulesfile(t, m, rfKey, []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}})

	pl.Spec.Config = &artifactv1alpha1.PluginConfig{Name: "renamed"}
	_, _, err = m.AddPluginConfig(context.Background(), pl, fetcher)

	require.Error(t, err, "the old name \"container\" is still required, so the rename must be refused")
	var blocked *nodeartifacts.BlockedError
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, "container", blocked.Name)
}

func TestManager_StoreRulesfile_ReplacesDependencies(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), fetcher)
	require.NoError(t, err)
	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}

	installTestRulesfile(t, m, rfKey, []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}})
	require.Error(t, m.RemovePluginConfig(context.Background(), fetcher, testPlugin("container")),
		"blocked while rfKey requires it")

	installTestRulesfile(t, m, rfKey, nil)
	require.NoError(t, m.RemovePluginConfig(context.Background(), fetcher, testPlugin("container")))
}

func TestManager_StoreRulesfile_PreservesOtherSourcesAndFailedWrites(t *testing.T) {
	for _, failure := range []string{writeFailure, "rename"} {
		t.Run(failure, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			m := nodeartifacts.NewManager(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
			_, _, addErr := m.AddPluginConfig(ctx, testPlugin("container"), &artifact.Fetcher{})
			require.NoError(t, addErr)
			m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
			fetcher := &artifact.Fetcher{}
			oldContent, err := fetcher.FetchInline(ctx, []byte("old rules"))
			require.NoError(t, err)
			newContent, err := fetcher.FetchInline(ctx, []byte("new rules"))
			require.NoError(t, err)
			key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "rules"}
			metadata := &commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}
			for _, medium := range []artifact.Medium{artifact.MediumOCI, artifact.MediumInline, artifact.MediumConfigMap} {
				_, _, err := m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, medium, oldContent, metadata, true)
				require.NoError(t, err)
			}
			// One source is replaced; the other two still need the old plugin.
			_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumOCI, newContent, &commonv1alpha1.ArtifactMeta{}, true)
			require.NoError(t, err)
			oldInline := m.FindInstalled(key, artifact.MediumInline)
			storeErr := errors.New("filesystem unavailable")
			if failure == writeFailure {
				fs.WriteErrFor = map[string]error{oldInline.Path + ".tmp": storeErr}
			} else {
				fs.RenameErrFor = map[string]error{oldInline.Path + ".tmp": storeErr}
			}
			_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumInline, newContent, &commonv1alpha1.ArtifactMeta{}, true)
			require.ErrorIs(t, err, storeErr)
			fs.WriteErrFor, fs.RenameErrFor = nil, nil
			assert.Equal(t, oldInline, m.FindInstalled(key, artifact.MediumInline))
			intact, err := m.Verify(ctx, oldInline)
			require.NoError(t, err)
			require.True(t, intact)
			var blocked *nodeartifacts.BlockedError
			require.ErrorAs(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container")), &blocked)
			assert.Equal(t, []nodeartifacts.Key{key}, blocked.BlockedBy, "report the CR once, even when two sources still require the plugin")

			_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumInline, newContent, &commonv1alpha1.ArtifactMeta{}, true)
			require.NoError(t, err)
			require.ErrorAs(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container")), &blocked)
			// A failed deletion must also retain the last source's protection.
			fs.RemoveErr = storeErr
			_, _, err = m.RemoveIfInstalled(ctx, key, artifact.MediumConfigMap)
			require.ErrorIs(t, err, storeErr)
			require.ErrorAs(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container")), &blocked)
			fs.RemoveErr = nil
			_, removed, err := m.RemoveIfInstalled(ctx, key, artifact.MediumConfigMap)
			require.NoError(t, err)
			require.True(t, removed)
			require.NoError(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container")))
		})
	}
}

func TestManager_StoreRulesfile_ChecksAndOwnsDependencies(t *testing.T) {
	ctx := t.Context()
	m := newTestManager()
	for _, name := range []string{"container", "container-alt"} {
		_, _, addErr := m.AddPluginConfig(ctx, testPlugin(name), &artifact.Fetcher{})
		require.NoError(t, addErr)
	}
	content, err := (&artifact.Fetcher{}).FetchInline(ctx, []byte("rules"))
	require.NoError(t, err)
	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "rules"}
	requires := []commonv1alpha1.ArtifactMetaDependency{{
		Name: "container", Version: "1.0.0",
		Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container-alt", Version: "1.0.0"}},
	}}
	metadata := &commonv1alpha1.ArtifactMeta{Dependencies: requires}
	_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumOCI, content,
		&commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{{}}}, true)
	require.Error(t, err, "an empty dependency is invalid")
	_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumOCI, content, metadata, true)
	var dependencyErr *nodeartifacts.DependencyError
	require.ErrorAs(t, err, &dependencyErr)
	assert.Nil(t, m.FindInstalled(key, artifact.MediumOCI), "failed check must not install a file")

	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
	_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumOCI, content, metadata, true)
	require.NoError(t, err)
	requires[0].Name = mutatedMetadataValue
	var blocked *nodeartifacts.BlockedError
	require.ErrorAs(t, m.RemovePluginConfig(ctx, &artifact.Fetcher{}, testPlugin("container")), &blocked,
		"mutating the caller's input must not change the installed dependencies")
	requires[0].Alternatives[0].Version = "2.0.0"
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{
		"container": "1.0.0", "container-alt": "1.0.0",
	}).Result)
	require.NoError(t, m.RemovePluginConfig(ctx, &artifact.Fetcher{}, testPlugin("container")),
		"mutating a caller-owned alternative must not replace the installed compatible alternative")
	require.ErrorAs(t, m.RemovePluginConfig(ctx, &artifact.Fetcher{}, testPlugin("container-alt")), &blocked)

	// Metadata may change without changing bytes: Unchanged still commits new dependencies.
	action, _, err := m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumOCI, content, &commonv1alpha1.ArtifactMeta{}, true)
	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUnchanged, action)
	require.NoError(t, m.RemovePluginConfig(ctx, &artifact.Fetcher{}, testPlugin("container-alt")))
}

func TestManager_StoreRulesfile_PriorityFailureKeepsInstalledState(t *testing.T) {
	const replacementFailure = "replace"
	for _, failure := range []string{writeFailure, "move", replacementFailure} {
		for _, recovery := range []string{"retry", "delete"} {
			t.Run(failure+"/"+recovery, func(t *testing.T) {
				ctx := t.Context()
				fs := fsfake.NewMockFileSystem()
				store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
				m := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))
				_, _, addErr := m.AddPluginConfig(ctx, testPlugin("container"), &artifact.Fetcher{})
				require.NoError(t, addErr)
				m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
				fetcher := &artifact.Fetcher{}
				oldContent, err := fetcher.FetchInline(ctx, []byte("old rules"))
				require.NoError(t, err)
				newContent, err := fetcher.FetchInline(ctx, []byte("new rules"))
				require.NoError(t, err)
				key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "rules"}
				_, oldFile, err := m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumOCI, oldContent,
					&commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}, true)
				require.NoError(t, err)
				newPath := artifact.ArtifactPath(store.Dirs, key.Name, 20, artifact.MediumOCI, artifact.TypeRulesfile)
				storeErr := errors.New("filesystem unavailable")
				switch failure {
				case writeFailure:
					fs.WriteErrFor = map[string]error{newPath + ".tmp": storeErr}
				case "move":
					fs.RenameErrFor = map[string]error{oldFile.Path: storeErr}
				case replacementFailure:
					fs.RenameErrFor = map[string]error{newPath + ".tmp": storeErr}
				}

				_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 20, artifact.MediumOCI, newContent, &commonv1alpha1.ArtifactMeta{}, true)

				require.ErrorIs(t, err, storeErr)
				fs.WriteErrFor, fs.RenameErrFor = nil, nil
				installed := m.FindInstalled(key, artifact.MediumOCI)
				require.NotNil(t, installed)
				assert.Equal(t, oldContent.ContentHash, installed.ContentHash)
				if failure == replacementFailure {
					assert.Equal(t, newPath, installed.Path, "the old content moved before replacement failed")
					assert.EqualValues(t, 20, installed.Priority)
				} else {
					assert.Equal(t, oldFile.Path, installed.Path)
				}
				intact, err := m.Verify(ctx, installed)
				require.NoError(t, err)
				require.True(t, intact)
				disk, err := m.ScanAll(ctx, artifact.TypeRulesfile)
				require.NoError(t, err)
				require.Len(t, disk[key.Name], 1, "there must never be two active revisions of one source")
				var blocked *nodeartifacts.BlockedError
				require.ErrorAs(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container")), &blocked)

				if recovery == "retry" {
					_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 20, artifact.MediumOCI, newContent, &commonv1alpha1.ArtifactMeta{}, true)
					require.NoError(t, err)
					assert.Equal(t, newContent.Content, fs.Files[newPath])
				} else {
					_, removed, removeErr := m.RemoveIfInstalled(ctx, key, artifact.MediumOCI)
					require.NoError(t, removeErr)
					require.True(t, removed)
					assert.NotContains(t, fs.Files, installed.Path)
				}
				require.NoError(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container")))
			})
		}
	}
}

func TestManager_SyncRulesfileDependencies_PreservesOtherSources(t *testing.T) {
	ctx := t.Context()
	m := newTestManager()
	_, _, addErr := m.AddPluginConfig(ctx, testPlugin("container"), &artifact.Fetcher{})
	require.NoError(t, addErr)
	content, err := (&artifact.Fetcher{}).FetchInline(ctx, []byte("rules"))
	require.NoError(t, err)
	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "rules"}
	metadata := &commonv1alpha1.ArtifactMeta{Digest: digest.FromString("installed").String(), Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
	for _, medium := range []artifact.Medium{artifact.MediumOCI, artifact.MediumInline} {
		_, _, err := m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, medium, content, metadata, true)
		require.NoError(t, err)
	}
	missing := &commonv1alpha1.ArtifactMeta{Digest: metadata.Digest, Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "missing", Version: "1.0.0"}}}
	var dependencyErr *nodeartifacts.DependencyError
	synced, err := m.SyncRulesfileDependencies(ctx, key, artifact.MediumOCI, missing, true)
	require.ErrorAs(t, err, &dependencyErr)
	assert.False(t, synced)
	var blocked *nodeartifacts.BlockedError
	require.ErrorAs(t, m.RemovePluginConfig(ctx, &artifact.Fetcher{}, testPlugin("container")), &blocked)
	synced, err = m.SyncRulesfileDependencies(ctx, key, artifact.MediumOCI, &commonv1alpha1.ArtifactMeta{Digest: metadata.Digest}, true)
	require.NoError(t, err)
	require.True(t, synced)
	require.ErrorAs(t, m.RemovePluginConfig(ctx, &artifact.Fetcher{}, testPlugin("container")), &blocked,
		"clearing OCI dependencies must preserve the installed inline source's dependencies")
	_, _, err = m.RemoveIfInstalled(ctx, key, artifact.MediumInline)
	require.NoError(t, err)
	require.NoError(t, m.RemovePluginConfig(ctx, &artifact.Fetcher{}, testPlugin("container")))
}

func TestManager_StoreRulesfile_MissingMetadata(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, enforce := range []bool{false, true} {
			t.Run(fmt.Sprintf("existing=%t/enforce=%t", existing, enforce), func(t *testing.T) {
				ctx := t.Context()
				fs := fsfake.NewMockFileSystem()
				store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
				m := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))
				_, _, addErr := m.AddPluginConfig(ctx, testPlugin("unrelated"), &artifact.Fetcher{})
				require.NoError(t, addErr)
				key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "rules"}
				content, err := (&artifact.Fetcher{}).FetchInline(ctx, []byte("rules"))
				require.NoError(t, err)
				if existing {
					_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumOCI, content, &commonv1alpha1.ArtifactMeta{}, true)
					require.NoError(t, err)
				}
				before := m.GetInstalled(key)
				writes := len(fs.WriteCalls)

				action, installed, err := m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumOCI, content, nil, enforce)

				if enforce {
					require.Error(t, err)
					assert.Nil(t, installed)
					assert.Equal(t, artifact.StoreActionNone, action)
					assert.Len(t, fs.WriteCalls, writes)
					assert.Equal(t, before, m.GetInstalled(key))
					return
				}
				require.NoError(t, err)
				require.NotNil(t, m.FindInstalled(key, artifact.MediumOCI))
				if existing {
					assert.Equal(t, artifact.StoreActionUnchanged, action)
				}
				require.NoError(t, m.RemovePluginConfig(ctx, &artifact.Fetcher{}, testPlugin("unrelated")),
					"unknown metadata cannot prove a dependency on an unrelated plugin")
			})
		}
	}
}

func TestManager_SyncRulesfileDependencies_RequiresVerifiedIdentity(t *testing.T) {
	const (
		nilPreservesUnknown = "nil metadata preserves unknown"
		inlineWithoutDigest = "inline without digest"
		readFailure         = "read failure"
	)
	for _, scenario := range []string{"nil metadata", nilPreservesUnknown, "unknown installed metadata", "empty digest", "different digest",
		"no installed file", "missing file", "corrupt file", readFailure, "same digest", inlineWithoutDigest} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			m := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))
			_, _, addErr := m.AddPluginConfig(ctx, testPlugin("container"), &artifact.Fetcher{})
			require.NoError(t, addErr)
			key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "rules"}
			content, err := (&artifact.Fetcher{}).FetchInline(ctx, []byte("rules"))
			require.NoError(t, err)
			medium := artifact.MediumOCI
			metadata := &commonv1alpha1.ArtifactMeta{Digest: digest.FromString("installed").String(), Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}
			candidate := &commonv1alpha1.ArtifactMeta{Digest: metadata.Digest}
			if scenario == inlineWithoutDigest {
				medium, metadata.Digest, candidate.Digest = artifact.MediumInline, "", ""
			}
			if scenario == "unknown installed metadata" || scenario == nilPreservesUnknown {
				metadata = nil
			}
			var installed *artifact.File
			if scenario != "no installed file" {
				_, installed, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, medium, content, metadata, false)
				require.NoError(t, err)
			}
			ioErr := errors.New("filesystem unavailable")
			switch scenario {
			case "nil metadata", nilPreservesUnknown:
				candidate = nil
			case "empty digest":
				candidate.Digest = ""
			case "different digest":
				candidate.Digest = digest.FromString("other").String()
			case "missing file":
				require.NoError(t, fs.Remove(installed.Path))
			case "corrupt file":
				require.NoError(t, fs.WriteFile(installed.Path, []byte("corrupt"), 0o644))
			case readFailure:
				fs.ReadErrFor = map[string]error{installed.Path: ioErr}
			}
			before := m.GetInstalled(key)
			writes := len(fs.WriteCalls)

			synced, err := m.SyncRulesfileDependencies(ctx, key, medium, candidate, true)

			if scenario == readFailure {
				require.ErrorIs(t, err, ioErr, "I/O failures must not be reported as a fetch fallback")
			} else {
				require.NoError(t, err)
			}
			if scenario == "same digest" || scenario == inlineWithoutDigest {
				require.True(t, synced)
				require.NoError(t, m.RemovePluginConfig(ctx, &artifact.Fetcher{}, testPlugin("container")))
				return
			}
			assert.False(t, synced)
			assert.Equal(t, before, m.GetInstalled(key), "fallback must not replace installed files")
			assert.Len(t, fs.WriteCalls, writes)
			if installed != nil && metadata != nil {
				var blocked *nodeartifacts.BlockedError
				require.ErrorAs(t, m.RemovePluginConfig(ctx, &artifact.Fetcher{}, testPlugin("container")), &blocked,
					"fallback must preserve the known installed dependency")
			} else {
				require.NoError(t, m.RemovePluginConfig(ctx, &artifact.Fetcher{}, testPlugin("container")),
					"missing metadata must not invent a dependency")
			}
		})
	}
}

func TestManager_RulesfileMetadata_IsOwned(t *testing.T) {
	const mutatedVersion = "99.0.0"
	for _, operation := range []string{"store", "sync"} {
		t.Run(operation, func(t *testing.T) {
			ctx := t.Context()
			store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
			m := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))
			fetcher := &artifact.Fetcher{}
			for _, name := range []string{"container", "container-alt"} {
				_, _, err := m.AddPluginConfig(ctx, testPlugin(name), fetcher)
				require.NoError(t, err)
			}
			metadata := &commonv1alpha1.ArtifactMeta{
				Digest: digest.FromString("installed").String(), SpecHash: "original-spec",
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{{Name: "engine_version_semver", Version: "0.42.0"}},
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0",
					Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container-alt", Version: "1.0.0"}}}},
			}
			content, err := (&artifact.Fetcher{}).FetchInline(ctx, []byte("rules"))
			require.NoError(t, err)
			key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "rules"}
			_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumOCI, content, metadata, false)
			require.NoError(t, err)
			if operation == "sync" {
				metadata.SpecHash = "updated-spec"
				synced, syncErr := m.SyncRulesfileDependencies(ctx, key, artifact.MediumOCI, metadata, false)
				require.NoError(t, syncErr)
				require.True(t, synced)
			}
			expected := metadata.DeepCopy()
			metadata.Digest, metadata.SpecHash = mutatedMetadataValue, mutatedMetadataValue
			metadata.Requirements[0].Version = mutatedVersion
			metadata.Dependencies[0].Name = mutatedMetadataValue
			metadata.Dependencies[0].Version = mutatedVersion
			metadata.Dependencies[0].Alternatives[0].Version = mutatedVersion
			versions := compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0", "container-alt": "1.0.0"}).Result
			m.OnFalcoVersionsObserved(versions)
			require.NoError(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container-alt")),
				"the copied primary name and version must still satisfy the dependency")
			_, _, err = m.AddPluginConfig(ctx, testPlugin("container-alt"), fetcher)
			require.NoError(t, err)
			m.OnFalcoVersionsObserved(versions)
			require.NoError(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container")),
				"the copied alternative must remain compatible")
			var blocked *nodeartifacts.BlockedError
			require.ErrorAs(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container-alt")), &blocked)
			expected.Dependencies = nil
			synced, err := m.SyncRulesfileDependencies(ctx, key, artifact.MediumOCI, expected, true)
			require.NoError(t, err)
			require.True(t, synced, "the copied digest must still identify the installed source")
			require.NoError(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container-alt")))
		})
	}
}

func TestManager_RemoveIfInstalled_ClearsDependenciesWhenFileIsMissing(t *testing.T) {
	ctx := t.Context()
	fs := fsfake.NewMockFileSystem()
	m := nodeartifacts.NewManager(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
	_, _, addErr := m.AddPluginConfig(ctx, testPlugin("container"), &artifact.Fetcher{})
	require.NoError(t, addErr)
	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "rules"}
	installTestRulesfile(t, m, key, []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}})
	installed := m.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, installed)
	require.NoError(t, fs.Remove(installed.Path))
	var blocked *nodeartifacts.BlockedError
	require.ErrorAs(t, m.RemovePluginConfig(ctx, &artifact.Fetcher{}, testPlugin("container")), &blocked)
	_, removed, err := m.RemoveIfInstalled(ctx, key, artifact.MediumOCI)
	require.NoError(t, err)
	assert.True(t, removed, "cleanup must remove the cache entry even if the file is already absent")
	_, removed, err = m.RemoveIfInstalled(ctx, key, artifact.MediumOCI)
	require.NoError(t, err)
	assert.False(t, removed, "repeated cleanup is a no-op")
	require.NoError(t, m.RemovePluginConfig(ctx, &artifact.Fetcher{}, testPlugin("container")))
}

func TestManager_StoreRulesfile_ConcurrentPluginRemoval(t *testing.T) {
	ctx := t.Context()
	fetcher := &artifact.Fetcher{}
	content, err := fetcher.FetchInline(ctx, []byte("rules"))
	require.NoError(t, err)
	for range 20 {
		m := newTestManagerWithFetcher(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}))
		_, _, err := m.AddPluginConfig(ctx, testPlugin("container"), fetcher)
		require.NoError(t, err)
		start := make(chan struct{})
		stored := make(chan error, 1)
		removed := make(chan error, 1)
		go func() {
			<-start
			_, _, err := m.StoreRulesfile(ctx, "ns", "rules", 50, artifact.MediumOCI, content,
				&commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}, true)
			stored <- err
		}()
		go func() {
			<-start
			removed <- m.RemovePluginConfig(ctx, fetcher, testPlugin("container"))
		}()
		close(start)
		storeErr, removeErr := <-stored, <-removed
		if storeErr == nil {
			var blocked *nodeartifacts.BlockedError
			require.ErrorAs(t, removeErr, &blocked, "installed rules must protect their provider")
		} else {
			var dependencyErr *nodeartifacts.DependencyError
			require.ErrorAs(t, storeErr, &dependencyErr)
			require.NoError(t, removeErr, "removal won: installation must be rejected")
			assert.Nil(t, m.FindInstalled(nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "rules"}, artifact.MediumOCI))
		}
	}
}

func TestManager_CheckRequirement_NotFoundBeforeAnyObservation(t *testing.T) {
	m := newTestManager()

	provided, found, satisfied, err := m.CheckRequirement("engine_version_semver", "0.57.0")

	require.NoError(t, err)
	assert.False(t, found)
	assert.False(t, satisfied)
	assert.Empty(t, provided)
}

func TestManager_CheckRequirement_SatisfiedAfterObservation(t *testing.T) {
	m := newTestManager()
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
		"engine_version_semver": "0.62.0",
	}).Result)

	provided, found, satisfied, err := m.CheckRequirement("engine_version_semver", "0.57.0")

	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, satisfied)
	assert.Equal(t, "0.62.0", provided)
}

func TestManager_CheckRequirement_NotSatisfiedWhenTooOld(t *testing.T) {
	m := newTestManager()
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
		"container": "0.3.0",
	}).Result)

	provided, found, satisfied, err := m.CheckRequirement("container", "0.4.0")

	require.NoError(t, err)
	assert.True(t, found)
	assert.False(t, satisfied)
	assert.Equal(t, "0.3.0", provided)
}

func TestManager_CheckRequirement_PluginAPIVersionUsesMajorCompatibility(t *testing.T) {
	m := newTestManager()
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
		"plugin_api_version": "3.12.0",
	}).Result)

	_, found, satisfied, err := m.CheckRequirement("plugin_api_version", "3.0.0")
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, satisfied, "3.12.0 is major-compatible with a 3.0.0 requirement")

	_, found, satisfied, err = m.CheckRequirement("plugin_api_version", "4.0.0")
	require.NoError(t, err)
	assert.True(t, found)
	assert.False(t, satisfied, "major version 3 cannot satisfy a major version 4 requirement")
}

func TestManager_CheckDependency_PrimarySatisfied(t *testing.T) {
	m := newTestManager()
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
		"container": "0.7.1",
	}).Result)

	matched, provided, satisfied, err := m.CheckDependency(
		commonv1alpha1.ArtifactMetaDependency{Name: "container", Version: "0.4.0"},
	)

	require.NoError(t, err)
	assert.True(t, satisfied)
	assert.Equal(t, "container", matched)
	assert.Equal(t, "0.7.1", provided)
}

func TestManager_CheckDependency_AlternativeSatisfied(t *testing.T) {
	m := newTestManager()
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
		"container-alt": "0.2.0",
	}).Result)

	matched, provided, satisfied, err := m.CheckDependency(
		commonv1alpha1.ArtifactMetaDependency{Name: "container", Version: "0.4.0",
			Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container-alt", Version: "0.1.0"}}},
	)

	require.NoError(t, err)
	assert.True(t, satisfied)
	assert.Equal(t, "container-alt", matched)
	assert.Equal(t, "0.2.0", provided)
}

func TestManager_CheckDependency_NoneSatisfied(t *testing.T) {
	m := newTestManager()

	matched, provided, satisfied, err := m.CheckDependency(
		commonv1alpha1.ArtifactMetaDependency{Name: "container", Version: "0.4.0",
			Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container-alt", Version: "0.1.0"}}},
	)

	require.NoError(t, err)
	assert.False(t, satisfied)
	assert.Empty(t, matched)
	assert.Empty(t, provided)
}

func TestManager_CheckDependency_WaitsForConfiguredCandidate(t *testing.T) {
	ctx := t.Context()
	versions := compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"})
	m := newTestManagerWithFetcher(versions)
	fetcher := &artifact.Fetcher{}
	dependency := commonv1alpha1.ArtifactMetaDependency{Name: "json", Version: "0.7.0",
		Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container", Version: "0.7.0"}}}
	check := func(wantMatch string, wantSatisfied bool) {
		t.Helper()
		matched, _, satisfied, err := m.CheckDependency(dependency)
		require.NoError(t, err)
		assert.Equal(t, wantMatch, matched)
		assert.Equal(t, wantSatisfied, satisfied)
	}

	// A genuinely absent primary allows fallback. A configured primary may already
	// have loaded since the last poll, so its unknown version must not allow fallback.
	m.OnFalcoVersionsObserved(versions.Result)
	check("container", true)
	_, _, err := m.AddPluginConfig(ctx, testPlugin("json"), fetcher)
	require.NoError(t, err)
	check("json", false)
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{
		"json": "0.7.4", "container": "0.7.1",
	}).Result)
	check("json", true)
	dependency.Version = "0.99.0"
	check("json", false)

	// A successful snapshot during reload can omit a still-configured primary.
	// It does not make the alternative safe for rules that the primary will reject.
	m.OnFalcoVersionsObserved(versions.Result)
	check("json", false)
	require.NoError(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("json")))
	check("container", true)
	_, _, err = m.AddPluginConfig(ctx, testPlugin("json"), fetcher)
	require.NoError(t, err)
	check("json", false)

	// The same rule applies to an earlier alternative awaiting observation.
	_, _, satisfied, err := m.CheckDependency(commonv1alpha1.ArtifactMetaDependency{
		Name: "absent", Version: "1.0.0",
		Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{
			{Name: dependency.Name, Version: dependency.Version}, dependency.Alternatives[0],
		},
	})
	require.NoError(t, err)
	assert.False(t, satisfied)
}

func TestManager_CheckDependency_FalcoCompatibility(t *testing.T) {
	dependency := commonv1alpha1.ArtifactMetaDependency{
		Name: "primary", Version: "1.2.0",
		Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{
			{Name: "z-first", Version: "1.0.0"},
			{Name: "a-second", Version: "2.0.0"},
		},
	}
	tests := []struct {
		name      string
		versions  map[string]string
		wantMatch string
		wantOK    bool
		wantErr   bool
	}{
		{name: "no observed candidate"},
		{name: "equal version", versions: map[string]string{"primary": "1.2.0"}, wantMatch: "primary", wantOK: true},
		{name: "higher minor", versions: map[string]string{"primary": "1.3.0"}, wantMatch: "primary", wantOK: true},
		{name: "higher major is incompatible", versions: map[string]string{"primary": "2.0.0"}},
		{name: "older primary cannot be bypassed", versions: map[string]string{"primary": "1.1.0", "z-first": "1.0.0"}},
		{name: "absent primary permits alternative", versions: map[string]string{"z-first": "1.1.0"}, wantMatch: "z-first", wantOK: true},
		{name: "first loaded alternative wins", versions: map[string]string{"z-first": "1.0.0", "a-second": "1.0.0"}, wantMatch: "z-first", wantOK: true},
		{name: "incompatible first alternative stops search", versions: map[string]string{"z-first": "2.0.0", "a-second": "2.0.0"}},
		{name: "absent first alternative permits second", versions: map[string]string{"a-second": "2.1.0"}, wantMatch: "a-second", wantOK: true},
		{name: "invalid primary cannot be bypassed", versions: map[string]string{"primary": "invalid", "z-first": "1.0.0"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestManager()
			m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(tt.versions).Result)
			matched, _, satisfied, err := m.CheckDependency(dependency)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantOK, satisfied)
			if tt.wantOK {
				assert.Equal(t, tt.wantMatch, matched)
			}
		})
	}
}

func TestManager_RemovePluginConfig_ChecksRemainingVersions(t *testing.T) {
	dep := commonv1alpha1.ArtifactMetaDependency{
		Name: "primary", Version: "1.0.0",
		Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{
			{Name: "z-first", Version: "1.2.0"},
			{Name: "a-second", Version: "2.0.0"},
		},
	}
	tests := []struct {
		name        string
		versions    map[string]string
		remove      string
		wantBlocked bool
	}{
		{name: "unconfirmed alternatives", wantBlocked: true},
		{name: "alternative too old", versions: map[string]string{"z-first": "1.1.0"}, wantBlocked: true},
		{name: "alternative different major", versions: map[string]string{"z-first": "2.0.0"}, wantBlocked: true},
		{name: "alternative invalid version", versions: map[string]string{"z-first": "invalid"}, wantBlocked: true},
		{name: "compatible alternative", versions: map[string]string{"z-first": "1.3.0"}},
		{name: "first alternative is decisive", versions: map[string]string{"z-first": "1.1.0", "a-second": "2.0.0"}, wantBlocked: true},
		{name: "configured earlier alternative awaiting observation", versions: map[string]string{"a-second": "2.0.0"}, wantBlocked: true},
		{name: "remove unused alternative", remove: "z-first"},
		{name: "remove unrelated plugin", remove: "unrelated"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := fsfake.NewMockFileSystem()
			m := nodeartifacts.NewManager(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
			fetcher := &artifact.Fetcher{}
			var configFile *artifact.File
			for _, name := range []string{"primary", "z-first", "a-second", "unrelated"} {
				_, file, err := m.AddPluginConfig(t.Context(), testPlugin(name), fetcher)
				require.NoError(t, err)
				configFile = file
			}
			versions := map[string]string{"primary": "1.0.0"}
			maps.Copy(versions, tt.versions)
			m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(versions).Result)
			key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "rules"}
			installTestRulesfile(t, m, key, []commonv1alpha1.ArtifactMetaDependency{dep})
			remove := tt.remove
			if remove == "" {
				remove = "primary"
			}
			before, err := fs.ReadFile(configFile.Path)
			require.NoError(t, err)
			err = m.RemovePluginConfig(t.Context(), fetcher, testPlugin(remove))
			if tt.wantBlocked {
				var blocked *nodeartifacts.BlockedError
				require.ErrorAs(t, err, &blocked)
				assert.Equal(t, []nodeartifacts.Key{key}, blocked.BlockedBy)
				after, readErr := fs.ReadFile(configFile.Path)
				require.NoError(t, readErr)
				assert.Equal(t, before, after, "blocked removal must leave the shared config untouched")
				return
			}
			require.NoError(t, err)
			_, found, _, err := m.CheckRequirement(remove, "1.0.0")
			require.NoError(t, err)
			assert.False(t, found)
		})
	}
}

func TestManager_CheckDependency_PreservesMetadataOrder(t *testing.T) {
	meta := &commonv1alpha1.ArtifactMeta{
		Dependencies: []commonv1alpha1.ArtifactMetaDependency{{
			Name: "absent", Version: "1.0.0",
			Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{
				{Name: "z-first", Version: "1.0.0"},
				{Name: "a-second", Version: "2.0.0"},
			},
		}},
	}
	artifact.DeduplicateArtifactMeta(meta)
	m := newTestManager()
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
		"z-first": "1.0.0", "a-second": "1.0.0",
	}).Result)
	d := meta.Dependencies[0]
	assert.Equal(t, "z-first", d.Alternatives[0].Name)
	matched, _, satisfied, err := m.CheckDependency(d)
	require.NoError(t, err)
	assert.True(t, satisfied)
	assert.Equal(t, "z-first", matched)
}

func TestManager_CheckDependency_ValidatesAllCandidates(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dependency commonv1alpha1.ArtifactMetaDependency
		wantErr    bool
	}{
		{name: "unused malformed alternative", dependency: commonv1alpha1.ArtifactMetaDependency{Name: "container", Version: "0.7.0",
			Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "unused", Version: "garbage"}}}, wantErr: true},
		{name: "duplicate name", dependency: commonv1alpha1.ArtifactMetaDependency{Name: "container", Version: "0.7.0",
			Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container", Version: "0.6.0"}}}, wantErr: true},
		{name: "short version", dependency: commonv1alpha1.ArtifactMetaDependency{Name: "container", Version: "0.7"}, wantErr: true},
		{name: "prefixed version", dependency: commonv1alpha1.ArtifactMetaDependency{Name: "container", Version: "v0.7.0"}, wantErr: true},
		{name: "numeric prefix matches Falco", dependency: commonv1alpha1.ArtifactMetaDependency{Name: "container", Version: "0.7.0junk"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager()
			m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"}).Result)
			_, _, satisfied, err := m.CheckDependency(tc.dependency)
			if tc.wantErr {
				require.Error(t, err)
				assert.False(t, satisfied)
			} else {
				require.NoError(t, err)
				assert.True(t, satisfied)
			}
		})
	}
}

func TestManager_RemovePluginConfig_StaleObservationCannotRestoreRemovedProvider(t *testing.T) {
	ctx := t.Context()
	falco := compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"json": "0.7.4", "container": "0.7.1"})
	m := newTestManagerWithFetcher(falco)
	fetcher := &artifact.Fetcher{}
	for _, name := range []string{"json", "container"} {
		_, _, err := m.AddPluginConfig(ctx, testPlugin(name), fetcher)
		require.NoError(t, err)
	}
	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "rules"}
	installTestRulesfile(t, m, key, []commonv1alpha1.ArtifactMetaDependency{{Name: "json", Version: "0.7.0", Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container", Version: "0.7.0"}}}})
	require.NoError(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("json")))
	// Falco has not reloaded yet, so the next successful poll still reports both plugins.
	m.OnFalcoVersionsObserved(falco.Result)
	_, found, _, err := m.CheckRequirement("json", "0.7.0")
	require.NoError(t, err)
	assert.False(t, found, "an observation must not undo our removal")
	var blocked *nodeartifacts.BlockedError
	require.ErrorAs(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container")), &blocked)
	assert.Equal(t, []nodeartifacts.Key{key}, blocked.BlockedBy)
	// Even a delayed old response after an observed unload cannot restore the name.
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"}).Result)
	m.OnFalcoVersionsObserved(falco.Result)
	require.ErrorAs(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container")), &blocked)
	// An explicit re-add, unlike a poll, makes json eligible again once observed.
	_, _, err = m.AddPluginConfig(ctx, testPlugin("json"), fetcher)
	require.NoError(t, err)
	require.NoError(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container")))
}

func TestManager_RemovePluginConfig_ObservedExternalAlternativeStillWorks(t *testing.T) {
	m := newTestManagerWithFetcher(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{
		"json": "0.7.4", "container": "0.7.1",
	}))
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(t.Context(), testPlugin("json"), fetcher)
	require.NoError(t, err)
	installTestRulesfile(t, m, nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "rules"},
		[]commonv1alpha1.ArtifactMetaDependency{{Name: "json", Version: "0.7.0", Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container", Version: "0.7.0"}}}})
	// container was loaded outside our shared config; it has not been explicitly removed.
	require.NoError(t, m.RemovePluginConfig(t.Context(), fetcher, testPlugin("json")))
}

func TestManager_RemovePluginConfig_RetryAfterConfigRemoval(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(t.Context(), testPlugin("json"), fetcher)
	require.NoError(t, err)
	require.NoError(t, m.RemovePluginConfig(t.Context(), fetcher, testPlugin("json")))
	// A newly registered dependency cannot block retrying the remaining binary/finalizer
	// cleanup: this config was already removed successfully in an earlier reconcile.
	installTestRulesfile(t, m, nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "new-rules"},
		[]commonv1alpha1.ArtifactMetaDependency{{Name: "json", Version: "0.7.0"}})
	require.NoError(t, m.RemovePluginConfig(t.Context(), fetcher, testPlugin("json")))
	_, _, err = m.AddPluginConfig(t.Context(), testPlugin("json"), fetcher)
	require.NoError(t, err)
	var blocked *nodeartifacts.BlockedError
	require.ErrorAs(t, m.RemovePluginConfig(t.Context(), fetcher, testPlugin("json")), &blocked,
		"an explicit re-add must restore normal deletion checks")
}

func TestManager_OnFalcoVersionsObserved_PreservesExistingKeyUpdatesVersion(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), fetcher)
	require.NoError(t, err)

	// AddPluginConfig already triggered an opportunistic refresh via the mock fetcher, which
	// reports nothing for "container". Observing a real version now must land without disturbing
	// the removal-blocking entry.
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"container": "0.7.1"}).Result)

	provided, found, _, err := m.CheckRequirement("container", "0.4.0")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "0.7.1", provided)

	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}
	installTestRulesfile(t, m, rfKey, []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "0.4.0"}})
	err = m.RemovePluginConfig(context.Background(), fetcher, testPlugin("container"))
	require.Error(t, err, "the PluginConfigKey-registered entry must still be tracked for removal-blocking after a version observation merged into it")
}

func TestManager_OnFalcoVersionsObserved_CreatesFalcoOwnedEntryForUnknownName(t *testing.T) {
	m := newTestManager()

	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
		"engine_version_semver": "0.62.0",
	}).Result)

	_, found, _, err := m.CheckRequirement("engine_version_semver", "0.57.0")
	require.NoError(t, err)
	assert.True(t, found, "a capability never explicitly registered via AddPluginConfig/SyncProvides must still be tracked once Falco reports it")
}

func TestManager_OnFalcoVersionsObserved_NotifiesOnNewCapability(t *testing.T) {
	m := newTestManager()
	ch := m.Events()

	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.62.0"}).Result)

	select {
	case <-ch:
	default:
		t.Fatal("expected an event when a previously-unknown capability is observed")
	}
}

func TestManager_OnFalcoVersionsObserved_NotifiesWhenConfigEntryVersionIsFirstConfirmed(t *testing.T) {
	// An empty-to-confirmed version transition on an existing provides entry counts as a change.
	m := newTestManager()
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), &artifact.Fetcher{})
	require.NoError(t, err)
	ch := m.Events()

	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"container": "0.7.1"}).Result)

	select {
	case <-ch:
	default:
		t.Fatal("expected an event when an already-tracked name's version is confirmed for the first time")
	}
}

func TestManager_OnFalcoVersionsObserved_NoNotifyWhenUnchanged(t *testing.T) {
	m := newTestManager()
	ch := m.Events()

	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.62.0"}).Result)
	select {
	case <-ch:
	default:
		t.Fatal("expected an event on the first observation")
	}

	// Observing the same value again must not fire an event, even though the Manager's own
	// bookkeeping went through an unrelated remove/re-add cycle for a different name in between.
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.62.0"}).Result)
	select {
	case <-ch:
		t.Fatal("unexpected event: capability value did not change")
	default:
	}
}

func TestManager_OnFalcoVersionsObserved_NotifiesOnVersionBump(t *testing.T) {
	m := newTestManager()
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"container": "0.7.1"}).Result)
	ch := m.Events()

	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"container": "0.7.2"}).Result)

	select {
	case <-ch:
	default:
		t.Fatal("expected an event when an existing capability's version changes")
	}
}

func TestManager_OnFalcoVersionsObserved_InvalidatesMissingVersions(t *testing.T) {
	for _, tc := range []struct {
		name, capability string
		configured       bool
	}{
		{"configured plugin", "container", true},
		{"observed-only plugin", "container", false},
		{"Falco capability", "engine_version_semver", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager()
			if tc.configured {
				_, _, err := m.AddPluginConfig(t.Context(), testPlugin(tc.capability), &artifact.Fetcher{})
				require.NoError(t, err)
			}
			loaded := compatfake.NewMockVersionsFetcher(map[string]string{tc.capability: "1.0.0", "other": "1.0.0"}).Result
			missing := compatfake.NewMockVersionsFetcher(map[string]string{"other": "1.0.0"}).Result
			m.OnFalcoVersionsObserved(loaded)
			chA, chB := m.Events(), m.Events()
			_, found, satisfied, err := m.CheckRequirement(tc.capability, "1.0.0")
			require.NoError(t, err)
			require.True(t, found && satisfied)

			m.OnFalcoVersionsObserved(missing)
			version, found, satisfied, err := m.CheckRequirement(tc.capability, "1.0.0")
			require.NoError(t, err)
			assert.Empty(t, version)
			assert.False(t, found, "a version absent from the latest successful observation is no longer confirmed")
			assert.False(t, satisfied)
			_, found, satisfied, err = m.CheckRequirement("other", "1.0.0")
			require.NoError(t, err)
			assert.True(t, found && satisfied, "unchanged capabilities must remain available")
			require.Len(t, chA, 1, "disappearance must notify every subscriber")
			require.Len(t, chB, 1)
			<-chA
			<-chB

			m.OnFalcoVersionsObserved(missing)
			assert.Empty(t, chA, "a repeated missing observation must not cause a reconcile loop")
			assert.Empty(t, chB)
			m.OnFalcoVersionsObserved(loaded)
			_, found, satisfied, err = m.CheckRequirement(tc.capability, "1.0.0")
			require.NoError(t, err)
			assert.True(t, found && satisfied)
			require.Len(t, chA, 1, "reappearance at the same version must notify subscribers")
			require.Len(t, chB, 1)
			<-chA
			<-chB

			m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(nil).Result)
			for _, name := range []string{tc.capability, "other"} {
				_, found, satisfied, err = m.CheckRequirement(name, "1.0.0")
				require.NoError(t, err)
				assert.False(t, found || satisfied, "a successful empty snapshot must invalidate every confirmed version")
			}
			assert.Len(t, chA, 1, "one snapshot emits one notification, even when multiple versions disappear")
			assert.Len(t, chB, 1)
		})
	}
}

func TestManager_Events_MultipleSubscribersEachReceiveEveryEvent(t *testing.T) {
	m := newTestManager()
	chA := m.Events()
	chB := m.Events()

	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.62.0"}).Result)

	select {
	case <-chA:
	default:
		t.Fatal("subscriber A did not receive the event")
	}
	select {
	case <-chB:
	default:
		t.Fatal("subscriber B did not receive the event")
	}
}

func TestManager_RefreshFalcoVersions_MergesFetchedSnapshot(t *testing.T) {
	m := newTestManagerWithFetcher(compatfake.NewMockVersionsFetcher(map[string]string{
		"engine_version_semver": "0.62.0",
	}))

	versions, err := m.RefreshFalcoVersions(context.Background())
	require.NoError(t, err)
	require.NotNil(t, versions)

	_, found, satisfied, err := m.CheckRequirement("engine_version_semver", "0.57.0")
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, satisfied)
}

func TestManager_RefreshFalcoVersions_PropagatesFetchError(t *testing.T) {
	fetcher := compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"})
	m := newTestManagerWithFetcher(fetcher)
	_, err := m.RefreshFalcoVersions(context.Background())
	require.NoError(t, err)
	ch := m.Events()
	fetcher.FetchErr = assert.AnError

	_, err = m.RefreshFalcoVersions(context.Background())

	require.Error(t, err)
	version, found, satisfied, err := m.CheckRequirement("container", "0.7.1")
	require.NoError(t, err)
	assert.Equal(t, "0.7.1", version)
	assert.True(t, found && satisfied, "a failed fetch must preserve the last successful observation")
	assert.Empty(t, ch)

	fetcher.FetchErr = nil
	fetcher.Result = compatfake.NewMockVersionsFetcherWithPlugins(nil).Result
	_, err = m.RefreshFalcoVersions(context.Background())
	require.NoError(t, err)
	_, found, satisfied, err = m.CheckRequirement("container", "0.7.1")
	require.NoError(t, err)
	assert.False(t, found || satisfied, "a subsequent successful empty response must invalidate the old version")
	assert.Len(t, ch, 1)
}

// TestManager_AddPluginConfig_ConcurrentWithCheckRequirement runs AddPluginConfig and
// CheckRequirement concurrently to detect deadlocks or data races; run with -race.
func TestManager_AddPluginConfig_ConcurrentWithCheckRequirement(t *testing.T) {
	m := newTestManagerWithFetcher(compatfake.NewMockVersionsFetcher(map[string]string{"container": "0.7.1"}))
	fetcher := &artifact.Fetcher{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 50 {
			_, _, _, _ = m.CheckRequirement("container", "0.4.0")
		}
	}()

	for range 20 {
		_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), fetcher)
		require.NoError(t, err)
	}
	<-done
}

func TestManager_StoreRepairsCorruptionWithoutChangingInstalledIdentity(t *testing.T) {
	fs := fsfake.NewMockFileSystem()
	manager := nodeartifacts.NewManager(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
	fetcher := &artifact.Fetcher{}
	result, err := fetcher.FetchInline(t.Context(), []byte("expected rules"))
	require.NoError(t, err)
	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "test", Name: "rules"}
	_, file, err := manager.StoreRulesfile(t.Context(), key.Namespace, key.Name, 10, artifact.MediumOCI, result, &commonv1alpha1.ArtifactMeta{}, true)
	require.NoError(t, err)
	manager.UpdateInstalledSpecHash(key, artifact.MediumOCI, "pinned-revision")
	fs.Files[file.Path] = []byte("corrupt")
	verified, err := manager.Verify(t.Context(), file)
	require.NoError(t, err)
	require.False(t, verified)

	action, repaired, err := manager.StoreRulesfile(t.Context(), key.Namespace, key.Name, 10, artifact.MediumOCI, result, &commonv1alpha1.ArtifactMeta{}, true)
	require.NoError(t, err)
	require.Equal(t, artifact.StoreActionUpdated, action)
	require.Equal(t, file.Path, repaired.Path)
	require.Equal(t, result.Content, fs.Files[repaired.Path])
	manager.UpdateInstalledSpecHash(key, artifact.MediumOCI, "pinned-revision")
	current := manager.FindInstalled(key, artifact.MediumOCI)
	require.Equal(t, "pinned-revision", current.SpecHash)
	verified, err = manager.Verify(t.Context(), current)
	require.NoError(t, err)
	require.True(t, verified)
}

func TestManager_PluginRemovalUsesOnlyKnownRulesfileDependencies(t *testing.T) {
	ctx := t.Context()
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	for _, name := range []string{"container", "unrelated"} {
		_, _, err := m.AddPluginConfig(ctx, testPlugin(name), fetcher)
		require.NoError(t, err)
	}
	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "rules"}
	content, err := fetcher.FetchInline(ctx, []byte("rules"))
	require.NoError(t, err)
	_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumOCI, content, nil, false)
	require.NoError(t, err)
	_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumInline, content,
		&commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}, false)
	require.NoError(t, err)

	require.NoError(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("unrelated")),
		"an unknown source must not block an unrelated plugin")
	var blocked *nodeartifacts.BlockedError
	require.ErrorAs(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container")), &blocked,
		"the other source's known dependency must remain protected")
	assert.Equal(t, []nodeartifacts.Key{key}, blocked.BlockedBy)
	_, removed, err := m.RemoveIfInstalled(ctx, key, artifact.MediumInline)
	require.NoError(t, err)
	require.True(t, removed)
	require.NotNil(t, m.FindInstalled(key, artifact.MediumOCI))
	require.NoError(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container")),
		"only an unknown source remains; no dependency can be attributed to it")
}

func TestManager_StoreRulesfile_DuplicateCleanupFailurePreservesDependencies(t *testing.T) {
	for _, sameContent := range []bool{false, true} {
		for _, recovery := range []string{"store", "sync"} {
			t.Run(fmt.Sprintf("same-content=%t/%s", sameContent, recovery), func(t *testing.T) {
				ctx := t.Context()
				fs := fsfake.NewMockFileSystem()
				store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
				m := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))
				fetcher := &artifact.Fetcher{}
				for _, name := range []string{"container", "json", "unrelated"} {
					_, _, err := m.AddPluginConfig(ctx, testPlugin(name), fetcher)
					require.NoError(t, err)
				}
				key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "rules"}
				oldContent, err := fetcher.FetchInline(ctx, []byte("old rules"))
				require.NoError(t, err)
				_, oldFile, err := m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumOCI, oldContent,
					&commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}, false)
				require.NoError(t, err)
				// Model duplicate paths carrying a revision already known in this process.
				installed := m.GetInstalled(key)
				duplicates := make([]string, 0, 2)
				for _, artifactPriority := range []int32{60, 70} {
					duplicate := installed[0]
					duplicate.Priority = artifactPriority
					duplicate.Path = artifact.ArtifactPath(store.Dirs, key.Name, artifactPriority, artifact.MediumOCI, artifact.TypeRulesfile)
					require.NoError(t, fs.WriteFile(duplicate.Path, oldContent.Content, oldContent.Perm))
					installed = append(installed, duplicate)
					duplicates = append(duplicates, duplicate.Path)
				}
				m.SeedInstalled(key, installed)
				content, err := fetcher.FetchInline(ctx, []byte("new rules"))
				require.NoError(t, err)
				if sameContent {
					content = oldContent
				}
				metadata := &commonv1alpha1.ArtifactMeta{Digest: digest.FromString("candidate").String(),
					Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "json", Version: "1.0.0"}}}
				ioErr := errors.New("duplicate cleanup failed")
				fs.RemoveErrFor = map[string]error{duplicates[1]: ioErr}

				_, file, err := m.StoreRulesfile(ctx, key.Namespace, key.Name, 20, artifact.MediumOCI, content, metadata, false)

				require.ErrorIs(t, err, ioErr)
				require.NotNil(t, file, "the replacement succeeded before cleanup failed")
				assert.Equal(t, content.ContentHash, file.ContentHash)
				assert.Equal(t, content.Content, fs.Files[file.Path])
				assert.NotContains(t, fs.Files, oldFile.Path)
				assert.NotContains(t, fs.Files, duplicates[0], "cleanup removed one duplicate before failing")
				assert.Equal(t, oldContent.Content, fs.Files[duplicates[1]])
				for _, name := range []string{"container", "json"} {
					var blocked *nodeartifacts.BlockedError
					require.ErrorAs(t, m.RemovePluginConfig(ctx, fetcher, testPlugin(name)), &blocked)
					assert.Equal(t, []nodeartifacts.Key{key}, blocked.BlockedBy)
				}
				require.NoError(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("unrelated")))

				// A later failed content update must not discard either surviving revision.
				failedContent, err := fetcher.FetchInline(ctx, []byte("rejected rules"))
				require.NoError(t, err)
				fs.WriteErrFor = map[string]error{file.Path + ".tmp": ioErr}
				_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 20, artifact.MediumOCI, failedContent, &commonv1alpha1.ArtifactMeta{}, false)
				require.ErrorIs(t, err, ioErr)
				for _, name := range []string{"container", "json"} {
					var blocked *nodeartifacts.BlockedError
					require.ErrorAs(t, m.RemovePluginConfig(ctx, fetcher, testPlugin(name)), &blocked)
				}
				fs.WriteErrFor, fs.RemoveErrFor = nil, nil
				if recovery == "store" {
					_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 20, artifact.MediumOCI, content, metadata, false)
					require.NoError(t, err)
				} else {
					synced, syncErr := m.SyncRulesfileDependencies(ctx, key, artifact.MediumOCI, metadata, false)
					require.NoError(t, syncErr)
					require.True(t, synced)
				}
				require.Len(t, m.GetInstalled(key), 1)
				assert.NotContains(t, fs.Files, duplicates[1])
				assert.Equal(t, content.Content, fs.Files[file.Path])
				require.NoError(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container")),
					"successful cleanup must release only the old revision")
				var blocked *nodeartifacts.BlockedError
				require.ErrorAs(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("json")), &blocked)
				require.NoError(t, m.Remove(ctx, key))
				require.NoError(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("json")))
			})
		}
	}
}

func TestManager_StoreRulesfile_UnknownMetadataPreservesKnownDependenciesForSameBytes(t *testing.T) {
	for _, replacement := range []string{"different bytes", "known empty metadata"} {
		t.Run(replacement, func(t *testing.T) {
			ctx := t.Context()
			m := newTestManager()
			fetcher := &artifact.Fetcher{}
			for _, name := range []string{"container", "unrelated"} {
				_, _, err := m.AddPluginConfig(ctx, testPlugin(name), fetcher)
				require.NoError(t, err)
			}
			key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "rules"}
			content, err := fetcher.FetchInline(ctx, []byte("installed rules"))
			require.NoError(t, err)
			_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumOCI, content,
				&commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}, false)
			require.NoError(t, err)

			action, _, err := m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumOCI, content, nil, false)

			require.NoError(t, err)
			assert.Equal(t, artifact.StoreActionUnchanged, action)
			var blocked *nodeartifacts.BlockedError
			require.ErrorAs(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container")), &blocked,
				"known dependencies for unchanged bytes must survive missing metadata")
			assert.Equal(t, []nodeartifacts.Key{key}, blocked.BlockedBy)
			require.NoError(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("unrelated")),
				"retaining known dependencies must not invent other dependencies")

			var metadata *commonv1alpha1.ArtifactMeta
			if replacement == "different bytes" {
				content, err = fetcher.FetchInline(ctx, []byte("different rules"))
				require.NoError(t, err)
			} else {
				metadata = &commonv1alpha1.ArtifactMeta{}
			}
			_, _, err = m.StoreRulesfile(ctx, key.Namespace, key.Name, 50, artifact.MediumOCI, content, metadata, false)
			require.NoError(t, err)
			require.NoError(t, m.RemovePluginConfig(ctx, fetcher, testPlugin("container")),
				"replaced bytes or verified empty metadata release the old dependency")
		})
	}
}
