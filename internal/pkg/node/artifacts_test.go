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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

func TestNode_RemoveIfInstalled_KeepsTheStatusWhileFilesRemain(t *testing.T) {
	m, published := newStatusManager(t, configMapFor(statusTestNamespace, "cfg-cm", "log_level: info\n"))
	config := inlineConfig(statusTestNamespace, "cfg", 50, configData)
	config.Spec.ConfigMapRef = &commonv1alpha1.ConfigMapRef{Name: "cfg-cm"}
	require.NoError(t, apply(t, m, config))
	key := artifact.RefOf(artifact.KindConfig, config)
	m.PublishStatus(artifact.KindConfig, artifactObj("cfg"), &artifactv1alpha1.NodeArtifactStatus{Conditions: statusConditions()})
	require.Eventually(t, func() bool { return len(published()) == 1 }, 2*time.Second, 5*time.Millisecond)

	_, removed, err := m.removeIfInstalled(t.Context(), key, artifact.MediumInline)
	require.NoError(t, err)
	require.True(t, removed)

	assert.Never(t, func() bool { return len(published()) == 0 }, 200*time.Millisecond, 10*time.Millisecond,
		"a file of the artifact is still installed, so its status must stay")
}

func TestNode_ScanAllPassesThroughToUnderlyingStore(t *testing.T) {
	m := newTestNode()
	installConfig(t, m, testutil.TestNamespace, "myfile")

	found, err := m.ScanAll(context.Background(), artifact.KindConfig)

	require.NoError(t, err)
	require.Len(t, found["myfile"], 1)
	assert.Equal(t, string(artifact.MediumInline), found["myfile"][0].Medium)
}

func TestNode_FindInstalled_ReturnsWhatWasWritten(t *testing.T) {
	m := newTestNode()
	key := artifact.Ref{Kind: artifact.KindConfig, Name: "myfile"}

	assert.Nil(t, m.FindInstalled(key, artifact.MediumInline), "nothing installed yet")

	installConfig(t, m, testutil.TestNamespace, key.Name)

	found := m.FindInstalled(key, artifact.MediumInline)
	require.NotNil(t, found)
	assert.Equal(t, testutil.MustArtifactPath(t, artifact.DefaultArtifactDirs(), key.Name, 50, artifact.MediumInline, artifact.KindConfig), found.Path)
	assert.Equal(t, testutil.SHA256Hex(inlineFile(t, configData)), found.ContentHash)
}

func TestNode_RemoveIfInstalled_NoOpWhenNothingInstalled(t *testing.T) {
	m := newTestNode()
	key := artifact.Ref{Kind: artifact.KindConfig, Name: "myfile"}

	path, removed, err := m.removeIfInstalled(context.Background(), key, artifact.MediumInline)

	require.NoError(t, err)
	assert.False(t, removed)
	assert.Empty(t, path)
}

func TestNode_RemoveIfInstalled_RemovesWhenInstalled(t *testing.T) {
	m := newTestNode()
	key := installConfig(t, m, testutil.TestNamespace, "myfile")
	file := m.FindInstalled(key, artifact.MediumInline)
	require.NotNil(t, file)

	path, removed, err := m.removeIfInstalled(context.Background(), key, artifact.MediumInline)

	require.NoError(t, err)
	assert.True(t, removed)
	assert.Equal(t, file.Path, path)
	assert.Nil(t, m.FindInstalled(key, artifact.MediumInline), "cache entry must be cleared")
	ok, err := m.Verify(context.Background(), file)
	require.NoError(t, err)
	assert.False(t, ok, "file must be removed from the underlying store")
}

func TestNode_SeedInstalled_ThenFindInstalled(t *testing.T) {
	m := newTestNode()
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "my-rules"}

	m.SeedInstalled(key, []artifactv1alpha1.InstalledArtifact{
		{Path: "/x", Medium: "oci", Priority: 50, ContentHash: "h1", SpecHash: "s1"},
	})

	found := m.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, found)
	assert.Equal(t, "/x", found.Path)
	assert.Equal(t, "s1", found.SpecHash)
}

func TestNode_UpdateInstalledSpecHash_SetsSpecHashOnCachedEntry(t *testing.T) {
	m := newTestNode()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "my-rules"}
	_, _, err := m.StoreRulesfile(context.Background(), "my-rules", 50, artifact.MediumOCI, result, &commonv1alpha1.ArtifactMeta{}, true)
	require.NoError(t, err)

	m.UpdateInstalledSpecHash(key, artifact.MediumOCI, "spec-hash-v1")

	found := m.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, found)
	assert.Equal(t, "spec-hash-v1", found.SpecHash)
}

// TestNode_SyncInstalledStatus_MirrorsCacheEvenWhenStatusStartsEmpty covers a reconcile that
// takes the "already verified on disk, skip re-fetch" shortcut (or hits StoreActionUnchanged): a
// status write gated on the StoreAction actually having changed something would leave
// status.InstalledArtifacts permanently missing an entry the cache (seeded by the warm sync, or
// surviving a status patch that lost an SSA conflict) already considers installed.
// SyncInstalledStatus must mirror the cache unconditionally, regardless of any StoreAction.
func TestNode_SyncInstalledStatus_MirrorsCacheEvenWhenStatusStartsEmpty(t *testing.T) {
	m := newTestNode()
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "my-rules"}
	m.SeedInstalled(key, []artifactv1alpha1.InstalledArtifact{
		{Path: "/x", Medium: "oci", Priority: 50, ContentHash: "h1", SpecHash: "s1"},
	})
	var status []artifactv1alpha1.InstalledArtifact

	m.syncInstalledStatus(key, artifact.MediumOCI, &status)

	entry := artifact.FindInstalled(status, artifact.MediumOCI)
	require.NotNil(t, entry, "status must be populated from the cache even though no Store call happened on this status object")
	assert.Equal(t, "/x", entry.Path)
	assert.Equal(t, "s1", entry.SpecHash)
}

// TestNode_SyncInstalledStatus_ClearsStatusWhenCacheHasNoEntry covers the removal direction:
// if the cache no longer has an entry for medium, status must not keep a stale one either.
func TestNode_SyncInstalledStatus_ClearsStatusWhenCacheHasNoEntry(t *testing.T) {
	m := newTestNode()
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "my-rules"}
	status := []artifactv1alpha1.InstalledArtifact{{Path: "/stale", Medium: "oci"}}

	m.syncInstalledStatus(key, artifact.MediumOCI, &status)

	assert.Nil(t, artifact.FindInstalled(status, artifact.MediumOCI))
}

func TestNode_GetInstalled_ReturnsIndependentCopy(t *testing.T) {
	m := newTestNode()
	key := artifact.Ref{Kind: artifact.KindPlugin, Name: "my-plugin"}
	m.SeedInstalled(key, []artifactv1alpha1.InstalledArtifact{{Path: "/x", Medium: "oci", ContentHash: "h"}})

	got := m.GetInstalled(key)
	got[0].Path = "/mutated"

	assert.Equal(t, "/x", m.FindInstalled(key, artifact.MediumOCI).Path, "caller mutation must not affect the cache")
}

func TestNode_RemoveIfInstalled_ClearsDependenciesWhenFileIsMissing(t *testing.T) {
	ctx := t.Context()
	fs := fsfake.NewMockFileSystem()
	m := newTestNodeOver(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
	_, _, addErr := m.AddPluginConfig(ctx, testPlugin("container"))
	require.NoError(t, addErr)
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
	installTestRulesfile(t, m, key, []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}})
	installed := m.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, installed)
	require.NoError(t, fs.Remove(installed.Path))
	var blocked *BlockedError
	require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("container")), &blocked)
	_, removed, err := m.removeIfInstalled(ctx, key, artifact.MediumOCI)
	require.NoError(t, err)
	assert.True(t, removed, "cleanup must remove the cache entry even if the file is already absent")
	_, removed, err = m.removeIfInstalled(ctx, key, artifact.MediumOCI)
	require.NoError(t, err)
	assert.False(t, removed, "repeated cleanup is a no-op")
	require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("container")))
}

func TestRemove_WithdrawsThePluginsEntryWhicheverIncarnationClaimedIt(t *testing.T) {
	ctx := t.Context()
	fs := fsfake.NewMockFileSystem()
	m := newTestNodeOver(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
	plugin := testPlugin("container")
	plugin.Namespace, plugin.UID = testutil.TestNamespace, "uid-1"
	require.NoError(t, apply(t, m, withBinary(plugin, "binary")))
	key := artifact.RefOf(artifact.KindPlugin, plugin)
	binary := m.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, binary)
	config := pluginsConfigFileOf(m)
	require.NotNil(t, config)

	// Removal needs only the key: the node holds one claim per plugin, and whoever removes the plugin's files
	// releases it, whichever incarnation of the plugin made it.
	require.NoError(t, m.Remove(ctx, key))

	assert.NotContains(t, fs.Files, binary.Path)
	var written map[string]any
	require.NoError(t, yaml.Unmarshal(fs.Files[config.Path], &written))
	assert.Empty(t, written["plugins"])
	assert.Empty(t, written["load_plugins"])
}

func TestRemove_KeepsAnEntryAnotherPluginOwns(t *testing.T) {
	ctx := t.Context()
	fs := fsfake.NewMockFileSystem()
	m := newTestNodeOver(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
	shared := testPlugin("shared")
	shared.Namespace, shared.UID = testutil.TestNamespace, "uid-shared"
	require.NoError(t, apply(t, m, withBinary(shared, "binary")))
	key := artifact.RefOf(artifact.KindPlugin, shared)
	binary := m.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, binary)
	// Another plugin's entry loads the same binary through a library path of its own.
	other := testPlugin("other")
	other.Namespace, other.UID = testutil.TestNamespace, "uid-other"
	other.Spec.Config = &artifactv1alpha1.PluginConfig{LibraryPath: binary.Path}
	_, _, err := m.AddPluginConfig(ctx, other)
	require.NoError(t, err)

	err = m.Remove(ctx, key)

	require.Error(t, err, "removing the binary would leave another plugin's entry pointing at nothing")
	assert.Contains(t, fs.Files, binary.Path)
}
