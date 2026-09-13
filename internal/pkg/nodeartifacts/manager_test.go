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
	"maps"
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
	_, _, err := m.Store(context.Background(), "", "myfile", 50, artifact.TypeConfig, artifact.MediumInline, result)
	require.NoError(t, err)

	found, err := m.ScanAll(context.Background(), artifact.TypeConfig)

	require.NoError(t, err)
	require.Len(t, found["myfile"], 1)
	assert.Equal(t, string(artifact.MediumInline), found["myfile"][0].Medium)
}

func TestManager_StorePassesThroughToUnderlyingStore(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}

	action, file, err := m.Store(context.Background(), "", "myfile", 50, artifact.TypeConfig, artifact.MediumInline, result)

	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionAdded, action)
	require.NotNil(t, file)

	ok, err := m.Verify(context.Background(), file)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestManager_RemovePassesThroughToUnderlyingStore(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}
	key := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Name: "myfile"}
	_, file, err := m.Store(context.Background(), "", "myfile", 50, artifact.TypeConfig, artifact.MediumInline, result)
	require.NoError(t, err)

	err = m.Remove(context.Background(), key, []artifactv1alpha1.InstalledArtifact{
		{Path: file.Path, Medium: string(artifact.MediumInline)},
	})
	require.NoError(t, err)

	ok, err := m.Verify(context.Background(), file)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestManager_Store_UsesCacheForCurrent_SecondIdenticalStoreIsUnchanged(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}

	action1, _, err := m.Store(context.Background(), "", "myfile", 50, artifact.TypeConfig, artifact.MediumInline, result)
	require.NoError(t, err)
	require.Equal(t, artifact.StoreActionAdded, action1)

	// No caller-supplied "current": Manager must derive it from its own cache, not from any
	// status object, to recognize the second call as a no-op.
	action2, _, err := m.Store(context.Background(), "", "myfile", 50, artifact.TypeConfig, artifact.MediumInline, result)
	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUnchanged, action2)
}

// TestManager_Store_IsolatesByNamespace proves that two artifacts with the same Kind and Name
// but different Namespace are tracked as distinct cache entries, not merged into one.
func TestManager_Store_IsolatesByNamespace(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}

	_, _, err := m.Store(context.Background(), "ns-a", "myfile", 50, artifact.TypeConfig, artifact.MediumInline, result)
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

	_, file, err := m.Store(context.Background(), "", "myfile", 50, artifact.TypeConfig, artifact.MediumInline, result)
	require.NoError(t, err)

	found := m.FindInstalled(key, artifact.MediumInline)
	require.NotNil(t, found)
	assert.Equal(t, file.Path, found.Path)
	assert.Equal(t, file.ContentHash, found.ContentHash)
}

func TestManager_Remove_ClearsCacheForRemovedMedium(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}
	key := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Name: "myfile"}
	_, file, err := m.Store(context.Background(), "", "myfile", 50, artifact.TypeConfig, artifact.MediumInline, result)
	require.NoError(t, err)

	require.NoError(t, m.Remove(context.Background(), key, []artifactv1alpha1.InstalledArtifact{
		{Path: file.Path, Medium: string(artifact.MediumInline)},
	}))

	assert.Nil(t, m.FindInstalled(key, artifact.MediumInline))
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
	_, _, err := m.Store(context.Background(), "", "my-rules", 50, artifact.TypeRulesfile, artifact.MediumOCI, result)
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
	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rules"}
	m.SeedInstalled(key, []artifactv1alpha1.InstalledArtifact{{Path: "/x", Medium: "oci"}})

	got := m.GetInstalled(key)
	got[0].Path = "/mutated"

	assert.Equal(t, "/x", m.FindInstalled(key, artifact.MediumOCI).Path, "caller mutation must not affect the cache")
}

func testPlugin(name string) *artifactv1alpha1.Plugin {
	return &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: name}}
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

func TestManager_RemovePluginConfigByName_AllowedWhenNothingRequiresIt(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), fetcher)
	require.NoError(t, err)

	err = m.RemovePluginConfigByName(context.Background(), fetcher, "container", "container")
	require.NoError(t, err)
}

func TestManager_RemovePluginConfigByName_BlockedWhenSoleProvider(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), fetcher)
	require.NoError(t, err)

	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}
	m.Sync(rfKey, []nodeartifacts.RequirementGroup{{{Name: "container", Version: "1.0.0"}}})

	err = m.RemovePluginConfigByName(context.Background(), fetcher, "container", "container")

	require.Error(t, err)
	var blocked *nodeartifacts.BlockedError
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, "container", blocked.Name)
	assert.Contains(t, blocked.BlockedBy, rfKey)
}

func TestManager_RemovePluginConfigByName_AllowedWhenAlternativeCoversTheGroup(t *testing.T) {
	m := newTestManagerWithFetcher(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{
		"container": "1.0.0", "container-alt": "1.0.0",
	}))
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), fetcher)
	require.NoError(t, err)
	_, _, err = m.AddPluginConfig(context.Background(), testPlugin("container-alt"), fetcher)
	require.NoError(t, err)

	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}
	m.Sync(rfKey, []nodeartifacts.RequirementGroup{{{Name: "container", Version: "1.0.0"}, {Name: "container-alt", Version: "1.0.0"}}})

	err = m.RemovePluginConfigByName(context.Background(), fetcher, "container", "container")

	require.NoError(t, err, "container-alt still satisfies the group, so removing container must be allowed")
}

func TestManager_RemovePluginConfigByName_ClearsProvidesOnSuccess(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), fetcher)
	require.NoError(t, err)
	require.NoError(t, m.RemovePluginConfigByName(context.Background(), fetcher, "container", "container"))

	// container must have been cleared from provides by the removal above; container-alt is now
	// the sole remaining provider, so removing it next must be blocked.
	_, _, err = m.AddPluginConfig(context.Background(), testPlugin("container-alt"), fetcher)
	require.NoError(t, err)
	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}
	m.Sync(rfKey, []nodeartifacts.RequirementGroup{{{Name: "container", Version: "1.0.0"}, {Name: "container-alt", Version: "1.0.0"}}})

	err = m.RemovePluginConfigByName(context.Background(), fetcher, "container-alt", "container-alt")
	require.Error(t, err, "container was already cleared from provides, so container-alt is the sole remaining provider and its removal must be blocked")
}

func TestManager_AddPluginConfig_RenameBlockedWhenOldNameStillRequired(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	pl := testPlugin("container")
	_, _, err := m.AddPluginConfig(context.Background(), pl, fetcher)
	require.NoError(t, err)

	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}
	m.Sync(rfKey, []nodeartifacts.RequirementGroup{{{Name: "container", Version: "1.0.0"}}})

	pl.Spec.Config = &artifactv1alpha1.PluginConfig{Name: "renamed"}
	_, _, err = m.AddPluginConfig(context.Background(), pl, fetcher)

	require.Error(t, err, "the old name \"container\" is still required, so the rename must be refused")
	var blocked *nodeartifacts.BlockedError
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, "container", blocked.Name)
}

func TestManager_Sync_ReplacesAndClears(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), fetcher)
	require.NoError(t, err)
	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}

	m.Sync(rfKey, []nodeartifacts.RequirementGroup{{{Name: "container", Version: "1.0.0"}}})
	require.Error(t, m.RemovePluginConfigByName(context.Background(), fetcher, "container", "container"),
		"blocked while rfKey requires it")

	m.Sync(rfKey, nil) // requirement gone (e.g. Rulesfile deleted or its deps changed)
	require.NoError(t, m.RemovePluginConfigByName(context.Background(), fetcher, "container", "container"))
}

func TestRequirementGroupsFromDependencies(t *testing.T) {
	deps := []commonv1alpha1.ArtifactMetaDependency{
		{
			Name:    "container",
			Version: "0.4.0",
			Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{
				{Name: "container-alt", Version: "0.1.0"},
			},
		},
		{Name: "k8saudit", Version: "1.0.0"},
	}

	got := nodeartifacts.RequirementGroupsFromDependencies(deps)

	require.Len(t, got, 2)
	assert.Equal(t, nodeartifacts.RequirementGroup{{Name: "container", Version: "0.4.0"}, {Name: "container-alt", Version: "0.1.0"}}, got[0])
	assert.Equal(t, nodeartifacts.RequirementGroup{{Name: "k8saudit", Version: "1.0.0"}}, got[1])
}

func TestRequirementGroupsFromDependencies_Nil(t *testing.T) {
	assert.Nil(t, nodeartifacts.RequirementGroupsFromDependencies(nil))
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
		nodeartifacts.Requirement{Name: "container", Version: "0.4.0"}, nil,
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
		nodeartifacts.Requirement{Name: "container", Version: "0.4.0"},
		[]nodeartifacts.Requirement{{Name: "container-alt", Version: "0.1.0"}},
	)

	require.NoError(t, err)
	assert.True(t, satisfied)
	assert.Equal(t, "container-alt", matched)
	assert.Equal(t, "0.2.0", provided)
}

func TestManager_CheckDependency_NoneSatisfied(t *testing.T) {
	m := newTestManager()

	matched, provided, satisfied, err := m.CheckDependency(
		nodeartifacts.Requirement{Name: "container", Version: "0.4.0"},
		[]nodeartifacts.Requirement{{Name: "container-alt", Version: "0.1.0"}},
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
	primary := nodeartifacts.Requirement{Name: "json", Version: "0.7.0"}
	alternatives := []nodeartifacts.Requirement{{Name: "container", Version: "0.7.0"}}
	check := func(wantMatch string, wantSatisfied bool) {
		t.Helper()
		matched, _, satisfied, err := m.CheckDependency(primary, alternatives)
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
	primary.Version = "0.99.0"
	check("json", false)

	// A successful snapshot during reload can omit a still-configured primary.
	// It does not make the alternative safe for rules that the primary will reject.
	m.OnFalcoVersionsObserved(versions.Result)
	check("json", false)
	require.NoError(t, m.RemovePluginConfigByName(ctx, fetcher, "json", "json"))
	check("container", true)
	_, _, err = m.AddPluginConfig(ctx, testPlugin("json"), fetcher)
	require.NoError(t, err)
	check("json", false)

	// The same rule applies to an earlier alternative awaiting observation.
	_, _, satisfied, err := m.CheckDependency(nodeartifacts.Requirement{Name: "absent", Version: "1.0.0"},
		[]nodeartifacts.Requirement{primary, alternatives[0]})
	require.NoError(t, err)
	assert.False(t, satisfied)
}

func TestManager_CheckDependency_FalcoCompatibility(t *testing.T) {
	primary := nodeartifacts.Requirement{Name: "primary", Version: "1.2.0"}
	alternatives := []nodeartifacts.Requirement{
		{Name: "z-first", Version: "1.0.0"},
		{Name: "a-second", Version: "2.0.0"},
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
			matched, _, satisfied, err := m.CheckDependency(primary, alternatives)
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

func TestManager_RemovePluginConfigByName_ChecksRemainingVersions(t *testing.T) {
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
			m.Sync(key, nodeartifacts.RequirementGroupsFromDependencies([]commonv1alpha1.ArtifactMetaDependency{dep}))
			remove := tt.remove
			if remove == "" {
				remove = "primary"
			}
			before, err := fs.ReadFile(configFile.Path)
			require.NoError(t, err)
			err = m.RemovePluginConfigByName(t.Context(), fetcher, remove, remove)
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
	alternatives := make([]nodeartifacts.Requirement, len(d.Alternatives))
	for i, alt := range d.Alternatives {
		alternatives[i] = nodeartifacts.Requirement{Name: alt.Name, Version: alt.Version}
	}
	matched, _, satisfied, err := m.CheckDependency(nodeartifacts.Requirement{Name: d.Name, Version: d.Version}, alternatives)
	require.NoError(t, err)
	assert.True(t, satisfied)
	assert.Equal(t, "z-first", matched)
}

func TestManager_CheckDependency_ValidatesAllCandidates(t *testing.T) {
	for _, tc := range []struct {
		name         string
		primary      nodeartifacts.Requirement
		alternatives []nodeartifacts.Requirement
		wantErr      bool
	}{
		{name: "unused malformed alternative", primary: nodeartifacts.Requirement{Name: "container", Version: "0.7.0"},
			alternatives: []nodeartifacts.Requirement{{Name: "unused", Version: "garbage"}}, wantErr: true},
		{name: "duplicate name", primary: nodeartifacts.Requirement{Name: "container", Version: "0.7.0"},
			alternatives: []nodeartifacts.Requirement{{Name: "container", Version: "0.6.0"}}, wantErr: true},
		{name: "short version", primary: nodeartifacts.Requirement{Name: "container", Version: "0.7"}, wantErr: true},
		{name: "prefixed version", primary: nodeartifacts.Requirement{Name: "container", Version: "v0.7.0"}, wantErr: true},
		{name: "numeric prefix matches Falco", primary: nodeartifacts.Requirement{Name: "container", Version: "0.7.0junk"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager()
			m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"}).Result)
			_, _, satisfied, err := m.CheckDependency(tc.primary, tc.alternatives)
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

func TestManager_RemovePluginConfigByName_StaleObservationCannotRestoreRemovedProvider(t *testing.T) {
	ctx := t.Context()
	falco := compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"json": "0.7.4", "container": "0.7.1"})
	m := newTestManagerWithFetcher(falco)
	fetcher := &artifact.Fetcher{}
	for _, name := range []string{"json", "container"} {
		_, _, err := m.AddPluginConfig(ctx, testPlugin(name), fetcher)
		require.NoError(t, err)
	}
	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "rules"}
	m.Sync(key, []nodeartifacts.RequirementGroup{{{Name: "json", Version: "0.7.0"}, {Name: "container", Version: "0.7.0"}}})
	require.NoError(t, m.RemovePluginConfigByName(ctx, fetcher, "json", "json"))
	// Falco has not reloaded yet, so the next successful poll still reports both plugins.
	m.OnFalcoVersionsObserved(falco.Result)
	_, found, _, err := m.CheckRequirement("json", "0.7.0")
	require.NoError(t, err)
	assert.False(t, found, "an observation must not undo our removal")
	var blocked *nodeartifacts.BlockedError
	require.ErrorAs(t, m.RemovePluginConfigByName(ctx, fetcher, "container", "container"), &blocked)
	assert.Equal(t, []nodeartifacts.Key{key}, blocked.BlockedBy)
	// Even a delayed old response after an observed unload cannot restore the name.
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"}).Result)
	m.OnFalcoVersionsObserved(falco.Result)
	require.ErrorAs(t, m.RemovePluginConfigByName(ctx, fetcher, "container", "container"), &blocked)
	// An explicit re-add, unlike a poll, makes json eligible again once observed.
	_, _, err = m.AddPluginConfig(ctx, testPlugin("json"), fetcher)
	require.NoError(t, err)
	require.NoError(t, m.RemovePluginConfigByName(ctx, fetcher, "container", "container"))
}

func TestManager_RemovePluginConfigByName_ObservedExternalAlternativeStillWorks(t *testing.T) {
	m := newTestManagerWithFetcher(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{
		"json": "0.7.4", "container": "0.7.1",
	}))
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(t.Context(), testPlugin("json"), fetcher)
	require.NoError(t, err)
	m.Sync(nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "rules"},
		[]nodeartifacts.RequirementGroup{{{Name: "json", Version: "0.7.0"}, {Name: "container", Version: "0.7.0"}}})
	// container was loaded outside our shared config; it has not been explicitly removed.
	require.NoError(t, m.RemovePluginConfigByName(t.Context(), fetcher, "json", "json"))
}

func TestManager_RemovePluginConfigByName_RetryAfterConfigRemoval(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(t.Context(), testPlugin("json"), fetcher)
	require.NoError(t, err)
	require.NoError(t, m.RemovePluginConfigByName(t.Context(), fetcher, "json", "json"))
	// A newly registered dependency cannot block retrying the remaining binary/finalizer
	// cleanup: this config was already removed successfully in an earlier reconcile.
	m.Sync(nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "new-rules"},
		[]nodeartifacts.RequirementGroup{{{Name: "json", Version: "0.7.0"}}})
	require.NoError(t, m.RemovePluginConfigByName(t.Context(), fetcher, "json", "json"))
	_, _, err = m.AddPluginConfig(t.Context(), testPlugin("json"), fetcher)
	require.NoError(t, err)
	var blocked *nodeartifacts.BlockedError
	require.ErrorAs(t, m.RemovePluginConfigByName(t.Context(), fetcher, "json", "json"), &blocked,
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
	m.Sync(rfKey, []nodeartifacts.RequirementGroup{{{Name: "container", Version: "0.4.0"}}})
	err = m.RemovePluginConfigByName(context.Background(), fetcher, "container", "container")
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
				m.SyncProvides(nodeartifacts.PluginConfigKey, tc.capability)
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
