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
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

func newTestManager() *nodeartifacts.Manager {
	return newTestManagerWithFetcher(compat.NewMockVersionsFetcher(nil))
}

func newTestManagerWithFetcher(fetcher compat.VersionsFetcher) *nodeartifacts.Manager {
	store := &artifact.LocalStore{FS: filesystem.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	return nodeartifacts.NewManager(store, fetcher)
}

func TestManager_StorePassesThroughToUnderlyingStore(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644}

	action, file, err := m.Store(context.Background(), nil, "myfile", 50, artifact.TypeConfig, artifact.MediumInline, result)

	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionAdded, action)
	require.NotNil(t, file)

	ok, err := m.Verify(context.Background(), file)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestManager_RemovePassesThroughToUnderlyingStore(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644}
	_, file, err := m.Store(context.Background(), nil, "myfile", 50, artifact.TypeConfig, artifact.MediumInline, result)
	require.NoError(t, err)

	err = m.Remove(context.Background(), []artifactv1alpha1.InstalledArtifact{
		{Path: file.Path, Medium: string(artifact.MediumInline)},
	})
	require.NoError(t, err)

	ok, err := m.Verify(context.Background(), file)
	require.NoError(t, err)
	assert.False(t, ok)
}

func testPlugin(name string) *artifactv1alpha1.Plugin {
	return &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func TestManager_RemovePluginConfigByName_AllowedWhenNothingRequiresIt(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, fetcher)
	require.NoError(t, err)

	err = m.RemovePluginConfigByName(context.Background(), fetcher, "container", "container")
	require.NoError(t, err)
}

func TestManager_RemovePluginConfigByName_BlockedWhenSoleProvider(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, fetcher)
	require.NoError(t, err)

	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}
	m.Sync(rfKey, []nodeartifacts.RequirementGroup{{"container"}})

	err = m.RemovePluginConfigByName(context.Background(), fetcher, "container", "container")

	require.Error(t, err)
	var blocked *nodeartifacts.BlockedError
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, "container", blocked.Name)
	assert.Contains(t, blocked.BlockedBy, rfKey)
}

func TestManager_RemovePluginConfigByName_AllowedWhenAlternativeCoversTheGroup(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, fetcher)
	require.NoError(t, err)
	_, _, err = m.AddPluginConfig(context.Background(), testPlugin("container-alt"), nil, fetcher)
	require.NoError(t, err)

	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}
	m.Sync(rfKey, []nodeartifacts.RequirementGroup{{"container", "container-alt"}})

	err = m.RemovePluginConfigByName(context.Background(), fetcher, "container", "container")

	require.NoError(t, err, "container-alt still satisfies the group, so removing container must be allowed")
}

func TestManager_RemovePluginConfigByName_ClearsProvidesOnSuccess(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, fetcher)
	require.NoError(t, err)
	require.NoError(t, m.RemovePluginConfigByName(context.Background(), fetcher, "container", "container"))

	// container must have been cleared from provides by the removal above; container-alt is now
	// the sole remaining provider, so removing it next must be blocked.
	_, _, err = m.AddPluginConfig(context.Background(), testPlugin("container-alt"), nil, fetcher)
	require.NoError(t, err)
	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}
	m.Sync(rfKey, []nodeartifacts.RequirementGroup{{"container", "container-alt"}})

	err = m.RemovePluginConfigByName(context.Background(), fetcher, "container-alt", "container-alt")
	require.Error(t, err, "container was already cleared from provides, so container-alt is the sole remaining provider and its removal must be blocked")
}

func TestManager_AddPluginConfig_RenameBlockedWhenOldNameStillRequired(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	pl := testPlugin("container")
	_, _, err := m.AddPluginConfig(context.Background(), pl, nil, fetcher)
	require.NoError(t, err)

	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}
	m.Sync(rfKey, []nodeartifacts.RequirementGroup{{"container"}})

	pl.Spec.Config = &artifactv1alpha1.PluginConfig{Name: "renamed"}
	_, _, err = m.AddPluginConfig(context.Background(), pl, nil, fetcher)

	require.Error(t, err, "the old name \"container\" is still required, so the rename must be refused")
	var blocked *nodeartifacts.BlockedError
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, "container", blocked.Name)
}

func TestManager_Sync_ReplacesAndClears(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, fetcher)
	require.NoError(t, err)
	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}

	m.Sync(rfKey, []nodeartifacts.RequirementGroup{{"container"}})
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
	assert.Equal(t, nodeartifacts.RequirementGroup{"container", "container-alt"}, got[0])
	assert.Equal(t, nodeartifacts.RequirementGroup{"k8saudit"}, got[1])
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
	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(map[string]string{
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
	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(map[string]string{
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
	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(map[string]string{
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
	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(map[string]string{
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
	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(map[string]string{
		"container-alt": "1.0.0",
	}).Result)

	matched, provided, satisfied, err := m.CheckDependency(
		nodeartifacts.Requirement{Name: "container", Version: "0.4.0"},
		[]nodeartifacts.Requirement{{Name: "container-alt", Version: "0.1.0"}},
	)

	require.NoError(t, err)
	assert.True(t, satisfied)
	assert.Equal(t, "container-alt", matched)
	assert.Equal(t, "1.0.0", provided)
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

func TestManager_OnFalcoVersionsObserved_PreservesExistingKeyUpdatesVersion(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, fetcher)
	require.NoError(t, err)

	// AddPluginConfig already triggered an opportunistic refresh via the mock fetcher, which
	// reports nothing for "container". Observing a real version now must land without disturbing
	// the removal-blocking entry.
	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(map[string]string{"container": "0.7.1"}).Result)

	provided, found, _, err := m.CheckRequirement("container", "0.4.0")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "0.7.1", provided)

	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}
	m.Sync(rfKey, []nodeartifacts.RequirementGroup{{"container"}})
	err = m.RemovePluginConfigByName(context.Background(), fetcher, "container", "container")
	require.Error(t, err, "the PluginConfigKey-registered entry must still be tracked for removal-blocking after a version observation merged into it")
}

func TestManager_OnFalcoVersionsObserved_CreatesFalcoOwnedEntryForUnknownName(t *testing.T) {
	m := newTestManager()

	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(map[string]string{
		"engine_version_semver": "0.62.0",
	}).Result)

	_, found, _, err := m.CheckRequirement("engine_version_semver", "0.57.0")
	require.NoError(t, err)
	assert.True(t, found, "a capability never explicitly registered via AddPluginConfig/SyncProvides must still be tracked once Falco reports it")
}

func TestManager_OnFalcoVersionsObserved_NotifiesOnNewCapability(t *testing.T) {
	m := newTestManager()
	ch := m.Events()

	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.62.0"}).Result)

	select {
	case <-ch:
	default:
		t.Fatal("expected an event when a previously-unknown capability is observed")
	}
}

func TestManager_OnFalcoVersionsObserved_NotifiesWhenConfigEntryVersionIsFirstConfirmed(t *testing.T) {
	// An empty-to-confirmed version transition on an existing provides entry counts as a change.
	m := newTestManager()
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, &artifact.Fetcher{})
	require.NoError(t, err)
	ch := m.Events()

	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(map[string]string{"container": "0.7.1"}).Result)

	select {
	case <-ch:
	default:
		t.Fatal("expected an event when an already-tracked name's version is confirmed for the first time")
	}
}

func TestManager_OnFalcoVersionsObserved_NoNotifyWhenUnchanged(t *testing.T) {
	m := newTestManager()
	ch := m.Events()

	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.62.0"}).Result)
	select {
	case <-ch:
	default:
		t.Fatal("expected an event on the first observation")
	}

	// Observing the same value again must not fire an event, even though the Manager's own
	// bookkeeping went through an unrelated remove/re-add cycle for a different name in between.
	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.62.0"}).Result)
	select {
	case <-ch:
		t.Fatal("unexpected event: capability value did not change")
	default:
	}
}

func TestManager_OnFalcoVersionsObserved_NotifiesOnVersionBump(t *testing.T) {
	m := newTestManager()
	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(map[string]string{"container": "0.7.1"}).Result)
	ch := m.Events()

	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(map[string]string{"container": "0.7.2"}).Result)

	select {
	case <-ch:
	default:
		t.Fatal("expected an event when an existing capability's version changes")
	}
}

func TestManager_Events_MultipleSubscribersEachReceiveEveryEvent(t *testing.T) {
	m := newTestManager()
	chA := m.Events()
	chB := m.Events()

	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.62.0"}).Result)

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
	m := newTestManagerWithFetcher(compat.NewMockVersionsFetcher(map[string]string{
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
	m := newTestManagerWithFetcher(&compat.MockVersionsFetcher{FetchErr: assert.AnError})

	_, err := m.RefreshFalcoVersions(context.Background())

	require.Error(t, err)
}

// TestManager_AddPluginConfig_ConcurrentWithCheckRequirement runs AddPluginConfig and
// CheckRequirement concurrently to detect deadlocks or data races; run with -race.
func TestManager_AddPluginConfig_ConcurrentWithCheckRequirement(t *testing.T) {
	m := newTestManagerWithFetcher(compat.NewMockVersionsFetcher(map[string]string{"container": "0.7.1"}))
	fetcher := &artifact.Fetcher{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 50 {
			_, _, _, _ = m.CheckRequirement("container", "0.4.0")
		}
	}()

	for range 20 {
		_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, fetcher)
		require.NoError(t, err)
	}
	<-done
}
