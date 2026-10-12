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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
)

func TestNode_PluginRemovalUsesOnlyKnownRulesfileDependencies(t *testing.T) {
	ctx := t.Context()
	m := newTestNode()
	fetcher := &artifact.Fetcher{}
	for _, name := range []string{"container", "unrelated"} {
		_, _, err := m.AddPluginConfig(ctx, testPlugin(name))
		require.NoError(t, err)
	}
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
	content, err := fetcher.FetchInline(ctx, []byte("rules"))
	require.NoError(t, err)
	_, _, err = m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumOCI, content, nil, false)
	require.NoError(t, err)
	_, _, err = m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumInline, content,
		&commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}, false)
	require.NoError(t, err)

	require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("unrelated")),
		"an unknown source must not block an unrelated plugin")
	var blocked *BlockedError
	require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("container")), &blocked,
		"the other source's known dependency must remain protected")
	assert.Equal(t, []artifact.Ref{key}, blocked.BlockedBy)
	_, removed, err := m.removeIfInstalled(ctx, key, artifact.MediumInline)
	require.NoError(t, err)
	require.True(t, removed)
	require.NotNil(t, m.FindInstalled(key, artifact.MediumOCI))
	require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("container")),
		"only an unknown source remains; no dependency can be attributed to it")
}

func TestNode_CheckRequirement_NotFoundBeforeAnyObservation(t *testing.T) {
	m := newTestNode()

	provided, found, satisfied, err := m.checkRequirement("engine_version_semver", "0.57.0")

	require.NoError(t, err)
	assert.False(t, found)
	assert.False(t, satisfied)
	assert.Empty(t, provided)
}

func TestNode_CheckRequirement_SatisfiedAfterObservation(t *testing.T) {
	m := newTestNode()
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
		"engine_version_semver": "0.62.0",
	}).Result)

	provided, found, satisfied, err := m.checkRequirement("engine_version_semver", "0.57.0")

	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, satisfied)
	assert.Equal(t, "0.62.0", provided)
}

func TestNode_CheckRequirement_NotSatisfiedWhenTooOld(t *testing.T) {
	m := newTestNode()
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
		"container": "0.3.0",
	}).Result)

	provided, found, satisfied, err := m.checkRequirement("container", "0.4.0")

	require.NoError(t, err)
	assert.True(t, found)
	assert.False(t, satisfied)
	assert.Equal(t, "0.3.0", provided)
}

func TestNode_CheckRequirement_PluginAPIVersionUsesMajorCompatibility(t *testing.T) {
	m := newTestNode()
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
		"plugin_api_version": "3.12.0",
	}).Result)

	_, found, satisfied, err := m.checkRequirement("plugin_api_version", "3.0.0")
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, satisfied, "3.12.0 is major-compatible with a 3.0.0 requirement")

	_, found, satisfied, err = m.checkRequirement("plugin_api_version", "4.0.0")
	require.NoError(t, err)
	assert.True(t, found)
	assert.False(t, satisfied, "major version 3 cannot satisfy a major version 4 requirement")
}

func TestNode_CheckDependency_PrimarySatisfied(t *testing.T) {
	m := newTestNode()
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
		"container": "0.7.1",
	}).Result)

	matched, provided, satisfied, err := m.checkDependency(
		commonv1alpha1.ArtifactMetaDependency{Name: "container", Version: "0.4.0"},
	)

	require.NoError(t, err)
	assert.True(t, satisfied)
	assert.Equal(t, "container", matched)
	assert.Equal(t, "0.7.1", provided)
}

func TestNode_CheckDependency_AlternativeSatisfied(t *testing.T) {
	m := newTestNode()
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
		"container-alt": "0.2.0",
	}).Result)

	matched, provided, satisfied, err := m.checkDependency(
		commonv1alpha1.ArtifactMetaDependency{Name: "container", Version: "0.4.0",
			Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container-alt", Version: "0.1.0"}}},
	)

	require.NoError(t, err)
	assert.True(t, satisfied)
	assert.Equal(t, "container-alt", matched)
	assert.Equal(t, "0.2.0", provided)
}

func TestNode_CheckDependency_NoneSatisfied(t *testing.T) {
	m := newTestNode()

	matched, provided, satisfied, err := m.checkDependency(
		commonv1alpha1.ArtifactMetaDependency{Name: "container", Version: "0.4.0",
			Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container-alt", Version: "0.1.0"}}},
	)

	require.NoError(t, err)
	assert.False(t, satisfied)
	assert.Empty(t, matched)
	assert.Empty(t, provided)
}

func TestNode_CheckDependency_WaitsForConfiguredCandidate(t *testing.T) {
	ctx := t.Context()
	versions := compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"})
	m := newTestNodeWithFetcher(versions)
	dependency := commonv1alpha1.ArtifactMetaDependency{Name: "json", Version: "0.7.0",
		Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container", Version: "0.7.0"}}}
	check := func(wantMatch string, wantSatisfied bool) {
		t.Helper()
		matched, _, satisfied, err := m.checkDependency(dependency)
		require.NoError(t, err)
		assert.Equal(t, wantMatch, matched)
		assert.Equal(t, wantSatisfied, satisfied)
	}

	// A genuinely absent primary allows fallback. A configured primary may already
	// have loaded since the last poll, so its unknown version must not allow fallback.
	m.OnFalcoVersionsObserved(versions.Result)
	check("container", true)
	_, _, err := m.AddPluginConfig(ctx, testPlugin("json"))
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
	require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("json")))
	check("container", true)
	_, _, err = m.AddPluginConfig(ctx, testPlugin("json"))
	require.NoError(t, err)
	check("json", false)

	// The same rule applies to an earlier alternative awaiting observation.
	_, _, satisfied, err := m.checkDependency(commonv1alpha1.ArtifactMetaDependency{
		Name: "absent", Version: "1.0.0",
		Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{
			{Name: dependency.Name, Version: dependency.Version}, dependency.Alternatives[0],
		},
	})
	require.NoError(t, err)
	assert.False(t, satisfied)
}

func TestNode_CheckDependency_FalcoCompatibility(t *testing.T) {
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
			m := newTestNode()
			m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(tt.versions).Result)
			matched, _, satisfied, err := m.checkDependency(dependency)
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

func TestNode_CheckDependency_PreservesMetadataOrder(t *testing.T) {
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
	m := newTestNode()
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
		"z-first": "1.0.0", "a-second": "1.0.0",
	}).Result)
	d := meta.Dependencies[0]
	assert.Equal(t, "z-first", d.Alternatives[0].Name)
	matched, _, satisfied, err := m.checkDependency(d)
	require.NoError(t, err)
	assert.True(t, satisfied)
	assert.Equal(t, "z-first", matched)
}

func TestNode_CheckDependency_ValidatesAllCandidates(t *testing.T) {
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
			m := newTestNode()
			m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"}).Result)
			_, _, satisfied, err := m.checkDependency(tc.dependency)
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

func TestNode_OnFalcoVersionsObserved_PreservesExistingKeyUpdatesVersion(t *testing.T) {
	m := newTestNode()
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"))
	require.NoError(t, err)

	// AddPluginConfig already triggered an opportunistic refresh via the mock fetcher, which
	// reports nothing for "container". Observing a real version now must land without disturbing
	// the removal-blocking entry.
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"container": "0.7.1"}).Result)

	provided, found, _, err := m.checkRequirement("container", "0.4.0")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "0.7.1", provided)

	rfKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: "my-rulesfile"}
	installTestRulesfile(t, m, rfKey, []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "0.4.0"}})
	err = m.RemovePluginConfig(context.Background(), testPlugin("container"))
	require.Error(t, err, "the configured entry must still be tracked for removal-blocking after a version observation merged into it")
}

func TestNode_OnFalcoVersionsObserved_CreatesFalcoOwnedEntryForUnknownName(t *testing.T) {
	m := newTestNode()

	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
		"engine_version_semver": "0.62.0",
	}).Result)

	_, found, _, err := m.checkRequirement("engine_version_semver", "0.57.0")
	require.NoError(t, err)
	assert.True(t, found, "a capability never explicitly registered via AddPluginConfig/SyncProvides must still be tracked once Falco reports it")
}

func TestNode_OnFalcoVersionsObserved_NotifiesOnNewCapability(t *testing.T) {
	m := newTestNode()
	ch := m.Events()

	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.62.0"}).Result)

	select {
	case <-ch:
	default:
		t.Fatal("expected an event when a previously-unknown capability is observed")
	}
}

func TestNode_OnFalcoVersionsObserved_NotifiesWhenConfigEntryVersionIsFirstConfirmed(t *testing.T) {
	// An empty-to-confirmed version transition on an existing provides entry counts as a change.
	m := newTestNode()
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"))
	require.NoError(t, err)
	ch := m.Events()

	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"container": "0.7.1"}).Result)

	select {
	case <-ch:
	default:
		t.Fatal("expected an event when an already-tracked name's version is confirmed for the first time")
	}
}

func TestNode_OnFalcoVersionsObserved_NoNotifyWhenUnchanged(t *testing.T) {
	m := newTestNode()
	ch := m.Events()

	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.62.0"}).Result)
	select {
	case <-ch:
	default:
		t.Fatal("expected an event on the first observation")
	}

	// Observing the same value again must not fire an event, even though the node's own
	// bookkeeping went through an unrelated remove/re-add cycle for a different name in between.
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.62.0"}).Result)
	select {
	case <-ch:
		t.Fatal("unexpected event: capability value did not change")
	default:
	}
}

func TestNode_OnFalcoVersionsObserved_NotifiesOnVersionBump(t *testing.T) {
	m := newTestNode()
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"container": "0.7.1"}).Result)
	ch := m.Events()

	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{"container": "0.7.2"}).Result)

	select {
	case <-ch:
	default:
		t.Fatal("expected an event when an existing capability's version changes")
	}
}

func TestNode_OnFalcoVersionsObserved_InvalidatesMissingVersions(t *testing.T) {
	for _, tc := range []struct {
		name, capability string
		configured       bool
	}{
		{"configured plugin", "container", true},
		{"observed-only plugin", "container", false},
		{"Falco capability", "engine_version_semver", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestNode()
			if tc.configured {
				_, _, err := m.AddPluginConfig(t.Context(), testPlugin(tc.capability))
				require.NoError(t, err)
			}
			loaded := compatfake.NewMockVersionsFetcher(map[string]string{tc.capability: "1.0.0", "other": "1.0.0"}).Result
			missing := compatfake.NewMockVersionsFetcher(map[string]string{"other": "1.0.0"}).Result
			m.OnFalcoVersionsObserved(loaded)
			chA, chB := m.Events(), m.Events()
			_, found, satisfied, err := m.checkRequirement(tc.capability, "1.0.0")
			require.NoError(t, err)
			require.True(t, found && satisfied)

			m.OnFalcoVersionsObserved(missing)
			version, found, satisfied, err := m.checkRequirement(tc.capability, "1.0.0")
			require.NoError(t, err)
			assert.Empty(t, version)
			assert.False(t, found, "a version absent from the latest successful observation is no longer confirmed")
			assert.False(t, satisfied)
			_, found, satisfied, err = m.checkRequirement("other", "1.0.0")
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
			_, found, satisfied, err = m.checkRequirement(tc.capability, "1.0.0")
			require.NoError(t, err)
			assert.True(t, found && satisfied)
			require.Len(t, chA, 1, "reappearance at the same version must notify subscribers")
			require.Len(t, chB, 1)
			<-chA
			<-chB

			m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(nil).Result)
			for _, name := range []string{tc.capability, "other"} {
				_, found, satisfied, err = m.checkRequirement(name, "1.0.0")
				require.NoError(t, err)
				assert.False(t, found || satisfied, "a successful empty snapshot must invalidate every confirmed version")
			}
			assert.Len(t, chA, 1, "one snapshot emits one notification, even when multiple versions disappear")
			assert.Len(t, chB, 1)
		})
	}
}

func TestNode_Events_MultipleSubscribersEachReceiveEveryEvent(t *testing.T) {
	m := newTestNode()
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

func TestNode_RefreshFalcoVersions_MergesFetchedSnapshot(t *testing.T) {
	m := newTestNodeWithFetcher(compatfake.NewMockVersionsFetcher(map[string]string{
		"engine_version_semver": "0.62.0",
	}))

	versions, err := m.refreshFalcoVersions(context.Background())
	require.NoError(t, err)
	require.NotNil(t, versions)

	_, found, satisfied, err := m.checkRequirement("engine_version_semver", "0.57.0")
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, satisfied)
}

func TestNode_RefreshFalcoVersions_PropagatesFetchError(t *testing.T) {
	fetcher := compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"})
	m := newTestNodeWithFetcher(fetcher)
	_, err := m.refreshFalcoVersions(context.Background())
	require.NoError(t, err)
	ch := m.Events()
	fetcher.FetchErr = assert.AnError

	_, err = m.refreshFalcoVersions(context.Background())

	require.Error(t, err)
	version, found, satisfied, err := m.checkRequirement("container", "0.7.1")
	require.NoError(t, err)
	assert.Equal(t, "0.7.1", version)
	assert.True(t, found && satisfied, "a failed fetch must preserve the last successful observation")
	assert.Empty(t, ch)

	fetcher.FetchErr = nil
	fetcher.Result = compatfake.NewMockVersionsFetcherWithPlugins(nil).Result
	_, err = m.refreshFalcoVersions(context.Background())
	require.NoError(t, err)
	_, found, satisfied, err = m.checkRequirement("container", "0.7.1")
	require.NoError(t, err)
	assert.False(t, found || satisfied, "a subsequent successful empty response must invalidate the old version")
	assert.Len(t, ch, 1)
}
