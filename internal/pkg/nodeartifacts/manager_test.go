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
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, fetcher)
	require.NoError(t, err)
	_, _, err = m.AddPluginConfig(context.Background(), testPlugin("container-alt"), nil, fetcher)
	require.NoError(t, err)

	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "my-rulesfile"}
	m.Sync(rfKey, []nodeartifacts.RequirementGroup{{{Name: "container", Version: "1.0.0"}, {Name: "container-alt", Version: "1.0.0"}}})

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
	m.Sync(rfKey, []nodeartifacts.RequirementGroup{{{Name: "container", Version: "1.0.0"}, {Name: "container-alt", Version: "1.0.0"}}})

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
	m.Sync(rfKey, []nodeartifacts.RequirementGroup{{{Name: "container", Version: "1.0.0"}}})

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
			m.SyncProvides(nodeartifacts.PluginConfigKey, primary.Name)
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
		{name: "later alternative when first unobserved", versions: map[string]string{"a-second": "2.0.0"}},
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
				_, file, err := m.AddPluginConfig(t.Context(), testPlugin(name), nil, fetcher)
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

func TestManager_OnFalcoVersionsObserved_PreservesExistingKeyUpdatesVersion(t *testing.T) {
	m := newTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, fetcher)
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
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, &artifact.Fetcher{})
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
	m := newTestManagerWithFetcher(&compatfake.MockVersionsFetcher{FetchErr: assert.AnError})

	_, err := m.RefreshFalcoVersions(context.Background())

	require.Error(t, err)
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
		_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, fetcher)
		require.NoError(t, err)
	}
	<-done
}
