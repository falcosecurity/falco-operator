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
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

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
