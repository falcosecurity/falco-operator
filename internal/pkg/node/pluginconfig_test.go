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

// Internal test file for package node, covering the unexported types pluginConfig,
// initConfig, and pluginsConfig.
package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

// installedPluginName is the shared file's entry plugin currently holds, or "" if it holds none.
// Production resolves the owner itself and calls claimedNameLocked; these tests start from the CR,
// so they get the one-step form here rather than in the node's own code.
func (n *Node) installedPluginName(plugin *artifactv1alpha1.Plugin) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	owner := pluginOwner(plugin)
	return n.claimedNameLocked(&owner)
}

// removeConfig removes plugin's entry, resolved via resolveConfigName. Test-only: production
// code always resolves the config name itself and calls removeByName directly.
func (pc *pluginsConfig) removeConfig(plugin *artifactv1alpha1.Plugin) {
	pc.removeByName(resolveConfigName(plugin))
}

// isEmpty reports whether pc has no configs and no load_plugins entries. Test-only.
func (pc *pluginsConfig) isEmpty() bool {
	return len(pc.Configs) == 0 && len(pc.LoadPlugins) == 0
}

func defaultLibraryPath(t *testing.T, name string) string {
	t.Helper()
	return testutil.MustArtifactPath(t, artifact.DefaultArtifactDirs(), name, priority.DefaultPriority, artifact.MediumOCI, artifact.KindPlugin)
}

func TestNode_ObservationPreservesDesiredPluginConfig(t *testing.T) {
	ctx := context.Background()
	mockFS := fsfake.NewMockFileSystem()
	m := newArtifacts(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container"}}
	_, file, err := m.AddPluginConfig(ctx, plugin)
	require.NoError(t, err)
	rulesKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
	metadata := &commonv1alpha1.ArtifactMeta{
		Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "0.7.0"}},
	}
	fetcher := &artifact.Fetcher{}
	rulesContent, err := fetcher.FetchInline(ctx, []byte("test rules"))
	require.NoError(t, err)
	_, _, err = m.StoreRulesfile(ctx, rulesKey.Name, 50, artifact.MediumOCI, rulesContent, metadata, false)
	require.NoError(t, err)
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1", "external": "1.0.0"}).Result)
	content := string(mockFS.Files[file.Path])
	writes := len(mockFS.WriteCalls)

	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(nil).Result)
	p, ok := m.provides["container"]
	require.True(t, ok, "a configured plugin keeps its structural registration")
	assert.False(t, p.ObservedOnly, "it stays a configured plugin")
	assert.Empty(t, p.Version, "only its confirmed runtime version is invalidated")
	assert.NotContains(t, m.provides, "external", "an observation-only entry has no desired registration to preserve")
	assert.Equal(t, "container", m.installedPluginName(plugin))
	assert.Equal(t, []string{"container"}, m.pluginsConfig.LoadPlugins)
	assert.Equal(t, metadata, m.requiresLocked(rulesKey, artifact.MediumOCI)[0].Metadata)
	assert.Equal(t, content, string(mockFS.Files[file.Path]))
	assert.Len(t, mockFS.WriteCalls, writes, "an observation must not rewrite or remove artifact files")
	assert.Empty(t, mockFS.RemoveCalls)
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"}).Result)
	assert.Equal(t, provided{Version: "0.7.1"}, m.provides["container"])
}

func TestPluginsConfig_AddConfig(t *testing.T) {
	tests := []struct {
		name            string
		initial         *pluginsConfig
		plugin          *artifactv1alpha1.Plugin
		callTwice       bool
		expectedConfigs []pluginConfig
		expectedLoad    []string
	}{
		{
			name:    "add plugin with no spec.config",
			initial: &pluginsConfig{},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
			},
			expectedConfigs: []pluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath(t, "json")},
			},
			expectedLoad: []string{"json"},
		},
		{
			name:    "add plugin with spec.config.name override",
			initial: &pluginsConfig{},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-json-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						Name: "json",
					},
				},
			},
			expectedConfigs: []pluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath(t, "my-json-plugin")},
			},
			expectedLoad: []string{"json"},
		},
		{
			name:    "add plugin with full spec.config",
			initial: &pluginsConfig{},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						Name:        "json",
						LibraryPath: "/custom/path/json.so",
						InitConfig: &apiextensionsv1.JSON{
							Raw: []byte(`{"sssURL": "https://example.com"}`),
						},
						OpenParams: "some-params",
					},
				},
			},
			expectedConfigs: []pluginConfig{
				{
					Name:        "json",
					LibraryPath: "/custom/path/json.so",
					InitConfig:  &initConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"sssURL": "https://example.com"}`)}},
					OpenParams:  "some-params",
				},
			},
			expectedLoad: []string{"json"},
		},
		{
			name:      "skip identical config (no duplicate)",
			initial:   &pluginsConfig{},
			callTwice: true,
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
			},
			expectedConfigs: []pluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath(t, "json")},
			},
			expectedLoad: []string{"json"},
		},
		{
			name: "update existing config when initConfig changes",
			initial: &pluginsConfig{
				Configs: []pluginConfig{
					{
						Name:        "json",
						LibraryPath: defaultLibraryPath(t, "json"),
						InitConfig:  &initConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"sssURL": "https://initial.example.com"}`)}},
					},
				},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						InitConfig: &apiextensionsv1.JSON{Raw: []byte(`{"sssURL": "https://updated.example.com"}`)},
					},
				},
			},
			expectedConfigs: []pluginConfig{
				{
					Name:        "json",
					LibraryPath: defaultLibraryPath(t, "json"),
					InitConfig:  &initConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"sssURL": "https://updated.example.com"}`)}},
				},
			},
			expectedLoad: []string{"json"},
		},
		{
			name: "update existing config when openParams changes",
			initial: &pluginsConfig{
				Configs:     []pluginConfig{{Name: "json", LibraryPath: defaultLibraryPath(t, "json"), OpenParams: "old-params"}},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						OpenParams: "new-params",
					},
				},
			},
			expectedConfigs: []pluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath(t, "json"), OpenParams: "new-params"},
			},
			expectedLoad: []string{"json"},
		},
		{
			name: "add second plugin preserves existing",
			initial: &pluginsConfig{
				Configs:     []pluginConfig{{Name: "json", LibraryPath: defaultLibraryPath(t, "json")}},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "k8saudit"},
			},
			expectedConfigs: []pluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath(t, "json")},
				{Name: "k8saudit", LibraryPath: defaultLibraryPath(t, "k8saudit")},
			},
			expectedLoad: []string{"json", "k8saudit"},
		},
		{
			name: "loadPlugins uses config.Name not CR name",
			initial: &pluginsConfig{
				Configs:     []pluginConfig{{Name: "existing", LibraryPath: defaultLibraryPath(t, "existing")}},
				LoadPlugins: []string{"existing"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-json-cr"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						Name: "json",
					},
				},
			},
			expectedConfigs: []pluginConfig{
				{Name: "existing", LibraryPath: defaultLibraryPath(t, "existing")},
				{Name: "json", LibraryPath: defaultLibraryPath(t, "my-json-cr")},
			},
			expectedLoad: []string{"existing", "json"},
		},
		{
			name:    "empty initConfig raw bytes are ignored",
			initial: &pluginsConfig{},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						InitConfig: &apiextensionsv1.JSON{Raw: []byte{}},
					},
				},
			},
			expectedConfigs: []pluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath(t, "json")},
			},
			expectedLoad: []string{"json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := tt.initial

			if tt.callTwice {
				require.NoError(t, pc.addConfig(artifact.DefaultArtifactDirs().Plugin, tt.plugin))
			}
			require.NoError(t, pc.addConfig(artifact.DefaultArtifactDirs().Plugin, tt.plugin))

			assert.Equal(t, tt.expectedConfigs, pc.Configs)
			assert.Equal(t, tt.expectedLoad, pc.LoadPlugins)
		})
	}
}

func TestPluginsConfig_RemoveConfig(t *testing.T) {
	tests := []struct {
		name            string
		initial         *pluginsConfig
		plugin          *artifactv1alpha1.Plugin
		expectedConfigs []pluginConfig
		expectedLoad    []string
		expectedEmpty   bool
	}{
		{
			name: "remove plugin by CR name",
			initial: &pluginsConfig{
				Configs:     []pluginConfig{{Name: "json", LibraryPath: defaultLibraryPath(t, "json")}},
				LoadPlugins: []string{"json"},
			},
			plugin:          &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}},
			expectedConfigs: []pluginConfig{},
			expectedLoad:    []string{},
			expectedEmpty:   true,
		},
		{
			name: "remove plugin when spec.config.name differs from CR name",
			initial: &pluginsConfig{
				Configs:     []pluginConfig{{Name: "json", LibraryPath: defaultLibraryPath(t, "my-json-plugin")}},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-json-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{Name: "json"},
				},
			},
			expectedConfigs: []pluginConfig{},
			expectedLoad:    []string{},
			expectedEmpty:   true,
		},
		{
			name: "remove non-existent plugin is a no-op",
			initial: &pluginsConfig{
				Configs:     []pluginConfig{{Name: "json", LibraryPath: defaultLibraryPath(t, "json")}},
				LoadPlugins: []string{"json"},
			},
			plugin:          &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "nonexistent"}},
			expectedConfigs: []pluginConfig{{Name: "json", LibraryPath: defaultLibraryPath(t, "json")}},
			expectedLoad:    []string{"json"},
			expectedEmpty:   false,
		},
		{
			name: "remove one plugin preserves others",
			initial: &pluginsConfig{
				Configs: []pluginConfig{
					{Name: "json", LibraryPath: defaultLibraryPath(t, "json")},
					{Name: "k8saudit", LibraryPath: defaultLibraryPath(t, "k8saudit")},
				},
				LoadPlugins: []string{"json", "k8saudit"},
			},
			plugin:          &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}},
			expectedConfigs: []pluginConfig{{Name: "k8saudit", LibraryPath: defaultLibraryPath(t, "k8saudit")}},
			expectedLoad:    []string{"k8saudit"},
			expectedEmpty:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := tt.initial
			pc.removeConfig(tt.plugin)

			assert.Equal(t, tt.expectedConfigs, pc.Configs)
			assert.Equal(t, tt.expectedLoad, pc.LoadPlugins)
			assert.Equal(t, tt.expectedEmpty, pc.isEmpty())
		})
	}
}

func TestPluginsConfig_AddThenRemove_RoundTrip(t *testing.T) {
	t.Run("add and remove with mismatched names cleans up fully", func(t *testing.T) {
		pc := &pluginsConfig{}

		plugin := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "my-json-plugin"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{Name: "json"},
			},
		}

		require.NoError(t, pc.addConfig(artifact.DefaultArtifactDirs().Plugin, plugin))
		assert.Len(t, pc.Configs, 1)
		assert.Equal(t, "json", pc.Configs[0].Name)
		assert.Equal(t, []string{"json"}, pc.LoadPlugins)

		pc.removeConfig(plugin)
		assert.Empty(t, pc.Configs)
		assert.Empty(t, pc.LoadPlugins)
		assert.True(t, pc.isEmpty())
	})

	t.Run("changing spec.config.name removes stale entry via installed ownership", func(t *testing.T) {
		m := newPluginConfigTestManager()

		plugin := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{Name: "json"},
			},
		}
		_, _, err := m.AddPluginConfig(t.Context(), plugin)
		require.NoError(t, err)
		require.Len(t, m.pluginsConfig.Configs, 1)
		assert.Equal(t, "json", m.pluginsConfig.Configs[0].Name)
		assert.Equal(t, []string{"json"}, m.pluginsConfig.LoadPlugins)

		pluginRenamed := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{Name: "json-v2"},
			},
		}

		_, _, err = m.AddPluginConfig(t.Context(), pluginRenamed)
		require.NoError(t, err)

		require.Len(t, m.pluginsConfig.Configs, 1)
		assert.Equal(t, "json-v2", m.pluginsConfig.Configs[0].Name)
		assert.Equal(t, []string{"json-v2"}, m.pluginsConfig.LoadPlugins)

		require.NoError(t, m.RemovePluginConfig(t.Context(), pluginRenamed))
		assert.True(t, m.pluginsConfig.isEmpty())
	})

	t.Run("add, update, then remove", func(t *testing.T) {
		pc := &pluginsConfig{}

		plugin := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "json"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{
					InitConfig: &apiextensionsv1.JSON{Raw: []byte(`{"sssURL": "https://initial.example.com"}`)},
				},
			},
		}

		require.NoError(t, pc.addConfig(artifact.DefaultArtifactDirs().Plugin, plugin))
		var initialConfig map[string]any
		require.NoError(t, json.Unmarshal(pc.Configs[0].InitConfig.Raw, &initialConfig))
		assert.Equal(t, "https://initial.example.com", initialConfig["sssURL"])

		pluginUpdated := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "json"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{
					InitConfig: &apiextensionsv1.JSON{Raw: []byte(`{"sssURL": "https://updated.example.com"}`)},
				},
			},
		}
		require.NoError(t, pc.addConfig(artifact.DefaultArtifactDirs().Plugin, pluginUpdated))
		require.Len(t, pc.Configs, 1)
		var updatedConfig map[string]any
		require.NoError(t, json.Unmarshal(pc.Configs[0].InitConfig.Raw, &updatedConfig))
		assert.Equal(t, "https://updated.example.com", updatedConfig["sssURL"])
		assert.Equal(t, []string{"json"}, pc.LoadPlugins)

		pc.removeConfig(pluginUpdated)
		assert.True(t, pc.isEmpty())
	})
}

func TestPluginsConfig_ToString(t *testing.T) {
	tests := []struct {
		name        string
		pc          *pluginsConfig
		contains    []string
		notContains []string
	}{
		{
			name: "serializes to yaml",
			pc: &pluginsConfig{
				Configs: []pluginConfig{
					{Name: "json", LibraryPath: "/usr/share/falco/plugins/json.so"},
				},
				LoadPlugins: []string{"json"},
			},
			contains: []string{
				"name: json",
				"library_path: /usr/share/falco/plugins/json.so",
				"load_plugins:",
				"- json",
			},
		},
		{
			name:     "empty config serializes without load_plugins",
			pc:       &pluginsConfig{},
			contains: []string{"plugins: []"},
		},
		{
			name: "nested init_config serializes as nested yaml",
			pc: &pluginsConfig{
				Configs: []pluginConfig{
					{
						Name:        "container",
						LibraryPath: "/usr/share/falco/plugins/container.so",
						InitConfig: &initConfig{
							JSON: &apiextensionsv1.JSON{
								Raw: []byte(`{"hooks":["create"],"label_max_len":"100","engines":{"containerd":{"enabled":true}}}`),
							},
						},
					},
				},
				LoadPlugins: []string{"container"},
			},
			contains: []string{
				"init_config:",
				"hooks:",
				"- create",
				"label_max_len:",
				"engines:",
				"containerd:",
				"enabled: true",
			},
			notContains: []string{
				"raw:",
				"Raw:",
			},
		},
		{
			name: "config with open_params serializes correctly",
			pc: &pluginsConfig{
				Configs: []pluginConfig{
					{
						Name:        "k8saudit",
						LibraryPath: "/usr/share/falco/plugins/k8saudit.so",
						OpenParams:  "http://:9765/k8s-audit",
					},
				},
				LoadPlugins: []string{"k8saudit"},
			},
			contains: []string{
				"open_params: http://:9765/k8s-audit",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.pc.toString()
			require.NoError(t, err)
			for _, s := range tt.contains {
				assert.Contains(t, result, s)
			}
			for _, s := range tt.notContains {
				assert.NotContains(t, result, s)
			}
		})
	}
}

func TestPluginsConfig_IsEmpty(t *testing.T) {
	assert.True(t, (&pluginsConfig{}).isEmpty())
	assert.False(t, (&pluginsConfig{Configs: []pluginConfig{{Name: "json"}}}).isEmpty())
	assert.False(t, (&pluginsConfig{LoadPlugins: []string{"json"}}).isEmpty())
}

func TestPluginConfig_IsSame(t *testing.T) {
	tests := []struct {
		name     string
		a        pluginConfig
		b        pluginConfig
		expected bool
	}{
		{
			name:     "identical configs",
			a:        pluginConfig{LibraryPath: "/a.so", OpenParams: "p", InitConfig: &initConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"k": "v"}`)}}},
			b:        pluginConfig{LibraryPath: "/a.so", OpenParams: "p", InitConfig: &initConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"k": "v"}`)}}},
			expected: true,
		},
		{
			name:     "different library path",
			a:        pluginConfig{LibraryPath: "/a.so"},
			b:        pluginConfig{LibraryPath: "/b.so"},
			expected: false,
		},
		{
			name:     "different open params",
			a:        pluginConfig{LibraryPath: "/a.so", OpenParams: "p1"},
			b:        pluginConfig{LibraryPath: "/a.so", OpenParams: "p2"},
			expected: false,
		},
		{
			name:     "different init config",
			a:        pluginConfig{LibraryPath: "/a.so", InitConfig: &initConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"k": "v1"}`)}}},
			b:        pluginConfig{LibraryPath: "/a.so", InitConfig: &initConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"k": "v2"}`)}}},
			expected: false,
		},
		{
			name:     "name difference is ignored by isSame",
			a:        pluginConfig{Name: "a", LibraryPath: "/a.so"},
			b:        pluginConfig{Name: "b", LibraryPath: "/a.so"},
			expected: true,
		},
		{
			name:     "both nil init config",
			a:        pluginConfig{LibraryPath: "/a.so"},
			b:        pluginConfig{LibraryPath: "/a.so"},
			expected: true,
		},
		{
			name:     "one nil one non-nil init config",
			a:        pluginConfig{LibraryPath: "/a.so", InitConfig: &initConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{}`)}}},
			b:        pluginConfig{LibraryPath: "/a.so"},
			expected: false,
		},
		{
			name:     "reversed nil vs non-nil init config",
			a:        pluginConfig{LibraryPath: "/a.so"},
			b:        pluginConfig{LibraryPath: "/a.so", InitConfig: &initConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{}`)}}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.a.isSame(&tt.b))
		})
	}
}

func TestInitConfig_MarshalYAML(t *testing.T) {
	tests := []struct {
		name    string
		ic      *initConfig
		wantNil bool
		wantErr bool
	}{
		{
			name:    "nil initConfig returns nil",
			ic:      nil,
			wantNil: true,
		},
		{
			name:    "nil JSON returns nil",
			ic:      &initConfig{JSON: nil},
			wantNil: true,
		},
		{
			name:    "empty raw bytes returns nil",
			ic:      &initConfig{JSON: &apiextensionsv1.JSON{Raw: []byte{}}},
			wantNil: true,
		},
		{
			name: "valid JSON returns parsed data",
			ic:   &initConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"key":"value"}`)}},
		},
		{
			name:    "invalid JSON returns error",
			ic:      &initConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{invalid`)}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.ic.MarshalYAML()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}

func findPluginConfig(configs []pluginConfig, name string) *pluginConfig {
	for i := range configs {
		if configs[i].Name == name {
			return &configs[i]
		}
	}
	return nil
}

func newPluginConfigTestManager() *Node {
	return newArtifacts(&artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
}

func TestNode_AddPluginConfig_WritesConfigForBasicPlugin(t *testing.T) {
	m := newPluginConfigTestManager()
	pl := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "json"},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "r", Tag: "t"}},
		},
	}

	action, file, err := m.AddPluginConfig(context.Background(), pl)

	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionAdded, action)
	require.NotNil(t, file)
	require.Len(t, m.pluginsConfig.Configs, 1)
	found := findPluginConfig(m.pluginsConfig.Configs, "json")
	require.NotNil(t, found)
	assert.Equal(t, "json", m.installedPluginName(pl))
}

func TestNode_AddPluginConfig_WritesConfigWithInitConfig(t *testing.T) {
	m := newPluginConfigTestManager()
	pl := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "container"},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "r", Tag: "t"}},
			Config: &artifactv1alpha1.PluginConfig{
				InitConfig: &apiextensionsv1.JSON{Raw: []byte(`{"engines":{"containerd":{"enabled":true}}}`)},
			},
		},
	}

	_, _, err := m.AddPluginConfig(context.Background(), pl)

	require.NoError(t, err)
	found := findPluginConfig(m.pluginsConfig.Configs, "container")
	require.NotNil(t, found)
	require.NotNil(t, found.InitConfig)
	expected := string(pl.Spec.Config.InitConfig.Raw)
	pl.Spec.Config.InitConfig.Raw[0] = '['
	assert.JSONEq(t, expected, string(found.InitConfig.Raw), "installed config must not alias the caller's buffer")

	// Another plugin serializes the full aggregate again, including the owned init_config.
	another := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}
	_, file, err := m.AddPluginConfig(t.Context(), another)
	require.NoError(t, err)
	require.NotNil(t, file)
	data, err := m.disk.(*artifact.LocalStore).FS.ReadFile(file.Path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "containerd:")
	assert.Contains(t, string(data), "enabled: true")
}

func TestNode_AddPluginConfig_RenameRemovesStaleEntryWhenUnblocked(t *testing.T) {
	m := newPluginConfigTestManager()
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"}}
	_, _, err := m.AddPluginConfig(context.Background(), pl)
	require.NoError(t, err)
	require.NotNil(t, findPluginConfig(m.pluginsConfig.Configs, "my-plugin"))

	pl.Spec.Config = &artifactv1alpha1.PluginConfig{Name: "new-name"}
	_, _, err = m.AddPluginConfig(context.Background(), pl)

	require.NoError(t, err)
	require.Len(t, m.pluginsConfig.Configs, 1)
	assert.Nil(t, findPluginConfig(m.pluginsConfig.Configs, "my-plugin"))
	assert.NotNil(t, findPluginConfig(m.pluginsConfig.Configs, "new-name"))
	assert.Equal(t, "new-name", m.installedPluginName(pl))
}

func TestNode_AddPluginConfig_SameConfigNameDoesNotRemoveEntry(t *testing.T) {
	m := newPluginConfigTestManager()
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}
	_, _, err := m.AddPluginConfig(context.Background(), pl)
	require.NoError(t, err)

	_, _, err = m.AddPluginConfig(context.Background(), pl)

	require.NoError(t, err)
	require.Len(t, m.pluginsConfig.Configs, 1)
}

func TestNode_PluginConfigYAMLRoundTripPreservesNoOpAndOrder(t *testing.T) {
	ctx := t.Context()
	fs := fsfake.NewMockFileSystem()
	store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
	versions := compatfake.NewMockVersionsFetcher(nil)
	before := newArtifacts(store, versions)
	pluginA := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "a", UID: "uid-a"},
		Spec: artifactv1alpha1.PluginSpec{Config: &artifactv1alpha1.PluginConfig{
			InitConfig: &apiextensionsv1.JSON{Raw: []byte(`{ "nested": { "enabled": true } }`)},
		}},
	}
	pluginB := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "b", UID: "uid-b"}}
	for _, plugin := range []*artifactv1alpha1.Plugin{pluginA, pluginB} {
		_, _, err := before.AddPluginConfig(ctx, plugin)
		require.NoError(t, err)
	}
	file := before.pluginsConfigFile
	require.NotNil(t, file)
	content := string(fs.Files[file.Path])
	after := newArtifacts(store, versions)
	disk, err := after.ScanAll(ctx, artifact.KindConfig)
	require.NoError(t, err)
	after.seedPluginsConfigFile(disk[pluginConfigFileName][0])
	writes := len(fs.WriteCalls)
	fs.WriteErr = errors.New("unexpected no-op write")
	require.NoError(t, after.restorePluginsConfig(ctx, []*artifactv1alpha1.Plugin{pluginB, pluginA}))
	assert.Len(t, fs.WriteCalls, writes, "reading an unchanged aggregate must not rewrite it")
	assert.Equal(t, map[string]ownerRef{"a": pluginOwner(pluginA), "b": pluginOwner(pluginB)}, after.ownersLocked())
	require.Len(t, after.pluginsConfig.Configs, 2)
	require.NotNil(t, after.pluginsConfig.Configs[0].InitConfig)
	assert.JSONEq(t, string(pluginA.Spec.Config.InitConfig.Raw), string(after.pluginsConfig.Configs[0].InitConfig.Raw))
	require.NotEqual(t, string(pluginA.Spec.Config.InitConfig.Raw), string(after.pluginsConfig.Configs[0].InitConfig.Raw),
		"the fixture must exercise whitespace normalization when decoding init_config YAML")

	action, _, err := after.AddPluginConfig(ctx, pluginA)

	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUnchanged, action)
	assert.Len(t, fs.WriteCalls, writes)
	assert.Equal(t, content, string(fs.Files[file.Path]))
	assert.Equal(t, []string{"a", "b"}, after.pluginsConfig.LoadPlugins)
	require.Len(t, after.pluginsConfig.Configs, 2)
	assert.Equal(t, "a", after.pluginsConfig.Configs[0].Name)
	assert.Equal(t, "b", after.pluginsConfig.Configs[1].Name)
}

func TestNode_RestorePluginsConfig_UsesCurrentAliasesAndObservedSettings(t *testing.T) {
	ctx := t.Context()
	fs := fsfake.NewMockFileSystem()
	store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
	versions := compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{
		"kept": "0.7.4", "renamed": "0.7.4", "orphan": "0.7.4", "collision": "0.7.4",
	})
	before := newArtifacts(store, versions)
	kept := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "owner", UID: "old-uid"},
		Spec: artifactv1alpha1.PluginSpec{Config: &artifactv1alpha1.PluginConfig{
			Name: "kept", LibraryPath: "/custom/installed.so", OpenParams: "installed",
			InitConfig: &apiextensionsv1.JSON{Raw: []byte(`{"nested":{"enabled":true}}`)},
		}},
	}
	renamed := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "renamed", UID: "renamed-uid"}}
	collision := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "collision", UID: "collision-uid"}}
	orphan := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "orphan", UID: "orphan-uid"}}
	for _, plugin := range []*artifactv1alpha1.Plugin{kept, renamed, collision, orphan} {
		_, _, err := before.AddPluginConfig(ctx, plugin)
		require.NoError(t, err)
	}
	current := kept.DeepCopy()
	current.UID = "current-uid"
	current.Spec.Config.LibraryPath = "/custom/not-installed.so"
	current.Spec.Config.OpenParams = "not installed"
	current.Spec.Config.InitConfig.Raw = []byte(`{"nested":{"enabled":false}}`)
	renamed.Spec.Config = &artifactv1alpha1.PluginConfig{Name: "new-name"}
	other := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "other", UID: "other-uid"},
		Spec:       artifactv1alpha1.PluginSpec{Config: &artifactv1alpha1.PluginConfig{Name: "collision"}},
	}
	after := newArtifacts(store, versions)
	after.OnFalcoVersionsObserved(versions.Result)
	disk, err := after.ScanAll(ctx, artifact.KindConfig)
	require.NoError(t, err)
	after.seedPluginsConfigFile(disk[pluginConfigFileName][0])

	require.NoError(t, after.restorePluginsConfig(ctx, []*artifactv1alpha1.Plugin{current, renamed, collision, other}))

	require.Len(t, after.pluginsConfig.Configs, 1)
	assert.Equal(t, []string{"kept"}, after.pluginsConfig.LoadPlugins)
	assert.Equal(t, map[string]ownerRef{"kept": pluginOwner(current)}, after.ownersLocked(),
		"ownership is claimed by the current CR, not recovered from history")
	assert.Equal(t, kept.Spec.Config.LibraryPath, after.pluginsConfig.Configs[0].LibraryPath)
	assert.Equal(t, kept.Spec.Config.OpenParams, after.pluginsConfig.Configs[0].OpenParams)
	assert.JSONEq(t, string(kept.Spec.Config.InitConfig.Raw), string(after.pluginsConfig.Configs[0].InitConfig.Raw))
	assert.NotContains(t, after.provides, "new-name", "a changed alias is not installed by recovery")
	for _, name := range []string{"renamed", "orphan", "collision"} {
		assert.True(t, after.provides[name].Removed)
		assert.Empty(t, after.provides[name].Version)
	}
	after.OnFalcoVersionsObserved(versions.Result)
	assert.Equal(t, provided{Version: "0.7.4"}, after.provides["kept"])
	for _, name := range []string{"renamed", "orphan", "collision"} {
		assert.True(t, after.provides[name].Removed, "a pre-reload observation must not resurrect a pruned alias")
	}
	file := after.pluginsConfigFile
	require.NotNil(t, file)
	content, err := after.pluginsConfig.toString()
	require.NoError(t, err)
	assert.Equal(t, content, string(fs.Files[file.Path]))
	_, _, err = after.AddPluginConfig(ctx, current)
	require.NoError(t, err)
	assert.Equal(t, current.Spec.Config.LibraryPath, after.pluginsConfig.Configs[0].LibraryPath,
		"only normal reconciliation applies the changed settings")
	assert.Equal(t, current.Spec.Config.OpenParams, after.pluginsConfig.Configs[0].OpenParams)
}

func TestNode_RestorePluginsConfig_HandlesMissingCorruptAndFailedIO(t *testing.T) {
	const readFailure, writeFailure, renameFailure = "read failure", "write failure", "rename failure"
	const missingFile, invalidYAML = "missing file", "invalid YAML"
	for _, scenario := range []string{missingFile, invalidYAML, readFailure, writeFailure, renameFailure} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			before := newArtifacts(store, compatfake.NewMockVersionsFetcher(nil))
			plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "orphan", UID: "orphan-uid"}}
			_, file, err := before.AddPluginConfig(ctx, plugin)
			require.NoError(t, err)
			after := newArtifacts(store, compatfake.NewMockVersionsFetcher(nil))
			after.pluginsConfigFile = before.pluginsConfigFile
			original := string(fs.Files[file.Path])
			ioErr := errors.New("filesystem unavailable")
			switch scenario {
			case missingFile:
				require.NoError(t, fs.Remove(file.Path))
			case invalidYAML:
				require.NoError(t, fs.WriteFile(file.Path, []byte("plugins: ["), 0o644))
			case readFailure:
				fs.ReadErrFor = map[string]error{file.Path: ioErr}
			case writeFailure:
				fs.WriteErrFor = map[string]error{artifact.StagingPath(file.Path): ioErr}
			case renameFailure:
				fs.RenameErrFor = map[string]error{artifact.StagingPath(file.Path): ioErr}
			}

			err = after.restorePluginsConfig(ctx, nil)

			if scenario == missingFile {
				require.NoError(t, err)
				assert.Nil(t, after.pluginsConfigFile)
				assert.NotContains(t, fs.Files, file.Path)
				return
			}
			if scenario != invalidYAML {
				require.ErrorIs(t, err, ioErr)
				assert.Equal(t, original, string(fs.Files[file.Path]), "failed recovery must not replace installed output")
				assert.Empty(t, after.ownersLocked(), "failed recovery must not publish new ownership")
				fs.ReadErrFor, fs.WriteErrFor, fs.RenameErrFor = nil, nil, nil
				require.NoError(t, after.restorePluginsConfig(ctx, nil), "recovery must be retryable")
			} else {
				require.NoError(t, err, "malformed observed output must not prevent rebuilding from current CRs")
			}
			assert.Empty(t, after.pluginsConfig.Configs)
			assert.Empty(t, after.pluginsConfig.LoadPlugins)
			assert.Empty(t, after.ownersLocked())
			assert.NotContains(t, fs.Files, artifact.StagingPath(file.Path))
			assert.Contains(t, string(fs.Files[file.Path]), "plugins: []")
			intact, err := after.Verify(ctx, after.pluginsConfigFile)
			require.NoError(t, err)
			assert.True(t, intact)
		})
	}
}

func TestNode_AddPluginConfig_StoreFailureSurfacesError(t *testing.T) {
	mockFS := fsfake.NewMockFileSystem()
	mockFS.WriteErr = fmt.Errorf("disk full")
	m := newArtifacts(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "test-plugin"}}

	_, _, err := m.AddPluginConfig(context.Background(), pl)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk full")
	assert.Empty(t, m.pluginsConfig.Configs, "a failed addition must not change the aggregate")
	assert.Empty(t, m.ownersLocked())
	assert.Empty(t, m.provides)
}

func TestNode_PluginConfigWriteFailurePreservesCommittedState(t *testing.T) {
	const removeOperation, renameOperation = "remove", "rename"
	for _, operation := range []string{removeOperation, renameOperation, "update"} {
		t.Run(operation, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			falco := compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"json": "0.7.4"})
			m := newArtifacts(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, falco)
			plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}
			_, file, err := m.AddPluginConfig(ctx, plugin)
			require.NoError(t, err)
			before := string(fs.Files[file.Path])
			fs.WriteErrFor = map[string]error{artifact.StagingPath(file.Path): fmt.Errorf("disk full")}
			switch operation {
			case removeOperation:
				err = m.RemovePluginConfig(ctx, plugin)
			case renameOperation:
				plugin.Spec.Config = &artifactv1alpha1.PluginConfig{Name: "renamed"}
				_, _, err = m.AddPluginConfig(ctx, plugin)
			case "update":
				plugin.Spec.Config = &artifactv1alpha1.PluginConfig{OpenParams: "changed"}
				_, _, err = m.AddPluginConfig(ctx, plugin)
			}
			require.ErrorContains(t, err, "disk full")
			assert.Equal(t, before, string(fs.Files[file.Path]))
			assert.Equal(t, "json", m.installedPluginName(plugin))
			assert.Equal(t, []string{"json"}, m.pluginsConfig.LoadPlugins)
			assert.Equal(t, provided{Version: "0.7.4"}, m.provides["json"])
			fs.WriteErrFor = nil
			assert.Equal(t, before, string(fs.Files[file.Path]))
			// Retrying the same operation must still perform it, not mistake the failed
			// in-memory mutation for a completed change.
			if operation == removeOperation {
				require.NoError(t, m.RemovePluginConfig(ctx, plugin))
				assert.Empty(t, m.pluginsConfig.LoadPlugins)
				assert.True(t, m.provides["json"].Removed)
			} else {
				_, _, err = m.AddPluginConfig(ctx, plugin)
				require.NoError(t, err)
				assert.NotEqual(t, before, string(fs.Files[file.Path]))
				if operation == renameOperation {
					assert.True(t, m.provides["json"].Removed, "the post-install poll still reports the old name")
					assert.Empty(t, m.provides["json"].Version)
					assert.Equal(t, "renamed", m.installedPluginName(plugin))
				}
			}
		})
	}
}

func TestNode_RemovePluginConfig_EmptyAfterRemovalKeepsFileOnDisk(t *testing.T) {
	// Removing the last plugin config entry rewrites the file to an empty config instead of
	// deleting it.
	m := newPluginConfigTestManager()
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}
	_, file, err := m.AddPluginConfig(context.Background(), pl)
	require.NoError(t, err)

	err = m.RemovePluginConfig(context.Background(), pl)

	require.NoError(t, err)
	assert.True(t, m.pluginsConfig.isEmpty())
	ok, verifyErr := m.Verify(context.Background(), file)
	require.NoError(t, verifyErr)
	assert.False(t, ok, "content changed (the json entry is gone), so the old file's hash must no longer verify")

	content, readErr := m.disk.(*artifact.LocalStore).FS.ReadFile(file.Path)
	require.NoError(t, readErr, "the config file must still exist on disk, just rewritten empty")
	assert.Contains(t, string(content), "plugins: []")
}

func TestNode_RemovePluginConfig_NotEmptyAfterRemovalWritesUpdatedConfig(t *testing.T) {
	m := newPluginConfigTestManager()
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}
	_, _, err := m.AddPluginConfig(context.Background(), pl)
	require.NoError(t, err)
	_, _, err = m.AddPluginConfig(context.Background(), &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "k8saudit"}})
	require.NoError(t, err)

	err = m.RemovePluginConfig(context.Background(), pl)

	require.NoError(t, err)
	assert.False(t, m.pluginsConfig.isEmpty())
	require.Len(t, m.pluginsConfig.Configs, 1)
	assert.NotNil(t, findPluginConfig(m.pluginsConfig.Configs, "k8saudit"))
}

func TestNode_RemovePluginConfig_AlreadyAbsentIsANoOp(t *testing.T) {
	m := newPluginConfigTestManager()
	_, _, err := m.AddPluginConfig(context.Background(), &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}})
	require.NoError(t, err)

	absent := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "nonexistent"}}
	err = m.RemovePluginConfig(context.Background(), absent)

	require.NoError(t, err)
	assert.False(t, m.pluginsConfig.isEmpty())
	require.Len(t, m.pluginsConfig.Configs, 1)
}

func TestNode_RemovePluginConfig_RetainsTombstoneWithoutOwner(t *testing.T) {
	m := newPluginConfigTestManager()
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}
	_, _, err := m.AddPluginConfig(context.Background(), pl)
	require.NoError(t, err)
	require.Equal(t, "json", m.installedPluginName(pl))

	require.NoError(t, m.RemovePluginConfig(context.Background(), pl))

	assert.Empty(t, m.installedPluginName(pl))
	assert.NotContains(t, m.ownersLocked(), "json")
	assert.True(t, m.provides["json"].Removed)
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"json": "0.7.4"}).Result)
	assert.True(t, m.provides["json"].Removed, "a delayed observation must not restore the removed provider")
	assert.Empty(t, m.provides["json"].Version)
}

func TestNode_RemovePluginPreservesEquivalentLibraryPaths(t *testing.T) {
	for _, alias := range []string{"./a.so", "../plugins/a.so"} {
		t.Run(alias, func(t *testing.T) {
			ctx := t.Context()
			store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
			before := newArtifacts(store, compatfake.NewMockVersionsFetcher(nil))
			plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "a", UID: "uid-a"}}
			fetcher := &artifact.Fetcher{}
			content, err := fetcher.FetchInline(ctx, []byte("shared binary"))
			require.NoError(t, err)
			content.Perm = testutil.MustPermFor(t, artifact.KindPlugin)
			info, err := artifact.InfoForKind(artifact.KindPlugin)
			require.NoError(t, err)
			key := artifact.RefOf(artifact.KindPlugin, plugin)
			_, err = before.storeSource(ctx, &info, key, artifact.MediumOCI,
				desired{Priority: priority.DefaultPriority, claim: pluginClaim(plugin)}, content)
			require.NoError(t, err)
			binary := before.FindInstalled(key, artifact.MediumOCI)
			require.NotNil(t, binary)
			_, _, err = before.AddPluginConfig(ctx, plugin)
			require.NoError(t, err)
			other := &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "b", UID: "uid-b"},
				Spec:       artifactv1alpha1.PluginSpec{Config: &artifactv1alpha1.PluginConfig{LibraryPath: store.Dirs.Plugin + "/" + alias}},
			}
			_, _, err = before.AddPluginConfig(ctx, other)
			require.NoError(t, err)
			require.NoError(t, before.RemovePluginConfig(ctx, plugin))
			after := newArtifacts(store, compatfake.NewMockVersionsFetcher(nil))
			disk, err := after.ScanAll(ctx, artifact.KindPlugin)
			require.NoError(t, err)
			after.SeedInstalled(key, disk[plugin.Name])
			disk, err = after.ScanAll(ctx, artifact.KindConfig)
			require.NoError(t, err)
			after.seedPluginsConfigFile(disk[pluginConfigFileName][0])
			require.NoError(t, after.restorePluginsConfig(ctx, []*artifactv1alpha1.Plugin{other}))

			for _, m := range []*Node{before, after} {
				removeErr := m.Remove(ctx, key)
				require.Error(t, removeErr, "another installed plugin still references the same library")
				_, removed, err := m.removeIfInstalled(ctx, key, artifact.MediumOCI)
				require.Error(t, err)
				assert.False(t, removed)
				intact, err := m.Verify(ctx, binary)
				require.NoError(t, err)
				assert.True(t, intact)
			}
			require.NoError(t, after.RemovePluginConfig(ctx, other))
			require.NoError(t, after.Remove(ctx, key))
			intact, err := after.Verify(ctx, binary)
			require.NoError(t, err)
			assert.False(t, intact, "removal becomes safe after the last reference is removed")
		})
	}
}

// A repeated shared-config write must use the installed cache for content deduplication.
func TestWritePluginsConfig_ClassifiesUnchangedContentCorrectly(t *testing.T) {
	m := newPluginConfigTestManager()
	m.mu.Lock()
	defer m.mu.Unlock()
	config := &pluginsConfig{}

	action, file, err := m.writePluginsConfigLocked(context.Background(), config, map[string]ownerRef{})
	require.NoError(t, err)
	require.NotNil(t, file)
	assert.Equal(t, artifact.StoreActionAdded, action, "first write of the shared config file is a real install")

	action, _, err = m.writePluginsConfigLocked(context.Background(), config, map[string]ownerRef{})
	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUnchanged, action,
		"byte-identical content must not be misreported as a fresh install")
}

// TestNode_AddPluginConfig_DedupsFromItsOwnCacheNotTheCaller checks that the node decides from its
// own record of the shared file whether a write can be skipped: a second call with an identical
// plugin config writes nothing.
func TestNode_AddPluginConfig_DedupsFromItsOwnCacheNotTheCaller(t *testing.T) {
	m := newTestNode()

	action1, file, err := m.AddPluginConfig(context.Background(), testPlugin("container"))
	require.NoError(t, err)
	require.NotNil(t, file)
	assert.Equal(t, artifact.StoreActionAdded, action1)

	action2, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"))
	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUnchanged, action2)
}

func TestNode_RemovePluginConfig_AllowedWhenNothingRequiresIt(t *testing.T) {
	m := newTestNode()
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"))
	require.NoError(t, err)

	err = m.RemovePluginConfig(context.Background(), testPlugin("container"))
	require.NoError(t, err)
}

func TestNode_RemovePluginConfig_BlockedWhenSoleProvider(t *testing.T) {
	m := newTestNode()
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"))
	require.NoError(t, err)

	rfKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: "my-rulesfile"}
	installTestRulesfile(t, m, rfKey, []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}})

	err = m.RemovePluginConfig(context.Background(), testPlugin("container"))

	require.Error(t, err)
	var blocked *BlockedError
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, "container", blocked.Name)
	assert.Contains(t, blocked.BlockedBy, rfKey)
}

func TestNode_RemovePluginConfig_AllowedWhenAlternativeCoversTheGroup(t *testing.T) {
	m := newTestNodeWithFetcher(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{
		"container": "1.0.0", "container-alt": "1.0.0",
	}))
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"))
	require.NoError(t, err)
	_, _, err = m.AddPluginConfig(context.Background(), testPlugin("container-alt"))
	require.NoError(t, err)

	rfKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: "my-rulesfile"}
	installTestRulesfile(t, m, rfKey, []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0", Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container-alt", Version: "1.0.0"}}}})

	err = m.RemovePluginConfig(context.Background(), testPlugin("container"))

	require.NoError(t, err, "container-alt still satisfies the group, so removing container must be allowed")
}

func TestNode_RemovePluginConfig_ClearsProvidesOnSuccess(t *testing.T) {
	m := newTestNode()
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"))
	require.NoError(t, err)
	require.NoError(t, m.RemovePluginConfig(context.Background(), testPlugin("container")))

	// container must have been cleared from provides by the removal above; container-alt is now
	// the sole remaining provider, so removing it next must be blocked.
	_, _, err = m.AddPluginConfig(context.Background(), testPlugin("container-alt"))
	require.NoError(t, err)
	rfKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: "my-rulesfile"}
	installTestRulesfile(t, m, rfKey, []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0", Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container-alt", Version: "1.0.0"}}}})

	err = m.RemovePluginConfig(context.Background(), testPlugin("container-alt"))
	require.Error(t, err, "container was already cleared from provides, so container-alt is the sole remaining provider and its removal must be blocked")
}

func TestNode_AddPluginConfig_RenameBlockedWhenOldNameStillRequired(t *testing.T) {
	m := newTestNode()
	pl := testPlugin("container")
	_, _, err := m.AddPluginConfig(context.Background(), pl)
	require.NoError(t, err)

	rfKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: "my-rulesfile"}
	installTestRulesfile(t, m, rfKey, []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}})

	pl.Spec.Config = &artifactv1alpha1.PluginConfig{Name: "renamed"}
	_, _, err = m.AddPluginConfig(context.Background(), pl)

	require.Error(t, err, "the old name \"container\" is still required, so the rename must be refused")
	var blocked *BlockedError
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, "container", blocked.Name)
}

func TestNode_RemovePluginConfig_ChecksRemainingVersions(t *testing.T) {
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
			m := newTestNodeOver(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
			var configFile *artifact.File
			for _, name := range []string{"primary", "z-first", "a-second", "unrelated"} {
				_, file, err := m.AddPluginConfig(t.Context(), testPlugin(name))
				require.NoError(t, err)
				configFile = file
			}
			versions := map[string]string{"primary": "1.0.0"}
			maps.Copy(versions, tt.versions)
			m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(versions).Result)
			key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
			installTestRulesfile(t, m, key, []commonv1alpha1.ArtifactMetaDependency{dep})
			remove := tt.remove
			if remove == "" {
				remove = "primary"
			}
			before, err := fs.ReadFile(configFile.Path)
			require.NoError(t, err)
			err = m.RemovePluginConfig(t.Context(), testPlugin(remove))
			if tt.wantBlocked {
				var blocked *BlockedError
				require.ErrorAs(t, err, &blocked)
				assert.Equal(t, []artifact.Ref{key}, blocked.BlockedBy)
				after, readErr := fs.ReadFile(configFile.Path)
				require.NoError(t, readErr)
				assert.Equal(t, before, after, "blocked removal must leave the shared config untouched")
				return
			}
			require.NoError(t, err)
			_, found, _, err := m.checkRequirement(remove, "1.0.0")
			require.NoError(t, err)
			assert.False(t, found)
		})
	}
}

func TestNode_RemovePluginConfig_StaleObservationCannotRestoreRemovedProvider(t *testing.T) {
	ctx := t.Context()
	falco := compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"json": "0.7.4", "container": "0.7.1"})
	m := newTestNodeWithFetcher(falco)
	for _, name := range []string{"json", "container"} {
		_, _, err := m.AddPluginConfig(ctx, testPlugin(name))
		require.NoError(t, err)
	}
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
	installTestRulesfile(t, m, key, []commonv1alpha1.ArtifactMetaDependency{{Name: "json", Version: "0.7.0", Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container", Version: "0.7.0"}}}})
	require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("json")))
	// Falco has not reloaded yet, so the next successful poll still reports both plugins.
	m.OnFalcoVersionsObserved(falco.Result)
	_, found, _, err := m.checkRequirement("json", "0.7.0")
	require.NoError(t, err)
	assert.False(t, found, "an observation must not undo our removal")
	var blocked *BlockedError
	require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("container")), &blocked)
	assert.Equal(t, []artifact.Ref{key}, blocked.BlockedBy)
	// Even a delayed old response after an observed unload cannot restore the name.
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"}).Result)
	m.OnFalcoVersionsObserved(falco.Result)
	require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("container")), &blocked)
	// An explicit re-add, unlike a poll, makes json eligible again once observed.
	_, _, err = m.AddPluginConfig(ctx, testPlugin("json"))
	require.NoError(t, err)
	require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("container")))
}

func TestNode_RemovePluginConfig_ObservedExternalAlternativeStillWorks(t *testing.T) {
	m := newTestNodeWithFetcher(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{
		"json": "0.7.4", "container": "0.7.1",
	}))
	_, _, err := m.AddPluginConfig(t.Context(), testPlugin("json"))
	require.NoError(t, err)
	installTestRulesfile(t, m, artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"},
		[]commonv1alpha1.ArtifactMetaDependency{{Name: "json", Version: "0.7.0", Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container", Version: "0.7.0"}}}})
	// container was loaded outside our shared config; it has not been explicitly removed.
	require.NoError(t, m.RemovePluginConfig(t.Context(), testPlugin("json")))
}

func TestNode_RemovePluginConfig_RetryAfterConfigRemoval(t *testing.T) {
	m := newTestNode()
	_, _, err := m.AddPluginConfig(t.Context(), testPlugin("json"))
	require.NoError(t, err)
	require.NoError(t, m.RemovePluginConfig(t.Context(), testPlugin("json")))
	// A newly registered dependency cannot block retrying the remaining binary/finalizer
	// cleanup: this config was already removed successfully in an earlier reconcile.
	installTestRulesfile(t, m, artifact.Ref{Kind: artifact.KindRulesfile, Name: "new-rules"},
		[]commonv1alpha1.ArtifactMetaDependency{{Name: "json", Version: "0.7.0"}})
	require.NoError(t, m.RemovePluginConfig(t.Context(), testPlugin("json")))
	_, _, err = m.AddPluginConfig(t.Context(), testPlugin("json"))
	require.NoError(t, err)
	var blocked *BlockedError
	require.ErrorAs(t, m.RemovePluginConfig(t.Context(), testPlugin("json")), &blocked,
		"an explicit re-add must restore normal deletion checks")
}

// TestNode_AddPluginConfig_ConcurrentWithCheckRequirement runs AddPluginConfig and
// CheckRequirement concurrently to detect deadlocks or data races; run with -race.
func TestNode_AddPluginConfig_ConcurrentWithCheckRequirement(t *testing.T) {
	m := newTestNodeWithFetcher(compatfake.NewMockVersionsFetcher(map[string]string{"container": "0.7.1"}))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 50 {
			_, _, _, _ = m.checkRequirement("container", "0.4.0")
		}
	}()

	for range 20 {
		_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"))
		require.NoError(t, err)
	}
	<-done
}

// A file taken over as found can hold an entry load_plugins does not name. Adding the plugin of that name makes
// Falco load it, whether or not the entry itself had to change.
func TestPluginsConfig_AddConfigLoadsAnEntryThatWasNotLoaded(t *testing.T) {
	plugin := testPlugin("container")
	for name, existing := range map[string]pluginConfig{
		"an identical entry": {Name: "container", LibraryPath: "/plugins/container.so"},
		"a different entry":  {Name: "container", LibraryPath: "/elsewhere/container.so"},
	} {
		t.Run(name, func(t *testing.T) {
			pc := &pluginsConfig{Configs: []pluginConfig{existing}}

			require.NoError(t, pc.addConfig("/plugins", plugin))

			assert.Equal(t, []string{"container"}, pc.LoadPlugins)
			require.Len(t, pc.Configs, 1)
			assert.Equal(t, "/plugins/container.so", pc.Configs[0].LibraryPath)
		})
	}
}

// The entry names the binary where the node installs it, which is the node's own plugin directory and not the
// default one.
func TestNode_AddPluginConfig_NamesTheBinaryInTheNodesOwnDirectory(t *testing.T) {
	dirs := artifact.ArtifactDirs{Rulesfile: "/custom/rules.d", Plugin: "/custom/plugins", Config: "/custom/config.d"}
	scheme := runtime.NewScheme()
	require.NoError(t, artifactv1alpha1.AddToScheme(scheme))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(testutil.NewTestArtifactNode()).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
	n, err := New(&Config{
		Fetcher: newTestFetcher(cl), Client: cl, NodeName: testutil.TestNodeName, Namespace: testutil.TestNamespace,
		FalcoBaseURL: compat.DefaultBaseURL, ReloadCooldown: DefaultReloadCooldown, Dirs: dirs,
		Store:        &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: dirs},
		FalcoFetcher: compatfake.NewMockVersionsFetcher(nil),
	})
	require.NoError(t, err)

	_, file, err := n.AddPluginConfig(t.Context(), testPlugin("container"))

	require.NoError(t, err)
	require.NotNil(t, file)
	assert.Equal(t, "/custom/config.d", filepath.Dir(file.Path))
	n.mu.Lock()
	defer n.mu.Unlock()
	require.Len(t, n.pluginsConfig.Configs, 1)
	assert.Equal(t, "/custom/plugins/container.so", n.pluginsConfig.Configs[0].LibraryPath)
}
