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

// Internal test file for package nodeartifacts, covering the unexported types pluginConfig,
// initConfig, and pluginsConfig.
package nodeartifacts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// removeConfig removes plugin's entry, resolved via ResolveConfigName. Test-only: production
// code always resolves the config name itself and calls removeByName directly.
func (pc *pluginsConfig) removeConfig(plugin *artifactv1alpha1.Plugin) {
	pc.removeByName(ResolveConfigName(plugin))
}

// isEmpty reports whether pc has no configs and no load_plugins entries. Test-only.
func (pc *pluginsConfig) isEmpty() bool {
	return len(pc.Configs) == 0 && len(pc.LoadPlugins) == 0
}

func defaultLibraryPath(name string) string {
	return artifact.ArtifactPath(artifact.DefaultArtifactDirs(), name, priority.DefaultPriority, artifact.MediumOCI, artifact.TypePlugin)
}

func TestManager_ObservationPreservesDesiredPluginConfig(t *testing.T) {
	ctx := context.Background()
	mockFS := fsfake.NewMockFileSystem()
	m := NewManager(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container"}}
	fetcher := &artifact.Fetcher{}
	_, file, err := m.AddPluginConfig(ctx, plugin, fetcher)
	require.NoError(t, err)
	rulesKey := Key{Kind: KindRulesfile, Name: "rules"}
	metadata := &commonv1alpha1.ArtifactMeta{
		Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "0.7.0"}},
	}
	rulesContent, err := fetcher.FetchInline(ctx, []byte("test rules"))
	require.NoError(t, err)
	_, _, err = m.StoreRulesfile(ctx, rulesKey.Namespace, rulesKey.Name, 50, artifact.MediumOCI, rulesContent, metadata, false)
	require.NoError(t, err)
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1", "external": "1.0.0"}).Result)
	content := string(mockFS.Files[file.Path])
	writes := len(mockFS.WriteCalls)

	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(nil).Result)
	p, ok := m.provides["container"]
	require.True(t, ok, "a configured plugin keeps its structural registration")
	assert.Equal(t, PluginConfigKey, p.Key)
	assert.Empty(t, p.Version, "only its confirmed runtime version is invalidated")
	assert.NotContains(t, m.provides, "external", "an observation-only entry has no desired registration to preserve")
	assert.Equal(t, "container", m.installedPluginNameLocked(plugin))
	assert.Equal(t, []string{"container"}, m.pluginsConfig.LoadPlugins)
	assert.Equal(t, metadata, m.rulesfiles[rulesfileSourceKey{Key: rulesKey, Medium: artifact.MediumOCI}][0].Metadata)
	assert.Equal(t, content, string(mockFS.Files[file.Path]))
	assert.Len(t, mockFS.WriteCalls, writes, "an observation must not rewrite or remove artifact files")
	assert.Empty(t, mockFS.RemoveCalls)
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"}).Result)
	assert.Equal(t, provided{Key: PluginConfigKey, Version: "0.7.1"}, m.provides["container"])
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
				{Name: "json", LibraryPath: defaultLibraryPath("json")},
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
				{Name: "json", LibraryPath: defaultLibraryPath("my-json-plugin")},
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
				{Name: "json", LibraryPath: defaultLibraryPath("json")},
			},
			expectedLoad: []string{"json"},
		},
		{
			name: "update existing config when initConfig changes",
			initial: &pluginsConfig{
				Configs: []pluginConfig{
					{
						Name:        "json",
						LibraryPath: defaultLibraryPath("json"),
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
					LibraryPath: defaultLibraryPath("json"),
					InitConfig:  &initConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"sssURL": "https://updated.example.com"}`)}},
				},
			},
			expectedLoad: []string{"json"},
		},
		{
			name: "update existing config when openParams changes",
			initial: &pluginsConfig{
				Configs:     []pluginConfig{{Name: "json", LibraryPath: defaultLibraryPath("json"), OpenParams: "old-params"}},
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
				{Name: "json", LibraryPath: defaultLibraryPath("json"), OpenParams: "new-params"},
			},
			expectedLoad: []string{"json"},
		},
		{
			name: "add second plugin preserves existing",
			initial: &pluginsConfig{
				Configs:     []pluginConfig{{Name: "json", LibraryPath: defaultLibraryPath("json")}},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "k8saudit"},
			},
			expectedConfigs: []pluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath("json")},
				{Name: "k8saudit", LibraryPath: defaultLibraryPath("k8saudit")},
			},
			expectedLoad: []string{"json", "k8saudit"},
		},
		{
			name: "loadPlugins uses config.Name not CR name",
			initial: &pluginsConfig{
				Configs:     []pluginConfig{{Name: "existing", LibraryPath: defaultLibraryPath("existing")}},
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
				{Name: "existing", LibraryPath: defaultLibraryPath("existing")},
				{Name: "json", LibraryPath: defaultLibraryPath("my-json-cr")},
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
				{Name: "json", LibraryPath: defaultLibraryPath("json")},
			},
			expectedLoad: []string{"json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := tt.initial

			if tt.callTwice {
				pc.addConfig(artifact.DefaultArtifactDirs().Plugin, tt.plugin)
			}
			pc.addConfig(artifact.DefaultArtifactDirs().Plugin, tt.plugin)

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
				Configs:     []pluginConfig{{Name: "json", LibraryPath: defaultLibraryPath("json")}},
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
				Configs:     []pluginConfig{{Name: "json", LibraryPath: defaultLibraryPath("my-json-plugin")}},
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
				Configs:     []pluginConfig{{Name: "json", LibraryPath: defaultLibraryPath("json")}},
				LoadPlugins: []string{"json"},
			},
			plugin:          &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "nonexistent"}},
			expectedConfigs: []pluginConfig{{Name: "json", LibraryPath: defaultLibraryPath("json")}},
			expectedLoad:    []string{"json"},
			expectedEmpty:   false,
		},
		{
			name: "remove one plugin preserves others",
			initial: &pluginsConfig{
				Configs: []pluginConfig{
					{Name: "json", LibraryPath: defaultLibraryPath("json")},
					{Name: "k8saudit", LibraryPath: defaultLibraryPath("k8saudit")},
				},
				LoadPlugins: []string{"json", "k8saudit"},
			},
			plugin:          &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}},
			expectedConfigs: []pluginConfig{{Name: "k8saudit", LibraryPath: defaultLibraryPath("k8saudit")}},
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

		pc.addConfig(artifact.DefaultArtifactDirs().Plugin, plugin)
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
		fetcher := &artifact.Fetcher{}

		plugin := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{Name: "json"},
			},
		}
		_, _, err := m.AddPluginConfig(t.Context(), plugin, fetcher)
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

		_, _, err = m.AddPluginConfig(t.Context(), pluginRenamed, fetcher)
		require.NoError(t, err)

		require.Len(t, m.pluginsConfig.Configs, 1)
		assert.Equal(t, "json-v2", m.pluginsConfig.Configs[0].Name)
		assert.Equal(t, []string{"json-v2"}, m.pluginsConfig.LoadPlugins)

		require.NoError(t, m.RemovePluginConfig(t.Context(), fetcher, pluginRenamed))
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

		pc.addConfig(artifact.DefaultArtifactDirs().Plugin, plugin)
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
		pc.addConfig(artifact.DefaultArtifactDirs().Plugin, pluginUpdated)
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

func TestResolveConfigName(t *testing.T) {
	tests := []struct {
		name     string
		plugin   *artifactv1alpha1.Plugin
		expected string
	}{
		{
			name: "uses CR name when config is nil",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
			},
			expected: "my-plugin",
		},
		{
			name: "uses CR name when config name is empty",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{},
				},
			},
			expected: "my-plugin",
		},
		{
			name: "uses config name when set",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{Name: "custom-name"},
				},
			},
			expected: "custom-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ResolveConfigName(tt.plugin))
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

func newPluginConfigTestManager() *Manager {
	return NewManager(&artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
}

func TestManager_AddPluginConfig_WritesConfigForBasicPlugin(t *testing.T) {
	m := newPluginConfigTestManager()
	pl := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "json"},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "r", Tag: "t"}},
		},
	}

	action, file, err := m.AddPluginConfig(context.Background(), pl, &artifact.Fetcher{})

	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionAdded, action)
	require.NotNil(t, file)
	require.Len(t, m.pluginsConfig.Configs, 1)
	found := findPluginConfig(m.pluginsConfig.Configs, "json")
	require.NotNil(t, found)
	assert.Equal(t, "json", m.installedPluginNameLocked(pl))
}

func TestManager_AddPluginConfig_WritesConfigWithInitConfig(t *testing.T) {
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

	_, _, err := m.AddPluginConfig(context.Background(), pl, &artifact.Fetcher{})

	require.NoError(t, err)
	found := findPluginConfig(m.pluginsConfig.Configs, "container")
	require.NotNil(t, found)
	require.NotNil(t, found.InitConfig)
	expected := string(pl.Spec.Config.InitConfig.Raw)
	pl.Spec.Config.InitConfig.Raw[0] = '['
	assert.JSONEq(t, expected, string(found.InitConfig.Raw), "installed config must not alias the caller's buffer")

	// Another plugin serializes the full aggregate again, including the owned init_config.
	another := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}
	_, file, err := m.AddPluginConfig(t.Context(), another, &artifact.Fetcher{})
	require.NoError(t, err)
	require.NotNil(t, file)
	data, err := m.store.(*artifact.LocalStore).FS.ReadFile(file.Path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "containerd:")
	assert.Contains(t, string(data), "enabled: true")
}

func TestManager_AddPluginConfig_RenameRemovesStaleEntryWhenUnblocked(t *testing.T) {
	m := newPluginConfigTestManager()
	fetcher := &artifact.Fetcher{}
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"}}
	_, _, err := m.AddPluginConfig(context.Background(), pl, fetcher)
	require.NoError(t, err)
	require.NotNil(t, findPluginConfig(m.pluginsConfig.Configs, "my-plugin"))

	pl.Spec.Config = &artifactv1alpha1.PluginConfig{Name: "new-name"}
	_, _, err = m.AddPluginConfig(context.Background(), pl, fetcher)

	require.NoError(t, err)
	require.Len(t, m.pluginsConfig.Configs, 1)
	assert.Nil(t, findPluginConfig(m.pluginsConfig.Configs, "my-plugin"))
	assert.NotNil(t, findPluginConfig(m.pluginsConfig.Configs, "new-name"))
	assert.Equal(t, "new-name", m.installedPluginNameLocked(pl))
}

func TestManager_AddPluginConfig_SameConfigNameDoesNotRemoveEntry(t *testing.T) {
	m := newPluginConfigTestManager()
	fetcher := &artifact.Fetcher{}
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}
	_, _, err := m.AddPluginConfig(context.Background(), pl, fetcher)
	require.NoError(t, err)

	_, _, err = m.AddPluginConfig(context.Background(), pl, fetcher)

	require.NoError(t, err)
	require.Len(t, m.pluginsConfig.Configs, 1)
}

func TestManager_PluginConfigYAMLRoundTripPreservesNoOpAndOrder(t *testing.T) {
	ctx := t.Context()
	fs := fsfake.NewMockFileSystem()
	store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
	versions := compatfake.NewMockVersionsFetcher(nil)
	before := NewManager(store, versions)
	fetcher := &artifact.Fetcher{}
	pluginA := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "a", UID: "uid-a"},
		Spec: artifactv1alpha1.PluginSpec{Config: &artifactv1alpha1.PluginConfig{
			InitConfig: &apiextensionsv1.JSON{Raw: []byte(`{ "nested": { "enabled": true } }`)},
		}},
	}
	pluginB := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "b", UID: "uid-b"}}
	for _, plugin := range []*artifactv1alpha1.Plugin{pluginA, pluginB} {
		_, _, err := before.AddPluginConfig(ctx, plugin, fetcher)
		require.NoError(t, err)
	}
	file := before.FindInstalled(PluginConfigKey, artifact.MediumInline)
	require.NotNil(t, file)
	content := string(fs.Files[file.Path])
	after := NewManager(store, versions)
	disk, err := after.ScanAll(ctx, artifact.TypeConfig)
	require.NoError(t, err)
	after.SeedInstalled(PluginConfigKey, disk[pluginConfigFileName])
	writes := len(fs.WriteCalls)
	fs.WriteErr = errors.New("unexpected no-op write")
	require.NoError(t, after.restorePluginsConfig(ctx, []*artifactv1alpha1.Plugin{pluginB, pluginA}))
	assert.Len(t, fs.WriteCalls, writes, "reading an unchanged aggregate must not rewrite it")
	assert.Equal(t, map[string]corev1.ObjectReference{"a": pluginOwner(pluginA), "b": pluginOwner(pluginB)}, after.pluginConfigOwners)
	require.Len(t, after.pluginsConfig.Configs, 2)
	require.NotNil(t, after.pluginsConfig.Configs[0].InitConfig)
	assert.JSONEq(t, string(pluginA.Spec.Config.InitConfig.Raw), string(after.pluginsConfig.Configs[0].InitConfig.Raw))
	require.NotEqual(t, string(pluginA.Spec.Config.InitConfig.Raw), string(after.pluginsConfig.Configs[0].InitConfig.Raw),
		"the fixture must exercise whitespace normalization when decoding init_config YAML")

	action, _, err := after.AddPluginConfig(ctx, pluginA, fetcher)

	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUnchanged, action)
	assert.Len(t, fs.WriteCalls, writes)
	assert.Equal(t, content, string(fs.Files[file.Path]))
	assert.Equal(t, []string{"a", "b"}, after.pluginsConfig.LoadPlugins)
	require.Len(t, after.pluginsConfig.Configs, 2)
	assert.Equal(t, "a", after.pluginsConfig.Configs[0].Name)
	assert.Equal(t, "b", after.pluginsConfig.Configs[1].Name)
}

func TestManager_RestorePluginsConfig_UsesCurrentAliasesAndObservedSettings(t *testing.T) {
	ctx := t.Context()
	fs := fsfake.NewMockFileSystem()
	store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
	versions := compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{
		"kept": "0.7.4", "renamed": "0.7.4", "orphan": "0.7.4", "collision": "0.7.4",
	})
	before := NewManager(store, versions)
	fetcher := &artifact.Fetcher{}
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
		_, _, err := before.AddPluginConfig(ctx, plugin, fetcher)
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
	after := NewManager(store, versions)
	after.OnFalcoVersionsObserved(versions.Result)
	disk, err := after.ScanAll(ctx, artifact.TypeConfig)
	require.NoError(t, err)
	after.SeedInstalled(PluginConfigKey, disk[pluginConfigFileName])

	require.NoError(t, after.restorePluginsConfig(ctx, []*artifactv1alpha1.Plugin{current, renamed, collision, other}))

	require.Len(t, after.pluginsConfig.Configs, 1)
	assert.Equal(t, []string{"kept"}, after.pluginsConfig.LoadPlugins)
	assert.Equal(t, map[string]corev1.ObjectReference{"kept": pluginOwner(current)}, after.pluginConfigOwners,
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
	assert.Equal(t, provided{Key: PluginConfigKey, Version: "0.7.4"}, after.provides["kept"])
	for _, name := range []string{"renamed", "orphan", "collision"} {
		assert.True(t, after.provides[name].Removed, "a pre-reload observation must not resurrect a pruned alias")
	}
	file := after.FindInstalled(PluginConfigKey, artifact.MediumInline)
	require.NotNil(t, file)
	content, err := after.pluginsConfig.toString()
	require.NoError(t, err)
	assert.Equal(t, content, string(fs.Files[file.Path]))
	_, _, err = after.AddPluginConfig(ctx, current, fetcher)
	require.NoError(t, err)
	assert.Equal(t, current.Spec.Config.LibraryPath, after.pluginsConfig.Configs[0].LibraryPath,
		"only normal reconciliation applies the changed settings")
	assert.Equal(t, current.Spec.Config.OpenParams, after.pluginsConfig.Configs[0].OpenParams)
}

func TestManager_RestorePluginsConfig_HandlesMissingCorruptAndFailedIO(t *testing.T) {
	const readFailure, writeFailure, renameFailure = "read failure", "write failure", "rename failure"
	const missingFile, invalidYAML = "missing file", "invalid YAML"
	for _, scenario := range []string{missingFile, invalidYAML, readFailure, writeFailure, renameFailure} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			before := NewManager(store, compatfake.NewMockVersionsFetcher(nil))
			plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "orphan", UID: "orphan-uid"}}
			_, file, err := before.AddPluginConfig(ctx, plugin, &artifact.Fetcher{})
			require.NoError(t, err)
			after := NewManager(store, compatfake.NewMockVersionsFetcher(nil))
			after.SeedInstalled(PluginConfigKey, before.GetInstalled(PluginConfigKey))
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
				fs.WriteErrFor = map[string]error{file.Path + ".tmp": ioErr}
			case renameFailure:
				fs.RenameErrFor = map[string]error{file.Path + ".tmp": ioErr}
			}

			err = after.restorePluginsConfig(ctx, nil)

			if scenario == missingFile {
				require.NoError(t, err)
				assert.Nil(t, after.FindInstalled(PluginConfigKey, artifact.MediumInline))
				assert.NotContains(t, fs.Files, file.Path)
				return
			}
			if scenario != invalidYAML {
				require.ErrorIs(t, err, ioErr)
				assert.Equal(t, original, string(fs.Files[file.Path]), "failed recovery must not replace installed output")
				assert.Empty(t, after.pluginConfigOwners, "failed recovery must not publish new ownership")
				fs.ReadErrFor, fs.WriteErrFor, fs.RenameErrFor = nil, nil, nil
				require.NoError(t, after.restorePluginsConfig(ctx, nil), "recovery must be retryable")
			} else {
				require.NoError(t, err, "malformed observed output must not prevent rebuilding from current CRs")
			}
			assert.Empty(t, after.pluginsConfig.Configs)
			assert.Empty(t, after.pluginsConfig.LoadPlugins)
			assert.Empty(t, after.pluginConfigOwners)
			assert.NotContains(t, fs.Files, file.Path+".tmp")
			assert.Contains(t, string(fs.Files[file.Path]), "plugins: []")
			intact, err := after.Verify(ctx, after.FindInstalled(PluginConfigKey, artifact.MediumInline))
			require.NoError(t, err)
			assert.True(t, intact)
		})
	}
}

func TestManager_AddPluginConfig_StoreFailureSurfacesError(t *testing.T) {
	mockFS := fsfake.NewMockFileSystem()
	mockFS.WriteErr = fmt.Errorf("disk full")
	m := NewManager(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "test-plugin"}}

	_, _, err := m.AddPluginConfig(context.Background(), pl, &artifact.Fetcher{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk full")
	assert.Empty(t, m.pluginsConfig.Configs, "a failed addition must not change the aggregate")
	assert.Empty(t, m.pluginConfigOwners)
	assert.Empty(t, m.provides)
}

func TestManager_PluginConfigWriteFailurePreservesCommittedState(t *testing.T) {
	const removeOperation, renameOperation = "remove", "rename"
	for _, operation := range []string{removeOperation, renameOperation, "update"} {
		t.Run(operation, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			falco := compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"json": "0.7.4"})
			m := NewManager(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, falco)
			plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}
			fetcher := &artifact.Fetcher{}
			_, file, err := m.AddPluginConfig(ctx, plugin, fetcher)
			require.NoError(t, err)
			before := string(fs.Files[file.Path])
			fs.WriteErrFor = map[string]error{file.Path + ".tmp": fmt.Errorf("disk full")}
			switch operation {
			case removeOperation:
				err = m.RemovePluginConfig(ctx, fetcher, plugin)
			case renameOperation:
				plugin.Spec.Config = &artifactv1alpha1.PluginConfig{Name: "renamed"}
				_, _, err = m.AddPluginConfig(ctx, plugin, fetcher)
			case "update":
				plugin.Spec.Config = &artifactv1alpha1.PluginConfig{OpenParams: "changed"}
				_, _, err = m.AddPluginConfig(ctx, plugin, fetcher)
			}
			require.ErrorContains(t, err, "disk full")
			assert.Equal(t, before, string(fs.Files[file.Path]))
			assert.Equal(t, "json", m.installedPluginNameLocked(plugin))
			assert.Equal(t, []string{"json"}, m.pluginsConfig.LoadPlugins)
			assert.Equal(t, provided{Key: PluginConfigKey, Version: "0.7.4"}, m.provides["json"])
			fs.WriteErrFor = nil
			assert.Equal(t, before, string(fs.Files[file.Path]))
			// Retrying the same operation must still perform it, not mistake the failed
			// in-memory mutation for a completed change.
			if operation == removeOperation {
				require.NoError(t, m.RemovePluginConfig(ctx, fetcher, plugin))
				assert.Empty(t, m.pluginsConfig.LoadPlugins)
				assert.True(t, m.provides["json"].Removed)
			} else {
				_, _, err = m.AddPluginConfig(ctx, plugin, fetcher)
				require.NoError(t, err)
				assert.NotEqual(t, before, string(fs.Files[file.Path]))
				if operation == renameOperation {
					assert.True(t, m.provides["json"].Removed, "the post-install poll still reports the old name")
					assert.Empty(t, m.provides["json"].Version)
					assert.Equal(t, "renamed", m.installedPluginNameLocked(plugin))
				}
			}
		})
	}
}

func TestManager_RemovePluginConfig_EmptyAfterRemovalKeepsFileOnDisk(t *testing.T) {
	// Removing the last plugin config entry rewrites the file to an empty config instead of
	// deleting it.
	m := newPluginConfigTestManager()
	fetcher := &artifact.Fetcher{}
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}
	_, file, err := m.AddPluginConfig(context.Background(), pl, fetcher)
	require.NoError(t, err)

	err = m.RemovePluginConfig(context.Background(), fetcher, pl)

	require.NoError(t, err)
	assert.True(t, m.pluginsConfig.isEmpty())
	ok, verifyErr := m.Verify(context.Background(), file)
	require.NoError(t, verifyErr)
	assert.False(t, ok, "content changed (the json entry is gone), so the old file's hash must no longer verify")

	require.Error(t, m.Remove(t.Context(), PluginConfigKey))
	_, removed, err := m.RemoveIfInstalled(t.Context(), PluginConfigKey, artifact.MediumInline)
	require.Error(t, err)
	assert.False(t, removed)

	content, readErr := m.store.(*artifact.LocalStore).FS.ReadFile(file.Path)
	require.NoError(t, readErr, "the config file must still exist on disk, just rewritten empty")
	assert.Contains(t, string(content), "plugins: []")
}

func TestManager_RemovePluginConfig_NotEmptyAfterRemovalWritesUpdatedConfig(t *testing.T) {
	m := newPluginConfigTestManager()
	fetcher := &artifact.Fetcher{}
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}
	_, _, err := m.AddPluginConfig(context.Background(), pl, fetcher)
	require.NoError(t, err)
	_, _, err = m.AddPluginConfig(context.Background(), &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "k8saudit"}}, fetcher)
	require.NoError(t, err)

	err = m.RemovePluginConfig(context.Background(), fetcher, pl)

	require.NoError(t, err)
	assert.False(t, m.pluginsConfig.isEmpty())
	require.Len(t, m.pluginsConfig.Configs, 1)
	assert.NotNil(t, findPluginConfig(m.pluginsConfig.Configs, "k8saudit"))
}

func TestManager_RemovePluginConfig_AlreadyAbsentIsANoOp(t *testing.T) {
	m := newPluginConfigTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}, fetcher)
	require.NoError(t, err)

	absent := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "nonexistent"}}
	err = m.RemovePluginConfig(context.Background(), fetcher, absent)

	require.NoError(t, err)
	assert.False(t, m.pluginsConfig.isEmpty())
	require.Len(t, m.pluginsConfig.Configs, 1)
}

func TestManager_RemovePluginConfig_RetainsTombstoneWithoutOwner(t *testing.T) {
	m := newPluginConfigTestManager()
	fetcher := &artifact.Fetcher{}
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}
	_, _, err := m.AddPluginConfig(context.Background(), pl, fetcher)
	require.NoError(t, err)
	require.Equal(t, "json", m.installedPluginNameLocked(pl))

	require.NoError(t, m.RemovePluginConfig(context.Background(), fetcher, pl))

	assert.Empty(t, m.installedPluginNameLocked(pl))
	assert.NotContains(t, m.pluginConfigOwners, "json")
	assert.True(t, m.provides["json"].Removed)
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"json": "0.7.4"}).Result)
	assert.True(t, m.provides["json"].Removed, "a delayed observation must not restore the removed provider")
	assert.Empty(t, m.provides["json"].Version)
}

func TestManager_Remove_ProtectsSharedPluginConfig(t *testing.T) {
	const absentMedium = "absent medium"
	for _, operation := range []string{"all", "medium", absentMedium} {
		t.Run(operation, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			m := NewManager(store, compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"}))
			fetcher := &artifact.Fetcher{}
			plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "container", UID: "uid-container"}}
			_, shared, err := m.AddPluginConfig(ctx, plugin, fetcher)
			require.NoError(t, err)
			require.NotNil(t, shared)
			unrelated := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "json", UID: "uid-json"}}
			_, _, err = m.AddPluginConfig(ctx, unrelated, fetcher)
			require.NoError(t, err)
			rules, err := fetcher.FetchInline(ctx, []byte("test rules"))
			require.NoError(t, err)
			_, _, err = m.StoreRulesfile(ctx, plugin.Namespace, "rules", 50, artifact.MediumInline, rules,
				&commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "0.7.0"}}}, true)
			require.NoError(t, err)
			config, owners, providers := m.pluginsConfig.clone(), maps.Clone(m.pluginConfigOwners), maps.Clone(m.provides)
			installed := m.GetInstalled(PluginConfigKey)
			files := maps.Clone(fs.Files)
			writes, removals := len(fs.WriteCalls), len(fs.RemoveCalls)

			if operation == "all" {
				err = m.Remove(ctx, PluginConfigKey)
			} else {
				var removed bool
				var path string
				medium := artifact.MediumInline
				if operation == absentMedium {
					medium = artifact.MediumConfigMap
				}
				path, removed, err = m.RemoveIfInstalled(ctx, PluginConfigKey, medium)
				assert.Empty(t, path)
				assert.False(t, removed)
			}

			if operation == absentMedium {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			assert.Equal(t, files, fs.Files, "artifact files must remain untouched")
			assert.Len(t, fs.WriteCalls, writes)
			assert.Len(t, fs.RemoveCalls, removals)
			assert.Equal(t, installed, m.GetInstalled(PluginConfigKey))
			assert.Equal(t, config, m.pluginsConfig)
			assert.Equal(t, owners, m.pluginConfigOwners)
			assert.Equal(t, providers, m.provides)
			var blocked *BlockedError
			require.ErrorAs(t, m.RemovePluginConfig(ctx, fetcher, plugin), &blocked)

			after := NewManager(store, compatfake.NewMockVersionsFetcher(nil))
			disk, err := after.ScanAll(ctx, artifact.TypeConfig)
			require.NoError(t, err)
			after.SeedInstalled(PluginConfigKey, disk[pluginConfigFileName])
			disk, err = after.ScanAll(ctx, artifact.TypeRulesfile)
			require.NoError(t, err)
			after.SeedInstalled(Key{Kind: KindRulesfile, Namespace: plugin.Namespace, Name: "rules"}, disk["rules"])
			require.NoError(t, after.restorePluginsConfig(ctx, []*artifactv1alpha1.Plugin{plugin, unrelated}))
			assert.Equal(t, config, after.pluginsConfig)
			assert.Equal(t, owners, after.pluginConfigOwners)
			require.NoError(t, after.RemovePluginConfig(ctx, fetcher, plugin),
				"disk files alone do not prove historical dependencies after restart")
			require.NoError(t, after.RemovePluginConfig(ctx, fetcher, unrelated))
		})
	}
}

func TestManager_RemovePluginPreservesEquivalentLibraryPaths(t *testing.T) {
	for _, alias := range []string{"./a.so", "../plugins/a.so"} {
		t.Run(alias, func(t *testing.T) {
			ctx := t.Context()
			store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
			before := NewManager(store, compatfake.NewMockVersionsFetcher(nil))
			fetcher := &artifact.Fetcher{}
			plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "a", UID: "uid-a"}}
			content, err := fetcher.FetchInline(ctx, []byte("shared binary"))
			require.NoError(t, err)
			content.Perm = artifact.PermFor(artifact.TypePlugin)
			_, binary, err := before.StorePlugin(ctx, plugin, content)
			require.NoError(t, err)
			_, _, err = before.AddPluginConfig(ctx, plugin, fetcher)
			require.NoError(t, err)
			other := &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "b", UID: "uid-b"},
				Spec:       artifactv1alpha1.PluginSpec{Config: &artifactv1alpha1.PluginConfig{LibraryPath: store.Dirs.Plugin + "/" + alias}},
			}
			_, _, err = before.AddPluginConfig(ctx, other, fetcher)
			require.NoError(t, err)
			require.NoError(t, before.RemovePluginConfig(ctx, fetcher, plugin))
			key := KeyFromObj(KindPlugin, plugin)
			after := NewManager(store, compatfake.NewMockVersionsFetcher(nil))
			disk, err := after.ScanAll(ctx, artifact.TypePlugin)
			require.NoError(t, err)
			after.SeedInstalled(key, disk[plugin.Name])
			disk, err = after.ScanAll(ctx, artifact.TypeConfig)
			require.NoError(t, err)
			after.SeedInstalled(PluginConfigKey, disk[pluginConfigFileName])
			require.NoError(t, after.restorePluginsConfig(ctx, []*artifactv1alpha1.Plugin{other}))

			for _, m := range []*Manager{before, after} {
				require.Error(t, m.Remove(ctx, key), "another installed plugin still references the same library")
				_, removed, err := m.RemoveIfInstalled(ctx, key, artifact.MediumOCI)
				require.Error(t, err)
				assert.False(t, removed)
				intact, err := m.Verify(ctx, binary)
				require.NoError(t, err)
				assert.True(t, intact)
			}
			require.NoError(t, after.RemovePluginConfig(ctx, fetcher, other))
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
	fetcher := &artifact.Fetcher{}
	config := &pluginsConfig{}

	action, file, err := m.writePluginsConfigLocked(context.Background(), fetcher, config, map[string]corev1.ObjectReference{})
	require.NoError(t, err)
	require.NotNil(t, file)
	assert.Equal(t, artifact.StoreActionAdded, action, "first write of the shared config file is a real install")

	action, _, err = m.writePluginsConfigLocked(context.Background(), fetcher, config, map[string]corev1.ObjectReference{})
	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUnchanged, action,
		"byte-identical content must not be misreported as a fresh install")
}
