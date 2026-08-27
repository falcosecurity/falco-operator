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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

func defaultLibraryPath(name string) string {
	return artifact.ArtifactPath(artifact.DefaultArtifactDirs(), name, priority.DefaultPriority, artifact.MediumOCI, artifact.TypePlugin)
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

	t.Run("changing spec.config.name removes stale entry via reconciler tracking", func(t *testing.T) {
		pc := &pluginsConfig{}
		crToConfigName := make(map[string]string)

		plugin := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{Name: "json"},
			},
		}
		crToConfigName[plugin.Name] = ResolveConfigName(plugin)
		pc.addConfig(artifact.DefaultArtifactDirs().Plugin, plugin)
		require.Len(t, pc.Configs, 1)
		assert.Equal(t, "json", pc.Configs[0].Name)
		assert.Equal(t, []string{"json"}, pc.LoadPlugins)

		pluginRenamed := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{Name: "json-v2"},
			},
		}

		newName := ResolveConfigName(pluginRenamed)
		if oldName, ok := crToConfigName[pluginRenamed.Name]; ok && oldName != newName {
			pc.removeByName(oldName)
		}
		crToConfigName[pluginRenamed.Name] = newName
		pc.addConfig(artifact.DefaultArtifactDirs().Plugin, pluginRenamed)

		require.Len(t, pc.Configs, 1)
		assert.Equal(t, "json-v2", pc.Configs[0].Name)
		assert.Equal(t, []string{"json-v2"}, pc.LoadPlugins)

		pc.removeConfig(pluginRenamed)
		delete(crToConfigName, pluginRenamed.Name)
		assert.True(t, pc.isEmpty())
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
	return NewManager(&artifact.LocalStore{FS: filesystem.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}, compat.NewMockVersionsFetcher(nil))
}

func TestManager_AddPluginConfig_WritesConfigForBasicPlugin(t *testing.T) {
	m := newPluginConfigTestManager()
	pl := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "json"},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "r", Tag: "t"}},
		},
	}

	action, file, err := m.AddPluginConfig(context.Background(), pl, nil, &artifact.Fetcher{})

	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionAdded, action)
	require.NotNil(t, file)
	require.Len(t, m.pluginsConfig.Configs, 1)
	found := findPluginConfig(m.pluginsConfig.Configs, "json")
	require.NotNil(t, found)
	assert.Equal(t, "json", m.crToConfigName["json"])
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

	_, _, err := m.AddPluginConfig(context.Background(), pl, nil, &artifact.Fetcher{})

	require.NoError(t, err)
	found := findPluginConfig(m.pluginsConfig.Configs, "container")
	require.NotNil(t, found)
	assert.NotNil(t, found.InitConfig)
}

func TestManager_AddPluginConfig_RenameRemovesStaleEntryWhenUnblocked(t *testing.T) {
	m := newPluginConfigTestManager()
	fetcher := &artifact.Fetcher{}
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"}}
	_, _, err := m.AddPluginConfig(context.Background(), pl, nil, fetcher)
	require.NoError(t, err)
	require.NotNil(t, findPluginConfig(m.pluginsConfig.Configs, "my-plugin"))

	pl.Spec.Config = &artifactv1alpha1.PluginConfig{Name: "new-name"}
	_, _, err = m.AddPluginConfig(context.Background(), pl, nil, fetcher)

	require.NoError(t, err)
	require.Len(t, m.pluginsConfig.Configs, 1)
	assert.Nil(t, findPluginConfig(m.pluginsConfig.Configs, "my-plugin"))
	assert.NotNil(t, findPluginConfig(m.pluginsConfig.Configs, "new-name"))
	assert.Equal(t, "new-name", m.crToConfigName["my-plugin"])
}

func TestManager_AddPluginConfig_SameConfigNameDoesNotRemoveEntry(t *testing.T) {
	m := newPluginConfigTestManager()
	fetcher := &artifact.Fetcher{}
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}
	_, _, err := m.AddPluginConfig(context.Background(), pl, nil, fetcher)
	require.NoError(t, err)

	_, _, err = m.AddPluginConfig(context.Background(), pl, nil, fetcher)

	require.NoError(t, err)
	require.Len(t, m.pluginsConfig.Configs, 1)
}

func TestManager_AddPluginConfig_StoreFailureSurfacesError(t *testing.T) {
	mockFS := filesystem.NewMockFileSystem()
	mockFS.WriteErr = fmt.Errorf("disk full")
	m := NewManager(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compat.NewMockVersionsFetcher(nil))
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "test-plugin"}}

	_, _, err := m.AddPluginConfig(context.Background(), pl, nil, &artifact.Fetcher{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk full")
}

func TestManager_RemovePluginConfigByName_EmptyAfterRemovalKeepsFileOnDisk(t *testing.T) {
	// Removing the last plugin config entry rewrites the file to an empty config instead of
	// deleting it.
	m := newPluginConfigTestManager()
	fetcher := &artifact.Fetcher{}
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}
	_, file, err := m.AddPluginConfig(context.Background(), pl, nil, fetcher)
	require.NoError(t, err)

	err = m.RemovePluginConfigByName(context.Background(), fetcher, "json", "json")

	require.NoError(t, err)
	assert.True(t, m.pluginsConfig.isEmpty())
	ok, verifyErr := m.Verify(context.Background(), file)
	require.NoError(t, verifyErr)
	assert.False(t, ok, "content changed (the json entry is gone), so the old file's hash must no longer verify")

	content, readErr := m.store.(*artifact.LocalStore).FS.ReadFile(file.Path)
	require.NoError(t, readErr, "the config file must still exist on disk, just rewritten empty")
	assert.Contains(t, string(content), "plugins: []")
}

func TestManager_RemovePluginConfigByName_NotEmptyAfterRemovalWritesUpdatedConfig(t *testing.T) {
	m := newPluginConfigTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}, nil, fetcher)
	require.NoError(t, err)
	_, _, err = m.AddPluginConfig(context.Background(), &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "k8saudit"}}, nil, fetcher)
	require.NoError(t, err)

	err = m.RemovePluginConfigByName(context.Background(), fetcher, "json", "json")

	require.NoError(t, err)
	assert.False(t, m.pluginsConfig.isEmpty())
	require.Len(t, m.pluginsConfig.Configs, 1)
	assert.NotNil(t, findPluginConfig(m.pluginsConfig.Configs, "k8saudit"))
}

func TestManager_RemovePluginConfigByName_AlreadyAbsentIsANoOp(t *testing.T) {
	m := newPluginConfigTestManager()
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}, nil, fetcher)
	require.NoError(t, err)

	err = m.RemovePluginConfigByName(context.Background(), fetcher, "nonexistent", "nonexistent")

	require.NoError(t, err)
	assert.False(t, m.pluginsConfig.isEmpty())
	require.Len(t, m.pluginsConfig.Configs, 1)
}

func TestManager_RemovePluginConfigByName_ForgetsCrToConfigName(t *testing.T) {
	m := newPluginConfigTestManager()
	fetcher := &artifact.Fetcher{}
	pl := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}}
	_, _, err := m.AddPluginConfig(context.Background(), pl, nil, fetcher)
	require.NoError(t, err)
	require.Contains(t, m.crToConfigName, "json")

	require.NoError(t, m.RemovePluginConfigByName(context.Background(), fetcher, "json", "json"))

	assert.NotContains(t, m.crToConfigName, "json")
}
