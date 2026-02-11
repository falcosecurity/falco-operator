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

package plugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// defaultLibraryPath returns the expected library path for a plugin with the given CR name.
func defaultLibraryPath(name string) string {
	return artifact.Path(name, priority.DefaultPriority, artifact.MediumOCI, artifact.TypePlugin)
}

func TestPluginsConfig_AddConfig(t *testing.T) {
	tests := []struct {
		name            string
		initial         *PluginsConfig
		plugin          *artifactv1alpha1.Plugin
		expectedConfigs []PluginConfig
		expectedLoad    []string
	}{
		{
			name:    "add plugin with no spec.config",
			initial: &PluginsConfig{},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
			},
			expectedConfigs: []PluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath("json")},
			},
			expectedLoad: []string{"json"},
		},
		{
			name:    "add plugin with spec.config.name override",
			initial: &PluginsConfig{},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-json-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						Name: "json",
					},
				},
			},
			expectedConfigs: []PluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath("my-json-plugin")},
			},
			expectedLoad: []string{"json"},
		},
		{
			name:    "add plugin with full spec.config",
			initial: &PluginsConfig{},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						Name:        "json",
						LibraryPath: "/custom/path/json.so",
						InitConfig:  map[string]string{"sssURL": "https://example.com"},
						OpenParams:  "some-params",
					},
				},
			},
			expectedConfigs: []PluginConfig{
				{
					Name:        "json",
					LibraryPath: "/custom/path/json.so",
					InitConfig:  map[string]string{"sssURL": "https://example.com"},
					OpenParams:  "some-params",
				},
			},
			expectedLoad: []string{"json"},
		},
		{
			name:    "skip identical config (no duplicate)",
			initial: &PluginsConfig{},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
			},
			// We'll call addConfig twice with the same plugin in the test body.
			expectedConfigs: []PluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath("json")},
			},
			expectedLoad: []string{"json"},
		},
		{
			name: "update existing config when initConfig changes",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{
						Name:        "json",
						LibraryPath: defaultLibraryPath("json"),
						InitConfig:  map[string]string{"sssURL": "https://initial.example.com"},
					},
				},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						InitConfig: map[string]string{"sssURL": "https://updated.example.com"},
					},
				},
			},
			expectedConfigs: []PluginConfig{
				{
					Name:        "json",
					LibraryPath: defaultLibraryPath("json"),
					InitConfig:  map[string]string{"sssURL": "https://updated.example.com"},
				},
			},
			expectedLoad: []string{"json"},
		},
		{
			name: "update existing config when openParams changes",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{
						Name:        "json",
						LibraryPath: defaultLibraryPath("json"),
						OpenParams:  "old-params",
					},
				},
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
			expectedConfigs: []PluginConfig{
				{
					Name:        "json",
					LibraryPath: defaultLibraryPath("json"),
					OpenParams:  "new-params",
				},
			},
			expectedLoad: []string{"json"},
		},
		{
			name: "add second plugin preserves existing",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{Name: "json", LibraryPath: defaultLibraryPath("json")},
				},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "k8saudit"},
			},
			expectedConfigs: []PluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath("json")},
				{Name: "k8saudit", LibraryPath: defaultLibraryPath("k8saudit")},
			},
			expectedLoad: []string{"json", "k8saudit"},
		},
		{
			name: "loadPlugins uses config.Name not CR name",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{Name: "existing", LibraryPath: defaultLibraryPath("existing")},
				},
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
			expectedConfigs: []PluginConfig{
				{Name: "existing", LibraryPath: defaultLibraryPath("existing")},
				{Name: "json", LibraryPath: defaultLibraryPath("my-json-cr")},
			},
			expectedLoad: []string{"existing", "json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := tt.initial

			if tt.name == "skip identical config (no duplicate)" {
				// Call addConfig twice to verify idempotency.
				pc.addConfig(tt.plugin)
			}
			pc.addConfig(tt.plugin)

			assert.Equal(t, tt.expectedConfigs, pc.Configs)
			assert.Equal(t, tt.expectedLoad, pc.LoadPlugins)
		})
	}
}

func TestPluginsConfig_RemoveConfig(t *testing.T) {
	tests := []struct {
		name            string
		initial         *PluginsConfig
		plugin          *artifactv1alpha1.Plugin
		expectedConfigs []PluginConfig
		expectedLoad    []string
		expectedEmpty   bool
	}{
		{
			name: "remove plugin by CR name",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{Name: "json", LibraryPath: defaultLibraryPath("json")},
				},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
			},
			expectedConfigs: []PluginConfig{},
			expectedLoad:    []string{},
			expectedEmpty:   true,
		},
		{
			name: "remove plugin when spec.config.name differs from CR name",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{Name: "json", LibraryPath: defaultLibraryPath("my-json-plugin")},
				},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-json-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						Name: "json",
					},
				},
			},
			expectedConfigs: []PluginConfig{},
			expectedLoad:    []string{},
			expectedEmpty:   true,
		},
		{
			name: "remove non-existent plugin is a no-op",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{Name: "json", LibraryPath: defaultLibraryPath("json")},
				},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "nonexistent"},
			},
			expectedConfigs: []PluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath("json")},
			},
			expectedLoad:  []string{"json"},
			expectedEmpty: false,
		},
		{
			name: "remove one plugin preserves others",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{Name: "json", LibraryPath: defaultLibraryPath("json")},
					{Name: "k8saudit", LibraryPath: defaultLibraryPath("k8saudit")},
				},
				LoadPlugins: []string{"json", "k8saudit"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
			},
			expectedConfigs: []PluginConfig{
				{Name: "k8saudit", LibraryPath: defaultLibraryPath("k8saudit")},
			},
			expectedLoad:  []string{"k8saudit"},
			expectedEmpty: false,
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
		pc := &PluginsConfig{}

		plugin := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "my-json-plugin"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{
					Name: "json",
				},
			},
		}

		pc.addConfig(plugin)
		assert.Len(t, pc.Configs, 1)
		assert.Equal(t, "json", pc.Configs[0].Name)
		assert.Equal(t, []string{"json"}, pc.LoadPlugins)

		pc.removeConfig(plugin)
		assert.Empty(t, pc.Configs)
		assert.Empty(t, pc.LoadPlugins)
		assert.True(t, pc.isEmpty())
	})

	t.Run("changing spec.config.name removes stale entry via reconciler tracking", func(t *testing.T) {
		pc := &PluginsConfig{}
		crToConfigName := make(map[string]string)

		// Initial: CR "my-plugin" with spec.config.name = "json".
		plugin := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{
					Name: "json",
				},
			},
		}
		crToConfigName[plugin.Name] = resolveConfigName(plugin)
		pc.addConfig(plugin)
		require.Len(t, pc.Configs, 1)
		assert.Equal(t, "json", pc.Configs[0].Name)
		assert.Equal(t, []string{"json"}, pc.LoadPlugins)

		// User changes spec.config.name from "json" to "json-v2".
		pluginRenamed := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{
					Name: "json-v2",
				},
			},
		}

		// Reconciler detects name change and removes stale entry before addConfig.
		newName := resolveConfigName(pluginRenamed)
		if oldName, ok := crToConfigName[pluginRenamed.Name]; ok && oldName != newName {
			pc.removeByName(oldName)
		}
		crToConfigName[pluginRenamed.Name] = newName
		pc.addConfig(pluginRenamed)

		// The old "json" entry must be gone, only "json-v2" should remain.
		require.Len(t, pc.Configs, 1)
		assert.Equal(t, "json-v2", pc.Configs[0].Name)
		assert.Equal(t, []string{"json-v2"}, pc.LoadPlugins)

		// Deletion should clean up fully.
		pc.removeConfig(pluginRenamed)
		delete(crToConfigName, pluginRenamed.Name)
		assert.True(t, pc.isEmpty())
	})

	t.Run("add, update, then remove", func(t *testing.T) {
		pc := &PluginsConfig{}

		plugin := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "json"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{
					InitConfig: map[string]string{"sssURL": "https://initial.example.com"},
				},
			},
		}

		// Add initial config.
		pc.addConfig(plugin)
		assert.Equal(t, "https://initial.example.com", pc.Configs[0].InitConfig["sssURL"])

		// Update initConfig.
		pluginUpdated := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "json"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{
					InitConfig: map[string]string{"sssURL": "https://updated.example.com"},
				},
			},
		}
		pc.addConfig(pluginUpdated)
		require.Len(t, pc.Configs, 1)
		assert.Equal(t, "https://updated.example.com", pc.Configs[0].InitConfig["sssURL"])
		assert.Equal(t, []string{"json"}, pc.LoadPlugins)

		// Remove.
		pc.removeConfig(pluginUpdated)
		assert.True(t, pc.isEmpty())
	})
}

func TestPluginsConfig_ToString(t *testing.T) {
	tests := []struct {
		name     string
		pc       *PluginsConfig
		contains []string
	}{
		{
			name: "serializes to yaml",
			pc: &PluginsConfig{
				Configs: []PluginConfig{
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
			pc:       &PluginsConfig{},
			contains: []string{"plugins: []"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.pc.toString()
			require.NoError(t, err)
			for _, s := range tt.contains {
				assert.Contains(t, result, s)
			}
		})
	}
}

func TestPluginsConfig_IsEmpty(t *testing.T) {
	assert.True(t, (&PluginsConfig{}).isEmpty())
	assert.False(t, (&PluginsConfig{Configs: []PluginConfig{{Name: "json"}}}).isEmpty())
	assert.False(t, (&PluginsConfig{LoadPlugins: []string{"json"}}).isEmpty())
}

func TestPluginConfig_IsSame(t *testing.T) {
	tests := []struct {
		name     string
		a        PluginConfig
		b        PluginConfig
		expected bool
	}{
		{
			name:     "identical configs",
			a:        PluginConfig{LibraryPath: "/a.so", OpenParams: "p", InitConfig: map[string]string{"k": "v"}},
			b:        PluginConfig{LibraryPath: "/a.so", OpenParams: "p", InitConfig: map[string]string{"k": "v"}},
			expected: true,
		},
		{
			name:     "different library path",
			a:        PluginConfig{LibraryPath: "/a.so"},
			b:        PluginConfig{LibraryPath: "/b.so"},
			expected: false,
		},
		{
			name:     "different open params",
			a:        PluginConfig{LibraryPath: "/a.so", OpenParams: "p1"},
			b:        PluginConfig{LibraryPath: "/a.so", OpenParams: "p2"},
			expected: false,
		},
		{
			name:     "different init config",
			a:        PluginConfig{LibraryPath: "/a.so", InitConfig: map[string]string{"k": "v1"}},
			b:        PluginConfig{LibraryPath: "/a.so", InitConfig: map[string]string{"k": "v2"}},
			expected: false,
		},
		{
			name:     "name difference is ignored by isSame",
			a:        PluginConfig{Name: "a", LibraryPath: "/a.so"},
			b:        PluginConfig{Name: "b", LibraryPath: "/a.so"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.a.isSame(&tt.b))
		})
	}
}
