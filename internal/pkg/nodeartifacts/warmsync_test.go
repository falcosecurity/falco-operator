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
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

func sha256hexForTest(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func controllerRef(kind, name string) metav1.OwnerReference {
	t := true
	return metav1.OwnerReference{
		APIVersion: artifactv1alpha1.GroupVersion.String(),
		Kind:       kind,
		Name:       name,
		Controller: &t,
	}
}

func newWarmSyncTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, artifactv1alpha1.AddToScheme(s))
	return s
}

func TestWarmSync_PopulatesFromExistingArtifactNodes(t *testing.T) {
	sch := newWarmSyncTestScheme(t)

	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "ns"},
		Spec:       artifactv1alpha1.PluginSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{}},
	}
	pluginNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "plugin--container--minikube",
			Namespace:       "ns",
			Labels:          map[string]string{"artifact.falcosecurity.dev/node": "minikube"},
			OwnerReferences: []metav1.OwnerReference{controllerRef("Plugin", "container")},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "minikube"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{{Path: "/x", Medium: "oci"}},
		},
	}
	rulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"},
		Status: artifactv1alpha1.RulesfileStatus{
			ArtifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "0.4.0"}},
			},
		},
	}
	rulesfileNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "rulesfile--my-rules--minikube",
			Namespace:       "ns",
			Labels:          map[string]string{"artifact.falcosecurity.dev/node": "minikube"},
			OwnerReferences: []metav1.OwnerReference{controllerRef("Rulesfile", "my-rules")},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "minikube"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{{Path: "/y", Medium: "oci"}},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithObjects(plugin, pluginNode, rulesfile, rulesfileNode).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	before := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))
	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: rulesfile.Namespace, Name: rulesfile.Name}
	installTestRulesfile(t, before, key, rulesfile.Status.ArtifactMeta.Dependencies)
	_, _, err := before.AddPluginConfig(t.Context(), plugin, &artifact.Fetcher{})
	require.NoError(t, err)
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

	require.NoError(t, nodeartifacts.WarmSync(t.Context(), cl, mgr, "ns", "minikube"))

	// Disk files are observed, but neither previous-process nor parent-status dependencies
	// are imported. A normal source reconcile must register current checked dependencies.
	assert.Equal(t, before.GetInstalled(key), mgr.GetInstalled(key))
	require.NoError(t, mgr.RemovePluginConfig(t.Context(), &artifact.Fetcher{}, plugin))
	assert.NotEmpty(t, mgr.GetInstalled(key), "dropping historical dependency protection does not remove the rules file")
}

func TestWarmSync_ConfigNamedPluginsConfigStaysSeparate(t *testing.T) {
	for _, scenario := range []struct {
		name       string
		medium     artifact.Medium
		priority   int32
		withPlugin bool
	}{
		{name: "inline without aggregate", medium: artifact.MediumInline, priority: 50},
		{name: "configmap without aggregate", medium: artifact.MediumConfigMap, priority: 99},
		{name: "inline alongside aggregate", medium: artifact.MediumInline, priority: 50, withPlugin: true},
		{name: "configmap alongside aggregate", medium: artifact.MediumConfigMap, priority: 99, withPlugin: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			versions := compatfake.NewMockVersionsFetcher(nil)
			before := nodeartifacts.NewManager(store, versions)
			fetcher := &artifact.Fetcher{}
			key := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Namespace: "ns", Name: "plugins-config"}
			content, err := fetcher.FetchInline(ctx, []byte("json_output: true\n"))
			require.NoError(t, err)
			_, configFile, err := before.StoreConfig(ctx, key.Namespace, key.Name, scenario.priority, scenario.medium, content)
			require.NoError(t, err)
			require.NotNil(t, configFile)
			var sharedFile *artifact.File
			var plugin *artifactv1alpha1.Plugin
			if scenario.withPlugin {
				plugin = testPlugin("container")
				plugin.Namespace = key.Namespace
				plugin.Spec.OCIArtifact = &commonv1alpha1.OCIArtifact{}
				_, sharedFile, err = before.AddPluginConfig(ctx, plugin, fetcher)
				require.NoError(t, err)
				require.NotNil(t, sharedFile)
			}
			node := &artifactv1alpha1.ArtifactNode{
				ObjectMeta: metav1.ObjectMeta{Name: "config--plugins-config--node", Namespace: key.Namespace,
					OwnerReferences: []metav1.OwnerReference{controllerRef("Config", key.Name)}},
				Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "node"},
			}
			objects := []client.Object{node}
			if plugin != nil {
				objects = append(objects, plugin, &artifactv1alpha1.ArtifactNode{
					ObjectMeta: metav1.ObjectMeta{Name: "plugin--container--node", Namespace: key.Namespace,
						OwnerReferences: []metav1.OwnerReference{controllerRef("Plugin", plugin.Name)}},
					Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "node"},
				})
			}
			cl := fake.NewClientBuilder().WithScheme(newWarmSyncTestScheme(t)).WithObjects(objects...).
				WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).Build()
			after := nodeartifacts.NewManager(store, versions)

			require.NoError(t, nodeartifacts.WarmSync(ctx, cl, after, key.Namespace, node.Spec.NodeName))

			assert.Equal(t, configFile, after.FindInstalled(key, scenario.medium))
			assert.Equal(t, sharedFile, after.FindInstalled(nodeartifacts.PluginConfigKey, artifact.MediumInline))
			assert.Equal(t, content.Content, fs.Files[configFile.Path])
			require.NoError(t, after.Remove(ctx, key))
			assert.NotContains(t, fs.Files, configFile.Path)
			if sharedFile != nil {
				intact, verifyErr := after.Verify(ctx, sharedFile)
				require.NoError(t, verifyErr)
				assert.True(t, intact, "removing the Config CR must not alter the shared plugin aggregate")
			}
		})
	}
}

func TestWarmSync_PreservesOtherInstalledPluginConfigs(t *testing.T) {
	const update = "update"
	for _, operation := range []string{update, "delete"} {
		t.Run(operation, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			versions := compatfake.NewMockVersionsFetcher(nil)
			before := nodeartifacts.NewManager(store, versions)
			fetcher := &artifact.Fetcher{}
			pluginA := &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "plugin-a", Namespace: "ns", UID: "uid-a"},
				Spec:       artifactv1alpha1.PluginSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{}, Config: &artifactv1alpha1.PluginConfig{Name: "custom-a"}},
			}
			pluginB := &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "plugin-b", Namespace: "ns", UID: "uid-b"},
				Spec: artifactv1alpha1.PluginSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{}, Config: &artifactv1alpha1.PluginConfig{
					Name: "custom-b", LibraryPath: "/plugins/installed-b.so", OpenParams: "installed-b",
					InitConfig: &apiextensionsv1.JSON{Raw: []byte(`{"nested": {"value": "installed"}}`)},
				}},
			}
			objects := make([]client.Object, 0, 5)
			for _, plugin := range []*artifactv1alpha1.Plugin{pluginA, pluginB} {
				_, _, err := before.AddPluginConfig(ctx, plugin, fetcher)
				require.NoError(t, err)
				objects = append(objects, &artifactv1alpha1.ArtifactNode{
					ObjectMeta: metav1.ObjectMeta{Name: "plugin--" + plugin.Name + "--node", Namespace: plugin.Namespace,
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(plugin, artifactv1alpha1.GroupVersion.WithKind("Plugin"))}},
					Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "node"},
				})
			}
			rulesKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "rules"}
			installTestRulesfile(t, before, rulesKey, []commonv1alpha1.ArtifactMetaDependency{{Name: "custom-b", Version: "1.0.0"}})
			objects = append(objects, &artifactv1alpha1.ArtifactNode{
				ObjectMeta: metav1.ObjectMeta{Name: "rulesfile--rules--node", Namespace: "ns",
					OwnerReferences: []metav1.OwnerReference{controllerRef("Rulesfile", rulesKey.Name)}},
				Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "node"},
			})
			installed := before.FindInstalled(nodeartifacts.PluginConfigKey, artifact.MediumInline)
			require.NotNil(t, installed)
			readEntries := func() (map[string]any, []any) {
				t.Helper()
				var config map[string]any
				require.NoError(t, yaml.Unmarshal(fs.Files[installed.Path], &config))
				entries := make(map[string]any)
				for _, entry := range config["plugins"].([]any) {
					plugin := entry.(map[string]any)
					entries[plugin["name"].(string)] = plugin
				}
				loads, _ := config["load_plugins"].([]any)
				return entries, loads
			}
			original, _ := readEntries()
			desiredB := pluginB.DeepCopy()
			desiredB.Generation = 2
			desiredB.Spec.Config.OpenParams = "not-installed"
			desiredB.Spec.Config.InitConfig = &apiextensionsv1.JSON{Raw: []byte(`{"nested":{"value":"not-installed"}}`)}
			// The current generation has not passed the normal controller's gate. WarmSync
			// uses its alias only for ownership, never to publish these desired config bytes.
			objects = append(objects, pluginA, desiredB)
			cl := fake.NewClientBuilder().WithScheme(newWarmSyncTestScheme(t)).WithObjects(objects...).
				WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).Build()
			after := nodeartifacts.NewManager(store, versions)

			require.NoError(t, nodeartifacts.WarmSync(ctx, cl, after, "ns", "node"))
			afterRejection, _ := readEntries()
			assert.Equal(t, original, afterRejection, "the unapplied desired config must not alter any installed entry")
			if operation == update {
				updatedA := pluginA.DeepCopy()
				updatedA.Spec.Config.OpenParams = "updated-a"
				_, _, err := after.AddPluginConfig(ctx, updatedA, fetcher)
				require.NoError(t, err)
			} else {
				identity := &artifactv1alpha1.Plugin{ObjectMeta: *pluginA.ObjectMeta.DeepCopy()}
				require.NoError(t, after.RemovePluginConfig(ctx, fetcher, identity), "deletion must resolve the installed custom name without spec")
			}

			entries, loads := readEntries()
			assert.Equal(t, original["custom-b"], entries["custom-b"], "B's complete installed config must survive an unrelated write")
			assert.Contains(t, loads, "custom-b")
			if operation == update {
				require.Contains(t, entries, "custom-a")
				assert.Equal(t, "updated-a", entries["custom-a"].(map[string]any)["open_params"])
			} else {
				assert.NotContains(t, entries, "custom-a")
				assert.NotContains(t, loads, "custom-a")
			}
		})
	}
}

func TestWarmSync_PluginConfigUsesOnlyCurrentAssignments(t *testing.T) {
	const unchanged = "unchanged"
	const renamed, aliasCollision, otherPluginName = "renamed", "alias collision", "plugin-b"
	const otherPluginUID = "uid-b"
	for _, scenario := range []string{unchanged, renamed, "missing parent", "stale UID", "deleting assignment",
		"deleting parent", "OCI removed", "other node", "non-controller owner", aliasCollision, "duplicate assignment"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			versions := compatfake.NewMockVersionsFetcher(nil)
			before := nodeartifacts.NewManager(store, versions)
			plugin := &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "plugin-a", Namespace: "ns", UID: "uid-a"},
				Spec: artifactv1alpha1.PluginSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{},
					Config: &artifactv1alpha1.PluginConfig{Name: "installed-alias", OpenParams: "installed"}},
			}
			_, configFile, err := before.AddPluginConfig(ctx, plugin, &artifact.Fetcher{})
			require.NoError(t, err)
			require.NotNil(t, configFile)
			node := &artifactv1alpha1.ArtifactNode{
				ObjectMeta: metav1.ObjectMeta{Name: "plugin-a-node", Namespace: "ns",
					OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(plugin, artifactv1alpha1.GroupVersion.WithKind("Plugin"))}},
				Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "node"},
			}
			objects := make([]client.Object, 0, 4)
			objects = append(objects, node, plugin)
			keep := false
			switch scenario {
			case unchanged:
				keep = true
			case renamed:
				plugin.Spec.Config.Name = "current-alias"
			case "missing parent":
				objects = objects[:1]
			case "stale UID":
				plugin.UID = "new-uid"
			case "deleting assignment":
				now := metav1.Now()
				node.DeletionTimestamp, node.Finalizers = &now, []string{"test/finalizer"}
			case "deleting parent":
				now := metav1.Now()
				plugin.DeletionTimestamp, plugin.Finalizers = &now, []string{"test/finalizer"}
			case "OCI removed":
				plugin.Spec.OCIArtifact = nil
			case "other node":
				node.Spec.NodeName = "other"
			case "non-controller owner":
				node.OwnerReferences[0].Controller = new(false)
			case aliasCollision:
				other := plugin.DeepCopy()
				other.Name, other.UID = otherPluginName, otherPluginUID
				otherNode := node.DeepCopy()
				otherNode.Name = "plugin-b-node"
				otherNode.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(other, artifactv1alpha1.GroupVersion.WithKind("Plugin"))}
				objects = append(objects, other, otherNode)
			case "duplicate assignment":
				otherNode := node.DeepCopy()
				otherNode.Name = "duplicate-node"
				objects = append(objects, otherNode)
				keep = true
			}
			cl := fake.NewClientBuilder().WithScheme(newWarmSyncTestScheme(t)).WithObjects(objects...).
				WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).Build()
			after := nodeartifacts.NewManager(store, versions)
			writes := len(fs.WriteCalls)

			require.NoError(t, nodeartifacts.WarmSync(ctx, cl, after, "ns", "node"), "a user alias collision must not prevent controller startup")
			var content map[string]any
			require.NoError(t, yaml.Unmarshal(fs.Files[configFile.Path], &content))
			if keep {
				assert.Equal(t, []any{"installed-alias"}, content["load_plugins"])
				assert.Len(t, fs.WriteCalls, writes, "unchanged observed config must not be rewritten")
			} else {
				assert.Empty(t, content["load_plugins"])
				assert.Empty(t, content["plugins"])
			}
			if scenario == renamed {
				_, _, err = after.AddPluginConfig(ctx, plugin, &artifact.Fetcher{})
				require.NoError(t, err)
				assert.NotContains(t, string(fs.Files[configFile.Path]), "installed-alias")
				assert.Contains(t, string(fs.Files[configFile.Path]), "current-alias")
			}
			if scenario == aliasCollision {
				_, _, err = after.AddPluginConfig(ctx, plugin, &artifact.Fetcher{})
				require.NoError(t, err, "normal reconciliation can claim an unassigned current alias")
				other := plugin.DeepCopy()
				other.Name, other.UID = otherPluginName, otherPluginUID
				_, _, err = after.AddPluginConfig(ctx, other, &artifact.Fetcher{})
				require.Error(t, err, "the competing current owner must not overwrite the first installation")
			}
			for path := range fs.Files {
				assert.False(t, strings.HasSuffix(path, ".json"), "no journal is created: %s", path)
			}
		})
	}
}

func TestWarmSync_PluginConfigRepairPrecedesOrphanRemoval(t *testing.T) {
	const namespace = "ns"
	for _, corrupt := range []bool{false, true} {
		name := "valid orphan config"
		if corrupt {
			name = "corrupt config"
		}
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			versions := compatfake.NewMockVersionsFetcher(nil)
			before := nodeartifacts.NewManager(store, versions)
			fetcher := &artifact.Fetcher{}
			plugin := testPlugin("orphan")
			plugin.Namespace, plugin.UID = namespace, "old-uid"
			plugin.Spec.OCIArtifact = &commonv1alpha1.OCIArtifact{}
			result, err := fetcher.FetchInline(ctx, []byte("orphan binary"))
			require.NoError(t, err)
			_, binary, err := before.StorePlugin(ctx, plugin, result)
			require.NoError(t, err)
			_, config, err := before.AddPluginConfig(ctx, plugin, fetcher)
			require.NoError(t, err)
			if corrupt {
				fs.Files[config.Path] = []byte("plugins: [")
			}
			original := string(fs.Files[config.Path])
			cl := fake.NewClientBuilder().WithScheme(newWarmSyncTestScheme(t)).
				WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).Build()
			fs.WriteErrFor = map[string]error{filepath.Join(filepath.Dir(config.Path), ".tmp", filepath.Base(config.Path)+".tmp"): assert.AnError}
			after := nodeartifacts.NewManager(store, versions)

			require.Error(t, nodeartifacts.WarmSync(ctx, cl, after, plugin.Namespace, "node"))
			assert.Equal(t, original, string(fs.Files[config.Path]), "failed atomic replacement preserves the observed bytes")
			assert.Contains(t, fs.Files, binary.Path, "never delete a binary before its config was removed successfully")
			assert.NotContains(t, fs.RemoveCalls, binary.Path)

			fs.WriteErrFor = nil
			after = nodeartifacts.NewManager(store, versions)
			require.NoError(t, nodeartifacts.WarmSync(ctx, cl, after, plugin.Namespace, "node"))
			assert.NotContains(t, fs.Files, binary.Path)
			var repaired map[string]any
			require.NoError(t, yaml.Unmarshal(fs.Files[config.Path], &repaired))
			assert.Empty(t, repaired["plugins"])
			assert.Empty(t, repaired["load_plugins"])
			writes := len(fs.WriteCalls)
			require.NoError(t, nodeartifacts.WarmSync(ctx, cl, nodeartifacts.NewManager(store, versions), plugin.Namespace, "node"))
			assert.Len(t, fs.WriteCalls, writes, "a repaired aggregate is a no-op at the following restart")
		})
	}
}

func TestWarmSync_CurrentPluginListFailure(t *testing.T) {
	for _, failPlugins := range []bool{false, true} {
		name := "ArtifactNodes"
		if failPlugins {
			name = "Plugins"
		}
		t.Run(name, func(t *testing.T) {
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			cl := fake.NewClientBuilder().WithScheme(newWarmSyncTestScheme(t)).
				WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
				WithInterceptorFuncs(interceptor.Funcs{
					List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						_, plugins := list.(*artifactv1alpha1.PluginList)
						if plugins == failPlugins {
							return assert.AnError
						}
						return cl.List(ctx, list, opts...)
					},
				}).Build()
			err := nodeartifacts.WarmSync(t.Context(), cl, nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil)), "ns", "node")
			require.ErrorIs(t, err, assert.AnError)
			assert.Empty(t, fs.WriteCalls)
			assert.Empty(t, fs.RemoveCalls)
		})
	}
}

// TestWarmSync_IgnoresOtherNodes verifies ArtifactNodes that exist only on a different node are
// excluded from this node's dependency registry.
func TestWarmSync_IgnoresOtherNodes(t *testing.T) {
	sch := newWarmSyncTestScheme(t)

	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "ns"},
	}
	pluginNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "plugin--container--other-node",
			Namespace:       "ns",
			Labels:          map[string]string{"artifact.falcosecurity.dev/node": "other-node"},
			OwnerReferences: []metav1.OwnerReference{controllerRef("Plugin", "container")},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "other-node"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{{Path: "/x", Medium: "oci"}},
		},
	}
	rulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"},
		Status: artifactv1alpha1.RulesfileStatus{
			ArtifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "0.4.0"}},
			},
		},
	}
	rulesfileNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "rulesfile--my-rules--other-node",
			Namespace:       "ns",
			Labels:          map[string]string{"artifact.falcosecurity.dev/node": "other-node"},
			OwnerReferences: []metav1.OwnerReference{controllerRef("Rulesfile", "my-rules")},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "other-node"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{{Path: "/y", Medium: "oci"}},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithObjects(plugin, pluginNode, rulesfile, rulesfileNode).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

	// Warm-syncing "minikube", which has no ArtifactNodes of its own, must not pick up
	// "other-node"'s entries.
	require.NoError(t, nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube"))

	require.NoError(t, mgr.RemovePluginConfig(context.Background(), &artifact.Fetcher{}, plugin))
}

// TestWarmSync_SeedsInstalledCacheFromDiskEvenWhenStatusDoesNotKnowAboutIt simulates the crash
// window where a file was written to disk but the process died before the status patch
// recording it landed: status is missing the inline medium's entry even though the file exists
// on disk. WarmSync must seed the manager's cache from disk ground truth regardless, since that
// cache (never status) is what every later filesystem decision reads from.
func TestWarmSync_SeedsInstalledCacheFromDiskEvenWhenStatusDoesNotKnowAboutIt(t *testing.T) {
	sch := newWarmSyncTestScheme(t)

	rulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"},
	}
	rulesfileNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "rulesfile--my-rules--minikube",
			Namespace:       "ns",
			Labels:          map[string]string{"artifact.falcosecurity.dev/node": "minikube"},
			OwnerReferences: []metav1.OwnerReference{controllerRef("Rulesfile", "my-rules")},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "minikube"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{
				{Path: "/rulesfiles/50-01-my-rules-oci.yaml", Medium: "oci", Priority: 50, ContentHash: "oci-hash"},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithObjects(rulesfile, rulesfileNode).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	fsys := fsfake.NewMockFileSystem()
	fsys.Files["/rulesfiles/50-01-my-rules-oci.yaml"] = []byte("oci content")
	fsys.Files["/rulesfiles/50-03-my-rules-inline.yaml"] = []byte("inline content")
	store := &artifact.LocalStore{FS: fsys, Dirs: artifact.ArtifactDirs{Rulesfile: "/rulesfiles", Plugin: "/plugins", Config: "/configs"}}
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

	require.NoError(t, nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube"))

	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "my-rules"}
	inlineEntry := mgr.FindInstalled(key, artifact.MediumInline)
	require.NotNil(t, inlineEntry, "the cache must reflect the file already on disk, regardless of what status says")
	assert.Equal(t, "/rulesfiles/50-03-my-rules-inline.yaml", inlineEntry.Path)

	// Status itself is never touched by WarmSync: it stays exactly as it was on disk/durably
	// stored, since it's read only by kubectl, never by a filesystem decision.
	got := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(rulesfileNode), got))
	assert.Nil(t, artifact.FindInstalled(got.Status.InstalledArtifacts, artifact.MediumInline))

	// The file itself must not have been touched (still present, unmodified).
	assert.Equal(t, []byte("inline content"), fsys.Files["/rulesfiles/50-03-my-rules-inline.yaml"])
}

// TestWarmSync_RemovesOrphanedFilesWithNoArtifactNode covers a name with files on disk but no
// ArtifactNode at all for this node (e.g. its parent CR was deleted and fully garbage collected
// while this node had no durable status recording those files, or before this scan existed).
// Nothing will ever ask about that name again, so WarmSync must remove it immediately.
func TestWarmSync_RemovesOrphanedFilesWithNoArtifactNode(t *testing.T) {
	sch := newWarmSyncTestScheme(t)

	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	fsys := fsfake.NewMockFileSystem()
	fsys.Files["/rulesfiles/50-01-orphaned-oci.yaml"] = []byte("stray content")
	store := &artifact.LocalStore{FS: fsys, Dirs: artifact.ArtifactDirs{Rulesfile: "/rulesfiles", Plugin: "/plugins", Config: "/configs"}}
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

	require.NoError(t, nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube"))

	_, exists := fsys.Files["/rulesfiles/50-01-orphaned-oci.yaml"]
	assert.False(t, exists, "orphaned file with no matching ArtifactNode must be removed")
}

// TestWarmSync_NeverPatchesStatus verifies WarmSync never writes to any ArtifactNode's status,
// since the cache it seeds (not status) is now the sole source filesystem decisions read from;
// status is a write-through mirror later reconciles maintain for observability only.
func TestWarmSync_NeverPatchesStatus(t *testing.T) {
	sch := newWarmSyncTestScheme(t)

	rulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"},
	}
	rulesfileNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "rulesfile--my-rules--minikube",
			Namespace:       "ns",
			Labels:          map[string]string{"artifact.falcosecurity.dev/node": "minikube"},
			OwnerReferences: []metav1.OwnerReference{controllerRef("Rulesfile", "my-rules")},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "minikube"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{
				{Path: "/rulesfiles/50-01-my-rules-oci.yaml", Medium: "oci", Priority: 50, ContentHash: sha256hexForTest("oci content")},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithObjects(rulesfile, rulesfileNode).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	got := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(rulesfileNode), got))
	beforeRV := got.ResourceVersion

	fsys := fsfake.NewMockFileSystem()
	fsys.Files["/rulesfiles/50-01-my-rules-oci.yaml"] = []byte("oci content")
	store := &artifact.LocalStore{FS: fsys, Dirs: artifact.ArtifactDirs{Rulesfile: "/rulesfiles", Plugin: "/plugins", Config: "/configs"}}
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

	require.NoError(t, nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube"))

	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(rulesfileNode), got))
	assert.Equal(t, beforeRV, got.ResourceVersion, "no patch should be issued when disk already agrees with status")
}

// Status does not establish the installed OCI identity; reconciliation must fetch
// the current pinned artifact before recording its spec hash again.
func TestWarmSync_DoesNotRecoverSpecHashFromStatus(t *testing.T) {
	sch := newWarmSyncTestScheme(t)

	rulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"},
	}
	ociContentHash := sha256hexForTest("oci content")
	rulesfileNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "rulesfile--my-rules--minikube",
			Namespace:       "ns",
			Labels:          map[string]string{"artifact.falcosecurity.dev/node": "minikube"},
			OwnerReferences: []metav1.OwnerReference{controllerRef("Rulesfile", "my-rules")},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "minikube"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{
				{Path: "/rulesfiles/50-01-my-rules-oci.yaml", Medium: "oci", Priority: 50, ContentHash: ociContentHash, SpecHash: "spec-abc"},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithObjects(rulesfile, rulesfileNode).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	fsys := fsfake.NewMockFileSystem()
	fsys.Files["/rulesfiles/50-01-my-rules-oci.yaml"] = []byte("oci content")
	store := &artifact.LocalStore{FS: fsys, Dirs: artifact.ArtifactDirs{Rulesfile: "/rulesfiles", Plugin: "/plugins", Config: "/configs"}}
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

	require.NoError(t, nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube"))

	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "my-rules"}
	ociEntry := mgr.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, ociEntry)
	assert.Empty(t, ociEntry.SpecHash,
		"even matching content does not make status a source of installed spec identity")
}

// TestWarmSync_FailsWhenScanAllErrors reproduces a real bug: a ScanAll error for one artifact
// Kind used to be logged and swallowed, letting WarmSync report success with that Kind's cache
// left completely unseeded. A later handleDeletion for an artifact of that Kind would then read
// nothing from the cache and release the finalizer without cleaning up whatever is actually on
// disk. WarmSync must instead fail loudly, since WarmSyncRunnable.Warmup surfaces its error by
// failing manager startup (see warmsync_runnable.go) rather than proceeding half-seeded.
func TestWarmSync_FailsWhenScanAllErrors(t *testing.T) {
	sch := newWarmSyncTestScheme(t)

	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	fsys := fsfake.NewMockFileSystem()
	fsys.Files["/plugins/json.so"] = []byte("plugin content")
	fsys.ReadErrFor = map[string]error{"/plugins/json.so": assert.AnError}
	store := &artifact.LocalStore{FS: fsys, Dirs: artifact.ArtifactDirs{Rulesfile: "/rulesfiles", Plugin: "/plugins", Config: "/configs"}}
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

	err := nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube")

	require.Error(t, err, "a ScanAll failure must fail WarmSync instead of leaving that Kind's cache silently unseeded")
}

func TestWarmSync_DeletingNodesWithoutFilesDoNotBlockRemoval(t *testing.T) {
	sch := newWarmSyncTestScheme(t)
	now := metav1.Now()
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "ns"},
	}
	pluginNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "plugin--container--minikube",
			Namespace:         "ns",
			Labels:            map[string]string{"artifact.falcosecurity.dev/node": "minikube"},
			OwnerReferences:   []metav1.OwnerReference{controllerRef("Plugin", "container")},
			DeletionTimestamp: &now,
			Finalizers:        []string{"keep-alive-for-test"},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "minikube"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{{Path: "/x", Medium: "oci"}},
		},
	}
	rulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"},
		Status: artifactv1alpha1.RulesfileStatus{
			ArtifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "0.4.0"}},
			},
		},
	}
	rulesfileNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "rulesfile--my-rules--minikube",
			Namespace:         "ns",
			Labels:            map[string]string{"artifact.falcosecurity.dev/node": "minikube"},
			OwnerReferences:   []metav1.OwnerReference{controllerRef("Rulesfile", "my-rules")},
			DeletionTimestamp: &now,
			Finalizers:        []string{"keep-alive-for-test"},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "minikube"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{{Path: "/y", Medium: "oci"}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(sch).WithObjects(plugin, pluginNode, rulesfile, rulesfileNode).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

	require.NoError(t, nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube"))

	// Neither obsolete status path exists; terminating objects do not invent installed dependencies.
	require.NoError(t, mgr.RemovePluginConfig(context.Background(), &artifact.Fetcher{}, plugin))
}
