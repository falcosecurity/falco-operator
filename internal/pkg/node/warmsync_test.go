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
	"errors"
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
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

// previousUID and recreatedUID are the UIDs of two incarnations of an artifact of the same name: the one that
// installed files, and the one that replaced it.
const (
	previousUID  = "old-uid"
	recreatedUID = "new-uid"
)

func sha256hexForTest(s string) string { return testutil.SHA256Hex([]byte(s)) }

// assignedNode is the ArtifactNode of nodeName in namespace, listing refs in its spec.
func assignedNode(namespace, nodeName string, refs ...artifactv1alpha1.NodeArtifactRef) *artifactv1alpha1.ArtifactNode {
	return &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: namespace},
		Spec:       artifactv1alpha1.ArtifactNodeSpec{NodeName: nodeName, Artifacts: refs},
	}
}

// refTo is the assignment of obj, an artifact of kind.
func refTo(kind artifactv1alpha1.ArtifactKind, obj metav1.Object) artifactv1alpha1.NodeArtifactRef {
	return artifactv1alpha1.NodeArtifactRef{Kind: kind, Name: obj.GetName(), UID: string(obj.GetUID())}
}

// warmNode is the Node of nodeName in namespace, over cl and store: what a restarted sidecar sees.
func warmNode(t *testing.T, cl client.Client, store artifact.ArtifactStore,
	versions compat.VersionsFetcher, namespace, nodeName string,
) *Node {
	t.Helper()
	n, err := New(&Config{
		Fetcher:        newTestFetcher(cl),
		Client:         cl,
		NodeName:       nodeName,
		Namespace:      namespace,
		FalcoBaseURL:   compat.DefaultBaseURL,
		ReloadCooldown: DefaultReloadCooldown,
		Store:          store,
		FalcoFetcher:   versions,
	})
	require.NoError(t, err)
	return n
}

var warmSyncDirs = artifact.ArtifactDirs{Rulesfile: "/rulesfiles", Plugin: "/plugins", Config: "/configs"}

func TestWarmSync_ObservesTheFilesOfTheAssignedArtifacts(t *testing.T) {
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "ns"},
		Spec:       artifactv1alpha1.PluginSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{}},
	}
	rulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"},
		Status: artifactv1alpha1.RulesfileStatus{
			ArtifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "0.4.0"}},
			},
		},
	}
	artifactNode := assignedNode("ns", "minikube", refTo("Plugin", plugin), refTo("Rulesfile", rulesfile))
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(plugin, rulesfile, artifactNode).Build()

	store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	before := newTestNodeOver(store, compatfake.NewMockVersionsFetcher(nil))
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: rulesfile.Name}
	installTestRulesfile(t, before, key, rulesfile.Status.ArtifactMeta.Dependencies)
	_, _, err := before.AddPluginConfig(t.Context(), plugin)
	require.NoError(t, err)
	mgr := warmNode(t, cl, store, compatfake.NewMockVersionsFetcher(nil), "ns", "minikube")

	require.NoError(t, mgr.runWarmSync(t.Context()))

	// Disk files are observed, but neither previous-process nor parent-status dependencies
	// are imported. A normal source reconcile must register current checked dependencies.
	assert.Equal(t, before.GetInstalled(key), mgr.GetInstalled(key))
	require.NoError(t, mgr.RemovePluginConfig(t.Context(), plugin))
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
			const content = "json_output: true\n"
			before := newTestNodeOver(store, versions, configMapFor("ns", "plugins-config-cm", content))
			config := configMapConfig("ns", "plugins-config", scenario.priority, "plugins-config-cm")
			if scenario.medium == artifact.MediumInline {
				config = inlineConfig("ns", "plugins-config", scenario.priority, `{"json_output":true}`)
			}
			key := artifact.RefOf(artifact.KindConfig, config)
			require.NoError(t, apply(t, before, config))
			configFile := before.FindInstalled(key, scenario.medium)
			require.NotNil(t, configFile)
			var err error
			var sharedFile *artifact.File
			var plugin *artifactv1alpha1.Plugin
			refs := []artifactv1alpha1.NodeArtifactRef{{Kind: "Config", Name: key.Name}}
			var objects []client.Object
			if scenario.withPlugin {
				plugin = testPlugin("container")
				plugin.Namespace = config.Namespace
				plugin.Spec.OCIArtifact = &commonv1alpha1.OCIArtifact{}
				_, sharedFile, err = before.AddPluginConfig(ctx, plugin)
				require.NoError(t, err)
				require.NotNil(t, sharedFile)
				refs = append(refs, refTo("Plugin", plugin))
				objects = append(objects, plugin)
			}
			objects = append(objects, assignedNode(config.Namespace, "node", refs...))
			cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(objects...).Build()
			after := warmNode(t, cl, store, versions, config.Namespace, "node")

			require.NoError(t, after.runWarmSync(ctx))

			assert.Equal(t, configFile, after.FindInstalled(key, scenario.medium))
			assert.Equal(t, sharedFile, pluginsConfigFileOf(after))
			assert.Equal(t, content, string(fs.Files[configFile.Path]))
			require.NoError(t, removeArtifact(ctx, after, key))
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
			before := newTestNodeOver(store, versions)
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
			refs := make([]artifactv1alpha1.NodeArtifactRef, 0, 3)
			for _, plugin := range []*artifactv1alpha1.Plugin{pluginA, pluginB} {
				_, _, err := before.AddPluginConfig(ctx, plugin)
				require.NoError(t, err)
				refs = append(refs, refTo("Plugin", plugin))
			}
			rulesKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
			installTestRulesfile(t, before, rulesKey, []commonv1alpha1.ArtifactMetaDependency{{Name: "custom-b", Version: "1.0.0"}})
			refs = append(refs, artifactv1alpha1.NodeArtifactRef{Kind: "Rulesfile", Name: rulesKey.Name})
			installed := pluginsConfigFileOf(before)
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
			// The current generation has not passed the normal controller's gate. The warm sync
			// uses its alias only for ownership, never to publish these desired config bytes.
			cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
				WithObjects(pluginA, desiredB, assignedNode("ns", "node", refs...)).Build()
			after := warmNode(t, cl, store, versions, "ns", "node")

			require.NoError(t, after.runWarmSync(ctx))
			afterRejection, _ := readEntries()
			assert.Equal(t, original, afterRejection, "the unapplied desired config must not alter any installed entry")
			if operation == update {
				updatedA := pluginA.DeepCopy()
				updatedA.Spec.Config.OpenParams = "updated-a"
				_, _, err := after.AddPluginConfig(ctx, updatedA)
				require.NoError(t, err)
			} else {
				identity := &artifactv1alpha1.Plugin{ObjectMeta: *pluginA.ObjectMeta.DeepCopy()}
				require.NoError(t, after.RemovePluginConfig(ctx, identity), "deletion must resolve the installed custom name without spec")
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
	for _, scenario := range []string{unchanged, renamed, "missing parent", "stale UID", "deleting node object",
		"deleting parent", "OCI removed", "node object not visible", aliasCollision} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			versions := compatfake.NewMockVersionsFetcher(nil)
			before := newTestNodeOver(store, versions)
			plugin := &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "plugin-a", Namespace: "ns", UID: "uid-a"},
				Spec: artifactv1alpha1.PluginSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{},
					Config: &artifactv1alpha1.PluginConfig{Name: "installed-alias", OpenParams: "installed"}},
			}
			_, configFile, err := before.AddPluginConfig(ctx, plugin)
			require.NoError(t, err)
			require.NotNil(t, configFile)
			artifactNode := assignedNode("ns", "node", refTo("Plugin", plugin))
			objects := []client.Object{artifactNode, plugin}
			keep := false
			switch scenario {
			case unchanged:
				keep = true
			case renamed:
				plugin.Spec.Config.Name = "current-alias"
			case "missing parent":
				objects = objects[:1]
			case "stale UID":
				plugin.UID = recreatedUID
			case "deleting node object":
				now := metav1.Now()
				artifactNode.DeletionTimestamp, artifactNode.Finalizers = &now, []string{"test/finalizer"}
			case "deleting parent":
				now := metav1.Now()
				plugin.DeletionTimestamp, plugin.Finalizers = &now, []string{"test/finalizer"}
			case "OCI removed":
				plugin.Spec.OCIArtifact = nil
			case "node object not visible":
				// With no ArtifactNode for this node, nothing says what is assigned, so nothing is pruned.
				otherNode := "other"
				artifactNode.Name, artifactNode.Spec.NodeName = otherNode, otherNode
				keep = true
			case aliasCollision:
				other := plugin.DeepCopy()
				other.Name, other.UID = otherPluginName, otherPluginUID
				artifactNode.Spec.Artifacts = append(artifactNode.Spec.Artifacts, refTo("Plugin", other))
				objects = append(objects, other)
			}
			cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(objects...).Build()
			after := warmNode(t, cl, store, versions, "ns", "node")
			writes := len(fs.WriteCalls)

			require.NoError(t, after.runWarmSync(ctx), "a user alias collision must not prevent controller startup")
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
				_, _, err = after.AddPluginConfig(ctx, plugin)
				require.NoError(t, err)
				assert.NotContains(t, string(fs.Files[configFile.Path]), "installed-alias")
				assert.Contains(t, string(fs.Files[configFile.Path]), "current-alias")
			}
			if scenario == aliasCollision {
				_, _, err = after.AddPluginConfig(ctx, plugin)
				require.NoError(t, err, "normal reconciliation can claim an unassigned current alias")
				other := plugin.DeepCopy()
				other.Name, other.UID = otherPluginName, otherPluginUID
				_, _, err = after.AddPluginConfig(ctx, other)
				require.Error(t, err, "the competing current owner must not overwrite the first installation")
			}
			for path := range fs.Files {
				assert.False(t, strings.HasSuffix(path, ".json"), "no journal is created: %s", path)
			}
		})
	}
}

// A plugin's config that no assigned plugin owns is pruned from the shared aggregate at startup, but its binary
// is left for the node controller's sweep: warm sync removes no artifact.
func TestWarmSync_PrunesTheAggregateButLeavesTheBinaryToTheSweep(t *testing.T) {
	const namespace = "ns"
	for _, corrupt := range []bool{false, true} {
		name := "valid unowned config"
		if corrupt {
			name = "corrupt config"
		}
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			versions := compatfake.NewMockVersionsFetcher(nil)
			before := newTestNodeOver(store, versions)
			plugin := testPlugin("orphan")
			plugin.Namespace, plugin.UID = namespace, previousUID
			require.NoError(t, apply(t, before, withBinary(plugin, "orphan binary")))
			binary := before.FindInstalled(artifact.RefOf(artifact.KindPlugin, plugin), artifact.MediumOCI)
			require.NotNil(t, binary)
			config := pluginsConfigFileOf(before)
			require.NotNil(t, config)
			if corrupt {
				fs.Files[config.Path] = []byte("plugins: [")
			}
			original := string(fs.Files[config.Path])
			// The node's ArtifactNode exists and assigns nothing.
			cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(assignedNode(namespace, "node")).Build()
			fs.WriteErrFor = map[string]error{artifact.StagingPath(config.Path): assert.AnError}
			after := warmNode(t, cl, store, versions, namespace, "node")

			require.Error(t, after.runWarmSync(ctx))
			assert.Equal(t, original, string(fs.Files[config.Path]), "failed atomic replacement preserves the observed bytes")

			fs.WriteErrFor = nil
			after = warmNode(t, cl, store, versions, namespace, "node")
			require.NoError(t, after.runWarmSync(ctx))
			var repaired map[string]any
			require.NoError(t, yaml.Unmarshal(fs.Files[config.Path], &repaired))
			assert.Empty(t, repaired["plugins"])
			assert.Empty(t, repaired["load_plugins"])
			assert.Contains(t, fs.Files, binary.Path, "warm sync never removes an artifact's files")
			assert.NotContains(t, fs.RemoveCalls, binary.Path)
			writes := len(fs.WriteCalls)
			require.NoError(t, (warmNode(t, cl, store, versions, namespace, "node")).runWarmSync(ctx))
			assert.Len(t, fs.WriteCalls, writes, "a repaired aggregate is a no-op at the following restart")
		})
	}
}

func TestWarmSync_ReadFailures(t *testing.T) {
	for _, failNode := range []bool{true, false} {
		name := "the node's ArtifactNode"
		if !failNode {
			name = "Plugins"
		}
		t.Run(name, func(t *testing.T) {
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(assignedNode("ns", "node")).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
						if _, isNode := obj.(*artifactv1alpha1.ArtifactNode); isNode && failNode {
							return assert.AnError
						}
						return cl.Get(ctx, key, obj, opts...)
					},
					List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						if _, plugins := list.(*artifactv1alpha1.PluginList); plugins && !failNode {
							return assert.AnError
						}
						return cl.List(ctx, list, opts...)
					},
				}).Build()

			err := (warmNode(t, cl, store, compatfake.NewMockVersionsFetcher(nil), "ns", "node")).runWarmSync(t.Context())

			require.ErrorIs(t, err, assert.AnError)
			assert.Empty(t, fs.WriteCalls)
			assert.Empty(t, fs.RemoveCalls)
		})
	}
}

// TestWarmSync_SeedsInstalledCacheFromDiskEvenWhenStatusDoesNotKnowAboutIt simulates the crash window where a
// file was written to disk but the process died before the status publish recording it landed: the status is
// missing the inline medium's entry even though the file exists on disk. The warm sync must seed the node's record
// from disk ground truth regardless, since that cache (never status) is what every later filesystem decision
// reads from.
func TestWarmSync_SeedsInstalledCacheFromDiskEvenWhenStatusDoesNotKnowAboutIt(t *testing.T) {
	rulesfile := &artifactv1alpha1.Rulesfile{ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"}}
	artifactNode := assignedNode("ns", "minikube", refTo("Rulesfile", rulesfile))
	artifactNode.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{{
		Kind: "Rulesfile", Name: "my-rules", UID: "u",
		InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{
			{Path: "/rulesfiles/50-01-my-rules-oci.yaml", Medium: "oci", Priority: 50, ContentHash: "oci-hash"},
		},
	}}
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(rulesfile, artifactNode).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()

	fsys := fsfake.NewMockFileSystem()
	fsys.Files["/rulesfiles/50-01-my-rules-oci.yaml"] = []byte("oci content")
	fsys.Files["/rulesfiles/50-03-my-rules-inline.yaml"] = []byte("inline content")
	mgr := warmNode(t, cl, &artifact.LocalStore{FS: fsys, Dirs: warmSyncDirs}, compatfake.NewMockVersionsFetcher(nil), "ns", "minikube")

	require.NoError(t, mgr.runWarmSync(t.Context()))

	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "my-rules"}
	inlineEntry := mgr.FindInstalled(key, artifact.MediumInline)
	require.NotNil(t, inlineEntry, "the cache must reflect the file already on disk, regardless of what status says")
	assert.Equal(t, "/rulesfiles/50-03-my-rules-inline.yaml", inlineEntry.Path)

	// The file itself must not have been touched (still present, unmodified).
	assert.Equal(t, []byte("inline content"), fsys.Files["/rulesfiles/50-03-my-rules-inline.yaml"])
}

// TestWarmSync_NeverPatchesStatus verifies the warm sync never writes to the ArtifactNode, since the cache it seeds
// (not status) is the sole source filesystem decisions read from; status is a mirror the publisher maintains
// for observability only.
func TestWarmSync_NeverPatchesStatus(t *testing.T) {
	rulesfile := &artifactv1alpha1.Rulesfile{ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"}}
	artifactNode := assignedNode("ns", "minikube", refTo("Rulesfile", rulesfile))
	artifactNode.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{{
		Kind: "Rulesfile", Name: "my-rules", UID: "u",
		InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{
			{Path: "/rulesfiles/50-01-my-rules-oci.yaml", Medium: "oci", Priority: 50, ContentHash: sha256hexForTest("oci content")},
		},
	}}
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(rulesfile, artifactNode).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
	got := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(artifactNode), got))
	beforeRV := got.ResourceVersion

	fsys := fsfake.NewMockFileSystem()
	fsys.Files["/rulesfiles/50-01-my-rules-oci.yaml"] = []byte("oci content")
	mgr := warmNode(t, cl, &artifact.LocalStore{FS: fsys, Dirs: warmSyncDirs}, compatfake.NewMockVersionsFetcher(nil), "ns", "minikube")

	require.NoError(t, mgr.runWarmSync(t.Context()))

	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(artifactNode), got))
	assert.Equal(t, beforeRV, got.ResourceVersion, "no patch should be issued when disk already agrees with status")
}

// Status does not establish the installed OCI identity; reconciliation must fetch the current pinned artifact
// before recording its spec hash again.
func TestWarmSync_DoesNotRecoverSpecHashFromStatus(t *testing.T) {
	rulesfile := &artifactv1alpha1.Rulesfile{ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"}}
	artifactNode := assignedNode("ns", "minikube", refTo("Rulesfile", rulesfile))
	artifactNode.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{{
		Kind: "Rulesfile", Name: "my-rules", UID: "u",
		InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{{
			Path: "/rulesfiles/50-01-my-rules-oci.yaml", Medium: "oci", Priority: 50,
			ContentHash: sha256hexForTest("oci content"), SpecHash: "spec-abc",
		}},
	}}
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(rulesfile, artifactNode).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()

	fsys := fsfake.NewMockFileSystem()
	fsys.Files["/rulesfiles/50-01-my-rules-oci.yaml"] = []byte("oci content")
	mgr := warmNode(t, cl, &artifact.LocalStore{FS: fsys, Dirs: warmSyncDirs}, compatfake.NewMockVersionsFetcher(nil), "ns", "minikube")

	require.NoError(t, mgr.runWarmSync(t.Context()))

	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "my-rules"}
	ociEntry := mgr.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, ociEntry)
	assert.Empty(t, ociEntry.SpecHash, "even matching content does not make status a source of installed spec identity")
}

// TestWarmSync_FailsWhenScanAllErrors checks that a ScanAll error for one artifact Kind fails the warm sync. Were it
// logged and swallowed, the warm sync would report success with that Kind's cache left unseeded, and a later cleanup
// of an artifact of that Kind would read nothing from the cache and finish without removing whatever is actually
// on disk. WarmSyncRunnable.Warmup surfaces the error by failing manager startup rather than proceeding
// half-seeded.
func TestWarmSync_FailsWhenScanAllErrors(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).Build()

	fsys := fsfake.NewMockFileSystem()
	fsys.Files["/plugins/json.so"] = []byte("plugin content")
	fsys.ReadErrFor = map[string]error{"/plugins/json.so": assert.AnError}
	mgr := warmNode(t, cl, &artifact.LocalStore{FS: fsys, Dirs: warmSyncDirs}, compatfake.NewMockVersionsFetcher(nil), "ns", "minikube")

	err := mgr.runWarmSync(t.Context())

	require.Error(t, err, "a ScanAll failure must fail the warm sync instead of leaving that Kind's cache silently unseeded")
}

// rulesWithPluginDependency is a Falco rules document that declares what it needs, the way a real
// one does. The requirement is in the file, so it survives a restart without any CR.
const rulesWithPluginDependency = `- required_engine_version: 0.31.0
- required_plugin_versions:
  - name: container
    version: 0.7.0
- rule: a rule
  desc: a rule
  condition: evt.type=open
  output: something
  priority: WARNING
`

// TestWarmSync_RecoversRequirementsFromTheRulesFileItself covers the window between a restart and
// the first rulesfile reconcile. Were the requires side of the graph empty until then, a plugin an
// installed rulesfile depends on could be removed out from under it.
//
// This is not the same as importing dependencies from a previous process or from the parent's
// status, which TestWarmSync_ObservesTheFilesOfTheAssignedArtifacts deliberately does not do:
// the requirement here is read out of the installed bytes, so it cannot disagree with them.
func TestWarmSync_RecoversRequirementsFromTheRulesFileItself(t *testing.T) {
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "ns"},
		Spec:       artifactv1alpha1.PluginSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{}},
	}
	rulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"},
	}
	artifactNode := assignedNode("ns", "minikube", refTo("Plugin", plugin), refTo("Rulesfile", rulesfile))
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(plugin, rulesfile, artifactNode).Build()

	store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	before := newTestNodeOver(store, compatfake.NewMockVersionsFetcher(nil))
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: rulesfile.Name}

	content, err := (&artifact.Fetcher{}).FetchInline(t.Context(), []byte(rulesWithPluginDependency))
	require.NoError(t, err)
	_, _, err = before.StoreRulesfile(t.Context(), key.Name, 50,
		artifact.MediumOCI, content, nil, false)
	require.NoError(t, err)
	_, _, err = before.AddPluginConfig(t.Context(), plugin)
	require.NoError(t, err)

	// The sidecar restarts: a fresh node over the same disk, nothing carried over in memory.
	restarted := warmNode(t, cl, store, compatfake.NewMockVersionsFetcher(nil), "ns", "minikube")
	require.NoError(t, restarted.runWarmSync(t.Context()))

	err = restarted.RemovePluginConfig(t.Context(), plugin)
	blocked, ok := errors.AsType[*BlockedError](err)
	require.True(t, ok, "the installed rules file requires this plugin, so its removal must be blocked: %v", err)
	assert.Equal(t, "container", blocked.Name)
	assert.Contains(t, blocked.BlockedBy, key)
}

func warmSyncClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, artifactv1alpha1.AddToScheme(s))
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
}

func installedKey(name string) artifact.Ref {
	return artifact.Ref{Kind: artifact.KindConfig, Name: name}
}

// installOnDisk returns the Node of the test node over a client holding artifactNode, with a config
// file already written to its disk. The install persists the Config's status entry to the node's
// ArtifactNode, so a nil artifactNode means one that is deleted once the file is written.
func installOnDisk(t *testing.T, name string, artifactNode *artifactv1alpha1.ArtifactNode) *Node {
	t.Helper()
	installedOn := artifactNode
	if installedOn == nil {
		installedOn = &artifactv1alpha1.ArtifactNode{
			ObjectMeta: metav1.ObjectMeta{Name: statusTestNode, Namespace: statusTestNamespace},
			Spec:       artifactv1alpha1.ArtifactNodeSpec{NodeName: statusTestNode},
		}
	}
	cl := warmSyncClient(t, installedOn)
	n := newWarmSyncNode(t, cl)
	installConfig(t, n, statusTestNamespace, name)
	if artifactNode == nil {
		require.NoError(t, cl.Delete(t.Context(), installedOn))
	}
	return n
}

// newWarmSyncNode is the Node of the warm-sync test node over cl.
func newWarmSyncNode(t *testing.T, cl client.Client) *Node {
	t.Helper()
	n, err := New(&Config{
		Fetcher:        newTestFetcher(cl),
		Client:         cl,
		NodeName:       statusTestNode,
		Namespace:      statusTestNamespace,
		FalcoBaseURL:   compat.DefaultBaseURL,
		ReloadCooldown: DefaultReloadCooldown,
		Store:          &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()},
		FalcoFetcher:   compatfake.NewMockVersionsFetcher(nil),
	})
	require.NoError(t, err)
	return n
}

func TestWarmSync_RecoversTheInstalledFilesWithoutRemovingAnything(t *testing.T) {
	// The file is on disk and the spec lists nothing: a warm sync that removed orphans would remove it.
	artifactNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{Name: statusTestNode, Namespace: statusTestNamespace},
		Spec:       artifactv1alpha1.ArtifactNodeSpec{NodeName: statusTestNode},
	}
	m := installOnDisk(t, "unlisted", artifactNode)

	require.NoError(t, m.runWarmSync(t.Context()))

	assert.NotEmpty(t, m.GetInstalled(installedKey("unlisted")),
		"removing is the node controller's job, after it has observed the ArtifactNode")
}

func TestWarmSync_DoesNothingButRecoverWhenTheArtifactNodeIsNotVisible(t *testing.T) {
	m := installOnDisk(t, "installed", nil)

	require.NoError(t, m.runWarmSync(t.Context()))

	assert.NotEmpty(t, m.GetInstalled(installedKey("installed")), "an ArtifactNode that cannot be seen is never a reason to remove")
}

func TestWarmSync_MakesThePublishedEntriesKnown(t *testing.T) {
	artifactNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{Name: statusTestNode, Namespace: statusTestNamespace},
		Spec:       artifactv1alpha1.ArtifactNodeSpec{NodeName: statusTestNode},
		Status: artifactv1alpha1.ArtifactNodeStatus{Artifacts: []artifactv1alpha1.NodeArtifactStatus{
			{Kind: "Rulesfile", Name: "reported", UID: "u"},
		}},
	}
	m := newWarmSyncNode(t, warmSyncClient(t, artifactNode))

	require.NoError(t, m.runWarmSync(t.Context()))

	assert.Contains(t, m.HeldKeys(),
		artifact.Ref{Kind: artifact.KindRulesfile, Name: "reported"},
		"the node controller must be able to see what a previous process reported")
}

func TestWarmSync_GetError(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build() // scheme without the type

	err := (newWarmSyncNode(t, cl)).runWarmSync(t.Context())

	require.Error(t, err)
}

// orphanPluginOnDisk installs a plugin with a binary through one Node and returns its key, binary and the
// shared plugins-config file, for a test that then restarts the sidecar over the same store.
func orphanPluginOnDisk(t *testing.T, store artifact.ArtifactStore, versions compat.VersionsFetcher, namespace string,
) (key artifact.Ref, binary, config *artifact.File) {
	t.Helper()
	before := newTestNodeOver(store, versions)
	plugin := testPlugin("orphan")
	plugin.Namespace, plugin.UID = namespace, previousUID
	require.NoError(t, apply(t, before, withBinary(plugin, "orphan binary")))
	key = artifact.RefOf(artifact.KindPlugin, plugin)
	binary = before.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, binary)
	config = pluginsConfigFileOf(before)
	require.NotNil(t, config)
	return key, binary, config
}

func TestWarmSync_WithoutAnArtifactNode_ARemovedOrphanPluginTakesItsConfigEntryAlong(t *testing.T) {
	const namespace = "ns"
	ctx := t.Context()
	fs := fsfake.NewMockFileSystem()
	store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
	versions := compatfake.NewMockVersionsFetcher(nil)
	key, binary, config := orphanPluginOnDisk(t, store, versions, namespace)

	// The restarted sidecar sees no ArtifactNode: warm sync only observes, and the node controller then has
	// everything held removed as orphans.
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).Build()
	after := warmNode(t, cl, store, versions, namespace, "node")
	require.NoError(t, after.runWarmSync(ctx))
	require.NoError(t, after.Remove(ctx, key))

	assert.NotContains(t, fs.Files, binary.Path)
	var written map[string]any
	require.NoError(t, yaml.Unmarshal(fs.Files[config.Path], &written))
	assert.Empty(t, written["plugins"], "the entry naming the removed binary must go with it, or Falco loads a file that is not there")
	assert.Empty(t, written["load_plugins"])
}

func TestWarmSync_WithoutAnArtifactNode_AnObservedEntryCanBeClaimedLater(t *testing.T) {
	const namespace = "ns"
	ctx := t.Context()
	fs := fsfake.NewMockFileSystem()
	store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
	versions := compatfake.NewMockVersionsFetcher(nil)
	_, _, config := orphanPluginOnDisk(t, store, versions, namespace)

	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).Build()
	after := warmNode(t, cl, store, versions, namespace, "node")
	require.NoError(t, after.runWarmSync(ctx))

	// The ArtifactNode appears and assigns the plugin again, under a new incarnation. Nobody owns the observed
	// entry, so the claim goes through.
	plugin := testPlugin("orphan")
	plugin.Namespace, plugin.UID = namespace, recreatedUID
	_, _, err := after.AddPluginConfig(ctx, plugin)
	require.NoError(t, err)
	var written map[string]any
	require.NoError(t, yaml.Unmarshal(fs.Files[config.Path], &written))
	assert.Len(t, written["plugins"], 1, "the claim replaces the observed entry instead of duplicating it")
	assert.Equal(t, []any{"orphan"}, written["load_plugins"])
}

// A plugin that is no longer assigned keeps its entry in the shared configuration across a restart while an
// installed Rulesfile requires it, and removing it is blocked as it was before the restart.
func TestWarmSync_KeepsTheConfigOfAPluginAnInstalledRulesfileRequires(t *testing.T) {
	const namespace = "ns"
	for _, scenario := range []string{"not assigned", "recreated parent", "parent being deleted", "ArtifactNode being deleted"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			versions := compatfake.NewMockVersionsFetcher(nil)
			before := newTestNodeOver(store, versions)
			plugin := testPlugin("container")
			plugin.Namespace, plugin.UID = namespace, previousUID
			require.NoError(t, apply(t, before, withBinary(plugin, "binary")))
			pluginKey := artifact.RefOf(artifact.KindPlugin, plugin)
			binary := before.FindInstalled(pluginKey, artifact.MediumOCI)
			require.NotNil(t, binary)
			config := pluginsConfigFileOf(before)
			require.NotNil(t, config)
			rules, err := (&artifact.Fetcher{}).FetchInline(ctx, []byte(rulesWithPluginDependency))
			require.NoError(t, err)
			_, _, err = before.StoreRulesfile(ctx, "my-rules", 50, artifact.MediumOCI, rules, nil, false)
			require.NoError(t, err)

			artifactNode := assignedNode(namespace, "node", refTo("Plugin", plugin))
			switch scenario {
			case "not assigned":
				artifactNode.Spec.Artifacts = nil
			case "recreated parent":
				plugin.UID = recreatedUID
			case "parent being deleted":
				now := metav1.Now()
				plugin.DeletionTimestamp, plugin.Finalizers = &now, []string{"test/finalizer"}
			case "ArtifactNode being deleted":
				now := metav1.Now()
				artifactNode.DeletionTimestamp, artifactNode.Finalizers = &now, []string{"test/finalizer"}
			}
			cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
				WithObjects(artifactNode, plugin).Build()
			after := warmNode(t, cl, store, versions, namespace, "node")
			writes := len(fs.WriteCalls)

			require.NoError(t, after.runWarmSync(ctx))

			assert.Contains(t, string(fs.Files[config.Path]), "container", "the rules still need the plugin loaded")
			assert.Len(t, fs.WriteCalls, writes, "a configuration kept as found is not rewritten")
			err = after.Remove(ctx, pluginKey)
			_, blocked := errors.AsType[*BlockedError](err)
			assert.True(t, blocked, "removing the plugin is blocked as it was before the restart: %v", err)
			assert.Contains(t, fs.Files, binary.Path)
		})
	}
}
