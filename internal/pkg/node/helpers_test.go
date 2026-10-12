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
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

// The tests put artifacts on a node the way a reconcile does, through ApplyArtifact: there is no
// other way in. These are the CRs they apply and the fetcher that serves their sources.

// configData is the inline content of a test Config, as the API server stores it.
const configData = `{"log_level":"info"}`

// testFetcher serves a test node's sources: inline and ConfigMap content through the real fetcher
// over the test client, and an OCI artifact as the bytes of the digest it is asked for, so a test
// chooses a plugin's binary by choosing the digest in its ArtifactMeta (see withBinary).
type testFetcher struct {
	*artifact.Fetcher
}

func newTestFetcher(cl client.Client) *testFetcher {
	return &testFetcher{Fetcher: &artifact.Fetcher{K8sClient: cl}}
}

func (f *testFetcher) FetchOCI(_ context.Context, _, _ string, kind artifact.Kind, digest string) (artifact.FetchResult, error) {
	perm, err := artifact.PermFor(kind)
	if err != nil {
		return artifact.FetchResult{}, err
	}
	content := []byte(digest)
	sum := sha256.Sum256(content)
	return artifact.FetchResult{Content: content, ContentHash: hex.EncodeToString(sum[:]), Perm: perm}, nil
}

// inlineConfig is a Config in namespace whose one source is inline data, already processed by the
// instance operator so that nothing waits on it.
func inlineConfig(namespace, name string, priority int32, data string) *artifactv1alpha1.Config {
	return &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(name + "-uid")},
		Spec:       artifactv1alpha1.ConfigSpec{Config: &apiextensionsv1.JSON{Raw: []byte(data)}, Priority: priority},
	}
}

// configMapConfig is a Config in namespace whose one source is the ConfigMap named configMap.
func configMapConfig(namespace, name string, priority int32, configMap string) *artifactv1alpha1.Config {
	return &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(name + "-uid")},
		Spec:       artifactv1alpha1.ConfigSpec{ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: configMap}, Priority: priority},
	}
}

// configMapFor is the ConfigMap a Config's configMapRef names, holding data under the config key.
func configMapFor(namespace, name, data string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Data:       map[string]string{commonv1alpha1.ConfigMapConfigKey: data},
	}
}

// inlineFile is what the node writes for a Config's inline data: the API server stores it as JSON,
// the node writes it as YAML.
func inlineFile(t *testing.T, data string) []byte {
	t.Helper()
	out, err := common.JSONRawToYAML(&apiextensionsv1.JSON{Raw: []byte(data)})
	require.NoError(t, err)
	return []byte(*out)
}

// withBinary makes plugin's OCI artifact resolve to binary on a node built over testFetcher.
func withBinary(plugin *artifactv1alpha1.Plugin, binary string) *artifactv1alpha1.Plugin {
	plugin = plugin.DeepCopy()
	if plugin.Spec.OCIArtifact == nil {
		plugin.Spec.OCIArtifact = &commonv1alpha1.OCIArtifact{}
	}
	plugin.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{Digest: binary}
	return plugin
}

// apply makes n hold what obj describes, as a reconcile of obj would.
func apply(t *testing.T, n *Node, obj artifactv1alpha1.Artifact) error {
	t.Helper()
	return n.ApplyArtifact(t.Context(), obj, &artifactv1alpha1.NodeArtifactStatus{})
}

// installConfig puts an inline Config's file on n and returns the Config's key.
func installConfig(t *testing.T, n *Node, namespace, name string) artifact.Ref {
	t.Helper()
	require.NoError(t, apply(t, n, inlineConfig(namespace, name, 50, configData)))
	return artifact.Ref{Kind: artifact.KindConfig, Name: name}
}

// startNode starts the node's status publisher. It stops with the test.
func startNode(t *testing.T, n *Node) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = n.status.Start(ctx) }()
}

// pluginsConfigFileOf is the node's record of the shared plugins-config file.
func pluginsConfigFileOf(n *Node) *artifact.File {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.pluginsConfigFile
}

const (
	statusTestNamespace = "falco-ns"
	statusTestNode      = "node-a"
)

// newStatusManager returns a Node wired to a running publisher over a fake client that holds the
// node's ArtifactNode and objs, and a function returning the entries the publisher has written to it.
func newStatusManager(t *testing.T, objs ...client.Object) (n *Node, published func() []string) {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, artifactv1alpha1.AddToScheme(s))
	artifactNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{Name: statusTestNode, Namespace: statusTestNamespace},
		Spec:       artifactv1alpha1.ArtifactNodeSpec{NodeName: statusTestNode},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(append(objs, artifactNode)...).WithStatusSubresource(artifactNode).Build()

	n, err := New(&Config{
		Fetcher:        newTestFetcher(cl),
		Client:         cl,
		NodeName:       statusTestNode,
		Namespace:      statusTestNamespace,
		FalcoBaseURL:   compat.DefaultBaseURL,
		ReloadCooldown: DefaultReloadCooldown,
		Store:          &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()},
		FalcoFetcher:   compatfake.NewMockVersionsFetcher(nil),
		StatusTimings:  &StatusTimings{Debounce: 5 * time.Millisecond, Retry: 5 * time.Millisecond},
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = n.status.Start(ctx) }()

	published = func() []string {
		got := &artifactv1alpha1.ArtifactNode{}
		require.NoError(t, cl.Get(t.Context(), client.ObjectKey{Namespace: statusTestNamespace, Name: statusTestNode}, got))
		out := make([]string, 0, len(got.Status.Artifacts))
		for _, e := range got.Status.Artifacts {
			out = append(out, string(e.Kind)+"/"+e.Name)
		}
		return out
	}
	return n, published
}

// artifactObj stands in for the parent CR: PublishStatus reads only its name, namespace and UID.
func artifactObj(name string) metav1.Object {
	return &metav1.PartialObjectMetadata{
		ObjectMeta: metav1.ObjectMeta{Namespace: statusTestNamespace, Name: name, UID: "uid"},
	}
}

func statusConditions() []metav1.Condition {
	return []metav1.Condition{{
		Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed", Message: "ok",
		LastTransitionTime: metav1.NewTime(time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)),
	}}
}

// newTestNode returns the Node of the test node, writing to a fake filesystem and backed by a fake
// client that already holds its ArtifactNode, so the status publisher has something to write to.
func newTestNode() *Node {
	return newTestNodeWithFetcher(compatfake.NewMockVersionsFetcher(nil))
}

func newTestNodeWithFetcher(fetcher compat.VersionsFetcher) *Node {
	return newTestNodeOver(&artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}, fetcher)
}

// newTestNodeOver is the test Node writing to store, over a client that holds its ArtifactNode and
// objs (the ConfigMaps a test Config reads, say).
func newTestNodeOver(store artifact.ArtifactStore, fetcher compat.VersionsFetcher, objs ...client.Object) *Node {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = artifactv1alpha1.AddToScheme(scheme)
	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(append(objs, testutil.NewTestArtifactNode())...).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
	n, err := New(&Config{
		Fetcher:        newTestFetcher(cl),
		Client:         cl,
		NodeName:       testutil.TestNodeName,
		Namespace:      testutil.TestNamespace,
		FalcoBaseURL:   compat.DefaultBaseURL,
		ReloadCooldown: DefaultReloadCooldown,
		Store:          store,
		FalcoFetcher:   fetcher,
	})
	if err != nil {
		panic(err) // a misconfigured test Node, not a failing assertion
	}
	return n
}

// removeArtifact takes key away, with no shared-file entry to withdraw. It drops the result the
// node hands back to the controller: the tests here assert on what is on disk and in the status,
// not on what gets published.
func removeArtifact(ctx context.Context, n *Node, key artifact.Ref) error {
	err := n.Remove(ctx, key)
	return err
}

func testPlugin(name string) *artifactv1alpha1.Plugin {
	return &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

// newArtifacts is a bare Node writing to store, with fetcher behind the post-install capability
// refresh. It builds the struct rather than calling New because these tests exercise the artifact
// machinery alone and have no API server, node name or Falco endpoint to give it. The tests below
// reach into the node's state directly, which is why this file is in-package.
func newArtifacts(store artifact.ArtifactStore, fetcher compat.VersionsFetcher) *Node {
	return &Node{
		disk:          store,
		fetcher:       &artifact.Fetcher{},
		falcoFetcher:  fetcher,
		recorder:      nopRecorder{},
		dirs:          artifact.DefaultArtifactDirs(),
		artifacts:     make(map[artifact.Ref]*nodeArtifact),
		provides:      make(map[string]provided),
		pluginsConfig: &pluginsConfig{},
		removals:      make(map[artifact.Kind]chan event.GenericEvent),
	}
}

const (
	judgeTestRulesfileName = "test-rulesfile"
	// testInlineRulesJSON is sample Falco rules in JSON form, for the *apiextensionsv1.JSON fields.
	testInlineRulesJSON = `[{"rule":"test_rule","desc":"test","condition":"always_true","output":"test","priority":"WARNING"}]`
)

// newJudgeTestNode is a bare Node for judging: it reaches no API server and no disk, because
// judging happens before anything is fetched or written.
func newJudgeTestNode(t *testing.T, enforce bool) *Node {
	t.Helper()
	n := newArtifacts(&artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()},
		compatfake.NewMockVersionsFetcher(nil))
	n.enforceRequirements = enforce
	return n
}

const (
	writeFailure         = "write"
	mutatedMetadataValue = "mutated"
)

func installTestRulesfile(t *testing.T, m *Node, key artifact.Ref,
	dependencies []commonv1alpha1.ArtifactMetaDependency,
) {
	t.Helper()
	content, err := (&artifact.Fetcher{}).FetchInline(t.Context(), []byte("test rules"))
	require.NoError(t, err)
	_, _, err = m.StoreRulesfile(t.Context(), key.Name, 50, artifact.MediumOCI, content,
		&commonv1alpha1.ArtifactMeta{Dependencies: dependencies}, false)
	require.NoError(t, err)
}
