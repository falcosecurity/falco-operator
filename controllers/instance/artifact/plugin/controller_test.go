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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

const (
	testPluginName   = "test-plugin"
	testPluginDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func testPluginNodeName() string {
	return controllerhelper.NodeObjectName(controllerhelper.ArtifactKindPlugin, testPluginName, testutil.TestNodeName)
}

func testOCIArtifact() *commonv1alpha1.OCIArtifact {
	return &commonv1alpha1.OCIArtifact{
		Image: commonv1alpha1.ImageSpec{Repository: "ghcr.io/test/plugin", Tag: "latest"},
	}
}

func newTestNode(name string, labels map[string]string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func newTestPlugin(opts ...func(*artifactv1alpha1.Plugin)) *artifactv1alpha1.Plugin {
	p := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func withPluginOCI() func(*artifactv1alpha1.Plugin) {
	return func(p *artifactv1alpha1.Plugin) {
		p.Spec.OCIArtifact = testOCIArtifact()
	}
}

func withPluginSelector() func(*artifactv1alpha1.Plugin) {
	return func(p *artifactv1alpha1.Plugin) {
		p.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}
	}
}

func newTestPluginNode(opts ...func(*artifactv1alpha1.ArtifactNode)) *artifactv1alpha1.ArtifactNode {
	isController := true
	n := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testPluginNodeName(),
			Namespace: testutil.TestNamespace,
			Labels:    controllerhelper.NodeObjectLabels(controllerhelper.ArtifactKindPlugin, testPluginName, testutil.TestNodeName),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: artifactv1alpha1.GroupVersion.String(),
				Kind:       "Plugin",
				Name:       testPluginName,
				Controller: &isController,
			}},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: testutil.TestNodeName},
	}
	for _, o := range opts {
		o(n)
	}
	return n
}

func newTestReconciler(t *testing.T, objs ...client.Object) (*PluginAggregatorReconciler, client.Client) {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	return NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil), cl
}

func newTestReconcilerWithPuller(t *testing.T, mockPuller puller.Puller, objs ...client.Object) (*PluginAggregatorReconciler, client.Client) {
	t.Helper()
	r, cl := newTestReconciler(t, objs...)
	r.ociPuller = mockPuller
	return r, cl
}

func addInUseFinalizer(t *testing.T, cl client.Client, plugin *artifactv1alpha1.Plugin) {
	t.Helper()
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(plugin), plugin))
	require.NoError(t, controllerhelper.EnsureInUseFinalizer(
		context.Background(), cl,
		controllerhelper.NodeObjectsInUseFinalizer,
		plugin, true,
	))
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(plugin), plugin))
}

const testFalcoName = "test-falco"

func newTestFalco() *instancev1alpha1.Falco {
	return &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{Name: testFalcoName, Namespace: testutil.TestNamespace},
	}
}

func newRunningFalcoPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "falco-pod",
			Namespace: testutil.TestNamespace,
			Labels:    map[string]string{"app.kubernetes.io/instance": testFalcoName},
		},
		Spec:   corev1.PodSpec{NodeName: testutil.TestNodeName},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func TestReconcile_NotFound(t *testing.T) {
	r, _ := newTestReconciler(t)
	result, err := r.Reconcile(context.Background(), testutil.Request("nonexistent"))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
}

func TestReconcile_GetError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return fmt.Errorf("api server error")
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.Error(t, err)
}

func TestReconcile_DeletionNoNodeObjects(t *testing.T) {
	// A finalizer makes cl.Delete set DeletionTimestamp on the object rather than removing it.
	plugin := newTestPlugin(func(p *artifactv1alpha1.Plugin) {
		p.Finalizers = []string{"test.example.com/keep-alive"}
	})
	r, cl := newTestReconciler(t, plugin)

	require.NoError(t, cl.Delete(context.Background(), plugin))

	result, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// No PluginNodes should exist.
	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Empty(t, nodeList.Items)
}

func TestReconcile_DeletionWithNodeObjects(t *testing.T) {
	// A finalizer makes cl.Delete set DeletionTimestamp on the object rather than removing it.
	plugin := newTestPlugin(func(p *artifactv1alpha1.Plugin) {
		p.Finalizers = []string{"test.example.com/keep-alive"}
	})
	pluginNode := newTestPluginNode()
	r, cl := newTestReconciler(t, plugin, pluginNode)

	require.NoError(t, cl.Delete(context.Background(), plugin))

	result, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// PluginNode should be deleted.
	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Empty(t, nodeList.Items)
}

func TestReconcile_NoMatchingNodes(t *testing.T) {
	plugin := newTestPlugin()
	r, cl := newTestReconciler(t, plugin)

	result, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Empty(t, nodeList.Items)

	got := &artifactv1alpha1.Plugin{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(plugin), got))
	cond := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionUnknown, cond.Status)
}

func TestReconcile_CreatesNodeObject(t *testing.T) {
	plugin := newTestPlugin()
	node := newTestNode(testutil.TestNodeName, nil)
	r, cl := newTestReconciler(t, plugin, node, newTestFalco(), newRunningFalcoPod())

	result, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	pluginNode := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(),
		types.NamespacedName{Name: testPluginNodeName(), Namespace: testutil.TestNamespace}, pluginNode))
	assert.Equal(t, testutil.TestNodeName, pluginNode.Spec.NodeName)

	got := &artifactv1alpha1.Plugin{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(plugin), got))
	assert.Contains(t, got.Finalizers, controllerhelper.NodeObjectsInUseFinalizer)
}

func TestReconcile_CreatesIndependentNodeObjectsForNamespaces(t *testing.T) {
	const (
		deploymentNamespace = "falco-deployment"
		daemonSetNamespace  = "falco-daemonset"
	)

	node := newTestNode(testutil.TestNodeName, nil)
	objects := make([]client.Object, 0, 7)
	objects = append(objects, node)
	for _, namespace := range []string{deploymentNamespace, daemonSetNamespace} {
		plugin := newTestPlugin()
		plugin.Namespace = namespace
		falco := newTestFalco()
		falco.Namespace = namespace
		pod := newRunningFalcoPod()
		pod.Namespace = namespace
		objects = append(objects, plugin, falco, pod)
	}
	r, cl := newTestReconciler(t, objects...)

	for _, namespace := range []string{deploymentNamespace, daemonSetNamespace} {
		result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{
			Name:      testPluginName,
			Namespace: namespace,
		}})
		require.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)

		pluginNode := &artifactv1alpha1.ArtifactNode{}
		require.NoError(t, cl.Get(context.Background(), types.NamespacedName{
			Name:      testPluginNodeName(),
			Namespace: namespace,
		}, pluginNode))
		assert.Equal(t, testutil.TestNodeName, pluginNode.Spec.NodeName)
	}

	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Len(t, nodeList.Items, 2)
}

func TestReconcile_NodeObjectAlreadyExists(t *testing.T) {
	plugin := newTestPlugin()
	node := newTestNode(testutil.TestNodeName, nil)
	existing := newTestPluginNode()
	r, cl := newTestReconciler(t, plugin, node, existing, newTestFalco(), newRunningFalcoPod())

	result, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	list := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), list))
	assert.Len(t, list.Items, 1)
}

func TestReconcile_NoFalcoPod_NoNodeObject(t *testing.T) {
	// Node matches the artifact selector but no Falco pod is running on it.
	plugin := newTestPlugin()
	node := newTestNode(testutil.TestNodeName, nil)
	r, cl := newTestReconciler(t, plugin, node) // no Falco CR or pod

	result, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Empty(t, nodeList.Items)
}

func TestReconcile_DeletesStaleNodeObject(t *testing.T) {
	plugin := newTestPlugin(withPluginSelector())
	staleNode := newTestPluginNode()
	plainNode := newTestNode(testutil.TestNodeName, nil)
	r, cl := newTestReconciler(t, plugin, staleNode, plainNode)

	result, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Empty(t, nodeList.Items)
}

func TestReconcile_TerminatingStaleNodeIsRetainedButNotAggregated(t *testing.T) {
	plugin := newTestPlugin(
		withPluginSelector(),
		func(p *artifactv1alpha1.Plugin) {
			p.Finalizers = []string{controllerhelper.NodeObjectsInUseFinalizer}
		},
	)
	staleNode := newTestPluginNode(func(n *artifactv1alpha1.ArtifactNode) {
		n.Finalizers = []string{"artifact.example.com/node-cleanup"}
		n.Status.Conditions = []metav1.Condition{{
			Type:    commonv1alpha1.ConditionProgrammed.String(),
			Status:  metav1.ConditionTrue,
			Reason:  "Programmed",
			Message: "old result",
		}}
	})
	r, cl := newTestReconciler(
		t, plugin, staleNode, newTestNode(testutil.TestNodeName, nil), newTestFalco(), newRunningFalcoPod(),
	)

	result, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	terminating := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(staleNode), terminating))
	assert.False(t, terminating.DeletionTimestamp.IsZero(), "the node-side finalizer keeps the stale child terminating")

	got := &artifactv1alpha1.Plugin{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(plugin), got))
	assert.Contains(t, got.Finalizers, controllerhelper.NodeObjectsInUseFinalizer,
		"the parent must stay alive until the terminating child is physically gone")
	condition := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionUnknown, condition.Status)
	assert.Equal(t, "NoNodesAssigned", condition.Reason,
		"the stale child's last successful result must not remain in the aggregate")
}

func TestReconcile_RemovesNodeObjectWhenFalcoPodGone(t *testing.T) {
	plugin := newTestPlugin(func(p *artifactv1alpha1.Plugin) {
		p.Finalizers = []string{controllerhelper.NodeObjectsInUseFinalizer}
	})
	staleNode := newTestPluginNode(func(n *artifactv1alpha1.ArtifactNode) {
		n.Finalizers = []string{"artifact.example.com/node-cleanup"}
	})
	// The Kubernetes Node still matches the Plugin selector, but no Falco pod remains there.
	r, cl := newTestReconciler(t, plugin, staleNode, newTestNode(testutil.TestNodeName, nil))

	result, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	got := &artifactv1alpha1.ArtifactNode{}
	err = cl.Get(context.Background(), client.ObjectKeyFromObject(staleNode), got)
	assert.True(t, k8serrors.IsNotFound(err),
		"the instance operator must garbage-collect the ArtifactNode when its artifact operator is gone")
}

func TestReconcile_ListMatchingNodesError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	plugin := newTestPlugin()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.NodeList); ok {
					return fmt.Errorf("node list failed")
				}
				return c.List(ctx, list, opts...)
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.Error(t, err)
}

func TestReconcile_ListNodeObjectsError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	plugin := newTestPlugin()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.ArtifactNodeList); ok {
					return fmt.Errorf("plugin node list failed")
				}
				return c.List(ctx, list, opts...)
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.Error(t, err)
}

func TestHandleDeletion_NoNodeObjects(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	plugin := newTestPlugin()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*instancev1alpha1.FalcoList); ok {
					return fmt.Errorf("Falco list should not be called without node objects")
				}
				return c.List(ctx, list, opts...)
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	addInUseFinalizer(t, cl, plugin)

	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	err := r.handleDeletion(context.Background(), plugin)
	require.NoError(t, err)

	got := &artifactv1alpha1.Plugin{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(plugin), got))
	assert.NotContains(t, got.Finalizers, controllerhelper.NodeObjectsInUseFinalizer)
}

func TestHandleDeletion_NodeObjectsPresent(t *testing.T) {
	plugin := newTestPlugin()
	pluginNode := newTestPluginNode()
	r, cl := newTestReconciler(t, plugin, pluginNode)

	err := r.handleDeletion(context.Background(), plugin)
	require.NoError(t, err)

	node := &artifactv1alpha1.ArtifactNode{}
	err = cl.Get(context.Background(),
		types.NamespacedName{Name: testPluginNodeName(), Namespace: testutil.TestNamespace}, node)
	assert.Error(t, err)
}

func TestHandleDeletion_EvictsCacheEntries(t *testing.T) {
	plugin := newTestPlugin()
	cacheDir := t.TempDir()
	r := newTestReconcilerWithCacheAndPuller(t, nil, cacheDir, plugin)

	// An exclusively-referenced blob: gone once this CR's last node object disappears.
	ownBlob := filepath.Join(cacheDir, "blobs", "own")
	require.NoError(t, artifactcache.Store(ownBlob, []byte("x"), 0o755))
	require.NoError(t, r.cache.Set(string(artifact.TypePlugin), testutil.TestNamespace, testPluginName, "linux-amd64", ownBlob))

	// A blob shared with another CR: refcount drops but the file survives.
	sharedBlob := filepath.Join(cacheDir, "blobs", "shared")
	require.NoError(t, artifactcache.Store(sharedBlob, []byte("y"), 0o755))
	require.NoError(t, r.cache.Set(string(artifact.TypePlugin), testutil.TestNamespace, testPluginName, "linux-arm64", sharedBlob))
	require.NoError(t, r.cache.Set(string(artifact.TypePlugin), testutil.TestNamespace, "other-plugin", "", sharedBlob))

	// No ArtifactNode objects owned by this Plugin exist, so handleDeletion evicts the cache entries now.
	err := r.handleDeletion(context.Background(), plugin)
	require.NoError(t, err)

	_, ok := r.cache.Lookup(string(artifact.TypePlugin), testutil.TestNamespace, testPluginName, "linux-amd64")
	assert.False(t, ok)
	_, err = os.Stat(ownBlob)
	assert.True(t, os.IsNotExist(err), "exclusively-referenced blob must be removed from disk")

	got, ok := r.cache.Lookup(string(artifact.TypePlugin), testutil.TestNamespace, "other-plugin", "")
	require.True(t, ok, "other CR's entry for the shared blob must survive")
	assert.Equal(t, sharedBlob, got)
	_, err = os.Stat(sharedBlob)
	assert.NoError(t, err, "shared blob must survive: another CR still references it")
}

func TestHandleDeletion_NodesRemaining_DoesNotEvictCache(t *testing.T) {
	plugin := newTestPlugin()
	pluginNode := newTestPluginNode()
	cacheDir := t.TempDir()
	r := newTestReconcilerWithCacheAndPuller(t, nil, cacheDir, plugin, pluginNode)

	blobPath := filepath.Join(cacheDir, "blobs", "own")
	require.NoError(t, artifactcache.Store(blobPath, []byte("x"), 0o755))
	require.NoError(t, r.cache.Set(string(artifact.TypePlugin), testutil.TestNamespace, testPluginName, "linux-amd64", blobPath))

	err := r.handleDeletion(context.Background(), plugin)
	require.NoError(t, err)

	got, ok := r.cache.Lookup(string(artifact.TypePlugin), testutil.TestNamespace, testPluginName, "linux-amd64")
	require.True(t, ok, "cache entry must survive while a node object still exists")
	assert.Equal(t, blobPath, got)
}

func TestHandleDeletion_SurfacesDeletionBlockedCondition(t *testing.T) {
	plugin := newTestPlugin()
	pluginNode := newTestPluginNode(func(n *artifactv1alpha1.ArtifactNode) {
		n.Status.Conditions = []metav1.Condition{
			{
				Type:    commonv1alpha1.ConditionDeletionBlocked.String(),
				Status:  metav1.ConditionTrue,
				Reason:  artifact.ReasonPluginConfigStillRequired,
				Message: `"container" is still required by [{Rulesfile some-rulesfile}]`,
			},
		}
	})
	r, cl := newTestReconciler(t, plugin, pluginNode)

	err := r.handleDeletion(context.Background(), plugin)
	require.NoError(t, err)

	got := &artifactv1alpha1.Plugin{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(plugin), got))
	cond := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionDeletionBlocked.String())
	require.NotNil(t, cond, "aggregator must surface the per-node DeletionBlocked condition onto the parent Plugin")
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Equal(t, artifact.ReasonPluginConfigStillRequired, cond.Reason)
}

func TestHandleDeletion_NodeObjectsBeingDeleted(t *testing.T) {
	plugin := newTestPlugin()
	pluginNode := newTestPluginNode(func(n *artifactv1alpha1.ArtifactNode) {
		now := metav1.Now()
		n.DeletionTimestamp = &now
		n.Finalizers = []string{"some-finalizer"}
	})
	r, _ := newTestReconciler(t, plugin, pluginNode)

	err := r.handleDeletion(context.Background(), plugin)
	require.NoError(t, err)
}

func TestHandleDeletion_ListError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	plugin := newTestPlugin()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.ArtifactNodeList); ok {
					return fmt.Errorf("list error")
				}
				return nil
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)

	err := r.handleDeletion(context.Background(), plugin)
	require.Error(t, err)
}

func TestEnsureNodeObject_AlreadyExists(t *testing.T) {
	plugin := newTestPlugin()
	existing := newTestPluginNode()
	r, cl := newTestReconciler(t, plugin, existing)

	err := controllerhelper.EnsureNodeObject(context.Background(), r.Client, plugin,
		artifactv1alpha1.GroupVersion.WithKind(controllerhelper.KindPlugin), controllerhelper.ArtifactKindPlugin, testutil.TestNodeName)
	require.NoError(t, err)

	list := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), list))
	assert.Len(t, list.Items, 1)
}

func TestEnsureNodeObject_Creates(t *testing.T) {
	plugin := newTestPlugin()
	r, cl := newTestReconciler(t, plugin)

	err := controllerhelper.EnsureNodeObject(context.Background(), r.Client, plugin,
		artifactv1alpha1.GroupVersion.WithKind(controllerhelper.KindPlugin), controllerhelper.ArtifactKindPlugin, testutil.TestNodeName)
	require.NoError(t, err)

	created := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(),
		types.NamespacedName{Name: testPluginNodeName(), Namespace: testutil.TestNamespace}, created))
	assert.Equal(t, testutil.TestNodeName, created.Spec.NodeName)
}

func TestEnsureNodeObject_GetError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	plugin := newTestPlugin()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
				if _, ok := obj.(*artifactv1alpha1.ArtifactNode); ok {
					return fmt.Errorf("get error")
				}
				return nil
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)

	err := controllerhelper.EnsureNodeObject(context.Background(), r.Client, plugin,
		artifactv1alpha1.GroupVersion.WithKind(controllerhelper.KindPlugin), controllerhelper.ArtifactKindPlugin, testutil.TestNodeName)
	require.Error(t, err)
}

func TestUpdateAggregateConditions_Empty(t *testing.T) {
	plugin := newTestPlugin()
	r, cl := newTestReconciler(t, plugin)

	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	err := controllerhelper.UpdateAggregateConditions(
		context.Background(), r.Client, r.Scheme, plugin, &plugin.Status.Conditions, nodeList, ControllerName,
	)
	require.NoError(t, err)

	got := &artifactv1alpha1.Plugin{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(plugin), got))
	cond := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionUnknown, cond.Status)
	assert.Equal(t, "NoNodesAssigned", cond.Reason)
}

func TestUpdateAggregateConditions_WithNodeConditions(t *testing.T) {
	plugin := newTestPlugin()
	r, cl := newTestReconciler(t, plugin)

	nodeList := &artifactv1alpha1.ArtifactNodeList{
		Items: []artifactv1alpha1.ArtifactNode{
			{
				Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: testutil.TestNodeName},
				Status: artifactv1alpha1.ArtifactNodeStatus{
					Conditions: []metav1.Condition{
						{
							Type:    commonv1alpha1.ConditionProgrammed.String(),
							Status:  metav1.ConditionTrue,
							Reason:  "Programmed",
							Message: "ok",
						},
					},
				},
			},
		},
	}

	err := controllerhelper.UpdateAggregateConditions(
		context.Background(), r.Client, r.Scheme, plugin, &plugin.Status.Conditions, nodeList, ControllerName,
	)
	require.NoError(t, err)

	got := &artifactv1alpha1.Plugin{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(plugin), got))
	cond := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
}

func TestFetchAndCacheArtifactMeta_NoOCI(t *testing.T) {
	plugin := newTestPlugin()
	r, _ := newTestReconciler(t, plugin)

	plugin.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{Digest: "old"}
	err := r.fetchAndCacheArtifactMeta(context.Background(), plugin)
	require.NoError(t, err)
	assert.Nil(t, plugin.Status.ArtifactMeta)
}

func TestFetchAndCacheArtifactMeta_CacheHit(t *testing.T) {
	mockPuller := &puller.MockOCIPuller{}
	plugin := newTestPlugin(withPluginOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, plugin)

	specHash, err := artifact.ComputeOCIArtifactSpecHash(plugin.Spec.OCIArtifact)
	require.NoError(t, err)
	plugin.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{
		SpecHash: specHash,
		Digest:   "sha256:abc123",
	}

	err = r.fetchAndCacheArtifactMeta(context.Background(), plugin)
	require.NoError(t, err)
	assert.Empty(t, mockPuller.FetchConfigCalls)
	assert.Equal(t, "sha256:abc123", plugin.Status.ArtifactMeta.Digest)
}

func TestFetchAndCacheArtifactMeta_CacheHitIgnoresDigest(t *testing.T) {
	// Spec hash matches even though the stored digest is stale, so the cache is still a hit.
	// Picking up a new image pushed to the same tag requires an explicit spec change.
	mockPuller := &puller.MockOCIPuller{}
	plugin := newTestPlugin(withPluginOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, plugin)

	specHash, err := artifact.ComputeOCIArtifactSpecHash(plugin.Spec.OCIArtifact)
	require.NoError(t, err)
	plugin.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{
		SpecHash: specHash,
		Digest:   "sha256:old",
	}

	err = r.fetchAndCacheArtifactMeta(context.Background(), plugin)
	require.NoError(t, err)
	assert.Empty(t, mockPuller.FetchConfigCalls, "spec hash match must skip FetchConfig regardless of digest")
	assert.Equal(t, "sha256:old", plugin.Status.ArtifactMeta.Digest, "stale digest must not be updated on cache hit")
}

func TestFetchAndCacheArtifactMeta_NoCacheNoStatus(t *testing.T) {
	mockPuller := &puller.MockOCIPuller{
		ConfigResult: &puller.ArtifactConfig{},
		ConfigDigest: "sha256:fresh",
	}
	plugin := newTestPlugin(withPluginOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, plugin)

	err := r.fetchAndCacheArtifactMeta(context.Background(), plugin)
	require.NoError(t, err)
	assert.Len(t, mockPuller.FetchConfigCalls, 1)
	require.NotNil(t, plugin.Status.ArtifactMeta)
	assert.Equal(t, "sha256:fresh", plugin.Status.ArtifactMeta.Digest)
}

func TestFetchAndCacheArtifactMeta_FetchConfigError(t *testing.T) {
	mockPuller := &puller.MockOCIPuller{
		FetchConfigErr: fmt.Errorf("registry unavailable"),
	}
	plugin := newTestPlugin(withPluginOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, plugin)

	err := r.fetchAndCacheArtifactMeta(context.Background(), plugin)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry unavailable")
	// Records a Warning event on the Plugin describing the OCI config fetch failure.
	testutil.RequireEvents(t, r.recorder.(*events.FakeRecorder).Events,
		[]string{"Warning OCIArtifactProgramFailed Failed to fetch OCI config layer: registry unavailable"})
}

func TestFetchAndCacheArtifactMeta_WithDependencies(t *testing.T) {
	mockPuller := &puller.MockOCIPuller{
		ConfigResult: &puller.ArtifactConfig{
			Dependencies: []puller.ArtifactDependency{
				{
					Name:    "json",
					Version: ">=0.7.0",
					Alternatives: []puller.Dependency{
						{Name: "json-alt", Version: ">=0.6.0"},
					},
				},
			},
		},
		ConfigDigest: "sha256:deps",
	}
	plugin := newTestPlugin(withPluginOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, plugin)

	err := r.fetchAndCacheArtifactMeta(context.Background(), plugin)
	require.NoError(t, err)
	require.NotNil(t, plugin.Status.ArtifactMeta)
	require.Len(t, plugin.Status.ArtifactMeta.Dependencies, 1)
	assert.Equal(t, "json", plugin.Status.ArtifactMeta.Dependencies[0].Name)
	require.Len(t, plugin.Status.ArtifactMeta.Dependencies[0].Alternatives, 1)
	assert.Equal(t, "json-alt", plugin.Status.ArtifactMeta.Dependencies[0].Alternatives[0].Name)
}

func TestFindPluginsForNode(t *testing.T) {
	plugin := newTestPlugin()
	r, _ := newTestReconciler(t, plugin)

	reqs := controllerhelper.EnqueueAllOfType(context.Background(), r.Client, &artifactv1alpha1.PluginList{})
	require.Len(t, reqs, 1)
	assert.Equal(t, testPluginName, reqs[0].Name)
}

func TestFindPluginsForNode_ListError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.PluginList); ok {
					return fmt.Errorf("list error")
				}
				return nil
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	reqs := controllerhelper.EnqueueAllOfType(context.Background(), cl, &artifactv1alpha1.PluginList{})
	assert.Nil(t, reqs)
}

func TestFindPluginsForNode_EmptyList(t *testing.T) {
	r, _ := newTestReconciler(t)
	reqs := controllerhelper.EnqueueAllOfType(context.Background(), r.Client, &artifactv1alpha1.PluginList{})
	assert.Empty(t, reqs)
}

// ── Reconcile remaining error paths ─────────────────────────────────────────

func TestReconcile_DeleteStaleNodeError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	// Selector requires env=prod; existing PluginNode is for a node without that label → stale.
	plugin := newTestPlugin(withPluginSelector())
	staleNode := newTestPluginNode()
	plainNode := newTestNode(testutil.TestNodeName, nil)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin, staleNode, plainNode).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if _, ok := obj.(*artifactv1alpha1.ArtifactNode); ok {
					return fmt.Errorf("delete failed")
				}
				return c.Delete(ctx, obj, opts...)
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.Error(t, err)
}

func TestReconcile_EnsureNodeObjectError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	plugin := newTestPlugin()
	node := newTestNode(testutil.TestNodeName, nil)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin, node, newTestFalco(), newRunningFalcoPod()).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*artifactv1alpha1.ArtifactNode); ok {
					return fmt.Errorf("create failed")
				}
				return c.Create(ctx, obj, opts...)
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.Error(t, err)
}

func TestReconcile_EnsureInUseFinalizerError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	plugin := newTestPlugin()
	node := newTestNode(testutil.TestNodeName, nil)
	pluginNode := newTestPluginNode() // makes ensureNodeObject a no-op
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin, node, pluginNode, newTestFalco(), newRunningFalcoPod()).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
				return fmt.Errorf("patch failed")
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.Error(t, err)
}

func TestReconcile_SecondListNodeObjectsError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	plugin := newTestPlugin()
	node := newTestNode(testutil.TestNodeName, nil)
	pluginNode := newTestPluginNode() // existing PluginNode makes ensureNodeObject a no-op
	var listCount int
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin, node, pluginNode).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.ArtifactNodeList); ok {
					listCount++
					if listCount == 2 {
						return fmt.Errorf("second list error")
					}
				}
				return c.List(ctx, list, opts...)
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.Error(t, err)
}

func TestReconcile_FetchAndCacheError(t *testing.T) {
	mockPuller := &puller.MockOCIPuller{
		FetchConfigErr: fmt.Errorf("registry down"),
	}
	plugin := newTestPlugin(withPluginOCI())
	node := newTestNode(testutil.TestNodeName, nil)
	pluginNode := newTestPluginNode() // pre-existing
	r, _ := newTestReconcilerWithPuller(t, mockPuller, plugin, node, pluginNode)
	_, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.Error(t, err)
}

// ── handleDeletion delete error ──────────────────────────────────────────────

func TestHandleDeletion_DeleteError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	plugin := newTestPlugin()
	pluginNode := newTestPluginNode()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin, pluginNode).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if _, ok := obj.(*artifactv1alpha1.ArtifactNode); ok {
					return fmt.Errorf("delete error")
				}
				return c.Delete(ctx, obj, opts...)
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	err := r.handleDeletion(context.Background(), plugin)
	require.Error(t, err)
}

// ── fetchAndCacheBlobs tests ──────────────────────────────────────────────

// newTestReconcilerWithCacheAndPuller creates a PluginAggregatorReconciler with a real,
// loaded artifact Cache rooted at cacheDir, and an injected mock OCI puller.
func newTestReconcilerWithCacheAndPuller(
	t *testing.T, mockPuller puller.Puller, cacheDir string, objs ...client.Object,
) *PluginAggregatorReconciler {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	// Zero grace period: dereferenced blobs are removed from disk immediately.
	cache := artifactcache.NewCache(cacheDir, artifactcache.WithEvictionGracePeriod(0))
	require.NoError(t, cache.Load())
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), cache)
	r.ociPuller = mockPuller
	return r
}

func TestFetchAndCacheBinaries_NoCache(t *testing.T) {
	// A nil cache disables caching; fetchAndCacheBlobs returns immediately.
	plugin := newTestPlugin(withPluginOCI())
	r, _ := newTestReconciler(t, plugin) // cache = nil
	node := newTestNode(testutil.TestNodeName, map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})
	err := r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node})
	require.NoError(t, err)
}

func TestFetchAndCacheBinaries_NoOCIArtifact(t *testing.T) {
	// No OCI spec → noop regardless of cacheDir.
	plugin := newTestPlugin() // no OCIArtifact
	cacheDir := t.TempDir()
	r := newTestReconcilerWithCacheAndPuller(t, nil, cacheDir, plugin)
	node := newTestNode(testutil.TestNodeName, map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})
	err := r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node})
	require.NoError(t, err)
}

func TestFetchAndCacheBinaries_NoOSArchLabels(t *testing.T) {
	// Nodes without kubernetes.io/os or kubernetes.io/arch labels → empty platform set → noop.
	plugin := newTestPlugin(withPluginOCI())
	cacheDir := t.TempDir()
	r := newTestReconcilerWithCacheAndPuller(t, nil, cacheDir, plugin)
	node := newTestNode(testutil.TestNodeName, nil)
	err := r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node})
	require.NoError(t, err)
}

func TestFetchAndCacheBinaries_FastPath(t *testing.T) {
	// This CR's cache entry already points at the blob for the known digest: no registry
	// call needed.
	cacheDir := t.TempDir()
	plugin := newTestPlugin(withPluginOCI())
	mockPuller := &puller.MockOCIPuller{} // must not be called
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, plugin)

	ref := artifact.ResolveReference(plugin.Spec.OCIArtifact)
	const digest = testPluginDigest
	blobPath := artifactcache.BlobPath(cacheDir, string(artifact.TypePlugin), ref, digest, "linux", "amd64")
	require.NoError(t, artifactcache.Store(blobPath, []byte("fake-plugin"), 0o755))
	require.NoError(t, r.cache.Set(string(artifact.TypePlugin), testutil.TestNamespace, testPluginName, "linux-amd64", blobPath))

	plugin.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{Digest: digest}

	node := newTestNode(testutil.TestNodeName, map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})
	require.NoError(t, r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node}))

	assert.Empty(t, mockPuller.ResolveDigestCalls)
	assert.Empty(t, mockPuller.PullCalls)

	idx, ok := r.cache.Lookup(string(artifact.TypePlugin), testutil.TestNamespace, testPluginName, "linux-amd64")
	require.True(t, ok)
	assert.Equal(t, blobPath, idx)
}

func TestFetchAndCacheBinaries_SlowPath(t *testing.T) {
	// Blob is missing: EnsureBlob pulls from registry and writes the index.
	cacheDir := t.TempDir()
	plugin := newTestPlugin(withPluginOCI())

	tarGz, err := puller.MakeTarGz("plugin.so", []byte("plugin-binary-content"))
	require.NoError(t, err)

	mockPuller := &puller.MockOCIPuller{
		ResolveDigestResult: testPluginDigest,
		Result:              &puller.RegistryResult{RootDigest: testPluginDigest, Type: puller.Plugin},
		LayerContent:        tarGz,
	}
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, plugin)

	node := newTestNode(testutil.TestNodeName, map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})
	require.NoError(t, r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node}))

	require.Len(t, mockPuller.PullCalls, 1)
	assert.Equal(t, "linux", mockPuller.PullCalls[0].OS)
	assert.Equal(t, "amd64", mockPuller.PullCalls[0].Arch)

	_, ok := r.cache.Lookup(string(artifact.TypePlugin), testutil.TestNamespace, testPluginName, "linux-amd64")
	require.True(t, ok)
}

func TestFetchAndCacheBinaries_PullError(t *testing.T) {
	cacheDir := t.TempDir()
	plugin := newTestPlugin(withPluginOCI())
	mockPuller := &puller.MockOCIPuller{
		ResolveDigestResult: testPluginDigest,
		PullErr:             fmt.Errorf("registry unreachable"),
	}
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, plugin)

	node := newTestNode(testutil.TestNodeName, map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})
	err := r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry unreachable")
}

func TestFetchAndCacheBinaries_DeduplicatesPlatforms(t *testing.T) {
	// Two nodes with the same (os, arch) should trigger only one pull.
	cacheDir := t.TempDir()
	plugin := newTestPlugin(withPluginOCI())

	tarGz, err := puller.MakeTarGz("plugin.so", []byte("data"))
	require.NoError(t, err)

	mockPuller := &puller.MockOCIPuller{
		ResolveDigestResult: testPluginDigest,
		Result:              &puller.RegistryResult{RootDigest: testPluginDigest, Type: puller.Plugin},
		LayerContent:        tarGz,
	}
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, plugin)

	labels := map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"}
	node1 := newTestNode("node-1", labels)
	node2 := newTestNode("node-2", labels)

	require.NoError(t, r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node1, *node2}))
	assert.Len(t, mockPuller.PullCalls, 1)
}

func TestFetchAndCacheBinaries_MultiplePlatforms(t *testing.T) {
	// Two nodes with different (os, arch) pairs must each trigger a pull.
	cacheDir := t.TempDir()
	plugin := newTestPlugin(withPluginOCI())

	tarGz, err := puller.MakeTarGz("plugin.so", []byte("data"))
	require.NoError(t, err)

	mockPuller := &puller.MockOCIPuller{
		ResolveDigestResult: testPluginDigest,
		Result:              &puller.RegistryResult{RootDigest: testPluginDigest, Type: puller.Plugin},
		LayerContent:        tarGz,
	}
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, plugin)

	node1 := newTestNode("node-1", map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})
	node2 := newTestNode("node-2", map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "arm64"})

	require.NoError(t, r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node1, *node2}))
	assert.Len(t, mockPuller.PullCalls, 2)
}

func TestReconcile_ClearFinalizersInStalePath_Error(t *testing.T) {
	// staleNode is stale: the plugin's env=prod selector excludes plainNode. staleNode carries a
	// finalizer and a Falco pod still runs there, so orphan detection calls Node.Get; the
	// interceptor fails that lookup with a
	// non-404 error that propagates back to Reconcile.
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	plugin := newTestPlugin(withPluginSelector())
	staleNode := newTestPluginNode(func(n *artifactv1alpha1.ArtifactNode) {
		n.Finalizers = []string{"some-finalizer"}
	})
	plainNode := newTestNode(testutil.TestNodeName, nil)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin, staleNode, plainNode, newTestFalco(), newRunningFalcoPod()).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Node); ok {
					return fmt.Errorf("node lookup error")
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "node lookup error")
}

func TestHandleDeletion_ClearFinalizersError(t *testing.T) {
	// pluginNode carries a finalizer and a Falco pod still runs on its node, so orphan detection
	// checks the Kubernetes Node via Get, which the interceptor fails with a non-404 error.
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	plugin := newTestPlugin()
	pluginNode := newTestPluginNode(func(n *artifactv1alpha1.ArtifactNode) {
		n.Finalizers = []string{"some-finalizer"}
	})
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin, pluginNode, newTestFalco(), newRunningFalcoPod()).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Node); ok {
					return fmt.Errorf("node lookup error")
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	err := r.handleDeletion(context.Background(), plugin)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "node lookup error")
}

func TestReconcile_FetchAndCacheBinariesError(t *testing.T) {
	// fetchAndCacheArtifactMeta succeeds and sets Status.ArtifactMeta.Digest.
	// fetchAndCacheBlobs uses that digest as knownDigest → skips ResolveDigest,
	// goes straight to Pull → Pull fails.
	cacheDir := t.TempDir()
	plugin := newTestPlugin(withPluginOCI())
	node := newTestNode(testutil.TestNodeName, map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})

	mockPuller := &puller.MockOCIPuller{
		ConfigResult: &puller.ArtifactConfig{},
		ConfigDigest: testPluginDigest,
		PullErr:      fmt.Errorf("registry down"),
	}
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, plugin, node, newTestFalco(), newRunningFalcoPod())
	_, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry down")
}
