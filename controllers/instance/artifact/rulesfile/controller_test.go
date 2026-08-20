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

package rulesfile

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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

const testRulesfileName = "test-rulesfile"

func testRulesfileNodeName() string {
	return controllerhelper.NodeObjectName(controllerhelper.ArtifactKindRulesfile, testRulesfileName, testutil.TestNodeName)
}

func testOCIArtifact() *commonv1alpha1.OCIArtifact {
	return &commonv1alpha1.OCIArtifact{
		Image: commonv1alpha1.ImageSpec{Repository: "ghcr.io/test/rulesfile", Tag: "latest"},
	}
}

func newTestNode() *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: testutil.TestNodeName}}
}

func newTestRulesfile(opts ...func(*artifactv1alpha1.Rulesfile)) *artifactv1alpha1.Rulesfile {
	rf := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
	}
	for _, o := range opts {
		o(rf)
	}
	return rf
}

func withRulesfileOCI() func(*artifactv1alpha1.Rulesfile) {
	return func(rf *artifactv1alpha1.Rulesfile) {
		rf.Spec.OCIArtifact = testOCIArtifact()
	}
}

func withRulesfileSelector() func(*artifactv1alpha1.Rulesfile) {
	return func(rf *artifactv1alpha1.Rulesfile) {
		rf.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}
	}
}

func withRulesfileConfigMapRef(name string) func(*artifactv1alpha1.Rulesfile) {
	return func(rf *artifactv1alpha1.Rulesfile) {
		rf.Spec.ConfigMapRef = &commonv1alpha1.ConfigMapRef{Name: name}
	}
}

func withInlineRules(yamlContent string) func(*artifactv1alpha1.Rulesfile) {
	return func(rf *artifactv1alpha1.Rulesfile) {
		rf.Spec.InlineRules = &apiextensionsv1.JSON{Raw: []byte(yamlContent)}
	}
}

func newTestRulesfileNode(opts ...func(*artifactv1alpha1.ArtifactNode)) *artifactv1alpha1.ArtifactNode {
	isController := true
	n := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRulesfileNodeName(),
			Namespace: testutil.TestNamespace,
			Labels:    controllerhelper.NodeObjectLabels(controllerhelper.ArtifactKindRulesfile, testRulesfileName, testutil.TestNodeName),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: artifactv1alpha1.GroupVersion.String(),
				Kind:       "Rulesfile",
				Name:       testRulesfileName,
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

func newTestReconciler(t *testing.T, objs ...client.Object) (*RulesfileAggregatorReconciler, client.Client) {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Rulesfile{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	return NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil), cl
}

func newTestReconcilerWithIndex(t *testing.T, objs ...client.Object) (*RulesfileAggregatorReconciler, client.Client) {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Rulesfile{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		WithIndex(&artifactv1alpha1.Rulesfile{}, index.ConfigMapOnRulesfile, index.RulesfileByConfigMapRef).
		Build()
	return NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil), cl
}

func newTestReconcilerWithPluginIndex(t *testing.T, objs ...client.Object) *RulesfileAggregatorReconciler {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Rulesfile{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		WithIndex(&artifactv1alpha1.Rulesfile{}, index.PluginOnRulesfile, index.RulesfileByPluginDependency).
		Build()
	return NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
}

func newTestReconcilerWithPuller(t *testing.T, mockPuller puller.Puller, objs ...client.Object) (*RulesfileAggregatorReconciler, client.Client) {
	t.Helper()
	r, cl := newTestReconciler(t, objs...)
	r.ociPuller = mockPuller
	return r, cl
}

func addInUseFinalizer(t *testing.T, cl client.Client, rf *artifactv1alpha1.Rulesfile) {
	t.Helper()
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(rf), rf))
	require.NoError(t, controllerhelper.EnsureInUseFinalizer(
		context.Background(), cl,
		controllerhelper.NodeObjectsInUseFinalizer,
		rf, true,
	))
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(rf), rf))
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
	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.Error(t, err)
}

func TestReconcile_DeletionNoNodeObjects(t *testing.T) {
	// A keep-alive finalizer makes cl.Delete set DeletionTimestamp without removing the object.
	rf := newTestRulesfile(func(r *artifactv1alpha1.Rulesfile) {
		r.Finalizers = []string{"test.example.com/keep-alive"}
	})
	rec, cl := newTestReconciler(t, rf)

	require.NoError(t, cl.Delete(context.Background(), rf))

	result, err := rec.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// No RulesfileNodes should exist.
	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Empty(t, nodeList.Items)
}

func TestReconcile_DeletionWithNodeObjects(t *testing.T) {
	// A keep-alive finalizer makes cl.Delete set DeletionTimestamp without removing the object.
	rf := newTestRulesfile(func(r *artifactv1alpha1.Rulesfile) {
		r.Finalizers = []string{"test.example.com/keep-alive"}
	})
	rfNode := newTestRulesfileNode()
	rec, cl := newTestReconciler(t, rf, rfNode)

	require.NoError(t, cl.Delete(context.Background(), rf))

	result, err := rec.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// RulesfileNode should be deleted.
	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Empty(t, nodeList.Items)
}

func TestReconcile_NoMatchingNodes(t *testing.T) {
	rf := newTestRulesfile()
	r, cl := newTestReconciler(t, rf)

	result, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Empty(t, nodeList.Items)

	got := &artifactv1alpha1.Rulesfile{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(rf), got))
	cond := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionUnknown, cond.Status)
}

func TestReconcile_CreatesNodeObject(t *testing.T) {
	rf := newTestRulesfile()
	node := newTestNode()
	r, cl := newTestReconciler(t, rf, node, newTestFalco(), newRunningFalcoPod())

	result, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	rfNode := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(),
		types.NamespacedName{Name: testRulesfileNodeName(), Namespace: testutil.TestNamespace}, rfNode))
	assert.Equal(t, testutil.TestNodeName, rfNode.Spec.NodeName)

	got := &artifactv1alpha1.Rulesfile{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(rf), got))
	assert.Contains(t, got.Finalizers, controllerhelper.NodeObjectsInUseFinalizer)
}

func TestReconcile_NodeObjectAlreadyExists(t *testing.T) {
	rf := newTestRulesfile()
	node := newTestNode()
	existing := newTestRulesfileNode()
	r, cl := newTestReconciler(t, rf, node, existing, newTestFalco(), newRunningFalcoPod())

	result, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	list := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), list))
	assert.Len(t, list.Items, 1)
}

func TestReconcile_NoFalcoPod_NoNodeObject(t *testing.T) {
	// Node matches the artifact selector but no Falco pod is running on it.
	rf := newTestRulesfile()
	node := newTestNode()
	r, cl := newTestReconciler(t, rf, node) // no Falco CR or pod

	result, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Empty(t, nodeList.Items)
}

func TestReconcile_DeletesStaleNodeObject(t *testing.T) {
	rf := newTestRulesfile(withRulesfileSelector())
	staleNode := newTestRulesfileNode()
	plainNode := newTestNode()
	r, cl := newTestReconciler(t, rf, staleNode, plainNode)

	result, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Empty(t, nodeList.Items)
}

func TestReconcile_TerminatingStaleNodeIsRetainedButNotAggregated(t *testing.T) {
	rf := newTestRulesfile(
		withRulesfileSelector(),
		func(r *artifactv1alpha1.Rulesfile) {
			r.Finalizers = []string{controllerhelper.NodeObjectsInUseFinalizer}
		},
	)
	staleNode := newTestRulesfileNode(func(n *artifactv1alpha1.ArtifactNode) {
		n.Finalizers = []string{"artifact.example.com/node-cleanup"}
		n.Status.Conditions = []metav1.Condition{{
			Type:    commonv1alpha1.ConditionProgrammed.String(),
			Status:  metav1.ConditionTrue,
			Reason:  "Programmed",
			Message: "old result",
		}}
	})
	r, cl := newTestReconciler(t, rf, staleNode, newTestNode())

	result, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	terminating := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(staleNode), terminating))
	assert.False(t, terminating.DeletionTimestamp.IsZero(), "the node-side finalizer keeps the stale child terminating")

	got := &artifactv1alpha1.Rulesfile{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(rf), got))
	assert.Contains(t, got.Finalizers, controllerhelper.NodeObjectsInUseFinalizer,
		"the parent must stay alive until the terminating child is physically gone")
	condition := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionUnknown, condition.Status)
	assert.Equal(t, "NoNodesAssigned", condition.Reason,
		"the stale child's last successful result must not remain in the aggregate")
}

func TestReconcile_ListMatchingNodesError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	rf := newTestRulesfile()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rf).
		WithStatusSubresource(&artifactv1alpha1.Rulesfile{}).
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
	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.Error(t, err)
}

func TestReconcile_ListNodeObjectsError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	rf := newTestRulesfile()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rf).
		WithStatusSubresource(&artifactv1alpha1.Rulesfile{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.ArtifactNodeList); ok {
					return fmt.Errorf("rulesfile node list failed")
				}
				return c.List(ctx, list, opts...)
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.Error(t, err)
}

func TestHandleDeletion_NoNodeObjects(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	rf := newTestRulesfile()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rf).
		WithStatusSubresource(&artifactv1alpha1.Rulesfile{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	addInUseFinalizer(t, cl, rf)

	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	err := r.handleDeletion(context.Background(), rf)
	require.NoError(t, err)

	got := &artifactv1alpha1.Rulesfile{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(rf), got))
	assert.NotContains(t, got.Finalizers, controllerhelper.NodeObjectsInUseFinalizer)
}

func TestHandleDeletion_NodeObjectsPresent(t *testing.T) {
	rf := newTestRulesfile()
	rfNode := newTestRulesfileNode()
	r, cl := newTestReconciler(t, rf, rfNode)

	err := r.handleDeletion(context.Background(), rf)
	require.NoError(t, err)

	node := &artifactv1alpha1.ArtifactNode{}
	err = cl.Get(context.Background(),
		types.NamespacedName{Name: testRulesfileNodeName(), Namespace: testutil.TestNamespace}, node)
	assert.Error(t, err)
}

func TestHandleDeletion_EvictsCacheEntry(t *testing.T) {
	rf := newTestRulesfile()
	cacheDir := t.TempDir()
	r := newTestReconcilerWithCacheAndPuller(t, nil, cacheDir, rf)

	blobPath := filepath.Join(cacheDir, "blobs", "own")
	require.NoError(t, artifactcache.Store(blobPath, []byte("x"), 0o644))
	require.NoError(t, r.cache.Set(string(artifact.TypeRulesfile), testutil.TestNamespace, testRulesfileName, "", blobPath))

	// No ArtifactNode objects are owned by this Rulesfile, so handleDeletion evicts the cache entry now.
	err := r.handleDeletion(context.Background(), rf)
	require.NoError(t, err)

	_, ok := r.cache.Lookup(string(artifact.TypeRulesfile), testutil.TestNamespace, testRulesfileName, "")
	assert.False(t, ok)
	_, statErr := os.Stat(blobPath)
	assert.True(t, os.IsNotExist(statErr), "exclusively-referenced blob must be removed from disk")
}

func TestHandleDeletion_SharedBlobSurvivesEviction(t *testing.T) {
	rf := newTestRulesfile()
	cacheDir := t.TempDir()
	r := newTestReconcilerWithCacheAndPuller(t, nil, cacheDir, rf)

	// Two Rulesfile CRs reference the same content-addressed blob; deleting one decrements
	// the refcount and leaves the file in place.
	sharedBlob := filepath.Join(cacheDir, "blobs", "shared")
	require.NoError(t, artifactcache.Store(sharedBlob, []byte("y"), 0o644))
	require.NoError(t, r.cache.Set(string(artifact.TypeRulesfile), testutil.TestNamespace, testRulesfileName, "", sharedBlob))
	require.NoError(t, r.cache.Set(string(artifact.TypeRulesfile), testutil.TestNamespace, "other-rulesfile", "", sharedBlob))

	err := r.handleDeletion(context.Background(), rf)
	require.NoError(t, err)

	_, ok := r.cache.Lookup(string(artifact.TypeRulesfile), testutil.TestNamespace, testRulesfileName, "")
	assert.False(t, ok)

	got, ok := r.cache.Lookup(string(artifact.TypeRulesfile), testutil.TestNamespace, "other-rulesfile", "")
	require.True(t, ok, "other CR's entry for the shared blob must survive")
	assert.Equal(t, sharedBlob, got)
	_, statErr := os.Stat(sharedBlob)
	assert.NoError(t, statErr, "shared blob must survive: another CR still references it")
}

func TestHandleDeletion_NodesRemaining_DoesNotEvictCache(t *testing.T) {
	rf := newTestRulesfile()
	rfNode := newTestRulesfileNode()
	cacheDir := t.TempDir()
	r := newTestReconcilerWithCacheAndPuller(t, nil, cacheDir, rf, rfNode)

	blobPath := filepath.Join(cacheDir, "blobs", "own")
	require.NoError(t, artifactcache.Store(blobPath, []byte("x"), 0o644))
	require.NoError(t, r.cache.Set(string(artifact.TypeRulesfile), testutil.TestNamespace, testRulesfileName, "", blobPath))

	err := r.handleDeletion(context.Background(), rf)
	require.NoError(t, err)

	got, ok := r.cache.Lookup(string(artifact.TypeRulesfile), testutil.TestNamespace, testRulesfileName, "")
	require.True(t, ok, "cache entry must survive while a node object still exists")
	assert.Equal(t, blobPath, got)
}

func TestHandleDeletion_NodeObjectsBeingDeleted(t *testing.T) {
	rf := newTestRulesfile()
	rfNode := newTestRulesfileNode(func(n *artifactv1alpha1.ArtifactNode) {
		now := metav1.Now()
		n.DeletionTimestamp = &now
		n.Finalizers = []string{"some-finalizer"}
	})
	r, _ := newTestReconciler(t, rf, rfNode)

	err := r.handleDeletion(context.Background(), rf)
	require.NoError(t, err)
}

func TestHandleDeletion_ListError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	rf := newTestRulesfile()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rf).
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
	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)

	err := r.handleDeletion(context.Background(), rf)
	require.Error(t, err)
}

func TestEnsureNodeObject_AlreadyExists(t *testing.T) {
	rf := newTestRulesfile()
	existing := newTestRulesfileNode()
	r, cl := newTestReconciler(t, rf, existing)

	err := controllerhelper.EnsureNodeObject(context.Background(), r.Client, rf,
		artifactv1alpha1.GroupVersion.WithKind(controllerhelper.KindRulesfile), controllerhelper.ArtifactKindRulesfile, testutil.TestNodeName)
	require.NoError(t, err)

	list := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), list))
	assert.Len(t, list.Items, 1)
}

func TestEnsureNodeObject_Creates(t *testing.T) {
	rf := newTestRulesfile()
	r, cl := newTestReconciler(t, rf)

	err := controllerhelper.EnsureNodeObject(context.Background(), r.Client, rf,
		artifactv1alpha1.GroupVersion.WithKind(controllerhelper.KindRulesfile), controllerhelper.ArtifactKindRulesfile, testutil.TestNodeName)
	require.NoError(t, err)

	created := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(),
		types.NamespacedName{Name: testRulesfileNodeName(), Namespace: testutil.TestNamespace}, created))
	assert.Equal(t, testutil.TestNodeName, created.Spec.NodeName)
	assert.Equal(t, testRulesfileName, created.Labels[controllerhelper.LabelArtifactParent])
}

func TestEnsureNodeObject_GetError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	rf := newTestRulesfile()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rf).
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
	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)

	err := controllerhelper.EnsureNodeObject(context.Background(), r.Client, rf,
		artifactv1alpha1.GroupVersion.WithKind(controllerhelper.KindRulesfile), controllerhelper.ArtifactKindRulesfile, testutil.TestNodeName)
	require.Error(t, err)
}

func TestUpdateAggregateConditions_Empty(t *testing.T) {
	rf := newTestRulesfile()
	r, cl := newTestReconciler(t, rf)

	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	err := controllerhelper.UpdateAggregateConditions(context.Background(), r.Client, r.Scheme, rf, &rf.Status.Conditions, nodeList, ControllerName)
	require.NoError(t, err)

	got := &artifactv1alpha1.Rulesfile{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(rf), got))
	cond := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionUnknown, cond.Status)
	assert.Equal(t, "NoNodesAssigned", cond.Reason)
}

func TestUpdateAggregateConditions_WithNodeConditions(t *testing.T) {
	rf := newTestRulesfile()
	r, cl := newTestReconciler(t, rf)

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

	err := controllerhelper.UpdateAggregateConditions(context.Background(), r.Client, r.Scheme, rf, &rf.Status.Conditions, nodeList, ControllerName)
	require.NoError(t, err)

	got := &artifactv1alpha1.Rulesfile{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(rf), got))
	cond := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
}

func TestFetchAndCacheArtifactMeta_NoSources(t *testing.T) {
	rf := newTestRulesfile()
	r, _ := newTestReconciler(t, rf)

	rf.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{Digest: "old"}
	err := r.fetchAndCacheArtifactMeta(context.Background(), rf)
	require.NoError(t, err)
	assert.Nil(t, rf.Status.ArtifactMeta)
}

func TestFetchAndCacheArtifactMeta_OCICacheHit(t *testing.T) {
	mockPuller := &puller.MockOCIPuller{}
	rf := newTestRulesfile(withRulesfileOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, rf)

	specHash, err := artifact.ComputeOCIArtifactSpecHash(rf.Spec.OCIArtifact)
	require.NoError(t, err)
	rf.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{
		SpecHash: specHash,
		Digest:   "sha256:abc",
	}

	err = r.fetchAndCacheArtifactMeta(context.Background(), rf)
	require.NoError(t, err)
	assert.Empty(t, mockPuller.FetchConfigCalls)
}

func TestFetchAndCacheArtifactMeta_OCICacheMiss(t *testing.T) {
	mockPuller := &puller.MockOCIPuller{
		ConfigResult: &puller.ArtifactConfig{
			Requirements: []puller.ArtifactRequirement{{Name: "engine_version", Version: "0.36.0"}},
		},
		ConfigDigest:  "sha256:new",
		ContentResult: nil, // no content
	}
	rf := newTestRulesfile(withRulesfileOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, rf)

	err := r.fetchAndCacheArtifactMeta(context.Background(), rf)
	require.NoError(t, err)
	assert.Len(t, mockPuller.FetchConfigCalls, 1)
	require.NotNil(t, rf.Status.ArtifactMeta)
	assert.Equal(t, "sha256:new", rf.Status.ArtifactMeta.Digest)
	require.Len(t, rf.Status.ArtifactMeta.Requirements, 1)
}

func TestFetchAndCacheArtifactMeta_OCIFetchConfigError(t *testing.T) {
	mockPuller := &puller.MockOCIPuller{
		FetchConfigErr: fmt.Errorf("registry unavailable"),
	}
	rf := newTestRulesfile(withRulesfileOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, rf)

	err := r.fetchAndCacheArtifactMeta(context.Background(), rf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry unavailable")
	// Records the failure as a Kubernetes event on the Rulesfile.
	testutil.RequireEvents(t, r.recorder.(*events.FakeRecorder).Events,
		[]string{"Warning OCIArtifactProgramFailed Failed to fetch OCI config layer: registry unavailable"})
}

func TestFetchAndCacheArtifactMeta_OCIContentFetchError(t *testing.T) {
	// The content layer is the only source of required_engine_version and
	// required_plugin_versions, so a content fetch error is fatal and metadata is not persisted.
	mockPuller := &puller.MockOCIPuller{
		ConfigResult:    &puller.ArtifactConfig{},
		ConfigDigest:    "sha256:ok",
		FetchContentErr: fmt.Errorf("content layer missing"),
	}
	rf := newTestRulesfile(withRulesfileOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, rf)

	err := r.fetchAndCacheArtifactMeta(context.Background(), rf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "content layer missing")
	assert.Nil(t, rf.Status.ArtifactMeta, "must not persist metadata computed from an incomplete fetch")
	testutil.RequireEvents(t, r.recorder.(*events.FakeRecorder).Events,
		[]string{"Warning OCIArtifactProgramFailed Failed to fetch OCI content layer: content layer missing"})
}

func TestFetchAndCacheArtifactMeta_OCIWithContentRequirements(t *testing.T) {
	// Content YAML declares engine version requirement.
	yamlContent := []byte(`- required_engine_version: 22`)
	mockPuller := &puller.MockOCIPuller{
		ConfigResult:  &puller.ArtifactConfig{},
		ConfigDigest:  "sha256:content",
		ContentResult: yamlContent,
	}
	rf := newTestRulesfile(withRulesfileOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, rf)

	err := r.fetchAndCacheArtifactMeta(context.Background(), rf)
	require.NoError(t, err)
	require.NotNil(t, rf.Status.ArtifactMeta)
	// engine_version from YAML content should appear in requirements.
	assert.NotEmpty(t, rf.Status.ArtifactMeta.Requirements)
}

func TestFetchAndCacheArtifactMeta_ConfigMap(t *testing.T) {
	yamlContent := `- required_engine_version: 15`
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules-cm", Namespace: testutil.TestNamespace},
		Data:       map[string]string{commonv1alpha1.ConfigMapRulesKey: yamlContent},
	}
	rf := newTestRulesfile(withRulesfileConfigMapRef("my-rules-cm"))
	r, _ := newTestReconciler(t, rf, cm)

	err := r.fetchAndCacheArtifactMeta(context.Background(), rf)
	require.NoError(t, err)
	require.NotNil(t, rf.Status.ArtifactMeta)
}

func TestFetchAndCacheArtifactMeta_ConfigMapMissing(t *testing.T) {
	rf := newTestRulesfile(withRulesfileConfigMapRef("missing-cm"))
	r, _ := newTestReconciler(t, rf)

	// ConfigMap not found: error is logged but ArtifactMeta is still set (empty).
	err := r.fetchAndCacheArtifactMeta(context.Background(), rf)
	require.NoError(t, err)
	require.NotNil(t, rf.Status.ArtifactMeta)
}

func TestFetchAndCacheArtifactMeta_InlineRules(t *testing.T) {
	rf := newTestRulesfile(withInlineRules("- required_engine_version: 10"))
	r, _ := newTestReconciler(t, rf)

	err := r.fetchAndCacheArtifactMeta(context.Background(), rf)
	require.NoError(t, err)
	require.NotNil(t, rf.Status.ArtifactMeta)
}

func TestFetchAndCacheArtifactMeta_ConfigMapAndInlineRules(t *testing.T) {
	// ConfigMap has no requirements; InlineRules declares required_engine_version.
	// Both sources are parsed into ArtifactMeta.Requirements.
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules-cm", Namespace: testutil.TestNamespace},
		Data:       map[string]string{commonv1alpha1.ConfigMapRulesKey: "- rule: plain\n  condition: true\n  output: x\n  desc: d\n  priority: DEBUG"},
	}
	rf := newTestRulesfile(
		withRulesfileConfigMapRef("my-rules-cm"),
		withInlineRules(`- required_engine_version: "0.30.0"`),
	)
	r, _ := newTestReconciler(t, rf, cm)

	err := r.fetchAndCacheArtifactMeta(context.Background(), rf)
	require.NoError(t, err)
	require.NotNil(t, rf.Status.ArtifactMeta)
	require.Len(t, rf.Status.ArtifactMeta.Requirements, 1)
	assert.Equal(t, "engine_version_semver", rf.Status.ArtifactMeta.Requirements[0].Name)
	assert.Equal(t, "0.30.0", rf.Status.ArtifactMeta.Requirements[0].Version)
}

func TestAppendYAMLRequirements_EngineVersionInt(t *testing.T) {
	meta := &commonv1alpha1.ArtifactMeta{}
	content := []byte(`- required_engine_version: 22`)
	appendYAMLRequirements(meta, content)
	require.Len(t, meta.Requirements, 1)
	assert.Equal(t, "engine_version", meta.Requirements[0].Name)
	assert.Equal(t, "22", meta.Requirements[0].Version)
}

func TestAppendYAMLRequirements_EngineVersionSemver(t *testing.T) {
	meta := &commonv1alpha1.ArtifactMeta{}
	content := []byte(`- required_engine_version: "0.36.0"`)
	appendYAMLRequirements(meta, content)
	require.Len(t, meta.Requirements, 1)
	assert.Equal(t, "engine_version_semver", meta.Requirements[0].Name)
}

func TestAppendYAMLRequirements_Empty(t *testing.T) {
	meta := &commonv1alpha1.ArtifactMeta{}
	appendYAMLRequirements(meta, nil)
	assert.Empty(t, meta.Requirements)
	assert.Empty(t, meta.Dependencies)
}

func TestAppendYAMLRequirements_InvalidYAML(t *testing.T) {
	meta := &commonv1alpha1.ArtifactMeta{}
	appendYAMLRequirements(meta, []byte("{invalid"))
	// Should not panic and should produce no requirements.
	assert.Empty(t, meta.Requirements)
}

func TestFindRulesfilesForNode(t *testing.T) {
	rf := newTestRulesfile()
	r, _ := newTestReconciler(t, rf)

	reqs := controllerhelper.EnqueueAllOfType(context.Background(), r.Client, &artifactv1alpha1.RulesfileList{})
	require.Len(t, reqs, 1)
	assert.Equal(t, testRulesfileName, reqs[0].Name)
}

func TestFindRulesfilesForNode_ListError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.RulesfileList); ok {
					return fmt.Errorf("list error")
				}
				return nil
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	reqs := controllerhelper.EnqueueAllOfType(context.Background(), cl, &artifactv1alpha1.RulesfileList{})
	assert.Nil(t, reqs)
}

func TestFindRulesfilesForConfigMap(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules-cm", Namespace: testutil.TestNamespace},
	}
	rf := newTestRulesfile(withRulesfileConfigMapRef("my-rules-cm"))
	r, _ := newTestReconcilerWithIndex(t, rf, cm)

	reqs := r.findRulesfilesForConfigMap(context.Background(), cm)
	require.Len(t, reqs, 1)
	assert.Equal(t, testRulesfileName, reqs[0].Name)
}

func TestFindRulesfilesForConfigMap_ListError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.RulesfileList); ok {
					return fmt.Errorf("list error")
				}
				return nil
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: testutil.TestNamespace}}
	reqs := r.findRulesfilesForConfigMap(context.Background(), cm)
	assert.Nil(t, reqs)
}

func TestFindRulesfilesForPlugin(t *testing.T) {
	const pluginName = "my-plugin"
	rf := newTestRulesfile(func(r *artifactv1alpha1.Rulesfile) {
		r.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{
			Dependencies: []commonv1alpha1.ArtifactMetaDependency{
				{Name: pluginName, Version: "0.1.0"},
			},
		}
	})
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: pluginName, Namespace: testutil.TestNamespace},
	}
	r := newTestReconcilerWithPluginIndex(t, rf, plugin)

	reqs := r.findRulesfilesForPlugin(context.Background(), plugin)
	require.Len(t, reqs, 1)
	assert.Equal(t, testRulesfileName, reqs[0].Name)
}

func TestFindRulesfilesForPlugin_NoMatch(t *testing.T) {
	rf := newTestRulesfile() // no ArtifactMeta → not indexed
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "unrelated-plugin", Namespace: testutil.TestNamespace},
	}
	r := newTestReconcilerWithPluginIndex(t, rf, plugin)

	reqs := r.findRulesfilesForPlugin(context.Background(), plugin)
	assert.Empty(t, reqs)
}

func TestFindRulesfilesForPlugin_ListError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.RulesfileList); ok {
					return fmt.Errorf("list error")
				}
				return nil
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		WithIndex(&artifactv1alpha1.Rulesfile{}, index.PluginOnRulesfile, index.RulesfileByPluginDependency).
		Build()
	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: testutil.TestNamespace}}
	reqs := r.findRulesfilesForPlugin(context.Background(), plugin)
	assert.Nil(t, reqs)
}

// ── Reconcile error-path coverage ───────────────────────────────────────────

func TestReconcile_DeleteStaleNodeError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	// Selector requires env=prod; testutil.TestNodeName has no such label → stale.
	rf := newTestRulesfile(withRulesfileSelector())
	staleNode := newTestRulesfileNode()
	plainNode := newTestNode()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rf, staleNode, plainNode).
		WithStatusSubresource(&artifactv1alpha1.Rulesfile{}).
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
	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.Error(t, err)
}

func TestReconcile_EnsureNodeObjectError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	rf := newTestRulesfile()
	node := newTestNode()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rf, node, newTestFalco(), newRunningFalcoPod()).
		WithStatusSubresource(&artifactv1alpha1.Rulesfile{}).
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
	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.Error(t, err)
}

func TestReconcile_EnsureInUseFinalizerError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	rf := newTestRulesfile()
	node := newTestNode()
	rfNode := newTestRulesfileNode() // pre-existing so ensureNodeObject is a no-op
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rf, node, rfNode, newTestFalco(), newRunningFalcoPod()).
		WithStatusSubresource(&artifactv1alpha1.Rulesfile{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
				return fmt.Errorf("patch failed")
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.Error(t, err)
}

func TestReconcile_SecondListNodeObjectsError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	rf := newTestRulesfile()
	node := newTestNode()
	rfNode := newTestRulesfileNode() // pre-existing so ensureNodeObject is a no-op
	var listCount int
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rf, node, rfNode).
		WithStatusSubresource(&artifactv1alpha1.Rulesfile{}).
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
	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.Error(t, err)
}

func TestReconcile_FetchAndCacheError(t *testing.T) {
	mockPuller := &puller.MockOCIPuller{
		FetchConfigErr: fmt.Errorf("registry down"),
	}
	rf := newTestRulesfile(withRulesfileOCI())
	node := newTestNode()
	rfNode := newTestRulesfileNode() // pre-existing
	r, _ := newTestReconcilerWithPuller(t, mockPuller, rf, node, rfNode)
	_, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.Error(t, err)
}

// ── fetchAndCacheArtifactMeta additional paths ───────────────────────────────

func TestFetchAndCacheArtifactMeta_OCIWithDependencies(t *testing.T) {
	// FetchConfig returns a dependency with an alternative.
	mockPuller := &puller.MockOCIPuller{
		ConfigResult: &puller.ArtifactConfig{
			Dependencies: []puller.ArtifactDependency{
				{
					Name:    "cloudtrail",
					Version: "0.9.0",
					Alternatives: []puller.Dependency{
						{Name: "k8saudit", Version: "0.7.0"},
					},
				},
			},
		},
		ConfigDigest:  "sha256:deps",
		ContentResult: nil,
	}
	rf := newTestRulesfile(withRulesfileOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, rf)

	err := r.fetchAndCacheArtifactMeta(context.Background(), rf)
	require.NoError(t, err)
	require.NotNil(t, rf.Status.ArtifactMeta)
	require.Len(t, rf.Status.ArtifactMeta.Dependencies, 1)
	require.Len(t, rf.Status.ArtifactMeta.Dependencies[0].Alternatives, 1)
	assert.Equal(t, "k8saudit", rf.Status.ArtifactMeta.Dependencies[0].Alternatives[0].Name)
}

func TestFetchAndCacheArtifactMeta_OCICacheHitIgnoresDigest(t *testing.T) {
	// Spec hash matches even though the stored digest is stale, so the cache is still a hit.
	// Picking up a new image pushed to the same tag requires an explicit spec change.
	mockPuller := &puller.MockOCIPuller{}
	rf := newTestRulesfile(withRulesfileOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, rf)

	specHash, err := artifact.ComputeOCIArtifactSpecHash(rf.Spec.OCIArtifact)
	require.NoError(t, err)
	rf.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{
		SpecHash: specHash,
		Digest:   "sha256:old",
	}

	err = r.fetchAndCacheArtifactMeta(context.Background(), rf)
	require.NoError(t, err)
	assert.Empty(t, mockPuller.FetchConfigCalls, "spec hash match must skip FetchConfig regardless of digest")
	assert.Equal(t, "sha256:old", rf.Status.ArtifactMeta.Digest, "stale digest must not be updated on cache hit")
}

// ── appendYAMLRequirements plugin-version paths ──────────────────────────────

func TestAppendYAMLRequirements_PluginVersions(t *testing.T) {
	meta := &commonv1alpha1.ArtifactMeta{}
	content := []byte("- required_plugin_versions:\n  - name: cloudtrail\n    version: \"0.9.0\"")
	appendYAMLRequirements(meta, content)
	require.Len(t, meta.Dependencies, 1)
	assert.Equal(t, "cloudtrail", meta.Dependencies[0].Name)
	assert.Equal(t, "0.9.0", meta.Dependencies[0].Version)
	assert.Empty(t, meta.Dependencies[0].Alternatives)
}

func TestAppendYAMLRequirements_PluginVersionsWithAlternatives(t *testing.T) {
	meta := &commonv1alpha1.ArtifactMeta{}
	content := []byte("- required_plugin_versions:\n  - name: cloudtrail\n    version: \"0.9.0\"\n" +
		"    alternatives:\n      - name: k8saudit\n        version: \"0.7.0\"")
	appendYAMLRequirements(meta, content)
	require.Len(t, meta.Dependencies, 1)
	assert.Equal(t, "cloudtrail", meta.Dependencies[0].Name)
	require.Len(t, meta.Dependencies[0].Alternatives, 1)
	assert.Equal(t, "k8saudit", meta.Dependencies[0].Alternatives[0].Name)
	assert.Equal(t, "0.7.0", meta.Dependencies[0].Alternatives[0].Version)
}

// ── handleDeletion error path ────────────────────────────────────────────────

func TestHandleDeletion_DeleteError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	rf := newTestRulesfile()
	rfNode := newTestRulesfileNode()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rf, rfNode).
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
	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	err := r.handleDeletion(context.Background(), rf)
	require.Error(t, err)
}

// ── fetchAndCacheBlob tests ────────────────────────────────────────────────

// newTestReconcilerWithCacheAndPuller creates a RulesfileAggregatorReconciler with a real,
// loaded artifact Cache rooted at cacheDir, and an injected mock OCI puller.
func newTestReconcilerWithCacheAndPuller(
	t *testing.T, mockPuller puller.Puller, cacheDir string, objs ...client.Object,
) *RulesfileAggregatorReconciler {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Rulesfile{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	// Zero grace period: a dereferenced blob is removed from disk immediately.
	cache := artifactcache.NewCache(cacheDir, artifactcache.WithEvictionGracePeriod(0))
	require.NoError(t, cache.Load())
	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), cache)
	r.ociPuller = mockPuller
	return r
}

func TestFetchAndCacheBinary_NoCache(t *testing.T) {
	// A nil cache disables caching; fetchAndCacheBlob returns immediately.
	rf := newTestRulesfile(withRulesfileOCI())
	r, _ := newTestReconciler(t, rf) // cache = nil
	err := r.fetchAndCacheBlob(context.Background(), rf)
	require.NoError(t, err)
}

func TestFetchAndCacheBinary_NoOCIArtifact(t *testing.T) {
	// Non-OCI source (ConfigMap ref) → noop regardless of cacheDir.
	rf := newTestRulesfile(withRulesfileConfigMapRef("my-cm"))
	cacheDir := t.TempDir()
	r := newTestReconcilerWithCacheAndPuller(t, nil, cacheDir, rf)
	err := r.fetchAndCacheBlob(context.Background(), rf)
	require.NoError(t, err)
}

func TestFetchAndCacheBinary_FastPath(t *testing.T) {
	// This CR's cache entry already points at the blob for the known digest: no registry
	// call needed.
	cacheDir := t.TempDir()
	rf := newTestRulesfile(withRulesfileOCI())
	mockPuller := &puller.MockOCIPuller{} // must not be called
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, rf)

	ref := artifact.ResolveReference(rf.Spec.OCIArtifact)
	const digest = "sha256:cached-rules"
	blobPath := artifactcache.BlobPath(cacheDir, string(artifact.TypeRulesfile), ref, digest, "", "")
	require.NoError(t, artifactcache.Store(blobPath, []byte("rule content"), 0o644))
	require.NoError(t, r.cache.Set(string(artifact.TypeRulesfile), testutil.TestNamespace, testRulesfileName, "", blobPath))

	rf.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{Digest: digest}

	require.NoError(t, r.fetchAndCacheBlob(context.Background(), rf))

	assert.Empty(t, mockPuller.ResolveDigestCalls)
	assert.Empty(t, mockPuller.PullCalls)

	idx, ok := r.cache.Lookup(string(artifact.TypeRulesfile), testutil.TestNamespace, testRulesfileName, "")
	require.True(t, ok)
	assert.Equal(t, blobPath, idx)
}

func TestFetchAndCacheBinary_SlowPath(t *testing.T) {
	// Blob is missing: EnsureBlob pulls from registry and writes the index.
	cacheDir := t.TempDir()
	rf := newTestRulesfile(withRulesfileOCI())

	tarGz, err := puller.MakeTarGz("rules.yml", []byte("- rule: test"))
	require.NoError(t, err)

	mockPuller := &puller.MockOCIPuller{
		ResolveDigestResult: "sha256:pulled-rules",
		Result:              &puller.RegistryResult{Type: puller.Rulesfile},
		LayerContent:        tarGz,
	}
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, rf)

	require.NoError(t, r.fetchAndCacheBlob(context.Background(), rf))

	assert.Len(t, mockPuller.PullCalls, 1)

	_, ok := r.cache.Lookup(string(artifact.TypeRulesfile), testutil.TestNamespace, testRulesfileName, "")
	require.True(t, ok)
}

func TestFetchAndCacheBinary_PullError(t *testing.T) {
	cacheDir := t.TempDir()
	rf := newTestRulesfile(withRulesfileOCI())
	mockPuller := &puller.MockOCIPuller{
		ResolveDigestResult: "sha256:xyz",
		PullErr:             fmt.Errorf("registry down"),
	}
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, rf)

	err := r.fetchAndCacheBlob(context.Background(), rf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry down")
}

func TestReconcile_ClearFinalizersInStalePath_Error(t *testing.T) {
	// Selector requires env=prod; plain node doesn't have that label → staleNode is stale.
	// staleNode has a finalizer so ClearFinalizersIfNodeGone doesn't short-circuit.
	// The interceptor makes Node.Get return a non-404 error propagated to Reconcile.
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	rf := newTestRulesfile(withRulesfileSelector())
	staleNode := newTestRulesfileNode(func(n *artifactv1alpha1.ArtifactNode) {
		n.Finalizers = []string{"some-finalizer"}
	})
	plainNode := newTestNode()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rf, staleNode, plainNode).
		WithStatusSubresource(&artifactv1alpha1.Rulesfile{}).
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
	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "node lookup error")
}

func TestHandleDeletion_ClearFinalizersError(t *testing.T) {
	// RulesfileNode has a finalizer so ClearFinalizersIfNodeGone proceeds to check the node.
	// The Node.Get interceptor returns a non-404 error that is propagated to the caller.
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	rf := newTestRulesfile()
	rfNode := newTestRulesfileNode(func(n *artifactv1alpha1.ArtifactNode) {
		n.Finalizers = []string{"some-finalizer"}
	})
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rf, rfNode).
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
	r := NewRulesfileAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	err := r.handleDeletion(context.Background(), rf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "node lookup error")
}

func TestReconcile_FetchAndCacheBinaryError(t *testing.T) {
	// fetchAndCacheArtifactMeta succeeds and sets Status.ArtifactMeta.Digest.
	// fetchAndCacheBlob uses that digest as knownDigest → skips ResolveDigest,
	// goes straight to Pull → Pull fails.
	cacheDir := t.TempDir()
	rf := newTestRulesfile(withRulesfileOCI())
	node := newTestNode()

	mockPuller := &puller.MockOCIPuller{
		ConfigResult: &puller.ArtifactConfig{},
		ConfigDigest: "sha256:meta",
		PullErr:      fmt.Errorf("registry down"),
	}
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, rf, node)
	_, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry down")
}
