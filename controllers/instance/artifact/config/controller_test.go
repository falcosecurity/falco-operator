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

package config

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
)

const testConfigName = "test-config"

func testConfigNodeName() string {
	return controllerhelper.NodeObjectName(controllerhelper.ArtifactKindConfig, testConfigName, testutil.TestNodeName)
}

func newTestNode() *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: testutil.TestNodeName},
	}
}

func newTestConfig(opts ...func(*artifactv1alpha1.Config)) *artifactv1alpha1.Config {
	c := &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func withConfigSelector(key, value string) func(*artifactv1alpha1.Config) {
	return func(c *artifactv1alpha1.Config) {
		c.Spec.Selector = &metav1.LabelSelector{
			MatchLabels: map[string]string{key: value},
		}
	}
}

func newTestConfigNode(opts ...func(*artifactv1alpha1.ArtifactNode)) *artifactv1alpha1.ArtifactNode {
	isController := true
	n := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testConfigNodeName(),
			Namespace: testutil.TestNamespace,
			Labels:    controllerhelper.NodeObjectLabels(controllerhelper.ArtifactKindConfig, testConfigName, testutil.TestNodeName),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: artifactv1alpha1.GroupVersion.String(),
				Kind:       "Config",
				Name:       testConfigName,
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

func newTestReconciler(t *testing.T, objs ...client.Object) (*ConfigAggregatorReconciler, client.Client) {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Config{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	return NewConfigAggregatorReconciler(cl, s), cl
}

func newTestReconcilerWithScheme(t *testing.T, s *runtime.Scheme, objs ...client.Object) (*ConfigAggregatorReconciler, client.Client) {
	t.Helper()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Config{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	return NewConfigAggregatorReconciler(cl, s), cl
}

// addInUseFinalizer adds the node-objects-in-use finalizer to config via server-side apply.
func addInUseFinalizer(t *testing.T, cl client.Client, config *artifactv1alpha1.Config) {
	t.Helper()
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(config), config))
	require.NoError(t, controllerhelper.EnsureInUseFinalizer(
		context.Background(), cl,
		controllerhelper.NodeObjectsInUseFinalizer,
		config, true,
	))
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(config), config))
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
	r := NewConfigAggregatorReconciler(cl, s)
	_, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.Error(t, err)
}

func TestReconcile_DeletionNoNodeObjects(t *testing.T) {
	// A finalizer makes cl.Delete set DeletionTimestamp on the object rather than removing it.
	config := newTestConfig(func(c *artifactv1alpha1.Config) {
		c.Finalizers = []string{"test.example.com/keep-alive"}
	})
	r, cl := newTestReconciler(t, config)

	require.NoError(t, cl.Delete(context.Background(), config))

	result, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// No ConfigNodes should exist.
	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Empty(t, nodeList.Items)
}

func TestReconcile_DeletionWithNodeObjects(t *testing.T) {
	// A finalizer makes cl.Delete set DeletionTimestamp on the object rather than removing it.
	config := newTestConfig(func(c *artifactv1alpha1.Config) {
		c.Finalizers = []string{"test.example.com/keep-alive"}
	})
	configNode := newTestConfigNode()
	r, cl := newTestReconciler(t, config, configNode)

	require.NoError(t, cl.Delete(context.Background(), config))

	result, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// ConfigNode should be deleted.
	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Empty(t, nodeList.Items)
}

func TestReconcile_NoMatchingNodes(t *testing.T) {
	config := newTestConfig()
	r, cl := newTestReconciler(t, config)

	result, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// No ConfigNodes should exist.
	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Empty(t, nodeList.Items)

	// Status should have Programmed=Unknown (no nodes assigned).
	got := &artifactv1alpha1.Config{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(config), got))
	cond := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionUnknown, cond.Status)
}

func TestReconcile_CreatesNodeObject(t *testing.T) {
	config := newTestConfig()
	node := newTestNode()
	r, cl := newTestReconciler(t, config, node, newTestFalco(), newRunningFalcoPod())

	result, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// ConfigNode should be created.
	configNode := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(),
		types.NamespacedName{Name: testConfigNodeName(), Namespace: testutil.TestNamespace},
		configNode))
	assert.Equal(t, testutil.TestNodeName, configNode.Spec.NodeName)

	// In-use finalizer should be added to the Config.
	got := &artifactv1alpha1.Config{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(config), got))
	assert.Contains(t, got.Finalizers, controllerhelper.NodeObjectsInUseFinalizer)
}

func TestReconcile_NodeObjectAlreadyExists(t *testing.T) {
	config := newTestConfig()
	node := newTestNode()
	existingConfigNode := newTestConfigNode()
	r, cl := newTestReconciler(t, config, node, existingConfigNode, newTestFalco(), newRunningFalcoPod())

	result, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Exactly one ConfigNode should exist (idempotent).
	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Len(t, nodeList.Items, 1)
}

func TestReconcile_NoFalcoPod_NoNodeObject(t *testing.T) {
	// Node matches the artifact selector but no Falco pod is running on it.
	config := newTestConfig()
	node := newTestNode()
	r, cl := newTestReconciler(t, config, node) // no Falco CR or pod

	result, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Empty(t, nodeList.Items)
}

func TestReconcile_DeletesStaleNodeObject(t *testing.T) {
	// Config targets nodes with label env=prod, but the existing ConfigNode is for a plain node.
	config := newTestConfig(withConfigSelector("env", "prod"))
	staleNode := newTestConfigNode()
	// The node exists but does NOT have the env=prod label.
	plainNode := newTestNode()
	r, cl := newTestReconciler(t, config, staleNode, plainNode)

	result, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Stale ConfigNode should be gone.
	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), nodeList))
	assert.Empty(t, nodeList.Items)
}

func TestReconcile_ListMatchingNodesError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	config := newTestConfig()
	listCallCount := 0
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(config).
		WithStatusSubresource(&artifactv1alpha1.Config{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.NodeList); ok {
					listCallCount++
					if listCallCount == 1 {
						return fmt.Errorf("node list failed")
					}
				}
				return c.List(ctx, list, opts...)
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewConfigAggregatorReconciler(cl, s)

	_, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "node list failed")
}

func TestReconcile_ListNodeObjectsError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	config := newTestConfig()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(config).
		WithStatusSubresource(&artifactv1alpha1.Config{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.ArtifactNodeList); ok {
					return fmt.Errorf("config node list failed")
				}
				return c.List(ctx, list, opts...)
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewConfigAggregatorReconciler(cl, s)

	_, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config node list failed")
}

func TestReconcile_EnsureNodeObjectCreateError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	config := newTestConfig()
	node := newTestNode()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(config, node, newTestFalco(), newRunningFalcoPod()).
		WithStatusSubresource(&artifactv1alpha1.Config{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.CreateOption) error {
				return fmt.Errorf("create failed")
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewConfigAggregatorReconciler(cl, s)

	_, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create failed")
}

func TestReconcile_EnsureInUseFinalizerError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	config := newTestConfig()
	node := newTestNode()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(config, node, newTestFalco(), newRunningFalcoPod()).
		WithStatusSubresource(&artifactv1alpha1.Config{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
				return fmt.Errorf("patch failed")
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewConfigAggregatorReconciler(cl, s)

	_, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.Error(t, err)
}

func TestHandleDeletion_NoNodeObjects(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	config := newTestConfig()
	_, cl := newTestReconcilerWithScheme(t, s, config)
	addInUseFinalizer(t, cl, config)

	r := NewConfigAggregatorReconciler(cl, s)
	err := r.handleDeletion(context.Background(), config)
	require.NoError(t, err)

	// Finalizer should be removed.
	got := &artifactv1alpha1.Config{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(config), got))
	assert.NotContains(t, got.Finalizers, controllerhelper.NodeObjectsInUseFinalizer)
}

func TestHandleDeletion_NodeObjectsPresent(t *testing.T) {
	config := newTestConfig()
	configNode := newTestConfigNode()
	r, cl := newTestReconciler(t, config, configNode)

	err := r.handleDeletion(context.Background(), config)
	require.NoError(t, err)

	// ConfigNode should be deleted.
	node := &artifactv1alpha1.ArtifactNode{}
	err = cl.Get(context.Background(),
		types.NamespacedName{Name: testConfigNodeName(), Namespace: testutil.TestNamespace}, node)
	assert.Error(t, err)
}

func TestHandleDeletion_NodeObjectsBeingDeleted(t *testing.T) {
	config := newTestConfig()
	configNode := newTestConfigNode(func(n *artifactv1alpha1.ArtifactNode) {
		now := metav1.Now()
		n.DeletionTimestamp = &now
		n.Finalizers = []string{"some-finalizer"} // keeps the object in the fake client after deletion
	})
	r, _ := newTestReconciler(t, config, configNode)

	// Should return nil and wait (not remove finalizer).
	err := r.handleDeletion(context.Background(), config)
	require.NoError(t, err)
}

func TestHandleDeletion_ListError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	config := newTestConfig()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(config).
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
	r := NewConfigAggregatorReconciler(cl, s)

	err := r.handleDeletion(context.Background(), config)
	require.Error(t, err)
}

func TestHandleDeletion_DeleteError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	config := newTestConfig()
	configNode := newTestConfigNode()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(config, configNode).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.DeleteOption) error {
				return fmt.Errorf("delete error")
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()
	r := NewConfigAggregatorReconciler(cl, s)

	err := r.handleDeletion(context.Background(), config)
	require.Error(t, err)
}

func TestEnsureNodeObject_AlreadyExists(t *testing.T) {
	config := newTestConfig()
	existing := newTestConfigNode()
	r, cl := newTestReconciler(t, config, existing)

	// Should be a no-op.
	err := controllerhelper.EnsureNodeObject(context.Background(), r.Client, config,
		artifactv1alpha1.GroupVersion.WithKind(controllerhelper.KindConfig), controllerhelper.ArtifactKindConfig, testutil.TestNodeName)
	require.NoError(t, err)

	// Still exactly one ConfigNode.
	list := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), list))
	assert.Len(t, list.Items, 1)
}

func TestEnsureNodeObject_Creates(t *testing.T) {
	config := newTestConfig()
	r, cl := newTestReconciler(t, config)

	err := controllerhelper.EnsureNodeObject(context.Background(), r.Client, config,
		artifactv1alpha1.GroupVersion.WithKind(controllerhelper.KindConfig), controllerhelper.ArtifactKindConfig, testutil.TestNodeName)
	require.NoError(t, err)

	created := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(),
		types.NamespacedName{Name: testConfigNodeName(), Namespace: testutil.TestNamespace}, created))
	assert.Equal(t, testutil.TestNodeName, created.Spec.NodeName)
	assert.Equal(t, testConfigName, created.Labels[controllerhelper.LabelArtifactParent])
}

func TestEnsureNodeObject_GetError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	config := newTestConfig()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(config).
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
	r := NewConfigAggregatorReconciler(cl, s)

	err := controllerhelper.EnsureNodeObject(context.Background(), r.Client, config,
		artifactv1alpha1.GroupVersion.WithKind(controllerhelper.KindConfig), controllerhelper.ArtifactKindConfig, testutil.TestNodeName)
	require.Error(t, err)
}

func TestUpdateAggregateConditions_Empty(t *testing.T) {
	config := newTestConfig()
	r, cl := newTestReconciler(t, config)

	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	err := controllerhelper.UpdateAggregateConditions(
		context.Background(), r.Client, r.Scheme, config, &config.Status.Conditions, nodeList, ControllerName,
	)
	require.NoError(t, err)

	got := &artifactv1alpha1.Config{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(config), got))
	cond := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionUnknown, cond.Status)
	assert.Equal(t, "NoNodesAssigned", cond.Reason)
}

func TestUpdateAggregateConditions_WithNodeConditions(t *testing.T) {
	config := newTestConfig()
	r, cl := newTestReconciler(t, config)

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
		context.Background(), r.Client, r.Scheme, config, &config.Status.Conditions, nodeList, ControllerName,
	)
	require.NoError(t, err)

	got := &artifactv1alpha1.Config{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(config), got))
	cond := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
}

func TestFindConfigsForNode(t *testing.T) {
	config := newTestConfig()
	r, _ := newTestReconciler(t, config)

	reqs := controllerhelper.EnqueueAllOfType(context.Background(), r.Client, &artifactv1alpha1.ConfigList{})
	require.Len(t, reqs, 1)
	assert.Equal(t, testConfigName, reqs[0].Name)
	assert.Equal(t, testutil.TestNamespace, reqs[0].Namespace)
}

func TestFindConfigsForNode_ListError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.ConfigList); ok {
					return fmt.Errorf("list error")
				}
				return nil
			},
		}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()

	reqs := controllerhelper.EnqueueAllOfType(context.Background(), cl, &artifactv1alpha1.ConfigList{})
	assert.Nil(t, reqs)
}

func TestFindConfigsForNode_EmptyList(t *testing.T) {
	r, _ := newTestReconciler(t)
	reqs := controllerhelper.EnqueueAllOfType(context.Background(), r.Client, &artifactv1alpha1.ConfigList{})
	assert.Empty(t, reqs)
}

// ── Reconcile remaining error paths ─────────────────────────────────────────

func TestReconcile_DeleteStaleNodeError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	// Selector requires env=prod; existing ConfigNode is for a node without that label → stale.
	config := newTestConfig(withConfigSelector("env", "prod"))
	staleNode := newTestConfigNode()
	plainNode := newTestNode()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(config, staleNode, plainNode).
		WithStatusSubresource(&artifactv1alpha1.Config{}).
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
	r := NewConfigAggregatorReconciler(cl, s)
	_, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.Error(t, err)
}

func TestReconcile_SecondListNodeObjectsError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	config := newTestConfig()
	node := newTestNode()
	configNode := newTestConfigNode() // makes ensureNodeObject a no-op
	var listCount int
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(config, node, configNode).
		WithStatusSubresource(&artifactv1alpha1.Config{}).
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
	r := NewConfigAggregatorReconciler(cl, s)
	_, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.Error(t, err)
}
