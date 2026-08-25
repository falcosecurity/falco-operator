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

package controllerhelper_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

// newNodeScheme returns a scheme with only corev1 registered, for node-only tests.
func newNodeScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	return s
}

func newConfigMapWithFinalizer() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "obj",
			Namespace:  "default",
			Finalizers: []string{"test.example.com/my-finalizer"},
		},
	}
}

func TestClearFinalizersIfNodeOrPodGone_NoFinalizers(t *testing.T) {
	s := newNodeScheme(t)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "obj", Namespace: "default"}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(node, cm).Build()

	err := controllerhelper.ClearFinalizersIfNodeOrPodGone(context.Background(), cl, "worker-1", nil, cm)
	require.NoError(t, err)
	// Object had no finalizers, so Patch was never called.
	got := &corev1.ConfigMap{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(cm), got))
	assert.Empty(t, got.Finalizers)
}

func TestClearFinalizersIfNodeOrPodGone_NodeAndPodExist(t *testing.T) {
	s := newNodeScheme(t)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}}
	cm := newConfigMapWithFinalizer()
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(node, cm).Build()

	err := controllerhelper.ClearFinalizersIfNodeOrPodGone(
		context.Background(), cl, "worker-1", map[string]struct{}{"worker-1": {}}, cm,
	)
	require.NoError(t, err)
	// Both the node and its artifact operator still exist, so finalizers must be preserved.
	got := &corev1.ConfigMap{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(cm), got))
	assert.NotEmpty(t, got.Finalizers)
}

func TestClearFinalizersIfNodeOrPodGone_PodGone(t *testing.T) {
	s := newNodeScheme(t)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}}
	cm := newConfigMapWithFinalizer()
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(node, cm).Build()

	err := controllerhelper.ClearFinalizersIfNodeOrPodGone(context.Background(), cl, "worker-1", nil, cm)
	require.NoError(t, err)
	// The node still exists, but no artifact operator can release its finalizer.
	got := &corev1.ConfigMap{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(cm), got))
	assert.Empty(t, got.Finalizers)
}

func TestClearFinalizersIfNodeOrPodGone_NodeGone(t *testing.T) {
	s := newNodeScheme(t)
	cm := newConfigMapWithFinalizer()
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cm).Build() // node NOT created

	err := controllerhelper.ClearFinalizersIfNodeOrPodGone(
		context.Background(), cl, "worker-1", map[string]struct{}{"worker-1": {}}, cm,
	)
	require.NoError(t, err)
	// Finalizers are cleared once the node is gone.
	got := &corev1.ConfigMap{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(cm), got))
	assert.Empty(t, got.Finalizers)
}

func TestClearFinalizersIfNodeOrPodGone_GetNodeError(t *testing.T) {
	s := newNodeScheme(t)
	cm := newConfigMapWithFinalizer()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(cm).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Node); ok {
					return fmt.Errorf("api server error")
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	err := controllerhelper.ClearFinalizersIfNodeOrPodGone(
		context.Background(), cl, "worker-1", map[string]struct{}{"worker-1": {}}, cm,
	)
	require.Error(t, err)
}

func TestClearFinalizersIfNodeOrPodGone_PatchError(t *testing.T) {
	s := newNodeScheme(t)
	cm := newConfigMapWithFinalizer()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(cm).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				return fmt.Errorf("patch error")
			},
		}).
		Build()

	// Patch is attempted when the Falco pod is gone, and its error is returned.
	err := controllerhelper.ClearFinalizersIfNodeOrPodGone(context.Background(), cl, "worker-1", nil, cm)
	require.Error(t, err)
}

func TestListMatchingNodes_NilSelectorMatchesAll(t *testing.T) {
	s := newNodeScheme(t)
	n1 := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1"}}
	n2 := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node2", Labels: map[string]string{"pool": "gpu"}}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(n1, n2).Build()

	nodes, err := controllerhelper.ListMatchingNodes(context.Background(), cl, nil)
	require.NoError(t, err)
	assert.Len(t, nodes, 2)
}

func TestListMatchingNodes_SelectorMatchesSubset(t *testing.T) {
	s := newNodeScheme(t)
	n1 := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1", Labels: map[string]string{"pool": "gpu"}}}
	n2 := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node2", Labels: map[string]string{"pool": "cpu"}}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(n1, n2).Build()

	nodes, err := controllerhelper.ListMatchingNodes(context.Background(), cl,
		&metav1.LabelSelector{MatchLabels: map[string]string{"pool": "gpu"}})
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	assert.Equal(t, "node1", nodes[0].Name)
}

func TestListMatchingNodes_InvalidSelector(t *testing.T) {
	s := newNodeScheme(t)
	cl := fake.NewClientBuilder().WithScheme(s).Build()

	_, err := controllerhelper.ListMatchingNodes(context.Background(), cl, &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "key1", Operator: "NotAnOperator"},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid node selector")
}

func TestListMatchingNodes_ListError(t *testing.T) {
	s := newNodeScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return fmt.Errorf("api server unavailable")
			},
		}).
		Build()

	_, err := controllerhelper.ListMatchingNodes(context.Background(), cl, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api server unavailable")
}

func TestFalcoPodChangePredicate(t *testing.T) {
	pred := controllerhelper.FalcoPodChangePredicate()
	makePod := func() *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app.kubernetes.io/instance": "falco"}},
			Spec:       corev1.PodSpec{NodeName: "node-1"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}
	}

	assert.True(t, pred.Create(event.CreateEvent{Object: makePod()}))
	assert.True(t, pred.Delete(event.DeleteEvent{Object: makePod()}))
	assert.False(t, pred.Create(event.CreateEvent{Object: &corev1.Pod{}}))
	assert.False(t, pred.Delete(event.DeleteEvent{Object: &corev1.Pod{}}))

	t.Run("instance label added", func(t *testing.T) {
		oldPod, newPod := makePod(), makePod()
		oldPod.Labels = nil
		assert.True(t, pred.Update(event.UpdateEvent{ObjectOld: oldPod, ObjectNew: newPod}))
	})

	t.Run("instance label removed", func(t *testing.T) {
		oldPod, newPod := makePod(), makePod()
		newPod.Labels = nil
		assert.True(t, pred.Update(event.UpdateEvent{ObjectOld: oldPod, ObjectNew: newPod}))
	})

	t.Run("instance label changed", func(t *testing.T) {
		oldPod, newPod := makePod(), makePod()
		newPod.Labels["app.kubernetes.io/instance"] = "other-falco"
		assert.True(t, pred.Update(event.UpdateEvent{ObjectOld: oldPod, ObjectNew: newPod}))
	})

	t.Run("node assignment changed", func(t *testing.T) {
		oldPod, newPod := makePod(), makePod()
		oldPod.Spec.NodeName = ""
		assert.True(t, pred.Update(event.UpdateEvent{ObjectOld: oldPod, ObjectNew: newPod}))
	})

	t.Run("phase changed", func(t *testing.T) {
		oldPod, newPod := makePod(), makePod()
		oldPod.Status.Phase = corev1.PodPending
		assert.True(t, pred.Update(event.UpdateEvent{ObjectOld: oldPod, ObjectNew: newPod}))
	})

	t.Run("irrelevant status changed", func(t *testing.T) {
		oldPod, newPod := makePod(), makePod()
		newPod.Status.PodIP = "10.0.0.1"
		assert.False(t, pred.Update(event.UpdateEvent{ObjectOld: oldPod, ObjectNew: newPod}))
	})

	t.Run("unrelated pod changed", func(t *testing.T) {
		oldPod, newPod := &corev1.Pod{}, &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning}}
		assert.False(t, pred.Update(event.UpdateEvent{ObjectOld: oldPod, ObjectNew: newPod}))
	})
}

func TestIsBeingDeleted_NotDeleted(t *testing.T) {
	s := newNodeScheme(t)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "obj", Namespace: "default"}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cm).Build()

	deleting, err := controllerhelper.IsBeingDeleted(context.Background(), cl, cm)
	require.NoError(t, err)
	assert.False(t, deleting)
}

func TestIsBeingDeleted_DeletionTimestampSet(t *testing.T) {
	s := newNodeScheme(t)
	now := metav1.Now()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "obj", Namespace: "default",
			Finalizers:        []string{"test.example.com/finalizer"}, // a DeletionTimestamp requires a finalizer to be set
			DeletionTimestamp: &now,
		},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cm).Build()

	deleting, err := controllerhelper.IsBeingDeleted(context.Background(), cl, cm)
	require.NoError(t, err)
	assert.True(t, deleting)
}

func TestIsBeingDeleted_ObjectGone(t *testing.T) {
	s := newNodeScheme(t)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "obj", Namespace: "default"}}
	cl := fake.NewClientBuilder().WithScheme(s).Build() // never created

	deleting, err := controllerhelper.IsBeingDeleted(context.Background(), cl, cm)
	require.NoError(t, err)
	assert.True(t, deleting, "a gone object is treated the same as being deleted")
}

func TestIsBeingDeleted_GetError(t *testing.T) {
	s := newNodeScheme(t)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "obj", Namespace: "default"}}
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(cm).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return fmt.Errorf("api server unavailable")
			},
		}).
		Build()

	_, err := controllerhelper.IsBeingDeleted(context.Background(), cl, cm)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api server unavailable")
}

func TestNodeMatchesSelector(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name          string
		nodeName      string
		nodeLabels    map[string]string
		labelSelector *metav1.LabelSelector
		expectedMatch bool
		expectedError bool
	}{
		{
			name:     "Node matches labelSelector",
			nodeName: "node1",
			nodeLabels: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			labelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"key1": "value1",
				},
			},
			expectedMatch: true,
			expectedError: false,
		},
		{
			name:     "Node does not match labelSelector",
			nodeName: "node2",
			nodeLabels: map[string]string{
				"key1": "value1",
			},
			labelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"key2": "value2",
				},
			},
			expectedMatch: false,
			expectedError: false,
		},
		{
			name:     "Invalid labelSelector",
			nodeName: "node3",
			nodeLabels: map[string]string{
				"key1": "value1",
			},
			labelSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "key1",
						Operator: "InvalidOperator",
					},
				},
			},
			expectedMatch: false,
			expectedError: true,
		},
		{
			name:          "Nil labelSelector (matches all nodes)",
			nodeName:      "node4",
			nodeLabels:    map[string]string{},
			labelSelector: nil,
			expectedMatch: true,
			expectedError: false,
		},
		{
			name:       "Node not found",
			nodeName:   "nonexistent-node",
			nodeLabels: map[string]string{},
			labelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"key1": "value1",
				},
			},
			expectedMatch: false,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fakeClient client.Client
			if tt.name != "Node not found" { // Only add the node if it exists
				node := &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   tt.nodeName,
						Labels: tt.nodeLabels,
					},
				}
				fakeClient = fake.NewClientBuilder().WithScheme(scheme).WithObjects(node).Build()
			} else {
				// Create a fake client without any objects, to simulate a node not found.
				fakeClient = fake.NewClientBuilder().WithScheme(scheme).Build()
			}

			match, err := controllerhelper.NodeMatchesSelector(context.TODO(), fakeClient, tt.nodeName, tt.labelSelector)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedMatch, match)
		})
	}
}
