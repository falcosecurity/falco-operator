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

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

func TestListMatchingNodes_NilSelectorMatchesAll(t *testing.T) {
	s := testutil.Scheme(t)
	n1 := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1"}}
	n2 := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node2", Labels: map[string]string{"pool": "gpu"}}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(n1, n2).Build()

	nodes, err := controllerhelper.ListMatchingNodes(context.Background(), cl, nil)
	require.NoError(t, err)
	assert.Len(t, nodes, 2)
}

func TestListMatchingNodes_SelectorMatchesSubset(t *testing.T) {
	s := testutil.Scheme(t)
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
	s := testutil.Scheme(t)
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
	s := testutil.Scheme(t)
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

func TestFilterNodesByName(t *testing.T) {
	nodes := []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "a"}}, {ObjectMeta: metav1.ObjectMeta{Name: "b"}}, {ObjectMeta: metav1.ObjectMeta{Name: "c"}}}
	tests := []struct {
		name    string
		desired map[string]struct{}
		want    []string
	}{
		{name: "the desired nodes, in order", desired: map[string]struct{}{"c": {}, "a": {}}, want: []string{"a", "c"}},
		{name: "a desired node that is not in the list is ignored", desired: map[string]struct{}{"z": {}}},
		{name: "nothing desired", desired: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, n := range controllerhelper.FilterNodesByName(nodes, tt.desired) {
				got = append(got, n.Name)
			}

			assert.Equal(t, tt.want, got)
		})
	}
	assert.Len(t, nodes, 3, "the list given is left as it was")
}

func TestListFalcoRunningPods(t *testing.T) {
	const ns = "falco"
	falco := func(name string) *instancev1alpha1.Falco {
		return &instancev1alpha1.Falco{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	}
	pod := func(name, instance, node string, phase corev1.PodPhase) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: map[string]string{"app.kubernetes.io/instance": instance}},
			Spec:       corev1.PodSpec{NodeName: node},
			Status:     corev1.PodStatus{Phase: phase},
		}
	}
	tests := []struct {
		name       string
		objects    []client.Object
		listFailOn string // "Falco" or "Pod"
		want       map[string]int
		wantErr    string
	}{
		{name: "nothing runs", objects: []client.Object{falco("f")}, want: map[string]int{}},
		{
			name:    "running pods of a Falco, by node",
			objects: []client.Object{falco("f"), pod("p1", "f", "n1", corev1.PodRunning), pod("p2", "f", "n2", corev1.PodRunning)},
			want:    map[string]int{"n1": 1, "n2": 1},
		},
		{
			name:    "pods that are not running or not scheduled do not count",
			objects: []client.Object{falco("f"), pod("p1", "f", "n1", corev1.PodPending), pod("p2", "f", "", corev1.PodRunning), pod("p3", "f", "n3", corev1.PodFailed)},
			want:    map[string]int{},
		},
		{
			name:    "pods of something that is not a Falco do not count",
			objects: []client.Object{falco("f"), pod("p1", "other", "n1", corev1.PodRunning)},
			want:    map[string]int{},
		},
		{
			name: "a pod being deleted does not count",
			objects: []client.Object{falco("f"), pod("p1", "f", "n1", corev1.PodRunning), func() *corev1.Pod {
				p := pod("p2", "f", "n1", corev1.PodRunning)
				now := metav1.Now()
				p.DeletionTimestamp, p.Finalizers = &now, []string{"test/finalizer"}
				return p
			}()},
			want: map[string]int{"n1": 1},
		},
		{
			name:    "two Falcos on one node count twice",
			objects: []client.Object{falco("f"), falco("g"), pod("p1", "f", "n1", corev1.PodRunning), pod("p2", "g", "n1", corev1.PodRunning)},
			want:    map[string]int{"n1": 2},
		},
		{name: "the Falcos cannot be listed", listFailOn: "Falco", wantErr: "list Falco CRs"},
		{name: "the pods cannot be listed", objects: []client.Object{falco("f")}, listFailOn: "Pod", wantErr: `list pods for Falco "f"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := runtime.NewScheme()
			require.NoError(t, corev1.AddToScheme(s))
			require.NoError(t, instancev1alpha1.AddToScheme(s))
			cl := fake.NewClientBuilder().WithScheme(s).WithObjects(tt.objects...).
				WithIndex(&corev1.Pod{}, index.PodNodeName, index.PodByNodeName).WithInterceptorFuncs(interceptor.Funcs{
				List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					switch list.(type) {
					case *instancev1alpha1.FalcoList:
						if tt.listFailOn == "Falco" {
							return fmt.Errorf("boom")
						}
					case *corev1.PodList:
						if tt.listFailOn == "Pod" {
							return fmt.Errorf("boom")
						}
					}
					return cl.List(ctx, list, opts...)
				},
			}).Build()

			names, err := controllerhelper.ListFalcoRunningNodeNames(t.Context(), cl, ns)
			_, countErr := controllerhelper.CountFalcoRunningPodsOnNode(t.Context(), cl, ns, "n1")

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.ErrorContains(t, countErr, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Len(t, names, len(tt.want))
			for node, want := range tt.want {
				assert.Contains(t, names, node)
				got, err := controllerhelper.CountFalcoRunningPodsOnNode(t.Context(), cl, ns, node)
				require.NoError(t, err)
				assert.Equal(t, want, got, "node %s", node)
			}
		})
	}
}

func TestCountFalcoRunningPodsOnNode(t *testing.T) {
	const ns = "falco"
	falco := func(name string) *instancev1alpha1.Falco {
		return &instancev1alpha1.Falco{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	}
	pod := func(name, instance, node string, mods ...func(*corev1.Pod)) *corev1.Pod {
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: map[string]string{"app.kubernetes.io/instance": instance}},
			Spec:       corev1.PodSpec{NodeName: node},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}
		for _, mod := range mods {
			mod(p)
		}
		return p
	}
	pending := func(p *corev1.Pod) { p.Status.Phase = corev1.PodPending }
	named := func(app string) func(*corev1.Pod) {
		return func(p *corev1.Pod) { p.Labels["app.kubernetes.io/name"] = app }
	}
	deleting := func(p *corev1.Pod) {
		now := metav1.Now()
		p.DeletionTimestamp, p.Finalizers = &now, []string{"test/finalizer"}
	}
	tests := []struct {
		name    string
		objects []client.Object
		want    int
	}{
		{name: "no Falco", objects: []client.Object{pod("p1", "f", "n1")}},
		{name: "one pod on the node", objects: []client.Object{falco("f"), pod("p1", "f", "n1"), pod("p2", "f", "n2")}, want: 1},
		{name: "two Falcos on the node", objects: []client.Object{falco("f"), falco("g"), pod("p1", "f", "n1"), pod("p2", "g", "n1")}, want: 2},
		{name: "pending, deleting and foreign pods do not count", objects: []client.Object{falco("f"),
			pod("p1", "f", "n1", pending), pod("p2", "f", "n1", deleting), pod("p3", "other", "n1")}},
		// A pod of another workload whose instance label carries the Falco's name, a Helm release called like it,
		// is told apart by its name label. The operator gives its own pods the Falco's name in both.
		{name: "a pod named as another app is not a Falco pod", objects: []client.Object{falco("f"),
			pod("p1", "f", "n1", named("f")), pod("p2", "f", "n1", named("falcosidekick"))}, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := runtime.NewScheme()
			require.NoError(t, corev1.AddToScheme(s))
			require.NoError(t, instancev1alpha1.AddToScheme(s))
			cl := fake.NewClientBuilder().WithScheme(s).WithObjects(tt.objects...).
				WithIndex(&corev1.Pod{}, index.PodNodeName, index.PodByNodeName).Build()

			got, err := controllerhelper.CountFalcoRunningPodsOnNode(t.Context(), cl, ns, "n1")

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCountFalcoRunningPodsOnNode_Errors(t *testing.T) {
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, instancev1alpha1.AddToScheme(s))
	falco := &instancev1alpha1.Falco{ObjectMeta: metav1.ObjectMeta{Namespace: "falco", Name: "f"}}
	for name, failFalcos := range map[string]bool{"the Falcos cannot be listed": true, "the pods cannot be listed": false} {
		t.Run(name, func(t *testing.T) {
			cl := fake.NewClientBuilder().WithScheme(s).WithObjects(falco).
				WithIndex(&corev1.Pod{}, index.PodNodeName, index.PodByNodeName).
				WithInterceptorFuncs(interceptor.Funcs{
					List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						if _, isFalco := list.(*instancev1alpha1.FalcoList); isFalco == failFalcos {
							return fmt.Errorf("boom")
						}
						return cl.List(ctx, list, opts...)
					},
				}).Build()

			_, err := controllerhelper.CountFalcoRunningPodsOnNode(t.Context(), cl, "falco", "n1")

			require.ErrorContains(t, err, "boom")
		})
	}
}
