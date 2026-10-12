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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// A cached Node keeps its name and labels, which the artifacts' selectors and the plugin platforms are read from,
// and loses its status and managed fields.
func TestStripNode(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:          "n1",
			Labels:        map[string]string{"kubernetes.io/arch": "arm64"},
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubelet"}},
		},
		Spec:   corev1.NodeSpec{Taints: []corev1.Taint{{Key: corev1.TaintNodeUnreachable, Effect: corev1.TaintEffectNoExecute}}},
		Status: corev1.NodeStatus{Images: []corev1.ContainerImage{{Names: []string{"falco"}}}},
	}

	got, err := stripNode(node)

	require.NoError(t, err)
	stripped := got.(*corev1.Node)
	assert.Equal(t, "n1", stripped.Name)
	assert.Equal(t, "arm64", stripped.Labels["kubernetes.io/arch"])
	assert.Empty(t, stripped.ManagedFields)
	assert.Empty(t, stripped.Status.Images)
	assert.Len(t, stripped.Spec.Taints, 1, "the taints say whether the node is reachable")

	other := &corev1.Pod{}
	got, err = stripNode(other)
	require.NoError(t, err)
	assert.Same(t, other, got, "anything but a Node is left alone")
}

func TestStripPod(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:          "p1",
			Labels:        map[string]string{"app.kubernetes.io/instance": "falco"},
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubelet"}},
		},
		Spec:   corev1.PodSpec{NodeName: "n1", Containers: []corev1.Container{{Name: "falco"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.1"},
	}

	got, err := stripPod(pod)

	require.NoError(t, err)
	stripped := got.(*corev1.Pod)
	assert.Equal(t, "falco", stripped.Labels["app.kubernetes.io/instance"])
	assert.Equal(t, "n1", stripped.Spec.NodeName)
	assert.Equal(t, corev1.PodRunning, stripped.Status.Phase)
	assert.Empty(t, stripped.ManagedFields)
	assert.Empty(t, stripped.Spec.Containers)
	assert.Empty(t, stripped.Status.PodIP)

	other := &corev1.Node{}
	got, err = stripPod(other)
	require.NoError(t, err)
	assert.Same(t, other, got, "anything but a Pod is left alone")
}

// The pod cache keeps every pod that carries the instance label, whoever created it, and drops the others.
func TestFalcoPodSelector(t *testing.T) {
	selector := falcoPodSelector()

	assert.True(t, selector.Matches(labels.Set{"app.kubernetes.io/instance": "my-falco"}), "a Falco pod, created by anyone")
	assert.False(t, selector.Matches(labels.Set{"app": "web"}), "any other pod")
}
