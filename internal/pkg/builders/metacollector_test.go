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

package builders

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewMetacollector_Empty(t *testing.T) {
	mc := NewMetacollector().Build()
	assert.Empty(t, mc.Name)
	assert.Empty(t, mc.Namespace)
}

func TestMetacollectorBuilder(t *testing.T) {
	labels := map[string]string{"app": "metacollector"}
	now := metav1.Now()

	mc := NewMetacollector().
		WithName("my-mc").
		WithNamespace("ns").
		WithLabels(labels).
		WithFinalizers([]string{"metacollector.falcosecurity.dev/finalizer"}).
		WithDeletionTimestamp(&now).
		WithReplicas(2).
		WithVersion("0.10.0").
		Build()

	assert.Equal(t, "my-mc", mc.Name)
	assert.Equal(t, "ns", mc.Namespace)
	assert.Equal(t, labels, mc.Labels)
	assert.Equal(t, []string{"metacollector.falcosecurity.dev/finalizer"}, mc.Finalizers)
	assert.Equal(t, &now, mc.DeletionTimestamp)
	require.NotNil(t, mc.Spec.Replicas)
	assert.Equal(t, int32(2), *mc.Spec.Replicas)
	assert.Equal(t, "0.10.0", mc.Spec.Version)
}

func TestMetacollectorBuilder_WithImage(t *testing.T) {
	mc := NewMetacollector().
		WithImage("metacollector", "custom:latest").
		Build()

	require.NotNil(t, mc.Spec.PodTemplateSpec)
	require.Len(t, mc.Spec.PodTemplateSpec.Spec.Containers, 1)
	assert.Equal(t, "metacollector", mc.Spec.PodTemplateSpec.Spec.Containers[0].Name)
	assert.Equal(t, "custom:latest", mc.Spec.PodTemplateSpec.Spec.Containers[0].Image)
}

func TestMetacollectorBuilder_WithPodTemplateSpec(t *testing.T) {
	pts := &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c1"}},
		},
	}

	mc := NewMetacollector().WithPodTemplateSpec(pts).Build()
	assert.Equal(t, pts, mc.Spec.PodTemplateSpec)
}

func TestMetacollectorBuilder_WithStrategy(t *testing.T) {
	strategy := appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}
	mc := NewMetacollector().WithStrategy(strategy).Build()
	require.NotNil(t, mc.Spec.Strategy)
	assert.Equal(t, appsv1.RecreateDeploymentStrategyType, mc.Spec.Strategy.Type)
}
