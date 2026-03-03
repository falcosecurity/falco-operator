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

func TestNewFalco_Empty(t *testing.T) {
	f := NewFalco().Build()
	assert.Empty(t, f.Name)
	assert.Empty(t, f.Namespace)
	assert.Nil(t, f.Spec.Type)
	assert.Nil(t, f.Spec.Replicas)
	assert.Nil(t, f.Spec.Version)
	assert.Nil(t, f.Spec.PodTemplateSpec)
	assert.Nil(t, f.Spec.Strategy)
	assert.Nil(t, f.Spec.UpdateStrategy)
}

func TestFalcoBuilder(t *testing.T) {
	labels := map[string]string{"app": "falco"}
	now := metav1.Now()

	f := NewFalco().
		WithName("my-falco").
		WithNamespace("ns").
		WithLabels(labels).
		WithFinalizers([]string{"falco.falcosecurity.dev/finalizer"}).
		WithDeletionTimestamp(&now).
		WithType("DaemonSet").
		WithReplicas(3).
		WithVersion("0.39.2").
		Build()

	assert.Equal(t, "my-falco", f.Name)
	assert.Equal(t, "ns", f.Namespace)
	assert.Equal(t, labels, f.Labels)
	assert.Equal(t, []string{"falco.falcosecurity.dev/finalizer"}, f.Finalizers)
	assert.Equal(t, &now, f.DeletionTimestamp)
	require.NotNil(t, f.Spec.Type)
	assert.Equal(t, "DaemonSet", *f.Spec.Type)
	require.NotNil(t, f.Spec.Replicas)
	assert.Equal(t, int32(3), *f.Spec.Replicas)
	require.NotNil(t, f.Spec.Version)
	assert.Equal(t, "0.39.2", *f.Spec.Version)
}

func TestFalcoBuilder_WithImage(t *testing.T) {
	f := NewFalco().
		WithImage("falco", "custom:latest").
		Build()

	require.NotNil(t, f.Spec.PodTemplateSpec)
	require.Len(t, f.Spec.PodTemplateSpec.Spec.Containers, 1)
	assert.Equal(t, "falco", f.Spec.PodTemplateSpec.Spec.Containers[0].Name)
	assert.Equal(t, "custom:latest", f.Spec.PodTemplateSpec.Spec.Containers[0].Image)
}

func TestFalcoBuilder_WithPodTemplateSpec(t *testing.T) {
	pts := &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c1"}, {Name: "c2"}},
		},
	}

	f := NewFalco().WithPodTemplateSpec(pts).Build()
	assert.Equal(t, pts, f.Spec.PodTemplateSpec)
}

func TestFalcoBuilder_WithStrategy(t *testing.T) {
	strategy := appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}
	f := NewFalco().WithStrategy(strategy).Build()
	require.NotNil(t, f.Spec.Strategy)
	assert.Equal(t, appsv1.RecreateDeploymentStrategyType, f.Spec.Strategy.Type)
}

func TestFalcoBuilder_WithImageOverwrite(t *testing.T) {
	f := NewFalco().
		WithImage("first-container", "first:v1").
		WithImage("second-container", "second:v2").
		Build()

	require.NotNil(t, f.Spec.PodTemplateSpec)
	require.Len(t, f.Spec.PodTemplateSpec.Spec.Containers, 1, "second WithImage should overwrite first")
	assert.Equal(t, "second-container", f.Spec.PodTemplateSpec.Spec.Containers[0].Name)
	assert.Equal(t, "second:v2", f.Spec.PodTemplateSpec.Spec.Containers[0].Image)
}

func TestFalcoBuilder_WithUpdateStrategy(t *testing.T) {
	strategy := appsv1.DaemonSetUpdateStrategy{Type: appsv1.OnDeleteDaemonSetStrategyType}
	f := NewFalco().WithUpdateStrategy(strategy).Build()
	require.NotNil(t, f.Spec.UpdateStrategy)
	assert.Equal(t, appsv1.OnDeleteDaemonSetStrategyType, f.Spec.UpdateStrategy.Type)
}

func TestFalcoBuilder_StrategyIndependence(t *testing.T) {
	f := NewFalco().
		WithStrategy(appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}).
		WithUpdateStrategy(appsv1.DaemonSetUpdateStrategy{Type: appsv1.OnDeleteDaemonSetStrategyType}).
		Build()

	require.NotNil(t, f.Spec.Strategy)
	require.NotNil(t, f.Spec.UpdateStrategy)
	assert.Equal(t, appsv1.RecreateDeploymentStrategyType, f.Spec.Strategy.Type)
	assert.Equal(t, appsv1.OnDeleteDaemonSetStrategyType, f.Spec.UpdateStrategy.Type)
}
