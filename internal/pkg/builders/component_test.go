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

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

func TestNewComponent_Empty(t *testing.T) {
	c := NewComponent().Build()
	assert.Empty(t, c.Name)
	assert.Empty(t, c.Namespace)
	assert.Empty(t, c.Spec.Component.Type)
	assert.Nil(t, c.Spec.Component.Version)
	assert.Nil(t, c.Spec.Replicas)
	assert.Nil(t, c.Spec.PodTemplateSpec)
	assert.Nil(t, c.Spec.Strategy)
}

func TestComponentBuilder(t *testing.T) {
	labels := map[string]string{"app": "component"}
	now := metav1.Now()

	c := NewComponent().
		WithName("my-component").
		WithNamespace("ns").
		WithLabels(labels).
		WithFinalizers([]string{"component.instance.falcosecurity.dev/finalizer"}).
		WithDeletionTimestamp(&now).
		WithReplicas(2).
		WithComponentType(instancev1alpha1.ComponentTypeMetacollector).
		WithVersion("0.10.0").
		Build()

	assert.Equal(t, "my-component", c.Name)
	assert.Equal(t, "ns", c.Namespace)
	assert.Equal(t, labels, c.Labels)
	assert.Equal(t, []string{"component.instance.falcosecurity.dev/finalizer"}, c.Finalizers)
	assert.Equal(t, &now, c.DeletionTimestamp)
	require.NotNil(t, c.Spec.Replicas)
	assert.Equal(t, int32(2), *c.Spec.Replicas)
	assert.Equal(t, instancev1alpha1.ComponentTypeMetacollector, c.Spec.Component.Type)
	require.NotNil(t, c.Spec.Component.Version)
	assert.Equal(t, "0.10.0", *c.Spec.Component.Version)
}

func TestComponentBuilder_WithImage(t *testing.T) {
	c := NewComponent().
		WithImage("metacollector", "custom:latest").
		Build()

	require.NotNil(t, c.Spec.PodTemplateSpec)
	require.Len(t, c.Spec.PodTemplateSpec.Spec.Containers, 1)
	assert.Equal(t, "metacollector", c.Spec.PodTemplateSpec.Spec.Containers[0].Name)
	assert.Equal(t, "custom:latest", c.Spec.PodTemplateSpec.Spec.Containers[0].Image)
}

func TestComponentBuilder_WithPodTemplateSpec(t *testing.T) {
	pts := &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c1"}},
		},
	}

	c := NewComponent().WithPodTemplateSpec(pts).Build()
	assert.Equal(t, pts, c.Spec.PodTemplateSpec)
}

func TestComponentBuilder_WithImageOverwrite(t *testing.T) {
	c := NewComponent().
		WithImage("first-container", "first:v1").
		WithImage("second-container", "second:v2").
		Build()

	require.NotNil(t, c.Spec.PodTemplateSpec)
	require.Len(t, c.Spec.PodTemplateSpec.Spec.Containers, 1, "second WithImage should overwrite first")
	assert.Equal(t, "second-container", c.Spec.PodTemplateSpec.Spec.Containers[0].Name)
	assert.Equal(t, "second:v2", c.Spec.PodTemplateSpec.Spec.Containers[0].Image)
}

func TestComponentBuilder_WithStrategy(t *testing.T) {
	strategy := appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}
	c := NewComponent().WithStrategy(strategy).Build()
	require.NotNil(t, c.Spec.Strategy)
	assert.Equal(t, appsv1.RecreateDeploymentStrategyType, c.Spec.Strategy.Type)
}
