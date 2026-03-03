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

package controllerhelper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
)

func TestToUnstructured(t *testing.T) {
	tests := []struct {
		name    string
		obj     any
		wantErr bool
	}{
		{
			name: "already unstructured",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata": map[string]any{
						"name": "test",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "convert ConfigMap preserves fields",
			obj: builders.NewConfigMap().
				WithName("test-cm").
				WithNamespace("default").
				WithLabels(map[string]string{"app": "test"}).
				WithData(map[string]string{"key": "value"}).
				Build(),
			wantErr: false,
		},
		{
			name: "convert Deployment preserves nested structure",
			obj: builders.NewDeployment().
				WithName("test-deploy").
				WithNamespace("production").
				WithLabels(map[string]string{"app": "falco", "tier": "security"}).
				WithSelector(map[string]string{"app": "falco"}).
				WithStrategy(appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType}).
				AddContainer(&corev1.Container{
					Name:  "falco",
					Image: "falcosecurity/falco:latest",
					Ports: []corev1.ContainerPort{{ContainerPort: 8765, Protocol: corev1.ProtocolTCP}},
				}).
				AddInitContainer(&corev1.Container{
					Name:  "init",
					Image: "busybox:latest",
				}).
				Build(),
			wantErr: false,
		},
		{
			name:    "invalid object",
			obj:     make(chan int),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ToUnstructured(tt.obj)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.IsType(t, &unstructured.Unstructured{}, result)
		})
	}
}

func TestToUnstructured_ConfigMapPreservation(t *testing.T) {
	cm := builders.NewConfigMap().
		WithName("test-cm").
		WithNamespace("default").
		WithLabels(map[string]string{"app": "test"}).
		WithData(map[string]string{"key": "value"}).
		Build()

	result, err := ToUnstructured(cm)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "test-cm", result.GetName())
	assert.Equal(t, "default", result.GetNamespace())
	assert.Equal(t, "ConfigMap", result.GetKind())
	assert.Equal(t, "v1", result.GetAPIVersion())
	assert.Equal(t, map[string]string{"app": "test"}, result.GetLabels())
}

func TestToUnstructured_DeploymentPreservation(t *testing.T) {
	deploy := builders.NewDeployment().
		WithName("test-deploy").
		WithNamespace("production").
		WithLabels(map[string]string{"app": "falco", "tier": "security"}).
		WithSelector(map[string]string{"app": "falco"}).
		WithStrategy(appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType}).
		AddContainer(&corev1.Container{
			Name:  "falco",
			Image: "falcosecurity/falco:latest",
			Ports: []corev1.ContainerPort{{ContainerPort: 8765, Protocol: corev1.ProtocolTCP}},
		}).
		AddInitContainer(&corev1.Container{
			Name:  "init",
			Image: "busybox:latest",
		}).
		Build()

	result, err := ToUnstructured(deploy)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify top-level metadata
	assert.Equal(t, "test-deploy", result.GetName())
	assert.Equal(t, "production", result.GetNamespace())
	assert.Equal(t, "Deployment", result.GetKind())
	assert.Equal(t, "apps/v1", result.GetAPIVersion())
	assert.Equal(t, map[string]string{"app": "falco", "tier": "security"}, result.GetLabels())

	// Verify nested spec fields survived conversion
	spec, found, err := unstructured.NestedMap(result.Object, "spec")
	require.NoError(t, err)
	require.True(t, found, "spec should exist")

	strategyType, found, err := unstructured.NestedString(spec, "strategy", "type")
	require.NoError(t, err)
	require.True(t, found, "strategy.type should exist")
	assert.Equal(t, "RollingUpdate", strategyType)

	containers, found, err := unstructured.NestedSlice(spec, "template", "spec", "containers")
	require.NoError(t, err)
	require.True(t, found, "containers should exist")
	require.Len(t, containers, 1)

	container, ok := containers[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "falco", container["name"])
	assert.Equal(t, "falcosecurity/falco:latest", container["image"])

	initContainers, found, err := unstructured.NestedSlice(spec, "template", "spec", "initContainers")
	require.NoError(t, err)
	require.True(t, found, "initContainers should exist")
	require.Len(t, initContainers, 1)

	initContainer, ok := initContainers[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "init", initContainer["name"])
	assert.Equal(t, "busybox:latest", initContainer["image"])
}
