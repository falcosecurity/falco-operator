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

package instance

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
)

func testGenerateScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, rbacv1.AddToScheme(s))
	return s
}

func TestGenerateResource_InputValidation(t *testing.T) {
	scheme := testGenerateScheme(t)
	defaultClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	defaultObj := builders.NewConfigMap().WithName("test").WithNamespace("default").Build()
	dummyGenerator := func(_ *corev1.ConfigMap) runtime.Object { return nil }

	tests := []struct {
		name         string
		nilObj       bool
		nilClient    bool
		nilGenerator bool
		wantErr      string
	}{
		{
			name:    "nil instance",
			nilObj:  true,
			wantErr: "instance cannot be nil",
		},
		{
			name:      "nil client",
			nilClient: true,
			wantErr:   "client cannot be nil",
		},
		{
			name:         "nil generator function",
			nilGenerator: true,
			wantErr:      "generator function cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := defaultObj
			if tt.nilObj {
				obj = nil
			}
			cl := defaultClient
			if tt.nilClient {
				cl = nil
			}
			gen := dummyGenerator
			if tt.nilGenerator {
				gen = nil
			}

			_, err := GenerateResource(cl, obj, gen, GenerateOptions{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestGenerateResource_NamespacedResource(t *testing.T) {
	scheme := testGenerateScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	ownerCM := builders.NewConfigMap().WithName("test-owner").
		WithNamespace("default").
		WithLabels(map[string]string{"app": "test"}).Build()
	ownerCM.UID = "test-uid"

	generator := func(cm *corev1.ConfigMap) runtime.Object {
		return builders.NewService().
			WithNamespace(cm.Namespace).
			WithLabels(cm.Labels).Build()
	}

	result, err := GenerateResource(cl, ownerCM, generator, GenerateOptions{
		SetControllerRef: true,
		IsClusterScoped:  false,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "Service", result.GetKind())
	assert.Equal(t, "v1", result.GetAPIVersion())
	assert.Equal(t, "test-owner", result.GetName())
	assert.Equal(t, map[string]string{"app": "test"}, result.GetLabels())
}

func TestGenerateResource_ClusterScopedResource(t *testing.T) {
	scheme := testGenerateScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	ownerCM := builders.NewConfigMap().WithName("test-owner").WithNamespace("default").
		WithLabels(map[string]string{"app": "test"}).Build()

	generator := func(cm *corev1.ConfigMap) runtime.Object {
		return builders.NewClusterRole().
			WithName(GenerateUniqueName(cm.Name, cm.Namespace)).
			WithLabels(cm.Labels).Build()
	}

	result, err := GenerateResource(cl, ownerCM, generator, GenerateOptions{
		SetControllerRef: false,
		IsClusterScoped:  true,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "ClusterRole", result.GetKind())
	assert.Equal(t, "rbac.authorization.k8s.io/v1", result.GetAPIVersion())
	assert.Equal(t, "test-owner--default", result.GetName())
	assert.Equal(t, map[string]string{"app": "test"}, result.GetLabels())
}

func TestGenerateResource_ControllerRefFailure(t *testing.T) {
	scheme := testGenerateScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Owner without UID causes SetControllerReference to fail.
	ownerCM := builders.NewConfigMap().WithName("test-owner").WithNamespace("default").Build()

	generator := func(_ *corev1.ConfigMap) runtime.Object {
		return builders.NewService().Build()
	}

	_, err := GenerateResource(cl, ownerCM, generator, GenerateOptions{
		SetControllerRef: true,
		IsClusterScoped:  false,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to set controller reference")
}

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
			name:    "convert ConfigMap",
			obj:     builders.NewConfigMap().WithName("test").Build(),
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

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.IsType(t, &unstructured.Unstructured{}, result)
		})
	}
}
