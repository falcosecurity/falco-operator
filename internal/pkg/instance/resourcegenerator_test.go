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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGenerateResource(t *testing.T) {
	// Create a test scheme with ConfigMap as owner (implements client.Object).
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, rbacv1.AddToScheme(scheme))

	tests := []struct {
		name           string
		obj            *corev1.ConfigMap
		generator      ResourceGenerator[*corev1.ConfigMap]
		options        GenerateOptions
		mockClient     client.Client
		expectedError  string
		validateResult func(*testing.T, *unstructured.Unstructured)
	}{
		{
			name: "nil instance",
			obj:  nil,
			generator: func(_ *corev1.ConfigMap) runtime.Object {
				return nil
			},
			options:       GenerateOptions{},
			mockClient:    fake.NewClientBuilder().WithScheme(scheme).Build(),
			expectedError: "instance cannot be nil",
		},
		{
			name: "nil client",
			obj: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
			},
			generator: func(_ *corev1.ConfigMap) runtime.Object {
				return nil
			},
			options:       GenerateOptions{},
			mockClient:    nil,
			expectedError: "client cannot be nil",
		},
		{
			name: "nil generator function",
			obj: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
			},
			generator:     nil,
			options:       GenerateOptions{},
			mockClient:    fake.NewClientBuilder().WithScheme(scheme).Build(),
			expectedError: "generator function cannot be nil",
		},
		{
			name: "successful namespaced resource generation",
			obj: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-owner",
					Namespace: "default",
					UID:       "test-uid",
					Labels:    map[string]string{"app": "test"},
				},
			},
			generator: func(cm *corev1.ConfigMap) runtime.Object {
				return &corev1.Service{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Service",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Labels:    cm.Labels,
						Namespace: cm.Namespace,
					},
				}
			},
			options: GenerateOptions{
				SetControllerRef: true,
				IsClusterScoped:  false,
			},
			mockClient: fake.NewClientBuilder().WithScheme(scheme).Build(),
			validateResult: func(t *testing.T, obj *unstructured.Unstructured) {
				assert.Equal(t, "Service", obj.GetKind())
				assert.Equal(t, "v1", obj.GetAPIVersion())
				assert.Equal(t, "test-owner", obj.GetName())
				assert.Equal(t, map[string]string{"app": "test"}, obj.GetLabels())
			},
		},
		{
			name: "successful cluster-scoped resource generation",
			obj: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-owner",
					Namespace: "default",
					Labels:    map[string]string{"app": "test"},
				},
			},
			generator: func(cm *corev1.ConfigMap) runtime.Object {
				return &rbacv1.ClusterRole{
					TypeMeta: metav1.TypeMeta{
						Kind:       "ClusterRole",
						APIVersion: "rbac.authorization.k8s.io/v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:   GenerateUniqueName(cm.Name, cm.Namespace),
						Labels: cm.Labels,
					},
				}
			},
			options: GenerateOptions{
				SetControllerRef: false,
				IsClusterScoped:  true,
			},
			mockClient: fake.NewClientBuilder().WithScheme(scheme).Build(),
			validateResult: func(t *testing.T, obj *unstructured.Unstructured) {
				assert.Equal(t, "ClusterRole", obj.GetKind())
				assert.Equal(t, "rbac.authorization.k8s.io/v1", obj.GetAPIVersion())
				assert.Equal(t, "test-owner--default", obj.GetName())
				assert.Equal(t, map[string]string{"app": "test"}, obj.GetLabels())
			},
		},
		{
			name: "set controller reference fails",
			obj: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-owner",
					Namespace: "default",
				},
			},
			generator: func(_ *corev1.ConfigMap) runtime.Object {
				// Return a Service without TypeMeta — SetControllerReference
				// will fail because the owner (ConfigMap) has no UID.
				return &corev1.Service{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Service",
						APIVersion: "v1",
					},
				}
			},
			options: GenerateOptions{
				SetControllerRef: true,
				IsClusterScoped:  false,
			},
			mockClient:    fake.NewClientBuilder().WithScheme(scheme).Build(),
			expectedError: "failed to set controller reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GenerateResource(
				tt.mockClient,
				tt.obj,
				tt.generator,
				tt.options,
			)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)

			if tt.validateResult != nil {
				tt.validateResult(t, result)
			}
		})
	}
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
			name: "convert ConfigMap",
			obj: &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
			},
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
