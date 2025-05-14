// Copyright (C) 2025 The Falco Authors
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

package falco

import (
	"context"
	"fmt"
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

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

func TestGenerateResourceFromFalcoInstance(t *testing.T) {
	// Create a test scheme.
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, rbacv1.AddToScheme(scheme))
	require.NoError(t, instancev1alpha1.AddToScheme(scheme))

	tests := []struct {
		name           string
		falco          *instancev1alpha1.Falco
		generator      resourceGenerator
		options        generateOptions
		mockClient     client.Client
		expectedError  string
		validateResult func(*testing.T, *unstructured.Unstructured)
	}{
		{
			name:  "nil falco instance",
			falco: nil,
			generator: func(falco *instancev1alpha1.Falco) (runtime.Object, error) {
				return nil, nil
			},
			options:       generateOptions{},
			mockClient:    fake.NewClientBuilder().WithScheme(scheme).Build(),
			expectedError: "falco instance cannot be nil",
		},
		{
			name: "generator error",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
				},
			},
			generator: func(falco *instancev1alpha1.Falco) (runtime.Object, error) {
				return nil, fmt.Errorf("generator error")
			},
			options:       generateOptions{},
			mockClient:    fake.NewClientBuilder().WithScheme(scheme).Build(),
			expectedError: "failed to generate resource: generator error",
		},
		{
			name: "successful namespaced resource generation",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
					Labels: map[string]string{
						"app": "falco",
					},
				},
			},
			generator: func(falco *instancev1alpha1.Falco) (runtime.Object, error) {
				return &corev1.Service{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Service",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Labels:    falco.Labels,
						Name:      falco.Name,
						Namespace: falco.Namespace,
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Port: 8080,
							},
						},
					},
				}, nil
			},
			options: generateOptions{
				setControllerRef: true,
				isClusterScoped:  false,
			},
			mockClient: fake.NewClientBuilder().WithScheme(scheme).Build(),
			validateResult: func(t *testing.T, obj *unstructured.Unstructured) {
				assert.Equal(t, "Service", obj.GetKind())
				assert.Equal(t, "v1", obj.GetAPIVersion())
				assert.Equal(t, "test-falco", obj.GetName())
				assert.Equal(t, map[string]string{"app": "falco"}, obj.GetLabels())
			},
		},
		{
			name: "successful cluster-scoped resource generation",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
					Labels: map[string]string{
						"app": "falco",
					},
				},
			},
			generator: func(falco *instancev1alpha1.Falco) (runtime.Object, error) {
				return &rbacv1.ClusterRole{
					TypeMeta: metav1.TypeMeta{
						Kind:       "ClusterRole",
						APIVersion: "rbac.authorization.k8s.io/v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:   GenerateUniqueName(falco.Name, falco.Namespace),
						Labels: falco.Labels,
					},
				}, nil
			},
			options: generateOptions{
				setControllerRef: false,
				isClusterScoped:  true,
			},
			mockClient: fake.NewClientBuilder().WithScheme(scheme).Build(),
			validateResult: func(t *testing.T, obj *unstructured.Unstructured) {
				assert.Equal(t, "ClusterRole", obj.GetKind())
				assert.Equal(t, "rbac.authorization.k8s.io/v1", obj.GetAPIVersion())
				assert.Equal(t, "test-falco--default", obj.GetName())
				assert.Equal(t, map[string]string{"app": "falco"}, obj.GetLabels())
			},
		},
		{
			name: "client error during default value setting",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
				},
			},
			generator: func(falco *instancev1alpha1.Falco) (runtime.Object, error) {
				return &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      falco.Name,
						Namespace: falco.Namespace,
					},
				}, nil
			},
			options: generateOptions{
				setControllerRef: true,
				isClusterScoped:  false,
			},
			mockClient:    newMockFailingClient(),
			expectedError: "failed to set default values: failed to set default values by dry-run creating the object : mock error",
		},
		{
			name: "set controller reference fails",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
					// Namespace intentionally isn't set to trigger the error.
				},
			},
			generator: func(falco *instancev1alpha1.Falco) (runtime.Object, error) {
				return &corev1.Service{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Service",
						APIVersion: "v1",
					},
				}, nil
			},
			options: generateOptions{
				setControllerRef: true,
				isClusterScoped:  false,
			},
			mockClient:    fake.NewClientBuilder().WithScheme(scheme).Build(),
			expectedError: "failed to set controller reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := generateResourceFromFalcoInstance(
				context.Background(),
				tt.mockClient,
				tt.falco,
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

func TestSetDefaultValues(t *testing.T) {
	tests := []struct {
		name        string
		obj         *unstructured.Unstructured
		mockClient  client.Client
		expectError bool
		errorMsg    string
	}{
		{
			name: "successful default values setting",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Service",
					"metadata":   map[string]interface{}{},
				},
			},
			mockClient:  fake.NewClientBuilder().Build(),
			expectError: false,
		},
		{
			name: "error setting generateName field",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": 123,
				},
			},
			mockClient:  fake.NewClientBuilder().Build(),
			expectError: true,
			errorMsg:    "failed to set generateName field",
		},
		{
			name: "error setting name field",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": 123, // Invalid type for metadata field
				},
			},
			mockClient:  fake.NewClientBuilder().Build(),
			expectError: true,
			errorMsg:    "failed to set generateName field: ",
		},
		{
			name: "error in dry-run create",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Service",
					"metadata":   map[string]interface{}{},
				},
			},
			mockClient:  newMockFailingClient(),
			expectError: true,
			errorMsg:    "failed to set default values by dry-run creating the object",
		},
		{
			name:        "nil object",
			obj:         nil,
			mockClient:  newMockFailingClient(),
			expectError: true,
			errorMsg:    "unstructured object cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := setDefaultValues(context.Background(), tt.mockClient, tt.obj)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)

				// Verify the fields were set correctly
				generateName, _, err := unstructured.NestedString(tt.obj.Object, "metadata", "generateName")
				require.NoError(t, err)
				assert.Equal(t, "dry-run", generateName)

				name, _, err := unstructured.NestedString(tt.obj.Object, "metadata", "name")
				require.NoError(t, err)
				assert.Equal(t, "", name)
			}
		})
	}
}

func TestRemoveUnwantedFields(t *testing.T) {
	tests := []struct {
		name     string
		obj      *unstructured.Unstructured
		expected map[string]interface{}
	}{
		{
			name: "removes all unwanted fields",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"name":              "test",
						"uid":               "123",
						"resourceVersion":   "1",
						"managedFields":     []interface{}{},
						"creationTimestamp": "2023-01-01T00:00:00Z",
						"generateName":      "test-",
						"generation":        1,
						"annotations": map[string]interface{}{
							"deployment.kubernetes.io/revision":        "1",
							"deprecated.daemonset.template.generation": "2",
							"should-remain": "true",
						},
					},
					"spec": map[string]interface{}{
						"template": map[string]interface{}{
							"metadata": map[string]interface{}{
								"creationTimestamp": "2023-01-01T00:00:00Z",
							},
						},
						"revisionHistoryLimit": 10,
					},
					"status": map[string]interface{}{
						"replicas": 1,
					},
				},
			},
			expected: map[string]interface{}{
				"metadata": map[string]interface{}{
					"name": "test",
					"annotations": map[string]interface{}{
						"should-remain": "true",
					},
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"metadata": map[string]interface{}{},
					},
				},
			},
		},
		{
			name: "removes empty annotations",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"name": "test",
						"annotations": map[string]interface{}{
							"deployment.kubernetes.io/revision":        "1",
							"deprecated.daemonset.template.generation": "2",
						},
					},
				},
			},
			expected: map[string]interface{}{
				"metadata": map[string]interface{}{
					"name": "test",
				},
			},
		},
		{
			name: "removes service specific fields",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Service",
					"metadata": map[string]interface{}{
						"name": "test",
					},
					"spec": map[string]interface{}{
						"clusterIP":  "10.0.0.1",
						"clusterIPs": []string{"10.0.0.1"},
						"ports":      []interface{}{map[string]interface{}{"port": 80}},
					},
				},
			},
			expected: map[string]interface{}{
				"kind": "Service",
				"metadata": map[string]interface{}{
					"name": "test",
				},
				"spec": map[string]interface{}{
					"ports": []interface{}{map[string]interface{}{"port": 80}},
				},
			},
		},
		{
			name: "handles missing fields gracefully",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"name": "test",
					},
				},
			},
			expected: map[string]interface{}{
				"metadata": map[string]interface{}{
					"name": "test",
				},
			},
		},
		{
			name: "handles non-map metadata",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": "invalid",
				},
			},
			expected: map[string]interface{}{
				"metadata": "invalid",
			},
		},
		{
			name: "handles non-map annotations",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"name":        "test",
						"annotations": "invalid",
					},
				},
			},
			expected: map[string]interface{}{
				"metadata": map[string]interface{}{
					"name":        "test",
					"annotations": "invalid",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			removeUnwantedFields(tt.obj)
			assert.Equal(t, tt.expected, tt.obj.Object)
		})
	}
}
