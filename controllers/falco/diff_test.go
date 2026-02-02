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

package falco

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestGetTypePath(t *testing.T) {
	tests := []struct {
		name     string
		obj      *unstructured.Unstructured
		expected string
	}{
		{
			name: "core resource",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
				},
			},
			expected: "io.k8s.api.core.v1.ConfigMap",
		},
		{
			name: "rbac resource",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "rbac.authorization.k8s.io/v1",
					"kind":       "Role",
				},
			},
			expected: "io.k8s.api.rbac.v1.Role",
		},
		{
			name: "networking resource",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "networking.k8s.io/v1",
					"kind":       "NetworkPolicy",
				},
			},
			expected: "io.k8s.api.networking.v1.NetworkPolicy",
		},
		{
			name: "custom resource",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "custom.example.com/v1",
					"kind":       "Custom",
				},
			},
			expected: "io.k8s.api.custom.example.com.v1.Custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getTypePath(tt.obj)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestApiGroupToSchemaGroup(t *testing.T) {
	tests := []struct {
		name     string
		apiGroup string
		expected string
	}{
		{
			name:     "rbac group",
			apiGroup: "rbac.authorization.k8s.io",
			expected: "rbac",
		},
		{
			name:     "networking group",
			apiGroup: "networking.k8s.io",
			expected: "networking",
		},
		{
			name:     "unmapped group",
			apiGroup: "custom.example.com",
			expected: "custom.example.com",
		},
		{
			name:     "empty group",
			apiGroup: "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := apiGroupToSchemaGroup(tt.apiGroup)
			assert.Equal(t, tt.expected, result)
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

func TestDiff(t *testing.T) {
	tests := []struct {
		name    string
		current interface{}
		desired interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "same objects",
			current: &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Data: map[string]string{
					"key": "value",
				},
			},
			desired: &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Data: map[string]string{
					"key": "value",
				},
			},
			wantErr: false,
		},
		{
			name: "different objects",
			current: &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Data: map[string]string{
					"key": "value1",
				},
			},
			desired: &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Data: map[string]string{
					"key": "value2",
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid current object",
			current: make(chan int),
			desired: &corev1.ConfigMap{},
			wantErr: true,
			errMsg:  "failed to convert current object to unstructured",
		},
		{
			name:    "invalid desired object",
			current: &corev1.ConfigMap{},
			desired: make(chan int),
			wantErr: true,
			errMsg:  "failed to convert desired object to unstructured",
		},
		{
			name: "parser fails for unknown type - current object",
			current: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "unknown.group/v1",
					"kind":       "UnknownKind",
					"metadata": map[string]interface{}{
						"name": "test",
					},
				},
			},
			desired: &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
			},
			wantErr: true,
			errMsg:  "schema error: no type found matching: io.k8s.api.unknown.group.v1.UnknownKind",
		},
		{
			name: "parser fails for unknown type - desired object",
			current: &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
			},
			desired: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "unknown.group/v1",
					"kind":       "UnknownKind",
					"metadata": map[string]interface{}{
						"name": "test",
					},
				},
			},
			wantErr: true,
			errMsg:  "schema error: no type found matching: io.k8s.api.unknown.group.v1.UnknownKind",
		},
		{
			name: "parser fails for mismatched types",
			current: &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
			},
			desired: &corev1.Secret{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Secret",
				},
			},
			wantErr: true,
			errMsg:  "expected objects of the same type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := diff(tt.current, tt.desired)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, result)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}
