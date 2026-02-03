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

package managedfields

import (
	"testing"

	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestDeriveSchemaName(t *testing.T) {
	tests := []struct {
		name     string
		group    string
		version  string
		kind     string
		expected string
	}{
		{
			name:     "core resource",
			group:    "",
			version:  "v1",
			kind:     "ConfigMap",
			expected: "io.k8s.api.core.v1.ConfigMap",
		},
		{
			name:     "apps resource",
			group:    "apps",
			version:  "v1",
			kind:     "DaemonSet",
			expected: "io.k8s.api.apps.v1.DaemonSet",
		},
		{
			name:     "rbac resource",
			group:    "rbac.authorization.k8s.io",
			version:  "v1",
			kind:     "Role",
			expected: "io.k8s.api.rbac.v1.Role",
		},
		{
			name:     "networking resource",
			group:    "networking.k8s.io",
			version:  "v1",
			kind:     "NetworkPolicy",
			expected: "io.k8s.api.networking.v1.NetworkPolicy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deriveSchemaName(tt.group, tt.version, tt.kind)
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
			name:     "apps group",
			apiGroup: "apps",
			expected: "apps",
		},
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
			name:     "batch group",
			apiGroup: "batch",
			expected: "batch",
		},
		{
			name:     "unknown group extracts first part",
			apiGroup: "custom.example.com",
			expected: "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := apiGroupToSchemaGroup(tt.apiGroup)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetObjectType(t *testing.T) {
	tests := []struct {
		name    string
		obj     runtime.Object
		wantErr bool
	}{
		{
			name: "ConfigMap",
			obj: &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
			},
			wantErr: false,
		},
		{
			name: "DaemonSet",
			obj: &appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "apps/v1",
					Kind:       "DaemonSet",
				},
			},
			wantErr: false,
		},
		{
			name: "Deployment",
			obj: &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
				},
			},
			wantErr: false,
		},
		{
			name: "Role",
			obj: &rbacv1.Role{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "Role",
				},
			},
			wantErr: false,
		},
		{
			name: "Service",
			obj: &corev1.Service{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Service",
				},
			},
			wantErr: false,
		},
		{
			name: "ServiceAccount",
			obj: &corev1.ServiceAccount{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "ServiceAccount",
				},
			},
			wantErr: false,
		},
		{
			name: "Unstructured with valid type",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
				},
			},
			wantErr: false,
		},
		{
			name: "object without kind",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
				},
			},
			wantErr: true,
		},
		{
			name: "unknown type",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "unknown.example.com/v1",
					"kind":       "UnknownKind",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetObjectType(tt.obj)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
