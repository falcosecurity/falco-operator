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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestClusterScopedResourceHandler(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		obj      client.Object
		expected []reconcile.Request
	}{
		{
			name: "ClusterRoleBinding with valid name",
			obj: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "falco-test--default",
				},
			},
			expected: []reconcile.Request{
				{
					NamespacedName: types.NamespacedName{
						Name:      "falco-test",
						Namespace: "default",
					},
				},
			},
		},
		{
			name: "ClusterRole with valid name",
			obj: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "falco-test--custom-ns",
				},
			},
			expected: []reconcile.Request{
				{
					NamespacedName: types.NamespacedName{
						Name:      "falco-test",
						Namespace: "custom-ns",
					},
				},
			},
		},
		{
			name: "ClusterRoleBinding with invalid name format",
			obj: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "invalid-name-format",
				},
			},
			expected: nil,
		},
		{
			name: "Unsupported resource type",
			obj: &rbacv1.Role{ // Using Role as an unsupported type
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-name--default",
				},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := clusterScopedResourceHandler(ctx, tt.obj)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClusterScopedResourceHandlerEdgeCases(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		obj      client.Object
		expected []reconcile.Request
	}{
		{
			name: "Empty name returns nil",
			obj: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "",
				},
			},
			expected: nil,
		},
		{
			name: "Name with only separator returns empty name and namespace",
			obj: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "--",
				},
			},
			expected: nil, // ParseUniqueName returns error for "--"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := clusterScopedResourceHandler(ctx, tt.obj)
			assert.Equal(t, tt.expected, result)
		})
	}
}
