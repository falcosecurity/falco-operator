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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
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
			obj:  builders.NewClusterRoleBinding().WithName("falco-test--default").Build(),
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
			obj:  builders.NewClusterRole().WithName("falco-test--custom-ns").Build(),
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
			name:     "ClusterRoleBinding with invalid name format",
			obj:      builders.NewClusterRoleBinding().WithName("invalid-name-format").Build(),
			expected: nil,
		},
		{
			name:     "Unsupported resource type",
			obj:      builders.NewRole().WithName("test-name--default").Build(),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClusterScopedResourceHandler(ctx, tt.obj)
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
			name:     "Empty name returns nil",
			obj:      builders.NewClusterRoleBinding().WithName("").Build(),
			expected: nil,
		},
		{
			name:     "Name with only separator returns nil",
			obj:      builders.NewClusterRoleBinding().WithName("--").Build(),
			expected: nil, // ParseUniqueName returns error for "--"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClusterScopedResourceHandler(ctx, tt.obj)
			assert.Equal(t, tt.expected, result)
		})
	}
}
