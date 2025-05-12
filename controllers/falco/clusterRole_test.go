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
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

func TestGenerateClusterRole(t *testing.T) {
	// Create a fake client with the necessary schemes
	scheme := runtime.NewScheme()
	require.NoError(t, rbacv1.AddToScheme(scheme))
	require.NoError(t, instancev1alpha1.AddToScheme(scheme))

	tests := []struct {
		name    string
		falco   *instancev1alpha1.Falco
		verify  func(*testing.T, *unstructured.Unstructured)
		wantErr bool
	}{
		{
			name: "Basic ClusterRole creation",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
					Labels: map[string]string{
						"app": "falco",
					},
				},
			},
			verify: func(t *testing.T, obj *unstructured.Unstructured) {
				assert.Equal(t, "ClusterRole", obj.GetKind())
				assert.Equal(t, "rbac.authorization.k8s.io/v1", obj.GetAPIVersion())
				assert.Equal(t, "test-falco--default", obj.GetName())
				assert.Equal(t, map[string]string{"app": "falco"}, obj.GetLabels())

				// Verify rules
				rules, found, err := unstructured.NestedSlice(obj.Object, "rules")
				require.NoError(t, err)
				require.True(t, found)
				require.Len(t, rules, 2)

				// Check first rule (nodes)
				rule0 := rules[0].(map[string]interface{})
				assert.Equal(t, []interface{}{""}, rule0["apiGroups"])
				assert.Equal(t, []interface{}{"nodes"}, rule0["resources"])
				assert.Equal(t, []interface{}{"get", "list", "watch"}, rule0["verbs"])

				// Check second rule (RBAC)
				rule1 := rules[1].(map[string]interface{})
				assert.Equal(t, []interface{}{"rbac.authorization.k8s.io"}, rule1["apiGroups"])
				assert.Equal(t, []interface{}{"clusterroles", "clusterrolebindings"}, rule1["resources"])
				assert.Equal(t, []interface{}{"get", "list", "watch"}, rule1["verbs"])
			},
			wantErr: false,
		},
		{
			name: "ClusterRole with empty namespace",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-falco",
				},
			},
			verify: func(t *testing.T, obj *unstructured.Unstructured) {
				assert.Equal(t, "test-falco--", obj.GetName())
			},
			wantErr: false,
		},
		{
			name: "ClusterRole with no labels",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
				},
			},
			verify: func(t *testing.T, obj *unstructured.Unstructured) {
				labels := obj.GetLabels()
				assert.Empty(t, labels)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new client for each test
			cl := fake.NewClientBuilder().WithScheme(scheme).Build()

			// Execute the function
			obj, err := generateClusterRole(context.Background(), cl, tt.falco)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, obj)

			// Run the verification function
			tt.verify(t, obj)
		})
	}
}

// TestGenerateClusterRoleErrors tests error scenarios.
func TestGenerateClusterRoleErrors(t *testing.T) {
	// Create a failing client that always returns an error
	failingClient := &mockFailingClient{}

	falco := &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-falco",
			Namespace: "default",
		},
	}

	_, err := generateClusterRole(context.Background(), failingClient, falco)
	assert.Error(t, err)
}

// mockFailingClient implements client.Client and always returns errors.
type mockFailingClient struct {
	client.Client
}

func (m *mockFailingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	return fmt.Errorf("mock error")
}

func (m *mockFailingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	return fmt.Errorf("mock error")
}
