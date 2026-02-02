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
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

func TestGenerateRole(t *testing.T) {
	// Create a test scheme
	scheme := runtime.NewScheme()
	_ = rbacv1.AddToScheme(scheme)
	_ = instancev1alpha1.AddToScheme(scheme)

	tests := []struct {
		name    string
		falco   *instancev1alpha1.Falco
		wantErr bool
	}{
		{
			name: "successfully generate role",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
					Labels: map[string]string{
						"app": "falco",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fake client
			cl := fake.NewClientBuilder().WithScheme(scheme).Build()

			// Generate the role
			got, err := generateRole(cl, tt.falco)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, got)

			// Convert unstructured to Role
			role := &rbacv1.Role{}
			err = runtime.DefaultUnstructuredConverter.FromUnstructured(got.Object, role)
			assert.NoError(t, err)

			// Verify role properties
			assert.Equal(t, tt.falco.Name, role.Name)
			assert.Equal(t, tt.falco.Namespace, role.Namespace)
			assert.Equal(t, tt.falco.Labels, role.Labels)
			assert.Equal(t, "Role", role.Kind)
			assert.Equal(t, "rbac.authorization.k8s.io/v1", role.APIVersion)

			// Verify rules
			assert.Len(t, role.Rules, 2)

			// Verify configmaps rule
			assert.Contains(t, role.Rules, rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list"},
			})

			// Verify artifact rule
			assert.Contains(t, role.Rules, rbacv1.PolicyRule{
				APIGroups: []string{artifactv1alpha1.GroupVersion.Group},
				Resources: []string{"configs", "rulesfiles", "plugins"},
				Verbs:     []string{"get", "update", "list", "watch"},
			})
		})
	}
}

func TestGenerateRoleWithNilFalco(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = rbacv1.AddToScheme(scheme)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	_, err := generateRole(cl, nil)
	assert.Error(t, err)
}

func TestGenerateRoleWithNilClient(t *testing.T) {
	falco := &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-falco",
			Namespace: "default",
		},
	}

	_, err := generateRole(nil, falco)
	assert.Error(t, err)
}
