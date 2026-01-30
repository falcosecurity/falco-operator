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
	"testing"

	"github.com/stretchr/testify/assert"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

func TestGenerateRoleBinding(t *testing.T) {
	// Create a test scheme.
	scheme := runtime.NewScheme()
	_ = rbacv1.AddToScheme(scheme)
	_ = instancev1alpha1.AddToScheme(scheme)

	tests := []struct {
		name    string
		falco   *instancev1alpha1.Falco
		wantErr bool
	}{
		{
			name: "successfully generate role binding",
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
		{
			name:    "nil falco instance",
			falco:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fake client
			cl := fake.NewClientBuilder().WithScheme(scheme).Build()

			// Generate the role binding
			got, err := generateRoleBinding(cl, tt.falco)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, got)

			// Convert unstructured to RoleBinding
			roleBinding := &rbacv1.RoleBinding{}
			err = runtime.DefaultUnstructuredConverter.FromUnstructured(got.Object, roleBinding)
			assert.NoError(t, err)

			// Verify role binding properties
			assert.Equal(t, tt.falco.Name, roleBinding.Name)
			assert.Equal(t, tt.falco.Namespace, roleBinding.Namespace)
			assert.Equal(t, tt.falco.Labels, roleBinding.Labels)
			assert.Equal(t, "RoleBinding", roleBinding.Kind)
			assert.Equal(t, "rbac.authorization.k8s.io/v1", roleBinding.APIVersion)

			// Verify role ref
			assert.Equal(t, "Role", roleBinding.RoleRef.Kind)
			assert.Equal(t, "rbac.authorization.k8s.io", roleBinding.RoleRef.APIGroup)
			assert.Equal(t, tt.falco.Name, roleBinding.RoleRef.Name)

			// Verify subjects
			assert.Len(t, roleBinding.Subjects, 1)
			subject := roleBinding.Subjects[0]
			assert.Equal(t, "ServiceAccount", subject.Kind)
			assert.Equal(t, tt.falco.Name, subject.Name)
			assert.Equal(t, tt.falco.Namespace, subject.Namespace)
		})
	}
}

func TestGenerateRoleBindingWithNilClient(t *testing.T) {
	falco := &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-falco",
			Namespace: "default",
		},
	}

	_, err := generateRoleBinding(nil, falco)
	assert.Error(t, err)
}

func TestGenerateRoleBindingCustomLabels(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = rbacv1.AddToScheme(scheme)
	_ = instancev1alpha1.AddToScheme(scheme)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	customLabels := map[string]string{
		"app":         "falco",
		"environment": "test",
		"custom":      "label",
	}

	falco := &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-falco",
			Namespace: "default",
			Labels:    customLabels,
		},
	}

	got, err := generateRoleBinding(cl, falco)
	assert.NoError(t, err)
	assert.NotNil(t, got)

	roleBinding := &rbacv1.RoleBinding{}
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(got.Object, roleBinding)
	assert.NoError(t, err)

	// Verify custom labels are properly set
	assert.Equal(t, customLabels, roleBinding.Labels)
}
