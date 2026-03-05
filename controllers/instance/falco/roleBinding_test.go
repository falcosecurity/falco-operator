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
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
)

func TestGenerateRoleBinding(t *testing.T) {
	tests := []struct {
		name       string
		falco      *instancev1alpha1.Falco
		wantLabels map[string]string
	}{
		{
			name: "basic role binding",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
					Labels:    map[string]string{"app": "falco"},
				},
			},
			wantLabels: map[string]string{"app": "falco"},
		},
		{
			name: "role binding with custom labels",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
					Labels:    map[string]string{"app": "falco", "environment": "test", "custom": "label"},
				},
			},
			wantLabels: map[string]string{"app": "falco", "environment": "test", "custom": "label"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateRoleBinding(tt.falco)
			require.NotNil(t, result)

			rb := result.(*rbacv1.RoleBinding)
			assert.Equal(t, tt.falco.Namespace, rb.Namespace)
			assert.Equal(t, tt.wantLabels, rb.Labels)
			assert.Equal(t, "RoleBinding", rb.Kind)
			assert.Equal(t, "rbac.authorization.k8s.io/v1", rb.APIVersion)

			assert.Equal(t, "Role", rb.RoleRef.Kind)
			assert.Equal(t, "rbac.authorization.k8s.io", rb.RoleRef.APIGroup)
			assert.Equal(t, tt.falco.Name, rb.RoleRef.Name)

			require.Len(t, rb.Subjects, 1)
			assert.Equal(t, "ServiceAccount", rb.Subjects[0].Kind)
			assert.Equal(t, tt.falco.Name, rb.Subjects[0].Name)
			assert.Equal(t, tt.falco.Namespace, rb.Subjects[0].Namespace)
		})
	}
}

func TestEnsureRoleBinding(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	falco := newFalco()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(falco).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

	require.NoError(t, r.ensureRoleBinding(context.Background(), falco))

	rbList := &rbacv1.RoleBindingList{}
	require.NoError(t, cl.List(context.Background(), rbList, client.InNamespace(falco.Namespace)))
	require.Len(t, rbList.Items, 1)

	rb := rbList.Items[0]
	assert.Equal(t, "Role", rb.RoleRef.Kind)
	assert.Equal(t, falco.Name, rb.RoleRef.Name)
	require.Len(t, rb.Subjects, 1)
	assert.Equal(t, falco.Name, rb.Subjects[0].Name)
}
