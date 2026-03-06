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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

func TestGenerateClusterRoleBinding(t *testing.T) {
	tests := []struct {
		name       string
		falco      *instancev1alpha1.Falco
		wantName   string
		wantLabels map[string]string
	}{
		{
			name:       "basic cluster role binding",
			falco:      builders.NewFalco().WithName("test-falco").WithNamespace("test-namespace").WithLabels(map[string]string{"app": "falco"}).Build(),
			wantName:   "test-falco--test-namespace",
			wantLabels: map[string]string{"app": "falco"},
		},
		{
			name: "cluster role binding with multiple labels",
			falco: builders.NewFalco().WithName("test-falco").WithNamespace("test-namespace").
				WithLabels(map[string]string{"app": "falco", "version": "v1", "env": "test"}).Build(),
			wantName:   "test-falco--test-namespace",
			wantLabels: map[string]string{"app": "falco", "version": "v1", "env": "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateClusterRoleBinding(tt.falco)
			require.NotNil(t, result)

			crb := result.(*rbacv1.ClusterRoleBinding)
			assert.Equal(t, tt.wantName, crb.Name)
			assert.Equal(t, "ClusterRoleBinding", crb.Kind)
			assert.Equal(t, "rbac.authorization.k8s.io/v1", crb.APIVersion)
			assert.Equal(t, tt.wantLabels, crb.Labels)

			require.Len(t, crb.Subjects, 1)
			assert.Equal(t, "ServiceAccount", crb.Subjects[0].Kind)
			assert.Equal(t, tt.falco.Name, crb.Subjects[0].Name)
			assert.Equal(t, tt.falco.Namespace, crb.Subjects[0].Namespace)

			assert.Equal(t, "ClusterRole", crb.RoleRef.Kind)
			assert.Equal(t, tt.wantName, crb.RoleRef.Name)
			assert.Equal(t, "rbac.authorization.k8s.io", crb.RoleRef.APIGroup)
		})
	}
}

func TestGenerateClusterRoleBindingViaGenerateResource(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, rbacv1.AddToScheme(scheme))
	require.NoError(t, instancev1alpha1.AddToScheme(scheme))

	falco := builders.NewFalco().WithName("test-falco").WithNamespace("test-namespace").Build()
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	opts := instance.GenerateOptions{SetControllerRef: false, IsClusterScoped: true}
	result, err := instance.GenerateResource(cl, falco, generateClusterRoleBinding, opts)
	require.NoError(t, err)

	expectedName := instance.GenerateUniqueName("test-falco", "test-namespace")
	assert.Equal(t, expectedName, result.GetName())
	assert.Equal(t, "ClusterRoleBinding", result.GetKind())
}

func TestEnsureClusterRoleBinding(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	falco := builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).Build()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(falco).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

	require.NoError(t, r.ensureClusterRoleBinding(context.Background(), falco))

	uniqueName := instance.GenerateUniqueName(falco.Name, falco.Namespace)
	crb := &rbacv1.ClusterRoleBinding{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKey{Name: uniqueName}, crb))
	assert.Equal(t, uniqueName, crb.Name)
	assert.Equal(t, "ClusterRole", crb.RoleRef.Kind)
	assert.Equal(t, uniqueName, crb.RoleRef.Name)
	require.Len(t, crb.Subjects, 1)
	assert.Equal(t, falco.Name, crb.Subjects[0].Name)
}
