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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

func TestGenerateClusterRole(t *testing.T) {
	tests := []struct {
		name       string
		falco      *instancev1alpha1.Falco
		wantName   string
		wantLabels map[string]string
	}{
		{
			name: "basic ClusterRole creation",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
					Labels:    map[string]string{"app": "falco"},
				},
			},
			wantName:   "test-falco--default",
			wantLabels: map[string]string{"app": "falco"},
		},
		{
			name: "ClusterRole with empty namespace",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-falco",
				},
			},
			wantName: "test-falco--",
		},
		{
			name: "ClusterRole propagates nil labels correctly",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
				},
			},
			wantName: "test-falco--default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateClusterRole(tt.falco)
			require.NotNil(t, result)

			cr := result.(*rbacv1.ClusterRole)
			assert.Equal(t, tt.wantName, cr.Name)
			assert.Equal(t, "ClusterRole", cr.Kind)
			assert.Equal(t, "rbac.authorization.k8s.io/v1", cr.APIVersion)
			assert.Equal(t, tt.wantLabels, cr.Labels)

			require.Len(t, cr.Rules, 1)
			assert.Equal(t, []string{""}, cr.Rules[0].APIGroups)
			assert.Equal(t, []string{"nodes"}, cr.Rules[0].Resources)
			assert.Equal(t, []string{"get", "list", "watch"}, cr.Rules[0].Verbs)
		})
	}
}

func TestGenerateClusterRoleViaGenerateResource(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, rbacv1.AddToScheme(scheme))
	require.NoError(t, instancev1alpha1.AddToScheme(scheme))

	falco := &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{Name: "test-falco", Namespace: "default"},
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	result, err := instance.GenerateResource(cl, falco, generateClusterRole, instance.GenerateOptions{SetControllerRef: false, IsClusterScoped: true})
	require.NoError(t, err)

	expectedName := instance.GenerateUniqueName("test-falco", "default")
	assert.Equal(t, expectedName, result.GetName())
	assert.Equal(t, "ClusterRole", result.GetKind())
}

func TestEnsureClusterRole(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	falco := newFalco()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(falco).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

	require.NoError(t, r.ensureClusterRole(context.Background(), falco))

	cr := &rbacv1.ClusterRole{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKey{Name: instance.GenerateUniqueName(falco.Name, falco.Namespace)}, cr))
	assert.Equal(t, instance.GenerateUniqueName(falco.Name, falco.Namespace), cr.Name)
	assert.NotEmpty(t, cr.Rules)
	assert.Equal(t, []string{""}, cr.Rules[0].APIGroups)
}
