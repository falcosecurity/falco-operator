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
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
)

func TestGenerateRole(t *testing.T) {
	tests := []struct {
		name       string
		falco      *instancev1alpha1.Falco
		wantLabels map[string]string
	}{
		{
			name:       "Role with labels",
			falco:      builders.NewFalco().WithName("test-falco").WithNamespace("default").WithLabels(map[string]string{"app": "falco"}).Build(),
			wantLabels: map[string]string{"app": "falco"},
		},
		{
			name:  "Role with nil labels",
			falco: builders.NewFalco().WithName("test-falco").WithNamespace("default").Build(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateRole(tt.falco)
			require.NotNil(t, result)

			role := result.(*rbacv1.Role)
			assert.Equal(t, tt.falco.Name, role.Name)
			assert.Equal(t, tt.falco.Namespace, role.Namespace)
			assert.Equal(t, tt.wantLabels, role.Labels)
			assert.Equal(t, "Role", role.Kind)
			assert.Equal(t, "rbac.authorization.k8s.io/v1", role.APIVersion)

			require.Len(t, role.Rules, 4)

			assert.Contains(t, role.Rules, rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list", "watch"},
			})

			assert.Contains(t, role.Rules, rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs:     []string{"create", "patch"},
			})

			assert.Contains(t, role.Rules, rbacv1.PolicyRule{
				APIGroups: []string{artifactv1alpha1.GroupVersion.Group},
				Resources: []string{"configs", "rulesfiles", "plugins"},
				Verbs:     []string{"get", "list", "watch", "update", "patch"},
			})

			assert.Contains(t, role.Rules, rbacv1.PolicyRule{
				APIGroups: []string{artifactv1alpha1.GroupVersion.Group},
				Resources: []string{"configs/status", "rulesfiles/status", "plugins/status"},
				Verbs:     []string{"get", "update", "patch"},
			})
		})
	}
}

func TestEnsureRole(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	falco := builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).Build()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(falco).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

	require.NoError(t, r.ensureRole(context.Background(), falco))

	role := &rbacv1.Role{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(falco), role))
	assert.Equal(t, falco.Name, role.Name)
	assert.NotEmpty(t, role.Rules)
}
