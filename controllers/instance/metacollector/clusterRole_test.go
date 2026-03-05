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

package metacollector

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
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

func TestGenerateClusterRole(t *testing.T) {
	tests := []struct {
		name       string
		mc         *instancev1alpha1.Metacollector
		wantName   string
		wantLabels map[string]string
	}{
		{
			name: "basic ClusterRole creation",
			mc: &instancev1alpha1.Metacollector{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-mc",
					Namespace: "default",
					Labels:    map[string]string{"app": "metacollector"},
				},
			},
			wantName:   "test-mc--default",
			wantLabels: map[string]string{"app": "metacollector"},
		},
		{
			name: "ClusterRole propagates nil labels correctly",
			mc: &instancev1alpha1.Metacollector{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-mc",
					Namespace: "default",
				},
			},
			wantName: "test-mc--default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateClusterRole(tt.mc)
			require.NotNil(t, result)

			cr := result.(*rbacv1.ClusterRole)
			assert.Equal(t, tt.wantName, cr.Name)
			assert.Equal(t, "ClusterRole", cr.Kind)
			assert.Equal(t, "rbac.authorization.k8s.io/v1", cr.APIVersion)
			assert.Equal(t, tt.wantLabels, cr.Labels)

			require.Len(t, cr.Rules, 3)

			assert.Equal(t, []string{"apps"}, cr.Rules[0].APIGroups)
			assert.Contains(t, cr.Rules[0].Resources, "deployments")

			assert.Equal(t, []string{""}, cr.Rules[1].APIGroups)
			assert.Contains(t, cr.Rules[1].Resources, "pods")

			assert.Equal(t, []string{"discovery.k8s.io"}, cr.Rules[2].APIGroups)
			assert.Contains(t, cr.Rules[2].Resources, "endpointslices")
		})
	}
}

func TestEnsureClusterRole(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	mc := newMetacollector(withName("test-mc"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mc).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

	require.NoError(t, r.ensureClusterRole(context.Background(), mc))

	cr := &rbacv1.ClusterRole{}
	expectedName := instance.GenerateUniqueName(mc.Name, mc.Namespace)
	require.NoError(t, cl.Get(context.Background(), client.ObjectKey{Name: expectedName}, cr))
	assert.Equal(t, expectedName, cr.Name)
	require.NotEmpty(t, cr.Rules)

	foundAppsRule := false
	foundCoreRule := false
	foundDiscoveryRule := false
	for _, rule := range cr.Rules {
		for _, group := range rule.APIGroups {
			switch group {
			case "apps":
				foundAppsRule = true
				assert.Contains(t, rule.Resources, "deployments")
				assert.Contains(t, rule.Verbs, "get")
				assert.Contains(t, rule.Verbs, "list")
				assert.Contains(t, rule.Verbs, "watch")
			case "":
				foundCoreRule = true
				assert.Contains(t, rule.Resources, "pods")
			case "discovery.k8s.io":
				foundDiscoveryRule = true
				assert.Contains(t, rule.Resources, "endpointslices")
			}
		}
	}
	assert.True(t, foundAppsRule, "ClusterRole should have apps API group rule")
	assert.True(t, foundCoreRule, "ClusterRole should have core API group rule")
	assert.True(t, foundDiscoveryRule, "ClusterRole should have discovery.k8s.io API group rule")
}
