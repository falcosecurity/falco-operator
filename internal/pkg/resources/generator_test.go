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

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	testName      = "test-instance"
	testNamespace = "test-namespace"
)

var testLabels = map[string]string{"app": "test", "env": "dev"}

func testObject() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testName,
			Namespace: testNamespace,
			Labels:    testLabels,
		},
	}
}

func TestGenerateServiceAccount(t *testing.T) {
	obj := testObject()
	sa := GenerateServiceAccount(obj).(*corev1.ServiceAccount)

	assert.Equal(t, testName, sa.Name)
	assert.Equal(t, testNamespace, sa.Namespace)
	assert.Equal(t, testLabels, sa.Labels)
}

func TestGenerateService(t *testing.T) {
	tests := []struct {
		name          string
		defs          *InstanceDefaults
		wantPortCount int
	}{
		{
			name:          "falco service has 1 port",
			defs:          FalcoDefaults,
			wantPortCount: 1,
		},
		{
			name:          "metacollector service has 3 ports",
			defs:          MetacollectorDefaults,
			wantPortCount: 3,
		},
		{
			name:          "falcosidekick service has 1 port on 2801",
			defs:          FalcosidekickDefaults,
			wantPortCount: 1,
		},
		{
			name:          "falcosidekick-ui service has 1 port on 2802",
			defs:          FalcosidekickUIDefaults,
			wantPortCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := testObject()
			svc := GenerateService(obj, tt.defs).(*corev1.Service)

			assert.Equal(t, testName, svc.Name)
			assert.Equal(t, testNamespace, svc.Namespace)
			assert.Equal(t, testLabels, svc.Labels)
			assert.Equal(t, corev1.ServiceTypeClusterIP, svc.Spec.Type)
			assert.Equal(t, forgeSelectorLabels(testName), svc.Spec.Selector)
			require.Len(t, svc.Spec.Ports, tt.wantPortCount)
			for _, expectedPort := range tt.defs.ServicePorts {
				var found bool
				for _, actualPort := range svc.Spec.Ports {
					if actualPort.Name != expectedPort.Name {
						continue
					}
					assert.Equal(t, expectedPort.Port, actualPort.Port, "port %s should have correct port number", expectedPort.Name)
					assert.Equal(t, expectedPort.Protocol, actualPort.Protocol, "port %s should have correct protocol", expectedPort.Name)
					assert.Equal(t, expectedPort.TargetPort, actualPort.TargetPort, "port %s should have correct target port", expectedPort.Name)
					found = true
					break
				}
				assert.True(t, found, "expected port %s not found in service", expectedPort.Name)
			}
		})
	}
}

func TestGenerateClusterRole(t *testing.T) {
	tests := []struct {
		name          string
		defs          *InstanceDefaults
		wantRuleCount int
	}{
		{
			name:          "falco cluster role has 1 rule",
			defs:          FalcoDefaults,
			wantRuleCount: 1,
		},
		{
			name:          "metacollector cluster role has 3 rules",
			defs:          MetacollectorDefaults,
			wantRuleCount: 3,
		},
		{
			name:          "falcosidekick cluster role has 0 rules",
			defs:          FalcosidekickDefaults,
			wantRuleCount: 0,
		},
		{
			name:          "falcosidekick-ui cluster role has 0 rules",
			defs:          FalcosidekickUIDefaults,
			wantRuleCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := testObject()
			cr := GenerateClusterRole(obj, tt.defs).(*rbacv1.ClusterRole)

			wantName := GenerateUniqueName(testName, testNamespace)
			assert.Equal(t, wantName, cr.Name)
			assert.Equal(t, testLabels, cr.Labels)
			require.Len(t, cr.Rules, tt.wantRuleCount)
			// Verify rules match defaults exactly.
			for i, expectedRule := range tt.defs.ClusterRoleRules {
				assert.Equal(t, expectedRule.APIGroups, cr.Rules[i].APIGroups, "rule %d APIGroups", i)
				assert.Equal(t, expectedRule.Resources, cr.Rules[i].Resources, "rule %d Resources", i)
				assert.Equal(t, expectedRule.Verbs, cr.Rules[i].Verbs, "rule %d Verbs", i)
			}
		})
	}
}

func TestGenerateClusterRoleBinding(t *testing.T) {
	obj := testObject()
	crb := GenerateClusterRoleBinding(obj).(*rbacv1.ClusterRoleBinding)

	wantName := GenerateUniqueName(testName, testNamespace)
	assert.Equal(t, wantName, crb.Name)
	assert.Equal(t, testLabels, crb.Labels)
	require.Len(t, crb.Subjects, 1)
	assert.Equal(t, "ServiceAccount", crb.Subjects[0].Kind)
	assert.Equal(t, testName, crb.Subjects[0].Name)
	assert.Equal(t, testNamespace, crb.Subjects[0].Namespace)
	assert.Equal(t, "ClusterRole", crb.RoleRef.Kind)
	assert.Equal(t, wantName, crb.RoleRef.Name)
	assert.Equal(t, "rbac.authorization.k8s.io", crb.RoleRef.APIGroup)
}

func TestGenerateRole(t *testing.T) {
	tests := []struct {
		name          string
		defs          *InstanceDefaults
		wantRuleCount int
	}{
		{
			name:          "falco role has 4 rules",
			defs:          FalcoDefaults,
			wantRuleCount: 4,
		},
		{
			name:          "metacollector role has no rules",
			defs:          MetacollectorDefaults,
			wantRuleCount: 0,
		},
		{
			name:          "falcosidekick role has 1 rule for endpoints",
			defs:          FalcosidekickDefaults,
			wantRuleCount: 1,
		},
		{
			name:          "falcosidekick-ui role has no rules",
			defs:          FalcosidekickUIDefaults,
			wantRuleCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := testObject()
			role := GenerateRole(obj, tt.defs).(*rbacv1.Role)

			assert.Equal(t, testName, role.Name)
			assert.Equal(t, testNamespace, role.Namespace)
			assert.Equal(t, testLabels, role.Labels)
			require.Len(t, role.Rules, tt.wantRuleCount)
			// Verify rules match defaults exactly.
			for i, expectedRule := range tt.defs.RoleRules {
				assert.Equal(t, expectedRule.APIGroups, role.Rules[i].APIGroups, "rule %d APIGroups", i)
				assert.Equal(t, expectedRule.Resources, role.Rules[i].Resources, "rule %d Resources", i)
				assert.Equal(t, expectedRule.Verbs, role.Rules[i].Verbs, "rule %d Verbs", i)
			}
		})
	}
}

func TestGenerateRoleBinding(t *testing.T) {
	obj := testObject()
	rb := GenerateRoleBinding(obj).(*rbacv1.RoleBinding)

	assert.Equal(t, testName, rb.Name)
	assert.Equal(t, testNamespace, rb.Namespace)
	assert.Equal(t, testLabels, rb.Labels)
	require.Len(t, rb.Subjects, 1)
	assert.Equal(t, "ServiceAccount", rb.Subjects[0].Kind)
	assert.Equal(t, testName, rb.Subjects[0].Name)
	assert.Equal(t, testNamespace, rb.Subjects[0].Namespace)
	assert.Equal(t, "Role", rb.RoleRef.Kind)
	assert.Equal(t, testName, rb.RoleRef.Name)
	assert.Equal(t, "rbac.authorization.k8s.io", rb.RoleRef.APIGroup)
}

func TestGenerateConfigMap(t *testing.T) {
	tests := []struct {
		name         string
		defs         *InstanceDefaults
		workloadType string
		wantErr      bool
		wantDataKeys []string
		wantContains map[string]string
	}{
		{
			name:         "falco DaemonSet config",
			defs:         FalcoDefaults,
			workloadType: ResourceTypeDaemonSet,
			wantDataKeys: []string{"falco.yaml"},
			wantContains: map[string]string{"falco.yaml": "kind: modern_ebpf"},
		},
		{
			name:         "falco Deployment config",
			defs:         FalcoDefaults,
			workloadType: ResourceTypeDeployment,
			wantDataKeys: []string{"falco.yaml"},
			wantContains: map[string]string{"falco.yaml": "kind: nodriver"},
		},
		{
			name:         "unknown workload type returns error",
			defs:         FalcoDefaults,
			workloadType: "StatefulSet",
			wantErr:      true,
		},
		{
			name:         "metacollector has no ConfigMap data",
			defs:         MetacollectorDefaults,
			workloadType: ResourceTypeDeployment,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := testObject()
			result, err := GenerateConfigMap(obj, tt.defs, tt.workloadType)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			cm := result.(*corev1.ConfigMap)
			assert.Equal(t, testName, cm.Name)
			assert.Equal(t, testNamespace, cm.Namespace)
			assert.Equal(t, testLabels, cm.Labels)
			for _, key := range tt.wantDataKeys {
				assert.Contains(t, cm.Data, key)
				assert.NotEmpty(t, cm.Data[key])
			}
			for key, substring := range tt.wantContains {
				assert.Contains(t, cm.Data[key], substring, "ConfigMap key %s should contain %q", key, substring)
			}
		})
	}

	// Verify DaemonSet and Deployment configs have DIFFERENT content.
	t.Run("falco DaemonSet and Deployment configs differ", func(t *testing.T) {
		obj := testObject()
		dsResult, err := GenerateConfigMap(obj, FalcoDefaults, ResourceTypeDaemonSet)
		require.NoError(t, err)
		depResult, err := GenerateConfigMap(obj, FalcoDefaults, ResourceTypeDeployment)
		require.NoError(t, err)

		dsCM := dsResult.(*corev1.ConfigMap)
		depCM := depResult.(*corev1.ConfigMap)
		assert.NotEqual(t, dsCM.Data["falco.yaml"], depCM.Data["falco.yaml"],
			"DaemonSet and Deployment falco.yaml configs should differ")
	})
}
