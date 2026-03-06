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

package builders

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
)

// --- ClusterRole ---

func TestNewClusterRole_TypeMeta(t *testing.T) {
	cr := NewClusterRole().Build()
	assert.Equal(t, "ClusterRole", cr.Kind)
	assert.Equal(t, "rbac.authorization.k8s.io/v1", cr.APIVersion)
}

func TestClusterRoleBuilder(t *testing.T) {
	labels := map[string]string{"app": "test"}

	cr := NewClusterRole().
		WithName("my-cr").
		WithLabels(labels).
		Build()

	assert.Equal(t, "my-cr", cr.Name)
	assert.Equal(t, labels, cr.Labels)
}

func TestClusterRoleBuilder_AddRule(t *testing.T) {
	cr := NewClusterRole().
		AddRule(&rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"nodes"},
			Verbs:     []string{"get", "list"},
		}).
		AddRule(&rbacv1.PolicyRule{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get"},
		}).
		Build()

	require.Len(t, cr.Rules, 2)
	assert.Equal(t, []string{"nodes"}, cr.Rules[0].Resources)
	assert.Equal(t, []string{"deployments"}, cr.Rules[1].Resources)
}

// --- ClusterRoleBinding ---

func TestNewClusterRoleBinding_TypeMeta(t *testing.T) {
	crb := NewClusterRoleBinding().Build()
	assert.Equal(t, "ClusterRoleBinding", crb.Kind)
	assert.Equal(t, "rbac.authorization.k8s.io/v1", crb.APIVersion)
}

func TestClusterRoleBindingBuilder(t *testing.T) {
	labels := map[string]string{"app": "test"}
	roleRef := rbacv1.RoleRef{Kind: "ClusterRole", Name: "my-cr", APIGroup: "rbac.authorization.k8s.io"}

	crb := NewClusterRoleBinding().
		WithName("my-crb").
		WithLabels(labels).
		AddSubject(rbacv1.Subject{Kind: "ServiceAccount", Name: "sa", Namespace: "ns"}).
		AddSubject(rbacv1.Subject{Kind: "ServiceAccount", Name: "sa2", Namespace: "ns"}).
		WithRoleRef(roleRef).
		Build()

	assert.Equal(t, "my-crb", crb.Name)
	assert.Equal(t, labels, crb.Labels)
	require.Len(t, crb.Subjects, 2)
	assert.Equal(t, "sa", crb.Subjects[0].Name)
	assert.Equal(t, "sa2", crb.Subjects[1].Name)
	assert.Equal(t, roleRef, crb.RoleRef)
}

// --- Role ---

func TestNewRole_TypeMeta(t *testing.T) {
	role := NewRole().Build()
	assert.Equal(t, "Role", role.Kind)
	assert.Equal(t, "rbac.authorization.k8s.io/v1", role.APIVersion)
}

func TestRoleBuilder(t *testing.T) {
	labels := map[string]string{"app": "test"}

	role := NewRole().
		WithName("my-role").
		WithNamespace("ns").
		WithLabels(labels).
		AddRule(&rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "list", "watch"},
		}).
		Build()

	assert.Equal(t, "my-role", role.Name)
	assert.Equal(t, "ns", role.Namespace)
	assert.Equal(t, labels, role.Labels)
	require.Len(t, role.Rules, 1)
	assert.Equal(t, []string{"configmaps"}, role.Rules[0].Resources)
}

// --- RoleBinding ---

func TestNewRoleBinding_TypeMeta(t *testing.T) {
	rb := NewRoleBinding().Build()
	assert.Equal(t, "RoleBinding", rb.Kind)
	assert.Equal(t, "rbac.authorization.k8s.io/v1", rb.APIVersion)
}

func TestRoleBindingBuilder(t *testing.T) {
	labels := map[string]string{"app": "test"}
	roleRef := rbacv1.RoleRef{Kind: "Role", Name: "my-role", APIGroup: "rbac.authorization.k8s.io"}

	rb := NewRoleBinding().
		WithGenerateName("prefix-").
		WithNamespace("ns").
		WithLabels(labels).
		AddSubject(rbacv1.Subject{Kind: "ServiceAccount", Name: "sa", Namespace: "ns"}).
		WithRoleRef(roleRef).
		Build()

	assert.Equal(t, "prefix-", rb.GenerateName)
	assert.Equal(t, "ns", rb.Namespace)
	assert.Equal(t, labels, rb.Labels)
	require.Len(t, rb.Subjects, 1)
	assert.Equal(t, "sa", rb.Subjects[0].Name)
	assert.Equal(t, roleRef, rb.RoleRef)
}

func TestRoleBindingBuilder_WithName(t *testing.T) {
	rb := NewRoleBinding().WithName("explicit-name").Build()
	assert.Equal(t, "explicit-name", rb.Name)
	assert.Empty(t, rb.GenerateName)
}
