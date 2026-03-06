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
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- ClusterRole ---

// ClusterRoleBuilder provides a fluent API for constructing rbacv1.ClusterRole objects.
type ClusterRoleBuilder struct {
	cr *rbacv1.ClusterRole
}

// NewClusterRole creates a ClusterRoleBuilder with TypeMeta pre-populated.
func NewClusterRole() *ClusterRoleBuilder {
	return &ClusterRoleBuilder{
		cr: &rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ClusterRole",
				APIVersion: "rbac.authorization.k8s.io/v1",
			},
		},
	}
}

// WithName sets the name.
func (b *ClusterRoleBuilder) WithName(name string) *ClusterRoleBuilder {
	b.cr.Name = name
	return b
}

// WithLabels sets the labels.
func (b *ClusterRoleBuilder) WithLabels(labels map[string]string) *ClusterRoleBuilder {
	b.cr.Labels = labels
	return b
}

// AddRule adds a policy rule.
func (b *ClusterRoleBuilder) AddRule(rule *rbacv1.PolicyRule) *ClusterRoleBuilder {
	b.cr.Rules = append(b.cr.Rules, *rule)
	return b
}

// Build returns the constructed ClusterRole object.
func (b *ClusterRoleBuilder) Build() *rbacv1.ClusterRole {
	return b.cr
}

// --- ClusterRoleBinding ---

// ClusterRoleBindingBuilder provides a fluent API for constructing rbacv1.ClusterRoleBinding objects.
type ClusterRoleBindingBuilder struct {
	crb *rbacv1.ClusterRoleBinding
}

// NewClusterRoleBinding creates a ClusterRoleBindingBuilder with TypeMeta pre-populated.
func NewClusterRoleBinding() *ClusterRoleBindingBuilder {
	return &ClusterRoleBindingBuilder{
		crb: &rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ClusterRoleBinding",
				APIVersion: "rbac.authorization.k8s.io/v1",
			},
		},
	}
}

// WithName sets the name.
func (b *ClusterRoleBindingBuilder) WithName(name string) *ClusterRoleBindingBuilder {
	b.crb.Name = name
	return b
}

// WithLabels sets the labels.
func (b *ClusterRoleBindingBuilder) WithLabels(labels map[string]string) *ClusterRoleBindingBuilder {
	b.crb.Labels = labels
	return b
}

// AddSubject adds a subject.
func (b *ClusterRoleBindingBuilder) AddSubject(subject rbacv1.Subject) *ClusterRoleBindingBuilder {
	b.crb.Subjects = append(b.crb.Subjects, subject)
	return b
}

// WithRoleRef sets the role reference.
func (b *ClusterRoleBindingBuilder) WithRoleRef(roleRef rbacv1.RoleRef) *ClusterRoleBindingBuilder {
	b.crb.RoleRef = roleRef
	return b
}

// Build returns the constructed ClusterRoleBinding object.
func (b *ClusterRoleBindingBuilder) Build() *rbacv1.ClusterRoleBinding {
	return b.crb
}

// --- Role ---

// RoleBuilder provides a fluent API for constructing rbacv1.Role objects.
type RoleBuilder struct {
	role *rbacv1.Role
}

// NewRole creates a RoleBuilder with TypeMeta pre-populated.
func NewRole() *RoleBuilder {
	return &RoleBuilder{
		role: &rbacv1.Role{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Role",
				APIVersion: "rbac.authorization.k8s.io/v1",
			},
		},
	}
}

// WithName sets the name.
func (b *RoleBuilder) WithName(name string) *RoleBuilder {
	b.role.Name = name
	return b
}

// WithNamespace sets the namespace.
func (b *RoleBuilder) WithNamespace(namespace string) *RoleBuilder {
	b.role.Namespace = namespace
	return b
}

// WithLabels sets the labels.
func (b *RoleBuilder) WithLabels(labels map[string]string) *RoleBuilder {
	b.role.Labels = labels
	return b
}

// AddRule adds a policy rule.
func (b *RoleBuilder) AddRule(rule *rbacv1.PolicyRule) *RoleBuilder {
	b.role.Rules = append(b.role.Rules, *rule)
	return b
}

// Build returns the constructed Role object.
func (b *RoleBuilder) Build() *rbacv1.Role {
	return b.role
}

// --- RoleBinding ---

// RoleBindingBuilder provides a fluent API for constructing rbacv1.RoleBinding objects.
type RoleBindingBuilder struct {
	rb *rbacv1.RoleBinding
}

// NewRoleBinding creates a RoleBindingBuilder with TypeMeta pre-populated.
func NewRoleBinding() *RoleBindingBuilder {
	return &RoleBindingBuilder{
		rb: &rbacv1.RoleBinding{
			TypeMeta: metav1.TypeMeta{
				Kind:       "RoleBinding",
				APIVersion: "rbac.authorization.k8s.io/v1",
			},
		},
	}
}

// WithName sets the name.
func (b *RoleBindingBuilder) WithName(name string) *RoleBindingBuilder {
	b.rb.Name = name
	return b
}

// WithGenerateName sets the generate name prefix.
func (b *RoleBindingBuilder) WithGenerateName(generateName string) *RoleBindingBuilder {
	b.rb.GenerateName = generateName
	return b
}

// WithNamespace sets the namespace.
func (b *RoleBindingBuilder) WithNamespace(namespace string) *RoleBindingBuilder {
	b.rb.Namespace = namespace
	return b
}

// WithLabels sets the labels.
func (b *RoleBindingBuilder) WithLabels(labels map[string]string) *RoleBindingBuilder {
	b.rb.Labels = labels
	return b
}

// AddSubject adds a subject.
func (b *RoleBindingBuilder) AddSubject(subject rbacv1.Subject) *RoleBindingBuilder {
	b.rb.Subjects = append(b.rb.Subjects, subject)
	return b
}

// WithRoleRef sets the role reference.
func (b *RoleBindingBuilder) WithRoleRef(roleRef rbacv1.RoleRef) *RoleBindingBuilder {
	b.rb.RoleRef = roleRef
	return b
}

// Build returns the constructed RoleBinding object.
func (b *RoleBindingBuilder) Build() *rbacv1.RoleBinding {
	return b.rb
}
