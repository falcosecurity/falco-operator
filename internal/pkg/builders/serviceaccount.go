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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ServiceAccountBuilder provides a fluent API for constructing corev1.ServiceAccount objects.
type ServiceAccountBuilder struct {
	sa *corev1.ServiceAccount
}

// NewServiceAccount creates a ServiceAccountBuilder with TypeMeta pre-populated.
func NewServiceAccount() *ServiceAccountBuilder {
	return &ServiceAccountBuilder{
		sa: &corev1.ServiceAccount{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ServiceAccount",
				APIVersion: "v1",
			},
		},
	}
}

// WithName sets the name.
func (b *ServiceAccountBuilder) WithName(name string) *ServiceAccountBuilder {
	b.sa.Name = name
	return b
}

// WithNamespace sets the namespace.
func (b *ServiceAccountBuilder) WithNamespace(namespace string) *ServiceAccountBuilder {
	b.sa.Namespace = namespace
	return b
}

// WithLabels sets the labels.
func (b *ServiceAccountBuilder) WithLabels(labels map[string]string) *ServiceAccountBuilder {
	b.sa.Labels = labels
	return b
}

// Build returns the constructed ServiceAccount object.
func (b *ServiceAccountBuilder) Build() *corev1.ServiceAccount {
	return b.sa
}
