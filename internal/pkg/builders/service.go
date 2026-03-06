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

// ServiceBuilder provides a fluent API for constructing corev1.Service objects.
type ServiceBuilder struct {
	service *corev1.Service
}

// NewService creates a ServiceBuilder with TypeMeta pre-populated.
func NewService() *ServiceBuilder {
	return &ServiceBuilder{
		service: &corev1.Service{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Service",
				APIVersion: "v1",
			},
		},
	}
}

// WithName sets the name.
func (b *ServiceBuilder) WithName(name string) *ServiceBuilder {
	b.service.Name = name
	return b
}

// WithNamespace sets the namespace.
func (b *ServiceBuilder) WithNamespace(namespace string) *ServiceBuilder {
	b.service.Namespace = namespace
	return b
}

// WithLabels sets the labels.
func (b *ServiceBuilder) WithLabels(labels map[string]string) *ServiceBuilder {
	b.service.Labels = labels
	return b
}

// WithType sets the service type.
func (b *ServiceBuilder) WithType(serviceType corev1.ServiceType) *ServiceBuilder {
	b.service.Spec.Type = serviceType
	return b
}

// WithSelector sets the label selector.
func (b *ServiceBuilder) WithSelector(selector map[string]string) *ServiceBuilder {
	b.service.Spec.Selector = selector
	return b
}

// AddPort adds a service port.
func (b *ServiceBuilder) AddPort(port *corev1.ServicePort) *ServiceBuilder {
	b.service.Spec.Ports = append(b.service.Spec.Ports, *port)
	return b
}

// Build returns the constructed Service object.
func (b *ServiceBuilder) Build() *corev1.Service {
	return b.service
}
