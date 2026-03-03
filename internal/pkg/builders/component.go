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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

// ComponentBuilder provides a fluent API for constructing instancev1alpha1.Component objects.
type ComponentBuilder struct {
	c *instancev1alpha1.Component
}

// NewComponent creates a ComponentBuilder with no defaults.
func NewComponent() *ComponentBuilder {
	return &ComponentBuilder{
		c: &instancev1alpha1.Component{},
	}
}

// WithName sets the name.
func (b *ComponentBuilder) WithName(name string) *ComponentBuilder {
	b.c.Name = name
	return b
}

// WithNamespace sets the namespace.
func (b *ComponentBuilder) WithNamespace(namespace string) *ComponentBuilder {
	b.c.Namespace = namespace
	return b
}

// WithLabels sets the labels.
func (b *ComponentBuilder) WithLabels(labels map[string]string) *ComponentBuilder {
	b.c.Labels = labels
	return b
}

// WithFinalizers sets the finalizers.
func (b *ComponentBuilder) WithFinalizers(finalizers []string) *ComponentBuilder {
	b.c.Finalizers = finalizers
	return b
}

// WithDeletionTimestamp sets the deletion timestamp.
func (b *ComponentBuilder) WithDeletionTimestamp(ts *metav1.Time) *ComponentBuilder {
	b.c.DeletionTimestamp = ts
	return b
}

// WithReplicas sets the replica count.
func (b *ComponentBuilder) WithReplicas(r int32) *ComponentBuilder {
	b.c.Spec.Replicas = &r
	return b
}

// WithComponentType sets the component type.
func (b *ComponentBuilder) WithComponentType(ct instancev1alpha1.ComponentType) *ComponentBuilder {
	b.c.Spec.Component.Type = ct
	return b
}

// WithVersion sets the component version.
func (b *ComponentBuilder) WithVersion(v string) *ComponentBuilder {
	b.c.Spec.Component.Version = &v
	return b
}

// WithImage sets the container image.
func (b *ComponentBuilder) WithImage(containerName, image string) *ComponentBuilder {
	b.c.Spec.PodTemplateSpec = &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: containerName, Image: image}},
		},
	}
	return b
}

// WithPodTemplateSpec sets the pod template spec.
func (b *ComponentBuilder) WithPodTemplateSpec(pts *corev1.PodTemplateSpec) *ComponentBuilder {
	b.c.Spec.PodTemplateSpec = pts
	return b
}

// WithStrategy sets the deployment strategy.
func (b *ComponentBuilder) WithStrategy(s appsv1.DeploymentStrategy) *ComponentBuilder {
	b.c.Spec.Strategy = &s
	return b
}

// Build returns the constructed Component object.
func (b *ComponentBuilder) Build() *instancev1alpha1.Component {
	return b.c
}
