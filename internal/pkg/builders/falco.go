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

// FalcoBuilder provides a fluent API for constructing instancev1alpha1.Falco objects.
type FalcoBuilder struct {
	falco *instancev1alpha1.Falco
}

// NewFalco creates a FalcoBuilder with no defaults.
func NewFalco() *FalcoBuilder {
	return &FalcoBuilder{
		falco: &instancev1alpha1.Falco{},
	}
}

// WithName sets the name.
func (b *FalcoBuilder) WithName(name string) *FalcoBuilder {
	b.falco.Name = name
	return b
}

// WithNamespace sets the namespace.
func (b *FalcoBuilder) WithNamespace(namespace string) *FalcoBuilder {
	b.falco.Namespace = namespace
	return b
}

// WithLabels sets the labels.
func (b *FalcoBuilder) WithLabels(labels map[string]string) *FalcoBuilder {
	b.falco.Labels = labels
	return b
}

// WithFinalizers sets the finalizers.
func (b *FalcoBuilder) WithFinalizers(finalizers []string) *FalcoBuilder {
	b.falco.Finalizers = finalizers
	return b
}

// WithDeletionTimestamp sets the deletion timestamp.
func (b *FalcoBuilder) WithDeletionTimestamp(ts *metav1.Time) *FalcoBuilder {
	b.falco.DeletionTimestamp = ts
	return b
}

// WithType sets the Falco deployment type.
func (b *FalcoBuilder) WithType(t string) *FalcoBuilder {
	b.falco.Spec.Type = &t
	return b
}

// WithReplicas sets the replica count.
func (b *FalcoBuilder) WithReplicas(r int32) *FalcoBuilder {
	b.falco.Spec.Replicas = &r
	return b
}

// WithVersion sets the Falco version.
func (b *FalcoBuilder) WithVersion(v string) *FalcoBuilder {
	b.falco.Spec.Version = &v
	return b
}

// WithImage sets the container image.
func (b *FalcoBuilder) WithImage(containerName, image string) *FalcoBuilder {
	b.falco.Spec.PodTemplateSpec = &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: containerName, Image: image}},
		},
	}
	return b
}

// WithPodTemplateSpec sets the pod template spec.
func (b *FalcoBuilder) WithPodTemplateSpec(pts *corev1.PodTemplateSpec) *FalcoBuilder {
	b.falco.Spec.PodTemplateSpec = pts
	return b
}

// WithStrategy sets the deployment strategy.
func (b *FalcoBuilder) WithStrategy(s appsv1.DeploymentStrategy) *FalcoBuilder {
	b.falco.Spec.Strategy = &s
	return b
}

// WithUpdateStrategy sets the update strategy.
func (b *FalcoBuilder) WithUpdateStrategy(s appsv1.DaemonSetUpdateStrategy) *FalcoBuilder {
	b.falco.Spec.UpdateStrategy = &s
	return b
}

// Build returns the constructed Falco object.
func (b *FalcoBuilder) Build() *instancev1alpha1.Falco {
	return b.falco
}
