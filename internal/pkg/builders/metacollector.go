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

// MetacollectorBuilder provides a fluent API for constructing instancev1alpha1.Metacollector objects.
type MetacollectorBuilder struct {
	mc *instancev1alpha1.Metacollector
}

// NewMetacollector creates a MetacollectorBuilder with no defaults.
func NewMetacollector() *MetacollectorBuilder {
	return &MetacollectorBuilder{
		mc: &instancev1alpha1.Metacollector{},
	}
}

// WithName sets the name.
func (b *MetacollectorBuilder) WithName(name string) *MetacollectorBuilder {
	b.mc.Name = name
	return b
}

// WithNamespace sets the namespace.
func (b *MetacollectorBuilder) WithNamespace(namespace string) *MetacollectorBuilder {
	b.mc.Namespace = namespace
	return b
}

// WithLabels sets the labels.
func (b *MetacollectorBuilder) WithLabels(labels map[string]string) *MetacollectorBuilder {
	b.mc.Labels = labels
	return b
}

// WithFinalizers sets the finalizers.
func (b *MetacollectorBuilder) WithFinalizers(finalizers []string) *MetacollectorBuilder {
	b.mc.Finalizers = finalizers
	return b
}

// WithDeletionTimestamp sets the deletion timestamp.
func (b *MetacollectorBuilder) WithDeletionTimestamp(ts *metav1.Time) *MetacollectorBuilder {
	b.mc.DeletionTimestamp = ts
	return b
}

// WithReplicas sets the replica count.
func (b *MetacollectorBuilder) WithReplicas(r int32) *MetacollectorBuilder {
	b.mc.Spec.Replicas = &r
	return b
}

// WithVersion sets the Metacollector version.
func (b *MetacollectorBuilder) WithVersion(v string) *MetacollectorBuilder {
	b.mc.Spec.Version = v
	return b
}

// WithImage sets the container image.
func (b *MetacollectorBuilder) WithImage(containerName, image string) *MetacollectorBuilder {
	b.mc.Spec.PodTemplateSpec = &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: containerName, Image: image}},
		},
	}
	return b
}

// WithPodTemplateSpec sets the pod template spec.
func (b *MetacollectorBuilder) WithPodTemplateSpec(pts *corev1.PodTemplateSpec) *MetacollectorBuilder {
	b.mc.Spec.PodTemplateSpec = pts
	return b
}

// WithStrategy sets the deployment strategy.
func (b *MetacollectorBuilder) WithStrategy(s appsv1.DeploymentStrategy) *MetacollectorBuilder {
	b.mc.Spec.Strategy = &s
	return b
}

// Build returns the constructed Metacollector object.
func (b *MetacollectorBuilder) Build() *instancev1alpha1.Metacollector {
	return b.mc
}
