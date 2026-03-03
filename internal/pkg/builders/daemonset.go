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
)

// DaemonSetBuilder provides a fluent API for constructing appsv1.DaemonSet objects.
type DaemonSetBuilder struct {
	daemonset *appsv1.DaemonSet
}

// NewDaemonSet creates a DaemonSetBuilder with TypeMeta pre-populated.
func NewDaemonSet() *DaemonSetBuilder {
	return &DaemonSetBuilder{
		daemonset: &appsv1.DaemonSet{
			TypeMeta: metav1.TypeMeta{
				Kind:       "DaemonSet",
				APIVersion: "apps/v1",
			},
		},
	}
}

// WithName sets the name.
func (b *DaemonSetBuilder) WithName(name string) *DaemonSetBuilder {
	b.daemonset.Name = name
	return b
}

// WithNamespace sets the namespace.
func (b *DaemonSetBuilder) WithNamespace(namespace string) *DaemonSetBuilder {
	b.daemonset.Namespace = namespace
	return b
}

// WithLabels sets the labels.
func (b *DaemonSetBuilder) WithLabels(labels map[string]string) *DaemonSetBuilder {
	b.daemonset.Labels = labels
	return b
}

// WithSelector sets the label selector.
func (b *DaemonSetBuilder) WithSelector(matchLabels map[string]string) *DaemonSetBuilder {
	b.daemonset.Spec.Selector = &metav1.LabelSelector{
		MatchLabels: matchLabels,
	}
	return b
}

// WithPodTemplateLabels sets the pod template labels.
func (b *DaemonSetBuilder) WithPodTemplateLabels(labels map[string]string) *DaemonSetBuilder {
	b.daemonset.Spec.Template.Labels = labels
	return b
}

// WithTolerations sets the pod tolerations.
func (b *DaemonSetBuilder) WithTolerations(tolerations []corev1.Toleration) *DaemonSetBuilder {
	b.daemonset.Spec.Template.Spec.Tolerations = tolerations
	return b
}

// WithServiceAccount sets the service account name.
func (b *DaemonSetBuilder) WithServiceAccount(name string) *DaemonSetBuilder {
	b.daemonset.Spec.Template.Spec.ServiceAccountName = name
	return b
}

// WithPodSecurityContext sets the pod security context.
func (b *DaemonSetBuilder) WithPodSecurityContext(sc *corev1.PodSecurityContext) *DaemonSetBuilder {
	b.daemonset.Spec.Template.Spec.SecurityContext = sc
	return b
}

// WithVolumes sets the pod volumes.
func (b *DaemonSetBuilder) WithVolumes(volumes []corev1.Volume) *DaemonSetBuilder {
	b.daemonset.Spec.Template.Spec.Volumes = volumes
	return b
}

// AddContainer adds a container to the pod spec.
func (b *DaemonSetBuilder) AddContainer(container *corev1.Container) *DaemonSetBuilder {
	b.daemonset.Spec.Template.Spec.Containers = append(b.daemonset.Spec.Template.Spec.Containers, *container)
	return b
}

// AddInitContainer adds an init container to the pod spec.
func (b *DaemonSetBuilder) AddInitContainer(container *corev1.Container) *DaemonSetBuilder {
	b.daemonset.Spec.Template.Spec.InitContainers = append(b.daemonset.Spec.Template.Spec.InitContainers, *container)
	return b
}

// WithUpdateStrategy sets the update strategy.
func (b *DaemonSetBuilder) WithUpdateStrategy(strategy appsv1.DaemonSetUpdateStrategy) *DaemonSetBuilder {
	b.daemonset.Spec.UpdateStrategy = strategy
	return b
}

// Build returns the constructed DaemonSet object.
func (b *DaemonSetBuilder) Build() *appsv1.DaemonSet {
	return b.daemonset
}
