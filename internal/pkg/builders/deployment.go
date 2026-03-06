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

// DeploymentBuilder provides a fluent API for constructing appsv1.Deployment objects.
type DeploymentBuilder struct {
	deployment *appsv1.Deployment
}

// NewDeployment creates a DeploymentBuilder with TypeMeta pre-populated.
func NewDeployment() *DeploymentBuilder {
	return &DeploymentBuilder{
		deployment: &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Deployment",
				APIVersion: "apps/v1",
			},
		},
	}
}

// WithName sets the name.
func (b *DeploymentBuilder) WithName(name string) *DeploymentBuilder {
	b.deployment.Name = name
	return b
}

// WithNamespace sets the namespace.
func (b *DeploymentBuilder) WithNamespace(namespace string) *DeploymentBuilder {
	b.deployment.Namespace = namespace
	return b
}

// WithLabels sets the labels.
func (b *DeploymentBuilder) WithLabels(labels map[string]string) *DeploymentBuilder {
	b.deployment.Labels = labels
	return b
}

// WithSelector sets the label selector.
func (b *DeploymentBuilder) WithSelector(matchLabels map[string]string) *DeploymentBuilder {
	b.deployment.Spec.Selector = &metav1.LabelSelector{
		MatchLabels: matchLabels,
	}
	return b
}

// WithReplicas sets the replica count.
func (b *DeploymentBuilder) WithReplicas(replicas *int32) *DeploymentBuilder {
	b.deployment.Spec.Replicas = replicas
	return b
}

// WithPodTemplateLabels sets the pod template labels.
func (b *DeploymentBuilder) WithPodTemplateLabels(labels map[string]string) *DeploymentBuilder {
	b.deployment.Spec.Template.Labels = labels
	return b
}

// WithTolerations sets the pod tolerations.
func (b *DeploymentBuilder) WithTolerations(tolerations []corev1.Toleration) *DeploymentBuilder {
	b.deployment.Spec.Template.Spec.Tolerations = tolerations
	return b
}

// WithServiceAccount sets the service account name.
func (b *DeploymentBuilder) WithServiceAccount(name string) *DeploymentBuilder {
	b.deployment.Spec.Template.Spec.ServiceAccountName = name
	return b
}

// WithPodSecurityContext sets the pod security context.
func (b *DeploymentBuilder) WithPodSecurityContext(sc *corev1.PodSecurityContext) *DeploymentBuilder {
	b.deployment.Spec.Template.Spec.SecurityContext = sc
	return b
}

// WithVolumes sets the pod volumes.
func (b *DeploymentBuilder) WithVolumes(volumes []corev1.Volume) *DeploymentBuilder {
	b.deployment.Spec.Template.Spec.Volumes = volumes
	return b
}

// AddContainer adds a container to the pod spec.
func (b *DeploymentBuilder) AddContainer(container *corev1.Container) *DeploymentBuilder {
	b.deployment.Spec.Template.Spec.Containers = append(b.deployment.Spec.Template.Spec.Containers, *container)
	return b
}

// AddInitContainer adds an init container to the pod spec.
func (b *DeploymentBuilder) AddInitContainer(container *corev1.Container) *DeploymentBuilder {
	b.deployment.Spec.Template.Spec.InitContainers = append(b.deployment.Spec.Template.Spec.InitContainers, *container)
	return b
}

// WithStrategy sets the deployment strategy.
func (b *DeploymentBuilder) WithStrategy(strategy appsv1.DeploymentStrategy) *DeploymentBuilder {
	b.deployment.Spec.Strategy = strategy
	return b
}

// Build returns the constructed Deployment object.
func (b *DeploymentBuilder) Build() *appsv1.Deployment {
	return b.deployment
}
