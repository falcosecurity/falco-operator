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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

func TestNewDeployment_TypeMeta(t *testing.T) {
	dep := NewDeployment().Build()
	assert.Equal(t, "Deployment", dep.Kind)
	assert.Equal(t, "apps/v1", dep.APIVersion)
}

func TestDeploymentBuilder(t *testing.T) {
	labels := map[string]string{"app": "test"}
	selector := map[string]string{"app.kubernetes.io/name": "test"}
	podLabels := map[string]string{"pod": "label"}
	tolerations := []corev1.Toleration{{Key: "key", Effect: corev1.TaintEffectNoSchedule}}
	volumes := []corev1.Volume{{Name: "vol"}}
	psc := &corev1.PodSecurityContext{RunAsNonRoot: ptr.To(true)}
	strategy := appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType}
	replicas := ptr.To(int32(3))

	dep := NewDeployment().
		WithName("my-dep").
		WithNamespace("ns").
		WithLabels(labels).
		WithSelector(selector).
		WithReplicas(replicas).
		WithPodTemplateLabels(podLabels).
		WithTolerations(tolerations).
		WithServiceAccount("sa-name").
		WithPodSecurityContext(psc).
		WithVolumes(volumes).
		WithStrategy(strategy).
		Build()

	assert.Equal(t, "my-dep", dep.Name)
	assert.Equal(t, "ns", dep.Namespace)
	assert.Equal(t, labels, dep.Labels)
	require.NotNil(t, dep.Spec.Selector)
	assert.Equal(t, selector, dep.Spec.Selector.MatchLabels)
	assert.Equal(t, replicas, dep.Spec.Replicas)
	assert.Equal(t, podLabels, dep.Spec.Template.Labels)
	assert.Equal(t, tolerations, dep.Spec.Template.Spec.Tolerations)
	assert.Equal(t, "sa-name", dep.Spec.Template.Spec.ServiceAccountName)
	assert.Equal(t, psc, dep.Spec.Template.Spec.SecurityContext)
	assert.Equal(t, volumes, dep.Spec.Template.Spec.Volumes)
	assert.Equal(t, strategy, dep.Spec.Strategy)
}

func TestDeploymentBuilder_AddContainers(t *testing.T) {
	dep := NewDeployment().
		AddContainer(&corev1.Container{Name: "main"}).
		AddContainer(&corev1.Container{Name: "sidecar"}).
		AddInitContainer(&corev1.Container{Name: "init"}).
		AddInitContainer(&corev1.Container{Name: "init2"}).
		Build()

	require.Len(t, dep.Spec.Template.Spec.Containers, 2)
	assert.Equal(t, "main", dep.Spec.Template.Spec.Containers[0].Name)
	assert.Equal(t, "sidecar", dep.Spec.Template.Spec.Containers[1].Name)
	require.Len(t, dep.Spec.Template.Spec.InitContainers, 2)
	assert.Equal(t, "init", dep.Spec.Template.Spec.InitContainers[0].Name)
	assert.Equal(t, "init2", dep.Spec.Template.Spec.InitContainers[1].Name)
}
