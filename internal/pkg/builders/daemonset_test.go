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
)

func TestNewDaemonSet_TypeMeta(t *testing.T) {
	ds := NewDaemonSet().Build()
	assert.Equal(t, "DaemonSet", ds.Kind)
	assert.Equal(t, "apps/v1", ds.APIVersion)
}

func TestDaemonSetBuilder(t *testing.T) {
	labels := map[string]string{"app": "test"}
	selector := map[string]string{"app.kubernetes.io/name": "test"}
	podLabels := map[string]string{"pod": "label"}
	tolerations := []corev1.Toleration{{Key: "key", Effect: corev1.TaintEffectNoSchedule}}
	volumes := []corev1.Volume{{Name: "vol"}}
	psc := &corev1.PodSecurityContext{RunAsNonRoot: new(true)}
	strategy := appsv1.DaemonSetUpdateStrategy{Type: appsv1.RollingUpdateDaemonSetStrategyType}

	ds := NewDaemonSet().
		WithName("my-ds").
		WithNamespace("ns").
		WithLabels(labels).
		WithSelector(selector).
		WithPodTemplateLabels(podLabels).
		WithTolerations(tolerations).
		WithServiceAccount("sa-name").
		WithPodSecurityContext(psc).
		WithVolumes(volumes).
		WithUpdateStrategy(strategy).
		Build()

	assert.Equal(t, "my-ds", ds.Name)
	assert.Equal(t, "ns", ds.Namespace)
	assert.Equal(t, labels, ds.Labels)
	require.NotNil(t, ds.Spec.Selector)
	assert.Equal(t, selector, ds.Spec.Selector.MatchLabels)
	assert.Equal(t, podLabels, ds.Spec.Template.Labels)
	assert.Equal(t, tolerations, ds.Spec.Template.Spec.Tolerations)
	assert.Equal(t, "sa-name", ds.Spec.Template.Spec.ServiceAccountName)
	assert.Equal(t, psc, ds.Spec.Template.Spec.SecurityContext)
	assert.Equal(t, volumes, ds.Spec.Template.Spec.Volumes)
	assert.Equal(t, strategy, ds.Spec.UpdateStrategy)
}

func TestDaemonSetBuilder_AddContainers(t *testing.T) {
	ds := NewDaemonSet().
		AddContainer(&corev1.Container{Name: "main"}).
		AddContainer(&corev1.Container{Name: "sidecar"}).
		AddInitContainer(&corev1.Container{Name: "init"}).
		Build()

	require.Len(t, ds.Spec.Template.Spec.Containers, 2)
	assert.Equal(t, "main", ds.Spec.Template.Spec.Containers[0].Name)
	assert.Equal(t, "sidecar", ds.Spec.Template.Spec.Containers[1].Name)
	require.Len(t, ds.Spec.Template.Spec.InitContainers, 1)
	assert.Equal(t, "init", ds.Spec.Template.Spec.InitContainers[0].Name)
}
