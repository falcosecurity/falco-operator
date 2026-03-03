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

package component

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/resources"
)

var mcDefs = resources.MetacollectorDefaults

// mustGetContainers extracts the containers list from an unstructured workload.
func mustGetContainers(t *testing.T, obj *unstructured.Unstructured) []any {
	t.Helper()
	containers, found, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
	require.NoError(t, err)
	require.True(t, found, "containers not found")
	return containers
}

// mustFindContainer finds a container by name in the containers list.
func mustFindContainer(t *testing.T, containers []any, name string) map[string]any {
	t.Helper()
	for _, c := range containers {
		cm := c.(map[string]any)
		if cm["name"] == name {
			return cm
		}
	}
	t.Fatalf("container %q not found", name)
	return nil
}

func TestGenerateApplyConfiguration(t *testing.T) {
	tests := []struct {
		name                string
		comp                *instancev1alpha1.Component
		wantContainerCount  int
		wantMainImage       string
		wantTolerationCount int
		wantPodLabels       map[string]string
		wantReplicas        int64
		wantStrategyType    string
		wantVolumeMinCount  int
		wantErr             string
	}{
		{
			name:                "default metacollector produces expected base",
			comp:                newMetacollectorComponent("test-mc").Build(),
			wantContainerCount:  1,
			wantMainImage:       mcDefs.ImageRepository + ":" + mcDefs.ImageTag,
			wantTolerationCount: 0,
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-mc",
				"app.kubernetes.io/instance": "test-mc",
			},
			wantReplicas:       1,
			wantStrategyType:   string(appsv1.RollingUpdateDeploymentStrategyType),
			wantVolumeMinCount: 0,
		},
		{
			name:                "custom version overrides container image",
			comp:                newMetacollectorComponent("test-mc").WithVersion("0.2.0").Build(),
			wantContainerCount:  1,
			wantMainImage:       fmt.Sprintf("%s:%s", mcDefs.ImageRepository, "0.2.0"),
			wantTolerationCount: 0,
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-mc",
				"app.kubernetes.io/instance": "test-mc",
			},
			wantReplicas:       1,
			wantStrategyType:   string(appsv1.RollingUpdateDeploymentStrategyType),
			wantVolumeMinCount: 0,
		},
		{
			name:                "custom replicas are propagated",
			comp:                newMetacollectorComponent("test-mc").WithReplicas(5).Build(),
			wantContainerCount:  1,
			wantMainImage:       mcDefs.ImageRepository + ":" + mcDefs.ImageTag,
			wantTolerationCount: 0,
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-mc",
				"app.kubernetes.io/instance": "test-mc",
			},
			wantReplicas:       5,
			wantStrategyType:   string(appsv1.RollingUpdateDeploymentStrategyType),
			wantVolumeMinCount: 0,
		},
		{
			name: "Recreate strategy overrides default RollingUpdate",
			comp: newMetacollectorComponent("test-mc").
				WithStrategy(appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}).Build(),
			wantContainerCount:  1,
			wantMainImage:       mcDefs.ImageRepository + ":" + mcDefs.ImageTag,
			wantTolerationCount: 0,
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-mc",
				"app.kubernetes.io/instance": "test-mc",
			},
			wantReplicas:       1,
			wantStrategyType:   string(appsv1.RecreateDeploymentStrategyType),
			wantVolumeMinCount: 0,
		},
		{
			name: "CR labels propagate to pod template",
			comp: newMetacollectorComponent("test-mc").
				WithLabels(map[string]string{"team": "security", "env": "prod"}).Build(),
			wantContainerCount:  1,
			wantMainImage:       mcDefs.ImageRepository + ":" + mcDefs.ImageTag,
			wantTolerationCount: 0,
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-mc",
				"app.kubernetes.io/instance": "test-mc",
				"team":                       "security",
				"env":                        "prod",
			},
			wantReplicas:       1,
			wantStrategyType:   string(appsv1.RollingUpdateDeploymentStrategyType),
			wantVolumeMinCount: 0,
		},
		{
			name: "custom PodTemplateSpec merges with base preserving probes",
			comp: newMetacollectorComponent("test-mc").
				WithImage(mcDefs.ContainerName, "custom-repo/metacollector:custom").Build(),
			wantContainerCount:  1,
			wantMainImage:       "custom-repo/metacollector:custom",
			wantTolerationCount: 0,
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-mc",
				"app.kubernetes.io/instance": "test-mc",
			},
			wantReplicas:       1,
			wantStrategyType:   string(appsv1.RollingUpdateDeploymentStrategyType),
			wantVolumeMinCount: 0,
		},
		{
			name: "version is ignored when PodTemplateSpec provides main container",
			comp: newMetacollectorComponent("test-mc").
				WithVersion("0.2.0").
				WithImage(mcDefs.ContainerName, "custom-repo/metacollector:custom").Build(),
			wantContainerCount:  1,
			wantMainImage:       "custom-repo/metacollector:custom",
			wantTolerationCount: 0,
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-mc",
				"app.kubernetes.io/instance": "test-mc",
			},
			wantReplicas:       1,
			wantStrategyType:   string(appsv1.RollingUpdateDeploymentStrategyType),
			wantVolumeMinCount: 0,
		},
		{
			name: "version applies when PodTemplateSpec has only pod-level fields",
			comp: newMetacollectorComponent("test-mc").
				WithVersion("0.2.0").
				WithPodTemplateSpec(&corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						NodeSelector: map[string]string{"disktype": "ssd"},
					},
				}).Build(),
			wantContainerCount:  1,
			wantMainImage:       fmt.Sprintf("%s:%s", mcDefs.ImageRepository, "0.2.0"),
			wantTolerationCount: 0,
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-mc",
				"app.kubernetes.io/instance": "test-mc",
			},
			wantReplicas:       1,
			wantStrategyType:   string(appsv1.RollingUpdateDeploymentStrategyType),
			wantVolumeMinCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := generateApplyConfiguration(tt.comp, mcDefs)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, result)

			// Kind and identity.
			assert.Equal(t, resources.ResourceTypeDeployment, result.GetKind())
			assert.Equal(t, "apps/v1", result.GetAPIVersion())
			assert.Equal(t, tt.comp.Name, result.GetName())
			assert.Equal(t, testutil.TestNamespace, result.GetNamespace())

			// Pod template labels.
			podLabels, _, _ := unstructured.NestedStringMap(result.Object, "spec", "template", "metadata", "labels")
			for k, v := range tt.wantPodLabels {
				assert.Equal(t, v, podLabels[k], "pod template label %s", k)
			}

			// Containers.
			containers := mustGetContainers(t, result)
			assert.Len(t, containers, tt.wantContainerCount)
			mainContainer := mustFindContainer(t, containers, mcDefs.ContainerName)
			assert.Equal(t, tt.wantMainImage, mainContainer["image"])

			// Probes survive merge.
			assert.NotNil(t, mainContainer["livenessProbe"], "livenessProbe should survive merge")
			assert.NotNil(t, mainContainer["readinessProbe"], "readinessProbe should survive merge")

			// SecurityContext survives merge.
			assert.NotNil(t, mainContainer["securityContext"], "securityContext should survive merge")

			// Ports survive merge.
			ports, _, _ := unstructured.NestedSlice(mainContainer, "ports")
			assert.Len(t, ports, len(mcDefs.DefaultPorts))

			// Resources survive merge.
			assert.NotNil(t, mainContainer["resources"], "resources should survive merge")

			// ServiceAccount.
			saName, _, _ := unstructured.NestedString(result.Object, "spec", "template", "spec", "serviceAccountName")
			assert.Equal(t, tt.comp.Name, saName)

			// PodSecurityContext.
			podSecCtx, found, _ := unstructured.NestedMap(result.Object, "spec", "template", "spec", "securityContext")
			assert.True(t, found, "podSecurityContext should be present")
			assert.NotEmpty(t, podSecCtx)

			// Tolerations.
			tolerations, _, _ := unstructured.NestedSlice(result.Object, "spec", "template", "spec", "tolerations")
			assert.Len(t, tolerations, tt.wantTolerationCount)

			// Volumes.
			volumes, _, _ := unstructured.NestedSlice(result.Object, "spec", "template", "spec", "volumes")
			assert.GreaterOrEqual(t, len(volumes), tt.wantVolumeMinCount)

			// Replicas.
			if tt.wantReplicas > 0 {
				replicas, found, _ := unstructured.NestedInt64(result.Object, "spec", "replicas")
				require.True(t, found, "replicas should be set")
				assert.Equal(t, tt.wantReplicas, replicas)
			}

			// Strategy.
			if tt.wantStrategyType != "" {
				strategyType, _, _ := unstructured.NestedString(result.Object, "spec", "strategy", "type")
				assert.Equal(t, tt.wantStrategyType, strategyType)
			}
		})
	}
}
