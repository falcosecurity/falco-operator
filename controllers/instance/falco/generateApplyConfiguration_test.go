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

package falco

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
	"github.com/falcosecurity/falco-operator/internal/pkg/image"
	"github.com/falcosecurity/falco-operator/internal/pkg/resources"
)

var falcoDefs = resources.FalcoDefaults

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
		falco               *builders.FalcoBuilder
		nativeSidecar       bool
		wantKind            string
		wantContainerCount  int
		wantInitContainers  int
		wantMainImage       string
		wantTolerationCount int
		wantPodLabels       map[string]string
		wantReplicas        int64
		wantStrategyType    string
		wantUpdateStrategy  string
		wantVolumeMinCount  int
		wantErr             string
	}{
		{
			name:                "default DaemonSet produces expected base with sidecar as regular container",
			falco:               builders.NewFalco().WithName("test-f").WithNamespace(testutil.TestNamespace),
			nativeSidecar:       false,
			wantKind:            resources.ResourceTypeDaemonSet,
			wantContainerCount:  2,
			wantInitContainers:  0,
			wantMainImage:       image.BuildFalcoImageStringFromVersion(""),
			wantTolerationCount: len(falcoDefs.Tolerations),
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-f",
				"app.kubernetes.io/instance": "test-f",
			},
			wantUpdateStrategy: string(appsv1.RollingUpdateDaemonSetStrategyType),
			wantVolumeMinCount: len(falcoDefs.Volumes),
		},
		{
			name:                "native sidecar moves sidecar to initContainers",
			falco:               builders.NewFalco().WithName("test-f").WithNamespace(testutil.TestNamespace),
			nativeSidecar:       true,
			wantKind:            resources.ResourceTypeDaemonSet,
			wantContainerCount:  1,
			wantInitContainers:  1,
			wantMainImage:       image.BuildFalcoImageStringFromVersion(""),
			wantTolerationCount: len(falcoDefs.Tolerations),
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-f",
				"app.kubernetes.io/instance": "test-f",
			},
			wantUpdateStrategy: string(appsv1.RollingUpdateDaemonSetStrategyType),
			wantVolumeMinCount: len(falcoDefs.Volumes),
		},
		{
			name: "Deployment type produces Deployment kind",
			falco: builders.NewFalco().WithName("test-f").WithNamespace(testutil.TestNamespace).
				WithType(resources.ResourceTypeDeployment),
			nativeSidecar:       false,
			wantKind:            resources.ResourceTypeDeployment,
			wantContainerCount:  2,
			wantInitContainers:  0,
			wantMainImage:       image.BuildFalcoImageStringFromVersion(""),
			wantTolerationCount: len(falcoDefs.Tolerations),
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-f",
				"app.kubernetes.io/instance": "test-f",
			},
			wantReplicas:       1,
			wantStrategyType:   string(appsv1.RollingUpdateDeploymentStrategyType),
			wantVolumeMinCount: len(falcoDefs.Volumes),
		},
		{
			name: "custom version overrides container image",
			falco: builders.NewFalco().WithName("test-f").WithNamespace(testutil.TestNamespace).
				WithType(resources.ResourceTypeDeployment).WithVersion("0.38.0"),
			nativeSidecar:       false,
			wantKind:            resources.ResourceTypeDeployment,
			wantContainerCount:  2,
			wantInitContainers:  0,
			wantMainImage:       image.BuildFalcoImageStringFromVersion("0.38.0"),
			wantTolerationCount: len(falcoDefs.Tolerations),
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-f",
				"app.kubernetes.io/instance": "test-f",
			},
			wantReplicas:       1,
			wantStrategyType:   string(appsv1.RollingUpdateDeploymentStrategyType),
			wantVolumeMinCount: len(falcoDefs.Volumes),
		},
		{
			name: "custom replicas are propagated in Deployment",
			falco: builders.NewFalco().WithName("test-f").WithNamespace(testutil.TestNamespace).
				WithType(resources.ResourceTypeDeployment).WithReplicas(3),
			nativeSidecar:       false,
			wantKind:            resources.ResourceTypeDeployment,
			wantContainerCount:  2,
			wantInitContainers:  0,
			wantMainImage:       image.BuildFalcoImageStringFromVersion(""),
			wantTolerationCount: len(falcoDefs.Tolerations),
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-f",
				"app.kubernetes.io/instance": "test-f",
			},
			wantReplicas:       3,
			wantStrategyType:   string(appsv1.RollingUpdateDeploymentStrategyType),
			wantVolumeMinCount: len(falcoDefs.Volumes),
		},
		{
			name: "Recreate strategy overrides default RollingUpdate",
			falco: builders.NewFalco().WithName("test-f").WithNamespace(testutil.TestNamespace).
				WithType(resources.ResourceTypeDeployment).
				WithStrategy(appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}),
			nativeSidecar:       false,
			wantKind:            resources.ResourceTypeDeployment,
			wantContainerCount:  2,
			wantInitContainers:  0,
			wantMainImage:       image.BuildFalcoImageStringFromVersion(""),
			wantTolerationCount: len(falcoDefs.Tolerations),
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-f",
				"app.kubernetes.io/instance": "test-f",
			},
			wantReplicas:       1,
			wantStrategyType:   string(appsv1.RecreateDeploymentStrategyType),
			wantVolumeMinCount: len(falcoDefs.Volumes),
		},
		{
			name: "OnDelete updateStrategy overrides default RollingUpdate for DaemonSet",
			falco: builders.NewFalco().WithName("test-f").WithNamespace(testutil.TestNamespace).
				WithUpdateStrategy(appsv1.DaemonSetUpdateStrategy{Type: appsv1.OnDeleteDaemonSetStrategyType}),
			nativeSidecar:       false,
			wantKind:            resources.ResourceTypeDaemonSet,
			wantContainerCount:  2,
			wantInitContainers:  0,
			wantMainImage:       image.BuildFalcoImageStringFromVersion(""),
			wantTolerationCount: len(falcoDefs.Tolerations),
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-f",
				"app.kubernetes.io/instance": "test-f",
			},
			wantUpdateStrategy: string(appsv1.OnDeleteDaemonSetStrategyType),
			wantVolumeMinCount: len(falcoDefs.Volumes),
		},
		{
			name: "CR labels propagate to pod template",
			falco: builders.NewFalco().WithName("test-f").WithNamespace(testutil.TestNamespace).
				WithLabels(map[string]string{"team": "security", "env": "prod"}),
			nativeSidecar:       false,
			wantKind:            resources.ResourceTypeDaemonSet,
			wantContainerCount:  2,
			wantInitContainers:  0,
			wantMainImage:       image.BuildFalcoImageStringFromVersion(""),
			wantTolerationCount: len(falcoDefs.Tolerations),
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-f",
				"app.kubernetes.io/instance": "test-f",
				"team":                       "security",
				"env":                        "prod",
			},
			wantUpdateStrategy: string(appsv1.RollingUpdateDaemonSetStrategyType),
			wantVolumeMinCount: len(falcoDefs.Volumes),
		},
		{
			name: "custom PodTemplateSpec merges with base preserving probes and volumes",
			falco: builders.NewFalco().WithName("test-f").WithNamespace(testutil.TestNamespace).
				WithType(resources.ResourceTypeDeployment).
				WithImage(testContainerName, "custom-repo/falco:custom"),
			nativeSidecar:       false,
			wantKind:            resources.ResourceTypeDeployment,
			wantContainerCount:  2,
			wantInitContainers:  0,
			wantMainImage:       "custom-repo/falco:custom",
			wantTolerationCount: len(falcoDefs.Tolerations),
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-f",
				"app.kubernetes.io/instance": "test-f",
			},
			wantReplicas:       1,
			wantStrategyType:   string(appsv1.RollingUpdateDeploymentStrategyType),
			wantVolumeMinCount: len(falcoDefs.Volumes),
		},
		{
			name: "version is ignored when PodTemplateSpec provides main container",
			falco: builders.NewFalco().WithName("test-f").WithNamespace(testutil.TestNamespace).
				WithType(resources.ResourceTypeDeployment).
				WithVersion("0.38.0").
				WithImage(testContainerName, "custom-repo/falco:custom"),
			nativeSidecar:       false,
			wantKind:            resources.ResourceTypeDeployment,
			wantContainerCount:  2,
			wantInitContainers:  0,
			wantMainImage:       "custom-repo/falco:custom",
			wantTolerationCount: len(falcoDefs.Tolerations),
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-f",
				"app.kubernetes.io/instance": "test-f",
			},
			wantReplicas:       1,
			wantStrategyType:   string(appsv1.RollingUpdateDeploymentStrategyType),
			wantVolumeMinCount: len(falcoDefs.Volumes),
		},
		{
			name: "version applies when PodTemplateSpec has only pod-level fields",
			falco: builders.NewFalco().WithName("test-f").WithNamespace(testutil.TestNamespace).
				WithType(resources.ResourceTypeDeployment).
				WithVersion("0.38.0").
				WithPodTemplateSpec(&corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						NodeSelector: map[string]string{"disktype": "ssd"},
					},
				}),
			nativeSidecar:       false,
			wantKind:            resources.ResourceTypeDeployment,
			wantContainerCount:  2,
			wantInitContainers:  0,
			wantMainImage:       image.BuildFalcoImageStringFromVersion("0.38.0"),
			wantTolerationCount: len(falcoDefs.Tolerations),
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-f",
				"app.kubernetes.io/instance": "test-f",
			},
			wantReplicas:       1,
			wantStrategyType:   string(appsv1.RollingUpdateDeploymentStrategyType),
			wantVolumeMinCount: len(falcoDefs.Volumes),
		},
		{
			name: "version applies when PodTemplateSpec has only a sidecar container",
			falco: builders.NewFalco().WithName("test-f").WithNamespace(testutil.TestNamespace).
				WithType(resources.ResourceTypeDeployment).
				WithVersion("0.38.0").
				WithPodTemplateSpec(&corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "my-sidecar", Image: "sidecar:latest"}},
					},
				}),
			nativeSidecar:       false,
			wantKind:            resources.ResourceTypeDeployment,
			wantContainerCount:  3,
			wantInitContainers:  0,
			wantMainImage:       image.BuildFalcoImageStringFromVersion("0.38.0"),
			wantTolerationCount: len(falcoDefs.Tolerations),
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-f",
				"app.kubernetes.io/instance": "test-f",
			},
			wantReplicas:       1,
			wantStrategyType:   string(appsv1.RollingUpdateDeploymentStrategyType),
			wantVolumeMinCount: len(falcoDefs.Volumes),
		},
		{
			name: "invalid type returns error",
			falco: builders.NewFalco().WithName("test-f").WithNamespace(testutil.TestNamespace).
				WithType("InvalidType"),
			wantErr: "unsupported resource type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			falco := tt.falco.Build()
			result, err := generateApplyConfiguration(falco, tt.wantKind, tt.nativeSidecar)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, result)

			// Kind and identity.
			assert.Equal(t, tt.wantKind, result.GetKind())
			assert.Equal(t, "apps/v1", result.GetAPIVersion())
			assert.Equal(t, falco.Name, result.GetName())
			assert.Equal(t, testutil.TestNamespace, result.GetNamespace())

			// Pod template labels.
			podLabels, _, _ := unstructured.NestedStringMap(result.Object, "spec", "template", "metadata", "labels")
			for k, v := range tt.wantPodLabels {
				assert.Equal(t, v, podLabels[k], "pod template label %s", k)
			}

			// Containers.
			containers := mustGetContainers(t, result)
			assert.Len(t, containers, tt.wantContainerCount)
			mainContainer := mustFindContainer(t, containers, falcoDefs.ContainerName)
			assert.Equal(t, tt.wantMainImage, mainContainer["image"])

			// InitContainers.
			initContainers, _, _ := unstructured.NestedSlice(result.Object, "spec", "template", "spec", "initContainers")
			assert.Len(t, initContainers, tt.wantInitContainers)

			// Probes survive merge.
			assert.NotNil(t, mainContainer["livenessProbe"], "livenessProbe should survive merge")
			assert.NotNil(t, mainContainer["readinessProbe"], "readinessProbe should survive merge")

			// SecurityContext survives merge.
			assert.NotNil(t, mainContainer["securityContext"], "securityContext should survive merge")

			// Ports survive merge.
			ports, _, _ := unstructured.NestedSlice(mainContainer, "ports")
			assert.Len(t, ports, len(falcoDefs.DefaultPorts))

			// Resources survive merge.
			assert.NotNil(t, mainContainer["resources"], "resources should survive merge")

			// Env vars survive merge.
			envVars, _, _ := unstructured.NestedSlice(mainContainer, "env")
			assert.GreaterOrEqual(t, len(envVars), len(falcoDefs.EnvVars))

			// VolumeMounts survive merge.
			volumeMounts, _, _ := unstructured.NestedSlice(mainContainer, "volumeMounts")
			assert.GreaterOrEqual(t, len(volumeMounts), len(falcoDefs.VolumeMounts))

			// ServiceAccount.
			saName, _, _ := unstructured.NestedString(result.Object, "spec", "template", "spec", "serviceAccountName")
			assert.Equal(t, falco.Name, saName)

			// Tolerations.
			tolerations, _, _ := unstructured.NestedSlice(result.Object, "spec", "template", "spec", "tolerations")
			assert.Len(t, tolerations, tt.wantTolerationCount)

			// Volumes.
			volumes, _, _ := unstructured.NestedSlice(result.Object, "spec", "template", "spec", "volumes")
			assert.GreaterOrEqual(t, len(volumes), tt.wantVolumeMinCount)

			// Replicas (Deployment only).
			if tt.wantReplicas > 0 {
				replicas, found, _ := unstructured.NestedInt64(result.Object, "spec", "replicas")
				require.True(t, found, "replicas should be set")
				assert.Equal(t, tt.wantReplicas, replicas)
			}

			// Strategy (Deployment only).
			if tt.wantStrategyType != "" {
				strategyType, _, _ := unstructured.NestedString(result.Object, "spec", "strategy", "type")
				assert.Equal(t, tt.wantStrategyType, strategyType)
			}

			// UpdateStrategy (DaemonSet only).
			if tt.wantUpdateStrategy != "" {
				usType, _, _ := unstructured.NestedString(result.Object, "spec", "updateStrategy", "type")
				assert.Equal(t, tt.wantUpdateStrategy, usType)
			}

			// Verify sidecar container exists when expected.
			if tt.wantContainerCount > 1 {
				sidecarFound := false
				for _, c := range containers {
					cm := c.(map[string]any)
					if cm["name"] == falcoDefs.SidecarContainerName {
						sidecarFound = true
						break
					}
				}
				assert.True(t, sidecarFound, "sidecar container artifact-operator should be present")
			}

			// Verify sidecar in initContainers when nativeSidecar=true.
			if tt.wantInitContainers > 0 {
				initSidecarFound := false
				for _, c := range initContainers {
					cm := c.(map[string]any)
					if cm["name"] == falcoDefs.SidecarContainerName {
						initSidecarFound = true
						break
					}
				}
				assert.True(t, initSidecarFound, "sidecar should be in initContainers with nativeSidecar=true")
			}
		})
	}
}

// TestGenerateApplyConfigurationSidecarProbes verifies that the sidecar container
// retains its probes after the merge — structurally different from the table-driven test.
func TestGenerateApplyConfigurationSidecarProbes(t *testing.T) {
	falco := builders.NewFalco().WithName("test-f").WithNamespace(testutil.TestNamespace).
		WithType(resources.ResourceTypeDeployment).Build()

	result, err := generateApplyConfiguration(falco, resources.ResourceTypeDeployment, false)
	require.NoError(t, err)

	containers := mustGetContainers(t, result)
	sidecar := mustFindContainer(t, containers, falcoDefs.SidecarContainerName)
	assert.NotNil(t, sidecar["livenessProbe"], "sidecar livenessProbe should survive merge")
	assert.NotNil(t, sidecar["readinessProbe"], "sidecar readinessProbe should survive merge")
	assert.NotNil(t, sidecar["env"], "sidecar env vars should survive merge")

	sidecarVolumeMounts, _, _ := unstructured.NestedSlice(sidecar, "volumeMounts")
	assert.NotEmpty(t, sidecarVolumeMounts, "sidecar should have volumeMounts")
}

// TestGenerateApplyConfigurationConfigMapVolume verifies the configmap volume
// is added to the base — structurally different from the table-driven test.
func TestGenerateApplyConfigurationConfigMapVolume(t *testing.T) {
	falco := builders.NewFalco().WithName("test-f").WithNamespace(testutil.TestNamespace).
		WithType(resources.ResourceTypeDeployment).Build()

	result, err := generateApplyConfiguration(falco, resources.ResourceTypeDeployment, false)
	require.NoError(t, err)

	volumes, _, _ := unstructured.NestedSlice(result.Object, "spec", "template", "spec", "volumes")

	configMapVolumeFound := false
	for _, v := range volumes {
		vm := v.(map[string]any)
		if vm["name"] == falcoDefs.ConfigMapVolume.VolumeName {
			configMapVolumeFound = true
			cmSrc, _, _ := unstructured.NestedMap(vm, "configMap")
			assert.Equal(t, "test-f", cmSrc["name"], "configMap volume should reference the CR name")
			break
		}
	}
	assert.True(t, configMapVolumeFound, "configMap volume %q should be present", falcoDefs.ConfigMapVolume.VolumeName)

	containers := mustGetContainers(t, result)
	mainContainer := mustFindContainer(t, containers, falcoDefs.ContainerName)
	volumeMounts, _, _ := unstructured.NestedSlice(mainContainer, "volumeMounts")

	configMapMountFound := false
	for _, vm := range volumeMounts {
		m := vm.(map[string]any)
		if m["name"] == falcoDefs.ConfigMapVolume.VolumeName {
			configMapMountFound = true
			assert.Equal(t, falcoDefs.ConfigMapVolume.MountPath, m["mountPath"])
			assert.Equal(t, falcoDefs.ConfigMapVolume.SubPath, m["subPath"])
			break
		}
	}
	assert.True(t, configMapMountFound, "configMap volumeMount should be present")
}
