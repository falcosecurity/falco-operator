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

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/falcosecurity/falco-operator/internal/pkg/version"
)

//go:fix inline
func ptrInt32(v int32) *int32 { return new(v) }

// mustGetPodTemplateLabels extracts pod template labels from an unstructured workload.
func mustGetPodTemplateLabels(t *testing.T, obj *unstructured.Unstructured) map[string]string {
	t.Helper()
	labels, _, err := unstructured.NestedStringMap(obj.Object, "spec", "template", "metadata", "labels")
	require.NoError(t, err)
	return labels
}

func TestGenerateWorkload(t *testing.T) {
	tests := []struct {
		name               string
		kind               string
		defs               *InstanceDefaults
		nativeSidecar      bool
		wantInitContainers int
		wantContainers     int
		wantTolerations    int
		wantSidecarName    string
	}{
		{
			name:               "Falco Deployment non-native sidecar",
			kind:               ResourceTypeDeployment,
			defs:               FalcoDefaults,
			nativeSidecar:      false,
			wantInitContainers: 0,
			wantContainers:     2,
			wantTolerations:    2,
			wantSidecarName:    "artifact-operator",
		},
		{
			name:               "Falco Deployment native sidecar",
			kind:               ResourceTypeDeployment,
			defs:               FalcoDefaults,
			nativeSidecar:      true,
			wantInitContainers: 1,
			wantContainers:     1,
			wantTolerations:    2,
			wantSidecarName:    "artifact-operator",
		},
		{
			name:               "Falco DaemonSet non-native sidecar",
			kind:               ResourceTypeDaemonSet,
			defs:               FalcoDefaults,
			nativeSidecar:      false,
			wantInitContainers: 0,
			wantContainers:     2,
			wantTolerations:    2,
			wantSidecarName:    "artifact-operator",
		},
		{
			name:               "Falco DaemonSet native sidecar",
			kind:               ResourceTypeDaemonSet,
			defs:               FalcoDefaults,
			nativeSidecar:      true,
			wantInitContainers: 1,
			wantContainers:     1,
			wantTolerations:    2,
			wantSidecarName:    "artifact-operator",
		},
		{
			name:               "Metacollector Deployment without sidecar",
			kind:               ResourceTypeDeployment,
			defs:               MetacollectorDefaults,
			nativeSidecar:      false,
			wantInitContainers: 0,
			wantContainers:     1,
			wantTolerations:    0,
		},
		{
			name:               "Metacollector Deployment native sidecar flag has no effect",
			kind:               ResourceTypeDeployment,
			defs:               MetacollectorDefaults,
			nativeSidecar:      true,
			wantInitContainers: 0,
			wantContainers:     1,
			wantTolerations:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := &metav1.ObjectMeta{Name: "test", Namespace: testNamespace}
			obj, err := GenerateWorkload(tt.kind, meta, tt.defs, tt.nativeSidecar)
			require.NoError(t, err)

			var podSpec corev1.PodSpec
			var selector map[string]string
			var podTemplateLabels map[string]string

			switch w := obj.(type) {
			case *appsv1.Deployment:
				assert.Equal(t, "test", w.Name)
				assert.Equal(t, testNamespace, w.Namespace)
				assert.Empty(t, w.Labels)
				selector = w.Spec.Selector.MatchLabels
				podTemplateLabels = w.Spec.Template.Labels
				podSpec = w.Spec.Template.Spec
			case *appsv1.DaemonSet:
				assert.Equal(t, "test", w.Name)
				assert.Equal(t, testNamespace, w.Namespace)
				assert.Empty(t, w.Labels)
				selector = w.Spec.Selector.MatchLabels
				podTemplateLabels = w.Spec.Template.Labels
				podSpec = w.Spec.Template.Spec
			default:
				t.Fatalf("unexpected workload type: %T", obj)
			}

			assert.Equal(t, forgeSelectorLabels("test"), selector)
			assert.Equal(t, forgeSelectorLabels("test"), podTemplateLabels)
			assert.Equal(t, "test", podSpec.ServiceAccountName)
			assert.Len(t, podSpec.Tolerations, tt.wantTolerations)
			require.Len(t, podSpec.InitContainers, tt.wantInitContainers)
			require.Len(t, podSpec.Containers, tt.wantContainers)

			// Verify main container properties by looking it up by name.
			wantImage := tt.defs.ImageRepository + ":" + tt.defs.ImageTag
			var foundMain bool
			for _, c := range podSpec.Containers {
				if c.Name != tt.defs.ContainerName {
					continue
				}
				foundMain = true
				assert.Equal(t, wantImage, c.Image, "main container should have the correct image")
				assert.Equal(t, tt.defs.ImagePullPolicy, c.ImagePullPolicy, "main container should have the correct pull policy")
				assert.Equal(t, tt.defs.DefaultCommand, c.Command, "main container should have the correct command")
				assert.Equal(t, tt.defs.DefaultArgs, c.Args, "main container should have the correct args")
				// Verify ports by name lookup.
				for _, expectedPort := range tt.defs.DefaultPorts {
					var portFound bool
					for _, actualPort := range c.Ports {
						if actualPort.Name == expectedPort.Name {
							assert.Equal(t, expectedPort.ContainerPort, actualPort.ContainerPort, "port %s should have correct container port", expectedPort.Name)
							assert.Equal(t, expectedPort.Protocol, actualPort.Protocol, "port %s should have correct protocol", expectedPort.Name)
							portFound = true
							break
						}
					}
					assert.True(t, portFound, "expected container port %s not found", expectedPort.Name)
				}
				break
			}
			assert.True(t, foundMain, "main container %s not found in containers", tt.defs.ContainerName)

			// Verify sidecar container properties.
			if tt.wantSidecarName != "" {
				if tt.nativeSidecar {
					// Native sidecar: should be in initContainers with RestartPolicy Always.
					var foundSidecar bool
					for _, c := range podSpec.InitContainers {
						if c.Name != tt.wantSidecarName {
							continue
						}
						foundSidecar = true
						assert.Equal(t, version.ArtifactOperatorImage, c.Image, "sidecar should have the correct image")
						require.NotNil(t, c.RestartPolicy, "native sidecar should have RestartPolicy set")
						assert.Equal(t, corev1.ContainerRestartPolicyAlways, *c.RestartPolicy, "native sidecar RestartPolicy should be Always")
						break
					}
					assert.True(t, foundSidecar, "native sidecar %s not found in initContainers", tt.wantSidecarName)
					// Should NOT be in regular containers.
					for _, c := range podSpec.Containers {
						assert.NotEqual(t, tt.wantSidecarName, c.Name, "native sidecar should not be in containers")
					}
				} else {
					// Non-native sidecar: should be in containers with nil RestartPolicy.
					var foundSidecar bool
					for _, c := range podSpec.Containers {
						if c.Name == tt.wantSidecarName {
							foundSidecar = true
							assert.Equal(t, version.ArtifactOperatorImage, c.Image, "sidecar should have the correct image")
							assert.Nil(t, c.RestartPolicy, "non-native sidecar should have nil RestartPolicy")
							break
						}
					}
					assert.True(t, foundSidecar, "non-native sidecar %s not found in containers", tt.wantSidecarName)
					// Should NOT be in initContainers.
					for _, c := range podSpec.InitContainers {
						assert.NotEqual(t, tt.wantSidecarName, c.Name, "non-native sidecar should not be in initContainers")
					}
				}
			}
		})
	}
}

func TestGenerateWorkloadErrors(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		defs         *InstanceDefaults
		wantErrMsg   string
	}{
		{
			name:         "metacollector does not support DaemonSet",
			resourceType: ResourceTypeDaemonSet,
			defs:         MetacollectorDefaults,
			wantErrMsg:   "not supported",
		},
		{
			name:         "unsupported resource type",
			resourceType: "StatefulSet",
			defs:         FalcoDefaults,
			wantErrMsg:   "unsupported resource type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := &metav1.ObjectMeta{Name: "test", Namespace: testNamespace}
			_, err := GenerateWorkload(tt.resourceType, meta, tt.defs, false)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrMsg)
		})
	}
}

func TestGenerateUserOverlay(t *testing.T) {
	tests := []struct {
		name            string
		resourceType    string
		crLabels        map[string]string
		replicas        *int32
		updateStrategy  *appsv1.DaemonSetUpdateStrategy
		podTemplateSpec *corev1.PodTemplateSpec
		wantErr         bool
		wantPodLabels   map[string]string
		wantHasReplicas bool
	}{
		{
			name:         "Deployment with labels, replicas, and PodTemplateSpec",
			resourceType: ResourceTypeDeployment,
			crLabels:     map[string]string{"app": "falco", "env": "prod"},
			replicas:     ptrInt32(3),
			podTemplateSpec: &corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{"node": "worker"},
				},
			},
			wantPodLabels:   map[string]string{"app": "falco", "env": "prod"},
			wantHasReplicas: true,
		},
		{
			name:          "Deployment without PodTemplateSpec propagates labels to pod template",
			resourceType:  ResourceTypeDeployment,
			crLabels:      map[string]string{"app": "falco"},
			wantPodLabels: map[string]string{"app": "falco"},
		},
		{
			name:         "DaemonSet with update strategy",
			resourceType: ResourceTypeDaemonSet,
			crLabels:     map[string]string{"app": "falco"},
			updateStrategy: &appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.OnDeleteDaemonSetStrategyType,
			},
			wantPodLabels: map[string]string{"app": "falco"},
		},
		{
			name:         "unsupported resource type returns error",
			resourceType: "StatefulSet",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts []OverlayOption
			if tt.crLabels != nil {
				opts = append(opts, WithOverlayLabels(tt.crLabels))
			}
			if tt.replicas != nil {
				opts = append(opts, WithOverlayReplicas(tt.replicas))
			}
			if tt.updateStrategy != nil {
				opts = append(opts, WithOverlayUpdateStrategy(tt.updateStrategy))
			}
			if tt.podTemplateSpec != nil {
				opts = append(opts, WithOverlayPodTemplateSpec(tt.podTemplateSpec))
			}

			overlay, err := GenerateUserOverlay(tt.resourceType, "test", FalcoDefaults, opts...)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, overlay)

			if tt.crLabels != nil {
				for k, v := range tt.crLabels {
					assert.Equal(t, v, overlay.GetLabels()[k], "metadata label %s", k)
				}
			}

			templateLabels := mustGetPodTemplateLabels(t, overlay)
			for k, v := range tt.wantPodLabels {
				assert.Equal(t, v, templateLabels[k], "pod template label %s", k)
			}

			if tt.wantHasReplicas {
				replicas, found, _ := unstructured.NestedInt64(overlay.Object, "spec", "replicas")
				require.True(t, found)
				assert.Equal(t, int64(*tt.replicas), replicas)
			}
		})
	}
}

func TestForgeSelectorLabels(t *testing.T) {
	labels := forgeSelectorLabels("my-app")
	assert.Equal(t, "my-app", labels["app.kubernetes.io/name"])
	assert.Equal(t, "my-app", labels["app.kubernetes.io/instance"])
	assert.Len(t, labels, 2)
}

func TestForgePodTemplateSpecLabels(t *testing.T) {
	tests := []struct {
		name       string
		appName    string
		baseLabels map[string]string
		wantKeys   map[string]string
	}{
		{
			name:    "nil base labels returns selector labels only",
			appName: "test",
			wantKeys: map[string]string{
				"app.kubernetes.io/name":     "test",
				"app.kubernetes.io/instance": "test",
			},
		},
		{
			name:       "merges base labels with selector labels",
			appName:    "test",
			baseLabels: map[string]string{"app": "falco", "team": "security"},
			wantKeys: map[string]string{
				"app.kubernetes.io/name":     "test",
				"app.kubernetes.io/instance": "test",
				"app":                        "falco",
				"team":                       "security",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels := forgePodTemplateSpecLabels(tt.appName, tt.baseLabels)
			for k, v := range tt.wantKeys {
				assert.Equal(t, v, labels[k], "label %s", k)
			}
		})
	}
}

func TestForgeDeploymentStrategy(t *testing.T) {
	tests := []struct {
		name     string
		strategy *appsv1.DeploymentStrategy
		wantType appsv1.DeploymentStrategyType
	}{
		{
			name:     "nil defaults to RollingUpdate",
			strategy: nil,
			wantType: appsv1.RollingUpdateDeploymentStrategyType,
		},
		{
			name:     "Recreate strategy",
			strategy: &appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
			wantType: appsv1.RecreateDeploymentStrategyType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := forgeDeploymentStrategy(tt.strategy)
			assert.Equal(t, tt.wantType, s.Type)
		})
	}
}

func TestForgeDaemonSetUpdateStrategy(t *testing.T) {
	tests := []struct {
		name     string
		strategy *appsv1.DaemonSetUpdateStrategy
		wantType appsv1.DaemonSetUpdateStrategyType
	}{
		{
			name:     "nil defaults to RollingUpdate",
			strategy: nil,
			wantType: appsv1.RollingUpdateDaemonSetStrategyType,
		},
		{
			name:     "OnDelete strategy",
			strategy: &appsv1.DaemonSetUpdateStrategy{Type: appsv1.OnDeleteDaemonSetStrategyType},
			wantType: appsv1.OnDeleteDaemonSetStrategyType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := forgeDaemonSetUpdateStrategy(tt.strategy)
			assert.Equal(t, tt.wantType, s.Type)
		})
	}
}

func TestForgeMainContainer(t *testing.T) {
	tests := []struct {
		name string
		defs *InstanceDefaults
	}{
		{
			name: "Falco main container",
			defs: FalcoDefaults,
		},
		{
			name: "Metacollector main container",
			defs: MetacollectorDefaults,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := forgeMainContainer(tt.defs)
			require.NotNil(t, c)
			assert.Equal(t, tt.defs.ContainerName, c.Name)
			assert.Equal(t, tt.defs.ImageRepository+":"+tt.defs.ImageTag, c.Image)
			assert.Equal(t, tt.defs.ImagePullPolicy, c.ImagePullPolicy)
			assert.Equal(t, tt.defs.DefaultCommand, c.Command)
			assert.Equal(t, tt.defs.DefaultArgs, c.Args)
			assert.Equal(t, tt.defs.EnvVars, c.Env)
			assert.Equal(t, tt.defs.LivenessProbe, c.LivenessProbe)
			assert.Equal(t, tt.defs.ReadinessProbe, c.ReadinessProbe)
			assert.Equal(t, tt.defs.SecurityContext, c.SecurityContext)
			// Ports match defaults by name.
			for _, expectedPort := range tt.defs.DefaultPorts {
				var found bool
				for _, actualPort := range c.Ports {
					if actualPort.Name == expectedPort.Name {
						assert.Equal(t, expectedPort.ContainerPort, actualPort.ContainerPort)
						found = true
						break
					}
				}
				assert.True(t, found, "expected port %s not found", expectedPort.Name)
			}
		})
	}
}

func TestForgeVolumes(t *testing.T) {
	t.Run("with ConfigMapVolume adds ConfigMap volume", func(t *testing.T) {
		volumes := forgeVolumes("my-cr", FalcoDefaults)
		// Should include all defaults plus the ConfigMap volume.
		assert.Len(t, volumes, len(FalcoDefaults.Volumes)+1)
		var foundCMVol bool
		for _, v := range volumes {
			if v.Name == FalcoDefaults.ConfigMapVolume.VolumeName {
				foundCMVol = true
				require.NotNil(t, v.ConfigMap, "ConfigMap volume source should be set")
				assert.Equal(t, "my-cr", v.ConfigMap.Name)
				break
			}
		}
		assert.True(t, foundCMVol, "ConfigMap volume should be present")
	})

	t.Run("without ConfigMapVolume returns only default volumes", func(t *testing.T) {
		volumes := forgeVolumes("my-cr", MetacollectorDefaults)
		assert.Len(t, volumes, len(MetacollectorDefaults.Volumes))
		for _, v := range volumes {
			assert.Nil(t, v.ConfigMap, "no ConfigMap volume expected for metacollector")
		}
	})
}

func TestForgeVolumeMounts(t *testing.T) {
	t.Run("with ConfigMapVolume adds ConfigMap mount", func(t *testing.T) {
		mounts := forgeVolumeMounts(FalcoDefaults)
		// Should include all defaults plus the ConfigMap mount.
		assert.Len(t, mounts, len(FalcoDefaults.VolumeMounts)+1)
		var foundCMMount bool
		for _, m := range mounts {
			if m.Name == FalcoDefaults.ConfigMapVolume.VolumeName {
				foundCMMount = true
				assert.Equal(t, FalcoDefaults.ConfigMapVolume.MountPath, m.MountPath)
				assert.Equal(t, FalcoDefaults.ConfigMapVolume.SubPath, m.SubPath)
				break
			}
		}
		assert.True(t, foundCMMount, "ConfigMap volume mount should be present")
	})

	t.Run("without ConfigMapVolume returns only default mounts", func(t *testing.T) {
		mounts := forgeVolumeMounts(MetacollectorDefaults)
		assert.Len(t, mounts, len(MetacollectorDefaults.VolumeMounts))
	})
}

func TestRemoveEmptyContainers(t *testing.T) {
	tests := []struct {
		name       string
		obj        *unstructured.Unstructured
		wantErr    bool
		wantRemove bool
	}{
		{
			name: "removes nil containers field",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"spec": map[string]any{
						"template": map[string]any{
							"spec": map[string]any{
								"containers": nil,
							},
						},
					},
				},
			},
			wantRemove: true,
		},
		{
			name: "keeps non-nil containers field",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"spec": map[string]any{
						"template": map[string]any{
							"spec": map[string]any{
								"containers": []any{
									map[string]any{"name": "test"},
								},
							},
						},
					},
				},
			},
			wantRemove: false,
		},
		{
			name: "no-op when containers key is absent",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"spec": map[string]any{
						"template": map[string]any{
							"spec": map[string]any{},
						},
					},
				},
			},
			wantRemove: false,
		},
		{
			name: "returns error when spec.template.spec is missing",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"spec": map[string]any{
						"template": map[string]any{},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "returns error when spec.template is missing",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"spec": map[string]any{},
				},
			},
			wantErr: true,
		},
		{
			name: "removes empty slice containers field",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"spec": map[string]any{
						"template": map[string]any{
							"spec": map[string]any{
								"containers": []any{},
							},
						},
					},
				},
			},
			wantRemove: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := removeEmptyContainers(tt.obj)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			_, found, _ := unstructured.NestedSlice(tt.obj.Object, "spec", "template", "spec", "containers")
			if tt.wantRemove {
				assert.False(t, found, "containers should be removed")
			}
		})
	}
}
