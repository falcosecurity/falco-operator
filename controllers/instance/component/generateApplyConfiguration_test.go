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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/image"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
	"github.com/falcosecurity/falco-operator/internal/pkg/resources"
)

var (
	mcDefs = resources.MetacollectorDefaults
	skDefs = resources.FalcosidekickDefaults
	uiDefs = resources.FalcosidekickUIDefaults
)

func newSidekickComponent(name string) *instancev1alpha1.Component {
	return &instancev1alpha1.Component{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testutil.TestNamespace,
		},
		Spec: instancev1alpha1.ComponentSpec{
			Component: instancev1alpha1.ComponentInfo{Type: instancev1alpha1.ComponentTypeFalcosidekick},
		},
	}
}

func newSidekickUIComponent(name string) *instancev1alpha1.Component {
	return &instancev1alpha1.Component{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testutil.TestNamespace,
		},
		Spec: instancev1alpha1.ComponentSpec{
			Component: instancev1alpha1.ComponentInfo{Type: instancev1alpha1.ComponentTypeFalcosidekickUI},
		},
	}
}

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

func TestGenerateApplyConfigurationImages(t *testing.T) {
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const requested = "9.8.7"
	previous := image.Registry
	t.Cleanup(func() { image.Registry = previous })

	for _, component := range []struct {
		kind       instancev1alpha1.ComponentType
		defs       *resources.InstanceDefaults
		repository string
	}{
		{kind: instancev1alpha1.ComponentTypeMetacollector, defs: mcDefs, repository: "falcosecurity/k8s-metacollector"},
		{kind: instancev1alpha1.ComponentTypeFalcosidekick, defs: skDefs, repository: "falcosecurity/falcosidekick"},
		{kind: instancev1alpha1.ComponentTypeFalcosidekickUI, defs: uiDefs, repository: "falcosecurity/falcosidekick-ui"},
	} {
		defs := component.defs
		type testCase struct {
			name      string
			version   *string
			mainImage string
			memory    bool
			env       bool
			initImage string
			initEnv   bool
			extra     bool
			wantTag   string
		}
		tests := []testCase{
			{name: "default version", wantTag: defs.ImageTag},
			{name: "empty version uses default", version: new(""), wantTag: defs.ImageTag},
			{name: "requested version", version: new(requested), wantTag: requested},
			{name: "memory override keeps default version", memory: true, wantTag: defs.ImageTag},
			{name: "env override keeps default version", env: true, wantTag: defs.ImageTag},
			{name: "memory override with empty version", version: new(""), memory: true, wantTag: defs.ImageTag},
			{name: "explicit Docker Hub image wins", version: new(requested), mainImage: "docker.io/" + component.repository + ":custom"},
			{name: "explicit external image wins", version: new(requested), mainImage: "registry.example.net:5000/team/component:custom"},
			{name: "unqualified image remains literal", version: new(requested), mainImage: "custom/component:custom"},
			{name: "tagless image remains literal", version: new(requested), mainImage: "custom/component"},
			{name: "digest-only image remains literal", version: new(requested), memory: true, mainImage: "docker.io/custom/component@" + digest},
			{name: "tag and digest image remains literal", version: new(requested), mainImage: "docker.io/custom/component:custom@" + digest},
			{name: "additional containers remain literal", extra: true, wantTag: defs.ImageTag},
		}
		if component.kind == instancev1alpha1.ComponentTypeFalcosidekickUI {
			tests = append(tests,
				testCase{name: "explicit Redis image wins", initImage: "docker.io/custom/redis:7", wantTag: defs.ImageTag},
				testCase{name: "Redis digest remains literal", initImage: "quay.io/custom/redis@" + digest, wantTag: defs.ImageTag},
				testCase{name: "Redis env override keeps generated image", initEnv: true, wantTag: defs.ImageTag},
			)
		}
		for _, registry := range []string{"docker.io", "registry.example.com:5000/team/cache"} {
			for _, tt := range tests {
				t.Run(string(component.kind)+"/"+registry+"/"+tt.name, func(t *testing.T) {
					require.NoError(t, image.SetRegistry(registry))
					comp := &instancev1alpha1.Component{
						ObjectMeta: metav1.ObjectMeta{Name: "test-component", Namespace: testutil.TestNamespace},
						Spec: instancev1alpha1.ComponentSpec{
							Component: instancev1alpha1.ComponentInfo{Type: component.kind, Version: tt.version},
						},
					}
					template := &corev1.PodTemplateSpec{}
					if tt.mainImage != "" || tt.memory || tt.env {
						main := corev1.Container{Name: defs.ContainerName, Image: tt.mainImage}
						if tt.memory {
							main.Resources.Requests = corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")}
						}
						if tt.env {
							main.Env = []corev1.EnvVar{{Name: "CUSTOM", Value: "preserved"}}
						}
						template.Spec.Containers = append(template.Spec.Containers, main)
					}
					if tt.initImage != "" || tt.initEnv {
						init := corev1.Container{Name: "wait-redis", Image: tt.initImage}
						if tt.initEnv {
							init.Env = []corev1.EnvVar{{Name: "REDIS_ADDR", Value: "custom-redis:6379"}}
						}
						template.Spec.InitContainers = append(template.Spec.InitContainers, init)
					}
					if tt.extra {
						template.Spec.Containers = append(template.Spec.Containers,
							corev1.Container{Name: "user-sidecar", Image: "docker.io/library/busybox:1.37"})
						template.Spec.InitContainers = append(template.Spec.InitContainers,
							corev1.Container{Name: "user-init", Image: "docker.io/library/alpine:3.21"})
					}
					if len(template.Spec.Containers)+len(template.Spec.InitContainers) > 0 {
						comp.Spec.PodTemplateSpec = template
					}
					before := comp.DeepCopy()
					defaultsBefore, err := json.Marshal(defs)
					require.NoError(t, err)

					result, err := generateApplyConfiguration(comp, defs)
					require.NoError(t, err)
					assert.Equal(t, before, comp)
					defaultsAfterFirst, err := json.Marshal(defs)
					require.NoError(t, err)
					assert.Equal(t, defaultsBefore, defaultsAfterFirst)
					assert.Equal(t, resources.ResourceTypeDeployment, result.GetKind())
					containers := mustGetContainers(t, result)
					var main corev1.Container
					require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(
						mustFindContainer(t, containers, defs.ContainerName), &main))
					wantMain := registry + "/" + component.repository + ":" + tt.wantTag
					if tt.mainImage != "" {
						wantMain = tt.mainImage
					} else {
						assert.Equal(t, tt.wantTag, instance.ResolveVersion(comp, defs))
					}
					assert.Equal(t, wantMain, main.Image)
					if tt.memory {
						assert.Equal(t, resource.MustParse("256Mi"), main.Resources.Requests[corev1.ResourceMemory])
					}
					if tt.env {
						assert.Contains(t, main.Env, corev1.EnvVar{Name: "CUSTOM", Value: "preserved"})
					}
					initContainers, _, err := unstructured.NestedSlice(result.Object, "spec", "template", "spec", "initContainers")
					require.NoError(t, err)
					if component.kind == instancev1alpha1.ComponentTypeFalcosidekickUI {
						wantInit := registry + "/redis/redis-stack:" + image.RedisTag
						if tt.initImage != "" {
							wantInit = tt.initImage
						}
						var init corev1.Container
						require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(
							mustFindContainer(t, initContainers, "wait-redis"), &init))
						assert.Equal(t, wantInit, init.Image)
						wantAddress := resources.DefaultRedisAddress
						if tt.initEnv {
							wantAddress = "custom-redis:6379"
						}
						assert.Contains(t, init.Env, corev1.EnvVar{Name: "REDIS_ADDR", Value: wantAddress})
					}
					if tt.extra {
						assert.Len(t, containers, 2)
						assert.Len(t, initContainers, len(defs.InitContainers)+1)
						assert.Equal(t, "docker.io/library/busybox:1.37", mustFindContainer(t, containers, "user-sidecar")["image"])
						assert.Equal(t, "docker.io/library/alpine:3.21", mustFindContainer(t, initContainers, "user-init")["image"])
					} else {
						assert.Len(t, containers, 1)
						assert.Len(t, initContainers, len(defs.InitContainers))
					}

					first := result.DeepCopy()
					repeated, err := generateApplyConfiguration(comp, defs)
					require.NoError(t, err)
					assert.Equal(t, first, result)
					assert.Equal(t, first, repeated)
					assert.Equal(t, before, comp)
					defaultsAfter, err := json.Marshal(defs)
					require.NoError(t, err)
					assert.Equal(t, defaultsBefore, defaultsAfter)
				})
			}
		}
	}
}

func TestGenerateApplyConfiguration(t *testing.T) {
	tests := []struct {
		name                string
		comp                *instancev1alpha1.Component
		defs                *resources.InstanceDefaults
		wantContainerCount  int
		wantInitContainers  int
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
			defs:                mcDefs,
			comp:                newMetacollectorComponent("test-mc"),
			wantContainerCount:  1,
			wantMainImage:       mcDefs.ImageName.Ref(mcDefs.ImageTag),
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
			name: "custom version overrides container image",
			defs: mcDefs,
			comp: func() *instancev1alpha1.Component {
				c := newMetacollectorComponent("test-mc")
				c.Spec.Component.Version = new("0.2.0")
				return c
			}(),
			wantContainerCount:  1,
			wantMainImage:       mcDefs.ImageName.Ref("0.2.0"),
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
			name: "custom replicas are propagated",
			defs: mcDefs,
			comp: func() *instancev1alpha1.Component {
				c := newMetacollectorComponent("test-mc")
				c.Spec.Replicas = new(int32(5))
				return c
			}(),
			wantContainerCount:  1,
			wantMainImage:       mcDefs.ImageName.Ref(mcDefs.ImageTag),
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
			defs: mcDefs,
			comp: func() *instancev1alpha1.Component {
				c := newMetacollectorComponent("test-mc")
				c.Spec.Strategy = &appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}
				return c
			}(),
			wantContainerCount:  1,
			wantMainImage:       mcDefs.ImageName.Ref(mcDefs.ImageTag),
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
			defs: mcDefs,
			comp: func() *instancev1alpha1.Component {
				c := newMetacollectorComponent("test-mc")
				c.Labels = map[string]string{"team": "security", "env": "prod"}
				return c
			}(),
			wantContainerCount:  1,
			wantMainImage:       mcDefs.ImageName.Ref(mcDefs.ImageTag),
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
			defs: mcDefs,
			comp: func() *instancev1alpha1.Component {
				c := newMetacollectorComponent("test-mc")
				c.Spec.PodTemplateSpec = &corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: mcDefs.ContainerName, Image: "custom-repo/metacollector:custom"}},
					},
				}
				return c
			}(),
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
			defs: mcDefs,
			comp: func() *instancev1alpha1.Component {
				c := newMetacollectorComponent("test-mc")
				c.Spec.Component.Version = new("0.2.0")
				c.Spec.PodTemplateSpec = &corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: mcDefs.ContainerName, Image: "custom-repo/metacollector:custom"}},
					},
				}
				return c
			}(),
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
			defs: mcDefs,
			comp: func() *instancev1alpha1.Component {
				c := newMetacollectorComponent("test-mc")
				c.Spec.Component.Version = new("0.2.0")
				c.Spec.PodTemplateSpec = &corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						NodeSelector: map[string]string{"disktype": "ssd"},
					},
				}
				return c
			}(),
			wantContainerCount:  1,
			wantMainImage:       mcDefs.ImageName.Ref("0.2.0"),
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
			name:               "default falcosidekick produces expected base",
			defs:               skDefs,
			comp:               newSidekickComponent("test-sk"),
			wantContainerCount: 1,
			wantMainImage:      skDefs.ImageName.Ref(skDefs.ImageTag),
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-sk",
				"app.kubernetes.io/instance": "test-sk",
			},
			wantReplicas:     2,
			wantStrategyType: string(appsv1.RollingUpdateDeploymentStrategyType),
		},
		{
			name:               "falcosidekick-ui has wait-redis init container",
			defs:               uiDefs,
			comp:               newSidekickUIComponent("test-ui"),
			wantContainerCount: 1,
			wantInitContainers: 1,
			wantMainImage:      uiDefs.ImageName.Ref(uiDefs.ImageTag),
			wantPodLabels: map[string]string{
				"app.kubernetes.io/name":     "test-ui",
				"app.kubernetes.io/instance": "test-ui",
			},
			wantReplicas:     2,
			wantStrategyType: string(appsv1.RollingUpdateDeploymentStrategyType),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := generateApplyConfiguration(tt.comp, tt.defs)

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
			mainContainer := mustFindContainer(t, containers, tt.defs.ContainerName)
			assert.Equal(t, tt.wantMainImage, mainContainer["image"])

			// Init containers.
			if tt.wantInitContainers > 0 {
				initContainers, _, _ := unstructured.NestedSlice(result.Object, "spec", "template", "spec", "initContainers")
				assert.Len(t, initContainers, tt.wantInitContainers)
			}

			// Probes survive merge.
			assert.NotNil(t, mainContainer["livenessProbe"], "livenessProbe should survive merge")
			assert.NotNil(t, mainContainer["readinessProbe"], "readinessProbe should survive merge")

			// SecurityContext survives merge (only when defaults define it).
			if tt.defs.SecurityContext != nil {
				assert.NotNil(t, mainContainer["securityContext"], "securityContext should survive merge")
			}

			// Ports survive merge.
			ports, _, _ := unstructured.NestedSlice(mainContainer, "ports")
			assert.Len(t, ports, len(tt.defs.DefaultPorts))

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

				// Verify mutually exclusive fields: Recreate must NOT have rollingUpdate.
				if strategyType == string(appsv1.RecreateDeploymentStrategyType) {
					_, found, _ := unstructured.NestedMap(result.Object, "spec", "strategy", "rollingUpdate")
					assert.False(t, found, "rollingUpdate must be absent for Recreate strategy so SSA removes it")
				}
			}
		})
	}
}
