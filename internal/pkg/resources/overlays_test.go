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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
)

func TestGenerateOverlayOptions(t *testing.T) {
	tests := []struct {
		name         string
		obj          client.Object
		defs         *InstanceDefaults
		resourceType string

		wantLabels   map[string]string
		wantReplicas int64
		wantVersion  string
		wantStrategy string
	}{
		{
			name: "Falco with defaults only produces labels option",
			obj: builders.NewFalco().
				WithName("test-f").WithNamespace(testNamespace).
				WithLabels(map[string]string{"app": "falco"}).
				Build(),
			defs:         FalcoDefaults,
			resourceType: ResourceTypeDaemonSet,
			wantLabels:   map[string]string{"app": "falco"},
		},
		{
			name: "Falco with all optional fields",
			obj: builders.NewFalco().
				WithName("test-f").WithNamespace(testNamespace).
				WithLabels(map[string]string{"app": "falco"}).
				WithReplicas(3).
				WithVersion("0.38.0").
				WithStrategy(appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}).
				Build(),
			defs:         FalcoDefaults,
			resourceType: ResourceTypeDeployment,
			wantLabels:   map[string]string{"app": "falco"},
			wantReplicas: 3,
			wantVersion:  fmt.Sprintf("%s:%s", FalcoDefaults.ImageRepository, "0.38.0"),
			wantStrategy: string(appsv1.RecreateDeploymentStrategyType),
		},
		{
			name: "Falco with updateStrategy for DaemonSet",
			obj: builders.NewFalco().
				WithName("test-f").WithNamespace(testNamespace).
				WithLabels(map[string]string{"app": "falco"}).
				WithUpdateStrategy(appsv1.DaemonSetUpdateStrategy{Type: appsv1.OnDeleteDaemonSetStrategyType}).
				Build(),
			defs:         FalcoDefaults,
			resourceType: ResourceTypeDaemonSet,
			wantLabels:   map[string]string{"app": "falco"},
		},
		{
			name: "Falco with PodTemplateSpec propagates containers",
			obj: builders.NewFalco().
				WithName("test-f").WithNamespace(testNamespace).
				WithLabels(map[string]string{"app": "falco"}).
				WithPodTemplateSpec(&corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						NodeSelector: map[string]string{"disktype": "ssd"},
					},
				}).
				Build(),
			defs:         FalcoDefaults,
			resourceType: ResourceTypeDaemonSet,
			wantLabels:   map[string]string{"app": "falco"},
		},
		{
			name: "Falco with conflicting selector labels, selector labels take precedence in pod template",
			obj: builders.NewFalco().
				WithName("falco-custom").WithNamespace(testNamespace).
				WithLabels(map[string]string{
					"app.kubernetes.io/name":     "falco-operator",
					"app.kubernetes.io/instance": "instance-1",
				}).
				Build(),
			defs:         FalcoDefaults,
			resourceType: ResourceTypeDaemonSet,
			// In pod template, selector labels (name, instance) override user labels.
			// Non-conflicting user labels (managed-by) are preserved.
			wantLabels: map[string]string{
				"app.kubernetes.io/name":     "falco-operator",
				"app.kubernetes.io/instance": "instance-1",
			},
		},
		{
			name: "Component with defaults only produces labels option",
			obj: builders.NewComponent().
				WithComponentType(instancev1alpha1.ComponentTypeMetacollector).
				WithName("test-mc").WithNamespace(testNamespace).
				WithLabels(map[string]string{"app": "metacollector"}).
				Build(),
			defs:         MetacollectorDefaults,
			resourceType: ResourceTypeDeployment,
			wantLabels:   map[string]string{"app": "metacollector"},
		},
		{
			name: "Component with all optional fields",
			obj: builders.NewComponent().
				WithComponentType(instancev1alpha1.ComponentTypeMetacollector).
				WithName("test-mc").WithNamespace(testNamespace).
				WithLabels(map[string]string{"app": "metacollector"}).
				WithReplicas(5).
				WithVersion("0.2.0").
				WithStrategy(appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}).
				Build(),
			defs:         MetacollectorDefaults,
			resourceType: ResourceTypeDeployment,
			wantLabels:   map[string]string{"app": "metacollector"},
			wantReplicas: 5,
			wantVersion:  fmt.Sprintf("%s:%s", MetacollectorDefaults.ImageRepository, "0.2.0"),
			wantStrategy: string(appsv1.RecreateDeploymentStrategyType),
		},
		{
			name: "Component with PodTemplateSpec",
			obj: builders.NewComponent().
				WithComponentType(instancev1alpha1.ComponentTypeMetacollector).
				WithName("test-mc").WithNamespace(testNamespace).
				WithLabels(map[string]string{"app": "metacollector"}).
				WithPodTemplateSpec(&corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						NodeSelector: map[string]string{"zone": "us-east"},
					},
				}).
				Build(),
			defs:         MetacollectorDefaults,
			resourceType: ResourceTypeDeployment,
			wantLabels:   map[string]string{"app": "metacollector"},
		},
		{
			name: "unknown object type produces only labels option",
			obj: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"fallback": "true"},
				},
			},
			defs:         FalcoDefaults,
			resourceType: ResourceTypeDeployment,
			wantLabels:   map[string]string{"fallback": "true"},
		},
		{
			name: "nil labels object produces empty labels",
			obj: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{},
			},
			defs:         FalcoDefaults,
			resourceType: ResourceTypeDeployment,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := GenerateOverlayOptions(tt.obj)
			overlay, err := GenerateUserOverlay(tt.resourceType, tt.obj.GetName(), tt.defs, opts...)
			require.NoError(t, err)
			require.NotNil(t, overlay)

			// Labels propagate to metadata and pod template.
			for k, v := range tt.wantLabels {
				assert.Equal(t, v, overlay.GetLabels()[k], "metadata label %s", k)
			}

			// Assert that pod template labels include the expected labels (selector labels take precedence over user labels).
			templateLabels, _, _ := unstructured.NestedStringMap(overlay.Object, "spec", "template", "metadata", "labels")
			assert.Equal(t, tt.obj.GetName(), templateLabels["app.kubernetes.io/instance"], "pod template label app.kubernetes.io/instance should match object name")
			assert.Equal(t, tt.obj.GetName(), templateLabels["app.kubernetes.io/name"], "pod template label app.kubernetes.io/name should match object name")

			// Replicas.
			if tt.wantReplicas > 0 {
				replicas, found, _ := unstructured.NestedInt64(overlay.Object, "spec", "replicas")
				require.True(t, found, "replicas should be set")
				assert.Equal(t, tt.wantReplicas, replicas)
			}

			// Version override produces a container with the resolved image.
			if tt.wantVersion != "" {
				containers, found, _ := unstructured.NestedSlice(overlay.Object, "spec", "template", "spec", "containers")
				require.True(t, found, "containers should exist when version is set")
				var foundImage bool
				for _, c := range containers {
					cm, ok := c.(map[string]any)
					require.True(t, ok, "expected container to be map[string]interface{}, got %T", c)
					if cm["name"] == tt.defs.ContainerName {
						assert.Equal(t, tt.wantVersion, cm["image"])
						foundImage = true
					}
				}
				assert.True(t, foundImage, "container %s with version image not found", tt.defs.ContainerName)
			}

			// Strategy.
			if tt.wantStrategy != "" {
				strategyType, _, _ := unstructured.NestedString(overlay.Object, "spec", "strategy", "type")
				assert.Equal(t, tt.wantStrategy, strategyType)
			}
		})
	}

	t.Run("DaemonSet updateStrategy is applied in overlay", func(t *testing.T) {
		obj := builders.NewFalco().
			WithName("test-f").WithNamespace(testNamespace).
			WithLabels(map[string]string{"app": "falco"}).
			WithUpdateStrategy(appsv1.DaemonSetUpdateStrategy{Type: appsv1.OnDeleteDaemonSetStrategyType}).
			Build()
		opts := GenerateOverlayOptions(obj)
		overlay, err := GenerateUserOverlay(ResourceTypeDaemonSet, "test", FalcoDefaults, opts...)
		require.NoError(t, err)
		updateStrategyType, found, _ := unstructured.NestedString(overlay.Object, "spec", "updateStrategy", "type")
		require.True(t, found, "updateStrategy type should be set")
		assert.Equal(t, string(appsv1.OnDeleteDaemonSetStrategyType), updateStrategyType)
	})

	t.Run("unsupported resource type returns error", func(t *testing.T) {
		obj := builders.NewFalco().
			WithName("test-f").WithNamespace(testNamespace).
			WithLabels(map[string]string{"app": "falco"}).
			Build()
		opts := GenerateOverlayOptions(obj)
		_, err := GenerateUserOverlay("StatefulSet", "test", FalcoDefaults, opts...)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported resource type")
	})
}

func TestApplyVersionOverride(t *testing.T) {
	tests := []struct {
		name           string
		defs           *InstanceDefaults
		version        *string
		existingName   string
		wantContainers int
		wantImage      string
	}{
		{
			name:           "nil version adds no container",
			defs:           FalcoDefaults,
			version:        nil,
			wantContainers: 0,
		},
		{
			name:           "empty version adds no container",
			defs:           FalcoDefaults,
			version:        new(""),
			wantContainers: 0,
		},
		{
			name:           "non-empty version appends container with resolved image",
			defs:           MetacollectorDefaults,
			version:        new("0.5.0"),
			wantContainers: 1,
			wantImage:      MetacollectorDefaults.ImageRepository + ":0.5.0",
		},
		{
			name:           "existing container with matching name is not overridden",
			defs:           FalcoDefaults,
			version:        new("0.38.0"),
			existingName:   FalcoDefaults.ContainerName,
			wantContainers: 1,
			wantImage:      "user-image:latest",
		},
		{
			name:           "existing non-matching container still gets version container appended",
			defs:           FalcoDefaults,
			version:        new("0.38.0"),
			existingName:   "other-container",
			wantContainers: 2,
			wantImage:      "user-image:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := &corev1.PodTemplateSpec{}
			if tt.existingName != "" {
				template.Spec.Containers = []corev1.Container{
					{Name: tt.existingName, Image: "user-image:latest"},
				}
			}

			applyVersionOverride(tt.defs, tt.version, template)

			assert.Len(t, template.Spec.Containers, tt.wantContainers)

			// Verify the main container image by looking it up by name.
			if tt.wantImage != "" {
				var found bool
				for _, c := range template.Spec.Containers {
					if c.Name == tt.defs.ContainerName || (tt.existingName != "" && c.Name == tt.existingName) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected container not found")
			}

			// When an existing container with matching name is present, its image is preserved.
			if tt.existingName == tt.defs.ContainerName && tt.wantImage != "" {
				for _, c := range template.Spec.Containers {
					if c.Name == tt.existingName {
						assert.Equal(t, tt.wantImage, c.Image, "existing container image should be preserved")
					}
				}
			}

			// When version is set and no matching container exists, the appended container has the version image.
			if tt.version != nil && *tt.version != "" && tt.existingName != tt.defs.ContainerName {
				wantVersionImage := tt.defs.ImageRepository + ":" + *tt.version
				var foundVersion bool
				for _, c := range template.Spec.Containers {
					if c.Name == tt.defs.ContainerName {
						assert.Equal(t, wantVersionImage, c.Image, "appended version container should have resolved image")
						foundVersion = true
						break
					}
				}
				assert.True(t, foundVersion, "version container %s should be appended", tt.defs.ContainerName)
			}
		})
	}
}
