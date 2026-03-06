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

package metacollector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
	"github.com/falcosecurity/falco-operator/internal/pkg/image"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

func TestDeploymentStrategy(t *testing.T) {
	tests := []struct {
		name     string
		mc       *instancev1alpha1.Metacollector
		wantType appsv1.DeploymentStrategyType
	}{
		{
			name:     "nil strategy defaults to RollingUpdate",
			mc:       builders.NewMetacollector().WithName("test").WithNamespace(testutil.TestNamespace).Build(),
			wantType: appsv1.RollingUpdateDeploymentStrategyType,
		},
		{
			name: "custom Recreate strategy",
			mc: builders.NewMetacollector().WithName("test").WithNamespace(testutil.TestNamespace).
				WithStrategy(appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}).Build(),
			wantType: appsv1.RecreateDeploymentStrategyType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := instance.DeploymentStrategy(tt.mc.Spec.Strategy)
			assert.Equal(t, tt.wantType, s.Type)
		})
	}
}

func TestBaseDeployment(t *testing.T) {
	mc := builders.NewMetacollector().WithName("test-mc").WithNamespace("default").
		WithLabels(map[string]string{"app": "metacollector"}).WithVersion("0.2.0").Build()

	dep := baseDeployment(mc)

	assert.Equal(t, "test-mc", dep.Name)
	assert.Equal(t, "default", dep.Namespace)
	assert.Equal(t, map[string]string{"app": "metacollector"}, dep.Labels)
	assert.Equal(t, "test-mc", dep.Spec.Selector.MatchLabels["app.kubernetes.io/name"])
	require.Len(t, dep.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, "metacollector", dep.Spec.Template.Spec.Containers[0].Name)
	assert.Equal(t, image.BuildMetacollectorImageStringFromVersion("0.2.0"), dep.Spec.Template.Spec.Containers[0].Image)
	assert.Equal(t, "test-mc", dep.Spec.Template.Spec.ServiceAccountName)

	// Verify pod template spec labels include selector labels
	assert.Equal(t, "test-mc", dep.Spec.Template.Labels["app.kubernetes.io/name"])
	assert.Equal(t, "test-mc", dep.Spec.Template.Labels["app.kubernetes.io/instance"])
	// Base labels should also be present
	assert.Equal(t, "metacollector", dep.Spec.Template.Labels["app"])
}

func TestPodTemplateSpecLabels(t *testing.T) {
	tests := []struct {
		name       string
		appName    string
		baseLabels map[string]string
		wantKeys   map[string]string
	}{
		{
			name:    "with nil base labels",
			appName: "test",
			wantKeys: map[string]string{
				"app.kubernetes.io/name":     "test",
				"app.kubernetes.io/instance": "test",
			},
		},
		{
			name:       "merges base labels",
			appName:    "test",
			baseLabels: map[string]string{"app": "metacollector"},
			wantKeys: map[string]string{
				"app.kubernetes.io/name":     "test",
				"app.kubernetes.io/instance": "test",
				"app":                        "metacollector",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels := instance.PodTemplateSpecLabels(tt.appName, tt.baseLabels)
			for k, v := range tt.wantKeys {
				assert.Equal(t, v, labels[k], "label %s", k)
			}
		})
	}
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := instance.RemoveEmptyContainers(tt.obj)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			_, found, _ := unstructured.NestedSlice(tt.obj.Object, "spec", "template", "spec", "containers")
			if tt.wantRemove {
				assert.False(t, found, "containers should be removed")
			} else {
				assert.True(t, found, "containers should be present")
			}
		})
	}
}

func TestGenerateApplyConfiguration(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	tests := []struct {
		name    string
		mc      *instancev1alpha1.Metacollector
		verify  func(*testing.T, *unstructured.Unstructured)
		wantErr bool
	}{
		{
			name: "generates valid Deployment configuration",
			mc:   builders.NewMetacollector().WithName("test-mc").WithNamespace("default").Build(),
			verify: func(t *testing.T, obj *unstructured.Unstructured) {
				assert.Equal(t, instance.ResourceTypeDeployment, obj.GetKind())
				assert.Equal(t, "apps/v1", obj.GetAPIVersion())
				assert.Equal(t, "test-mc", obj.GetName())
			},
		},
		{
			name: "generates with custom version",
			mc:   builders.NewMetacollector().WithName("test-mc").WithNamespace("default").WithVersion("0.2.0").Build(),
			verify: func(t *testing.T, obj *unstructured.Unstructured) {
				containers, found, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
				require.NoError(t, err)
				require.True(t, found)
				require.NotEmpty(t, containers)

				c0 := containers[0].(map[string]any)
				assert.Equal(t, image.BuildMetacollectorImageStringFromVersion("0.2.0"), c0["image"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().WithScheme(scheme).Build()
			obj, err := generateApplyConfiguration(cl, tt.mc)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, obj)
			tt.verify(t, obj)
		})
	}
}
