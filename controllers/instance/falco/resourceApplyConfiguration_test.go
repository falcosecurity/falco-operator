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
		falco    *instancev1alpha1.Falco
		wantType appsv1.DeploymentStrategyType
	}{
		{
			name:     "nil strategy defaults to RollingUpdate",
			falco:    builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType(instance.ResourceTypeDeployment).Build(),
			wantType: appsv1.RollingUpdateDeploymentStrategyType,
		},
		{
			name: "custom Recreate strategy",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
				WithType(instance.ResourceTypeDeployment).
				WithStrategy(appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}).Build(),
			wantType: appsv1.RecreateDeploymentStrategyType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := instance.DeploymentStrategy(tt.falco.Spec.Strategy)
			assert.Equal(t, tt.wantType, s.Type)
		})
	}
}

func TestDaemonSetUpdateStrategy(t *testing.T) {
	tests := []struct {
		name     string
		falco    *instancev1alpha1.Falco
		wantType appsv1.DaemonSetUpdateStrategyType
	}{
		{
			name:     "nil strategy defaults to RollingUpdate",
			falco:    builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType(instance.ResourceTypeDaemonSet).Build(),
			wantType: appsv1.RollingUpdateDaemonSetStrategyType,
		},
		{
			name: "custom OnDelete strategy",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
				WithType(instance.ResourceTypeDaemonSet).
				WithUpdateStrategy(appsv1.DaemonSetUpdateStrategy{Type: appsv1.OnDeleteDaemonSetStrategyType}).Build(),
			wantType: appsv1.OnDeleteDaemonSetStrategyType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := instance.DaemonSetUpdateStrategy(tt.falco.Spec.UpdateStrategy)
			assert.Equal(t, tt.wantType, s.Type)
		})
	}
}

func TestBaseWorkload(t *testing.T) {
	tests := []struct {
		name               string
		kind               string
		nativeSidecar      bool
		falco              *instancev1alpha1.Falco
		wantImage          string
		wantInitContainers int
		wantContainers     int
	}{
		{
			name:               "Deployment: non-native sidecar adds artifact operator to containers",
			kind:               instance.ResourceTypeDeployment,
			nativeSidecar:      false,
			falco:              builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithVersion("0.38.0").Build(),
			wantImage:          image.BuildFalcoImageStringFromVersion("0.38.0"),
			wantInitContainers: 0,
			wantContainers:     2,
		},
		{
			name:               "Deployment: native sidecar adds artifact operator to initContainers",
			kind:               instance.ResourceTypeDeployment,
			nativeSidecar:      true,
			falco:              builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithVersion("0.38.0").Build(),
			wantImage:          image.BuildFalcoImageStringFromVersion("0.38.0"),
			wantInitContainers: 1,
			wantContainers:     1,
		},
		{
			name:               "DaemonSet: non-native sidecar adds artifact operator to containers",
			kind:               instance.ResourceTypeDaemonSet,
			nativeSidecar:      false,
			falco:              builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithVersion("0.38.0").Build(),
			wantImage:          image.BuildFalcoImageStringFromVersion("0.38.0"),
			wantInitContainers: 0,
			wantContainers:     2,
		},
		{
			name:               "DaemonSet: native sidecar adds artifact operator to initContainers",
			kind:               instance.ResourceTypeDaemonSet,
			nativeSidecar:      true,
			falco:              builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithVersion("0.38.0").Build(),
			wantImage:          image.BuildFalcoImageStringFromVersion("0.38.0"),
			wantInitContainers: 1,
			wantContainers:     1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var name, namespace string
			var selector map[string]string
			var podSpec corev1.PodSpec

			switch tt.kind {
			case instance.ResourceTypeDeployment:
				dep := baseDeployment(tt.nativeSidecar, tt.falco)
				name = dep.Name
				namespace = dep.Namespace
				selector = dep.Spec.Selector.MatchLabels
				podSpec = dep.Spec.Template.Spec
			case instance.ResourceTypeDaemonSet:
				ds := baseDaemonSet(tt.nativeSidecar, tt.falco)
				name = ds.Name
				namespace = ds.Namespace
				selector = ds.Spec.Selector.MatchLabels
				podSpec = ds.Spec.Template.Spec
			}

			assert.Equal(t, tt.falco.Name, name)
			assert.Equal(t, tt.falco.Namespace, namespace)
			assert.Equal(t, tt.falco.Name, selector["app.kubernetes.io/name"])
			assert.Equal(t, tt.falco.Name, podSpec.ServiceAccountName)
			require.Len(t, podSpec.Tolerations, 2)
			assert.Len(t, podSpec.InitContainers, tt.wantInitContainers)
			assert.Len(t, podSpec.Containers, tt.wantContainers)
			assert.Equal(t, tt.wantImage, podSpec.Containers[0].Image)
		})
	}
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
			baseLabels: map[string]string{"app": "falco"},
			wantKeys: map[string]string{
				"app.kubernetes.io/name":     "test",
				"app.kubernetes.io/instance": "test",
				"app":                        "falco",
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
		name   string
		falco  *instancev1alpha1.Falco
		verify func(*testing.T, *unstructured.Unstructured)
	}{
		{
			name:  "generates valid Deployment configuration",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType(instance.ResourceTypeDeployment).Build(),
			verify: func(t *testing.T, obj *unstructured.Unstructured) {
				assert.Equal(t, instance.ResourceTypeDeployment, obj.GetKind())
				assert.Equal(t, "apps/v1", obj.GetAPIVersion())
				assert.Equal(t, "test", obj.GetName())
			},
		},
		{
			name:  "generates valid DaemonSet configuration",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType(instance.ResourceTypeDaemonSet).Build(),
			verify: func(t *testing.T, obj *unstructured.Unstructured) {
				assert.Equal(t, instance.ResourceTypeDaemonSet, obj.GetKind())
				assert.Equal(t, "apps/v1", obj.GetAPIVersion())
				assert.Equal(t, "test", obj.GetName())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().WithScheme(scheme).Build()
			obj, err := generateApplyConfiguration(cl, tt.falco, false)
			require.NoError(t, err)
			require.NotNil(t, obj)
			tt.verify(t, obj)
		})
	}
}
