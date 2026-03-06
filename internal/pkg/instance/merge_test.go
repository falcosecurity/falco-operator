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

package instance

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
)

func TestMergeApplyConfiguration(t *testing.T) {
	tests := []struct {
		name               string
		kind               string
		base               runtime.Object
		user               *unstructured.Unstructured
		wantErr            bool
		wantKind           string
		wantAPIVersion     string
		wantContainerImage string
	}{
		{
			name: "merges Deployment with user overrides",
			kind: ResourceTypeDeployment,
			base: builders.NewDeployment().WithName("test").WithNamespace("default").
				WithSelector(map[string]string{"app": "test"}).
				AddContainer(&corev1.Container{Name: "app", Image: "base:v1"}).Build(),
			user: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"name": "test", "namespace": "default"},
					"spec": map[string]interface{}{
						"template": map[string]interface{}{
							"spec": map[string]interface{}{
								"containers": []interface{}{
									map[string]interface{}{"name": "app", "image": "user:v2"},
								},
							},
						},
					},
				},
			},
			wantKind:           ResourceTypeDeployment,
			wantAPIVersion:     "apps/v1",
			wantContainerImage: "user:v2",
		},
		{
			name: "merges DaemonSet with user overrides",
			kind: ResourceTypeDaemonSet,
			base: builders.NewDaemonSet().WithName("test").WithNamespace("default").
				WithSelector(map[string]string{"app": "test"}).
				AddContainer(&corev1.Container{Name: "app", Image: "base:v1"}).Build(),
			user: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"name": "test", "namespace": "default"},
					"spec":     map[string]interface{}{},
				},
			},
			wantKind:       ResourceTypeDaemonSet,
			wantAPIVersion: "apps/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := MergeApplyConfiguration(tt.kind, tt.base, tt.user)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.wantKind, result.GetKind())
			assert.Equal(t, tt.wantAPIVersion, result.GetAPIVersion())

			if tt.wantContainerImage != "" {
				containers, found, err := unstructured.NestedSlice(
					result.Object, "spec", "template", "spec", "containers",
				)
				require.NoError(t, err)
				require.True(t, found)
				require.NotEmpty(t, containers)
				c0 := containers[0].(map[string]interface{})
				assert.Equal(t, tt.wantContainerImage, c0["image"])
			}
		})
	}
}

func TestDeploymentStrategy(t *testing.T) {
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
			s := DeploymentStrategy(tt.strategy)
			assert.Equal(t, tt.wantType, s.Type)
		})
	}
}

func TestDaemonSetUpdateStrategy(t *testing.T) {
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
			s := DaemonSetUpdateStrategy(tt.strategy)
			assert.Equal(t, tt.wantType, s.Type)
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
			labels := PodTemplateSpecLabels(tt.appName, tt.baseLabels)
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
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"template": map[string]interface{}{
							"spec": map[string]interface{}{
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
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"template": map[string]interface{}{
							"spec": map[string]interface{}{
								"containers": []interface{}{
									map[string]interface{}{"name": "test"},
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
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"template": map[string]interface{}{
							"spec": map[string]interface{}{},
						},
					},
				},
			},
			wantRemove: false,
		},
		{
			name: "returns error when spec.template.spec is missing",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"template": map[string]interface{}{},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RemoveEmptyContainers(tt.obj)
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
