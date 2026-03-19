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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
	"github.com/falcosecurity/falco-operator/internal/pkg/resources"
)

func TestEnforceStrategyConstraints(t *testing.T) {
	tests := []struct {
		name                    string
		obj                     *unstructured.Unstructured
		wantRollingUpdateAbsent bool
		strategyPath            []string
	}{
		{
			name: "Deployment Recreate removes rollingUpdate",
			obj: &unstructured.Unstructured{Object: map[string]any{
				"kind": resources.ResourceTypeDeployment,
				"spec": map[string]any{
					"strategy": map[string]any{
						"type": "Recreate",
					},
				},
			}},
			wantRollingUpdateAbsent: true,
			strategyPath:            []string{"spec", "strategy"},
		},
		{
			name: "Deployment Recreate removes existing rollingUpdate",
			obj: &unstructured.Unstructured{Object: map[string]any{
				"kind": resources.ResourceTypeDeployment,
				"spec": map[string]any{
					"strategy": map[string]any{
						"type": "Recreate",
						"rollingUpdate": map[string]any{
							"maxSurge":       "25%",
							"maxUnavailable": "25%",
						},
					},
				},
			}},
			wantRollingUpdateAbsent: true,
			strategyPath:            []string{"spec", "strategy"},
		},
		{
			name: "Deployment RollingUpdate does not touch rollingUpdate",
			obj: &unstructured.Unstructured{Object: map[string]any{
				"kind": resources.ResourceTypeDeployment,
				"spec": map[string]any{
					"strategy": map[string]any{
						"type": "RollingUpdate",
						"rollingUpdate": map[string]any{
							"maxSurge": "50%",
						},
					},
				},
			}},
			wantRollingUpdateAbsent: false,
			strategyPath:            []string{"spec", "strategy"},
		},
		{
			name: "Deployment without strategy is a no-op",
			obj: &unstructured.Unstructured{Object: map[string]any{
				"kind": resources.ResourceTypeDeployment,
				"spec": map[string]any{},
			}},
			wantRollingUpdateAbsent: false,
			strategyPath:            []string{"spec", "strategy"},
		},
		{
			name: "DaemonSet OnDelete sets rollingUpdate to null",
			obj: &unstructured.Unstructured{Object: map[string]any{
				"kind": resources.ResourceTypeDaemonSet,
				"spec": map[string]any{
					"updateStrategy": map[string]any{
						"type": "OnDelete",
					},
				},
			}},
			wantRollingUpdateAbsent: true,
			strategyPath:            []string{"spec", "updateStrategy"},
		},
		{
			name: "DaemonSet OnDelete removes existing rollingUpdate",
			obj: &unstructured.Unstructured{Object: map[string]any{
				"kind": resources.ResourceTypeDaemonSet,
				"spec": map[string]any{
					"updateStrategy": map[string]any{
						"type": "OnDelete",
						"rollingUpdate": map[string]any{
							"maxUnavailable": 1,
						},
					},
				},
			}},
			wantRollingUpdateAbsent: true,
			strategyPath:            []string{"spec", "updateStrategy"},
		},
		{
			name: "DaemonSet RollingUpdate does not touch rollingUpdate",
			obj: &unstructured.Unstructured{Object: map[string]any{
				"kind": resources.ResourceTypeDaemonSet,
				"spec": map[string]any{
					"updateStrategy": map[string]any{
						"type": "RollingUpdate",
					},
				},
			}},
			wantRollingUpdateAbsent: false,
			strategyPath:            []string{"spec", "updateStrategy"},
		},
		{
			name: "unknown kind is a no-op",
			obj: &unstructured.Unstructured{Object: map[string]any{
				"kind": "StatefulSet",
				"spec": map[string]any{
					"updateStrategy": map[string]any{
						"type": "OnDelete",
					},
				},
			}},
			wantRollingUpdateAbsent: false,
			strategyPath:            []string{"spec", "updateStrategy"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := enforceStrategyConstraints(tt.obj)
			require.NoError(t, err)

			path := make([]string, len(tt.strategyPath)+1)
			copy(path, tt.strategyPath)
			path[len(path)-1] = "rollingUpdate"
			_, found, _ := unstructured.NestedFieldNoCopy(tt.obj.Object, path...)
			if tt.wantRollingUpdateAbsent {
				assert.False(t, found, "rollingUpdate must be absent so SSA drops ownership and removes it from the live object")
			}
		})
	}
}

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
			kind: resources.ResourceTypeDeployment,
			base: builders.NewDeployment().WithName("test").WithNamespace("default").
				WithSelector(map[string]string{"app": "test"}).
				AddContainer(&corev1.Container{Name: "app", Image: "base:v1"}).Build(),
			user: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{"name": "test", "namespace": "default"},
					"spec": map[string]any{
						"template": map[string]any{
							"spec": map[string]any{
								"containers": []any{
									map[string]any{"name": "app", "image": "user:v2"},
								},
							},
						},
					},
				},
			},
			wantKind:           resources.ResourceTypeDeployment,
			wantAPIVersion:     "apps/v1",
			wantContainerImage: "user:v2",
		},
		{
			name: "merges DaemonSet with user overrides",
			kind: resources.ResourceTypeDaemonSet,
			base: builders.NewDaemonSet().WithName("test").WithNamespace("default").
				WithSelector(map[string]string{"app": "test"}).
				AddContainer(&corev1.Container{Name: "app", Image: "base:v1"}).Build(),
			user: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{"name": "test", "namespace": "default"},
					"spec":     map[string]any{},
				},
			},
			wantKind:       resources.ResourceTypeDaemonSet,
			wantAPIVersion: "apps/v1",
		},
		{
			name: "merges DaemonSet with empty user spec preserves base containers",
			kind: resources.ResourceTypeDaemonSet,
			base: builders.NewDaemonSet().WithName("test").WithNamespace("default").
				WithSelector(map[string]string{"app": "test"}).
				AddContainer(&corev1.Container{Name: "app", Image: "base:v1"}).Build(),
			user: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{"name": "test", "namespace": "default"},
				},
			},
			wantKind:           resources.ResourceTypeDaemonSet,
			wantAPIVersion:     "apps/v1",
			wantContainerImage: "base:v1",
		},
		{
			name: "returns error for empty kind",
			kind: "",
			base: builders.NewDeployment().WithName("test").WithNamespace("default").
				WithSelector(map[string]string{"app": "test"}).
				AddContainer(&corev1.Container{Name: "app", Image: "base:v1"}).Build(),
			user: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{"name": "test", "namespace": "default"},
				},
			},
			wantErr: true,
		},
		{
			name: "returns error for unknown kind",
			kind: "NonExistent",
			base: builders.NewDeployment().WithName("test").WithNamespace("default").
				WithSelector(map[string]string{"app": "test"}).
				AddContainer(&corev1.Container{Name: "app", Image: "base:v1"}).Build(),
			user: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{"name": "test", "namespace": "default"},
				},
			},
			wantErr: true,
		},
		{
			name: "returns error when user overrides contain invalid type for field",
			kind: resources.ResourceTypeDeployment,
			base: builders.NewDeployment().WithName("test").WithNamespace("default").
				WithSelector(map[string]string{"app": "test"}).
				AddContainer(&corev1.Container{Name: "app", Image: "base:v1"}).Build(),
			user: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{"name": "test", "namespace": "default"},
					"spec": map[string]any{
						// replicas expects an integer, not a string — causes schema validation error.
						"replicas": "not-a-number",
					},
				},
			},
			wantErr: true,
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
				c0, ok := containers[0].(map[string]any)
				require.True(t, ok, "expected container to be map[string]interface{}")
				assert.Equal(t, tt.wantContainerImage, c0["image"])
			}
		})
	}
}
