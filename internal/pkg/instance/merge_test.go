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
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

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

func TestMergeApplyConfigurationPreservesListSemantics(t *testing.T) {
	volumes := []corev1.Volume{
		{Name: "config", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}},
		{Name: "other", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}
	app := &corev1.Container{Name: "app", Image: "base:v1", Args: []string{"--old", "--also-old"},
		Env: []corev1.EnvVar{{Name: "OVERRIDE", Value: "old"}, {Name: "KEEP", Value: "base"}}}
	sidecar := &corev1.Container{Name: "sidecar", Image: "sidecar:v1"}
	bases := map[string]runtime.Object{
		resources.ResourceTypeDeployment: builders.NewDeployment().WithName("test").WithVolumes(volumes).
			AddContainer(app).AddContainer(sidecar).Build(),
		resources.ResourceTypeDaemonSet: builders.NewDaemonSet().WithName("test").WithVolumes(volumes).
			AddContainer(app).AddContainer(sidecar).Build(),
	}
	size := resource.MustParse("128Mi")
	overrideSpec := corev1.PodSpec{
		Volumes: []corev1.Volume{{Name: "config", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &size}}}},
		Containers: []corev1.Container{{Name: "app", Image: "user:v2", Args: []string{"--new"},
			Env: []corev1.EnvVar{{Name: "OVERRIDE", Value: "new"}, {Name: "ADD", Value: "user"}}}},
	}
	for kind, originalBase := range bases {
		for _, hasTypeMeta := range []bool{true, false} {
			name := kind + "/with-type-meta"
			if !hasTypeMeta {
				name = kind + "/without-type-meta"
			}
			t.Run(name, func(t *testing.T) {
				base := originalBase.DeepCopyObject()
				if !hasTypeMeta {
					base.GetObjectKind().SetGroupVersionKind(schema.GroupVersionKind{})
				}
				spec, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&overrideSpec)
				require.NoError(t, err)
				user := &unstructured.Unstructured{Object: map[string]any{
					"spec": map[string]any{"template": map[string]any{"spec": spec}},
				}}
				beforeBase, beforeUser := base.DeepCopyObject(), user.DeepCopy()
				merged, err := MergeApplyConfiguration(kind, base, user)
				require.NoError(t, err)
				resultSpec, found, err := unstructured.NestedMap(merged.Object, "spec", "template", "spec")
				require.NoError(t, err)
				require.True(t, found)
				var result corev1.PodSpec
				require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(resultSpec, &result))
				expectedVolumes := []corev1.Volume{*volumes[0].DeepCopy(), *volumes[1].DeepCopy()}
				expectedVolumes[0].EmptyDir.SizeLimit = &size
				require.ElementsMatch(t, expectedVolumes, result.Volumes)
				expectedApp := app.DeepCopy()
				expectedApp.Image = "user:v2"
				expectedApp.Args = []string{"--new"}
				expectedApp.Env = []corev1.EnvVar{{Name: "OVERRIDE", Value: "new"}, {Name: "KEEP", Value: "base"}, {Name: "ADD", Value: "user"}}
				require.ElementsMatch(t, []corev1.Container{*expectedApp, *sidecar}, result.Containers)
				require.Equal(t, kind, merged.GetKind())
				require.Equal(t, "apps/v1", merged.GetAPIVersion())
				require.Equal(t, beforeBase, base)
				require.Equal(t, beforeUser, user)
			})
		}
	}
}

func TestMergeApplyConfigurationEnforcesStrategyConstraints(t *testing.T) {
	tests := []struct {
		kind, strategyField, strategyType string
	}{
		{resources.ResourceTypeDeployment, "strategy", "Recreate"},
		{resources.ResourceTypeDaemonSet, "updateStrategy", "OnDelete"},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			base := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "apps/v1", "kind": tt.kind,
				"spec": map[string]any{tt.strategyField: map[string]any{
					"type": "RollingUpdate", "rollingUpdate": map[string]any{"maxUnavailable": "25%"},
				}},
			}}
			overrides := &unstructured.Unstructured{Object: map[string]any{
				"spec": map[string]any{tt.strategyField: map[string]any{"type": tt.strategyType}},
			}}
			beforeBase, beforeOverrides := base.DeepCopy(), overrides.DeepCopy()
			merged, err := MergeApplyConfiguration(tt.kind, base, overrides)
			require.NoError(t, err)
			strategy, found, err := unstructured.NestedMap(merged.Object, "spec", tt.strategyField)
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, map[string]any{"type": tt.strategyType}, strategy)
			require.Equal(t, beforeBase, base)
			require.Equal(t, beforeOverrides, overrides)
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
