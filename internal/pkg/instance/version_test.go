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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/resources"
)

// configMapObject returns a ConfigMap that satisfies client.Object but is
// neither *Falco nor *Component, for testing the unknown-type branch.
func configMapObject() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "unknown"},
	}
}

func TestResolveVersion(t *testing.T) {
	tests := []struct {
		name string
		obj  *instancev1alpha1.Falco
		defs *resources.InstanceDefaults
		want string
	}{
		{
			name: "nothing defined returns default tag",
			obj:  &instancev1alpha1.Falco{},
			defs: resources.FalcoDefaults,
			want: resources.FalcoDefaults.ImageTag,
		},
		{
			name: "spec.version overrides default tag",
			obj: &instancev1alpha1.Falco{
				Spec: instancev1alpha1.FalcoSpec{
					Version: new("0.40.0"),
				},
			},
			defs: resources.FalcoDefaults,
			want: "0.40.0",
		},
		{
			name: "empty version string uses default tag",
			obj: &instancev1alpha1.Falco{
				Spec: instancev1alpha1.FalcoSpec{
					Version: new(""),
				},
			},
			defs: resources.FalcoDefaults,
			want: resources.FalcoDefaults.ImageTag,
		},
		{
			name: "podspec main container image tag wins",
			obj: &instancev1alpha1.Falco{
				Spec: instancev1alpha1.FalcoSpec{
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: resources.FalcoDefaults.ContainerName, Image: "custom-registry/falco:0.38.0"},
							},
						},
					},
				},
			},
			defs: resources.FalcoDefaults,
			want: "0.38.0",
		},
		{
			name: "podspec image tag takes precedence over spec.version",
			obj: &instancev1alpha1.Falco{
				Spec: instancev1alpha1.FalcoSpec{
					Version: new("0.35.0"),
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: resources.FalcoDefaults.ContainerName, Image: "custom-registry/falco:0.39.0"},
							},
						},
					},
				},
			},
			defs: resources.FalcoDefaults,
			want: "0.39.0",
		},
		{
			name: "podspec image without tag falls back to spec.version",
			obj: &instancev1alpha1.Falco{
				Spec: instancev1alpha1.FalcoSpec{
					Version: new("0.40.0"),
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: resources.FalcoDefaults.ContainerName, Image: "my-registry/my-falco"},
							},
						},
					},
				},
			},
			defs: resources.FalcoDefaults,
			want: "0.40.0",
		},
		{
			name: "podspec image without tag and no version falls back to default",
			obj: &instancev1alpha1.Falco{
				Spec: instancev1alpha1.FalcoSpec{
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: resources.FalcoDefaults.ContainerName, Image: "my-registry/my-falco"},
							},
						},
					},
				},
			},
			defs: resources.FalcoDefaults,
			want: resources.FalcoDefaults.ImageTag,
		},
		{
			name: "ignores containers with different names",
			obj: &instancev1alpha1.Falco{
				Spec: instancev1alpha1.FalcoSpec{
					Version: new("0.40.0"),
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: "sidecar", Image: "some-image:1.0.0"},
							},
						},
					},
				},
			},
			defs: resources.FalcoDefaults,
			want: "0.40.0",
		},
		{
			name: "container with empty image string falls back to spec.version",
			obj: &instancev1alpha1.Falco{
				Spec: instancev1alpha1.FalcoSpec{
					Version: new("0.40.0"),
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: resources.FalcoDefaults.ContainerName, Image: ""},
							},
						},
					},
				},
			},
			defs: resources.FalcoDefaults,
			want: "0.40.0",
		},
		{
			name: "empty containers slice falls back to spec.version",
			obj: &instancev1alpha1.Falco{
				Spec: instancev1alpha1.FalcoSpec{
					Version: new("0.41.0"),
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{},
						},
					},
				},
			},
			defs: resources.FalcoDefaults,
			want: "0.41.0",
		},
		{
			name: "empty containers slice and nil version falls back to default",
			obj: &instancev1alpha1.Falco{
				Spec: instancev1alpha1.FalcoSpec{
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{},
						},
					},
				},
			},
			defs: resources.FalcoDefaults,
			want: resources.FalcoDefaults.ImageTag,
		},
		{
			name: "image with only tag and no repository returns the tag",
			obj: &instancev1alpha1.Falco{
				Spec: instancev1alpha1.FalcoSpec{
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: resources.FalcoDefaults.ContainerName, Image: ":v1"},
							},
						},
					},
				},
			},
			defs: resources.FalcoDefaults,
			want: "v1",
		},
		{
			name: "nil version and no matching container falls back to default",
			obj: &instancev1alpha1.Falco{
				Spec: instancev1alpha1.FalcoSpec{
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: "sidecar", Image: "some-image:1.0.0"},
							},
						},
					},
				},
			},
			defs: resources.FalcoDefaults,
			want: resources.FalcoDefaults.ImageTag,
		},
		{
			name: "multiple containers with same name uses first match",
			obj: &instancev1alpha1.Falco{
				Spec: instancev1alpha1.FalcoSpec{
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: resources.FalcoDefaults.ContainerName, Image: "registry/falco:0.42.0"},
								{Name: resources.FalcoDefaults.ContainerName, Image: "registry/falco:0.43.0"},
							},
						},
					},
				},
			},
			defs: resources.FalcoDefaults,
			want: "0.42.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveVersion(tt.obj, tt.defs)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveVersionComponent(t *testing.T) {
	tests := []struct {
		name string
		obj  *instancev1alpha1.Component
		defs *resources.InstanceDefaults
		want string
	}{
		{
			name: "nothing defined returns default tag",
			obj: &instancev1alpha1.Component{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: instancev1alpha1.ComponentSpec{
					Component: instancev1alpha1.ComponentInfo{
						Type: instancev1alpha1.ComponentTypeMetacollector,
					},
				},
			},
			defs: resources.MetacollectorDefaults,
			want: resources.MetacollectorDefaults.ImageTag,
		},
		{
			name: "spec.component.version overrides default tag",
			obj: &instancev1alpha1.Component{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: instancev1alpha1.ComponentSpec{
					Component: instancev1alpha1.ComponentInfo{
						Type:    instancev1alpha1.ComponentTypeMetacollector,
						Version: new("0.2.0"),
					},
				},
			},
			defs: resources.MetacollectorDefaults,
			want: "0.2.0",
		},
		{
			name: "podspec main container image tag wins",
			obj: &instancev1alpha1.Component{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: instancev1alpha1.ComponentSpec{
					Component: instancev1alpha1.ComponentInfo{
						Type: instancev1alpha1.ComponentTypeMetacollector,
					},
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: resources.MetacollectorDefaults.ContainerName, Image: "custom/metacollector:0.3.0"},
							},
						},
					},
				},
			},
			defs: resources.MetacollectorDefaults,
			want: "0.3.0",
		},
		{
			name: "empty version string uses default tag",
			obj: &instancev1alpha1.Component{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: instancev1alpha1.ComponentSpec{
					Component: instancev1alpha1.ComponentInfo{
						Type:    instancev1alpha1.ComponentTypeMetacollector,
						Version: new(""),
					},
				},
			},
			defs: resources.MetacollectorDefaults,
			want: resources.MetacollectorDefaults.ImageTag,
		},
		{
			name: "podspec image tag takes precedence over spec.component.version",
			obj: &instancev1alpha1.Component{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: instancev1alpha1.ComponentSpec{
					Component: instancev1alpha1.ComponentInfo{
						Type:    instancev1alpha1.ComponentTypeMetacollector,
						Version: new("0.1.0"),
					},
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: resources.MetacollectorDefaults.ContainerName, Image: "custom/metacollector:0.4.0"},
							},
						},
					},
				},
			},
			defs: resources.MetacollectorDefaults,
			want: "0.4.0",
		},
		{
			name: "empty containers slice falls back to spec.component.version",
			obj: &instancev1alpha1.Component{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: instancev1alpha1.ComponentSpec{
					Component: instancev1alpha1.ComponentInfo{
						Type:    instancev1alpha1.ComponentTypeMetacollector,
						Version: new("0.5.0"),
					},
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{},
						},
					},
				},
			},
			defs: resources.MetacollectorDefaults,
			want: "0.5.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveVersion(tt.obj, tt.defs)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestResolveVersion_UnknownObjectType verifies that passing an object that is
// neither *Falco nor *Component causes the function to skip the type switch
// (version and podTemplateSpec remain nil) and return the default image tag.
func TestResolveVersion_UnknownObjectType(t *testing.T) {
	got := ResolveVersion(configMapObject(), resources.FalcoDefaults)
	assert.Equal(t, resources.FalcoDefaults.ImageTag, got, "unknown object type should fall back to default image tag")
}
