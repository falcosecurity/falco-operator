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

package index_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
)

func TestPluginBySecretRef(t *testing.T) {
	tests := []struct {
		name   string
		plugin *artifactv1alpha1.Plugin
		want   []string
	}{
		{
			name: "nil OCIArtifact returns nil",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin", Namespace: testNamespace},
			},
			want: nil,
		},
		{
			name: "nil Registry returns nil",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin", Namespace: testNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "my-repo"},
					},
				},
			},
			want: nil,
		},
		{
			name: "nil Auth returns nil",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin", Namespace: testNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image:    commonv1alpha1.ImageSpec{Repository: "my-repo"},
						Registry: &commonv1alpha1.RegistryConfig{Name: "ghcr.io"},
					},
				},
			},
			want: nil,
		},
		{
			name: "nil SecretRef returns nil",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin", Namespace: testNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "my-repo"},
						Registry: &commonv1alpha1.RegistryConfig{
							Name: "ghcr.io",
							Auth: &commonv1alpha1.RegistryAuth{},
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "with secret ref returns index key",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin", Namespace: testNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "my-repo"},
						Registry: &commonv1alpha1.RegistryConfig{
							Name: "ghcr.io",
							Auth: &commonv1alpha1.RegistryAuth{
								SecretRef: &commonv1alpha1.SecretRef{Name: "my-secret"},
							},
						},
					},
				},
			},
			want: []string{testNamespace + "/my-secret"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, index.PluginBySecretRef(tt.plugin))
		})
	}
}

func TestPluginBySecretRef_WrongType(t *testing.T) {
	rulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rulesfile", Namespace: testNamespace},
	}
	assert.Nil(t, index.PluginBySecretRef(rulesfile))
}
