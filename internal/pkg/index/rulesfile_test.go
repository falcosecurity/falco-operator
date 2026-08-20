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

func TestRulesfileByConfigMapRef(t *testing.T) {
	tests := []struct {
		name      string
		rulesfile *artifactv1alpha1.Rulesfile
		want      []string
	}{
		{
			name: "no configmap ref returns nil",
			rulesfile: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: "my-rulesfile", Namespace: testNamespace},
			},
			want: nil,
		},
		{
			name: "with configmap ref returns index key",
			rulesfile: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: "my-rulesfile", Namespace: testNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-rules-cm"},
				},
			},
			want: []string{testNamespace + "/my-rules-cm"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, index.RulesfileByConfigMapRef(tt.rulesfile))
		})
	}
}

func TestRulesfileBySecretRef(t *testing.T) {
	tests := []struct {
		name      string
		rulesfile *artifactv1alpha1.Rulesfile
		want      []string
	}{
		{
			name: "nil OCIArtifact returns nil",
			rulesfile: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: "my-rulesfile", Namespace: testNamespace},
			},
			want: nil,
		},
		{
			name: "nil Registry returns nil",
			rulesfile: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: "my-rulesfile", Namespace: testNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "my-repo"},
					},
				},
			},
			want: nil,
		},
		{
			name: "nil Auth returns nil",
			rulesfile: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: "my-rulesfile", Namespace: testNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
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
			rulesfile: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: "my-rulesfile", Namespace: testNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
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
			rulesfile: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: "my-rulesfile", Namespace: testNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
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
			assert.Equal(t, tt.want, index.RulesfileBySecretRef(tt.rulesfile))
		})
	}
}

func TestRulesfileBySecretRef_WrongType(t *testing.T) {
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "my-plugin", Namespace: testNamespace},
	}
	assert.Nil(t, index.RulesfileBySecretRef(plugin))
}

func TestRulesfileByPluginDependency(t *testing.T) {
	tests := []struct {
		name      string
		rulesfile *artifactv1alpha1.Rulesfile
		want      []string
	}{
		{
			name: "nil ArtifactMeta returns nil",
			rulesfile: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: "rf", Namespace: testNamespace},
			},
			want: nil,
		},
		{
			name: "empty dependencies returns nil",
			rulesfile: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: "rf", Namespace: testNamespace},
				Status: artifactv1alpha1.RulesfileStatus{
					ArtifactMeta: &commonv1alpha1.ArtifactMeta{},
				},
			},
			want: nil,
		},
		{
			name: "single dependency no alternatives",
			rulesfile: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: "rf", Namespace: testNamespace},
				Status: artifactv1alpha1.RulesfileStatus{
					ArtifactMeta: &commonv1alpha1.ArtifactMeta{
						Dependencies: []commonv1alpha1.ArtifactMetaDependency{
							{Name: "k8saudit", Version: "0.7.0"},
						},
					},
				},
			},
			want: []string{"k8saudit"},
		},
		{
			name: "dependency with alternatives",
			rulesfile: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: "rf", Namespace: testNamespace},
				Status: artifactv1alpha1.RulesfileStatus{
					ArtifactMeta: &commonv1alpha1.ArtifactMeta{
						Dependencies: []commonv1alpha1.ArtifactMetaDependency{
							{
								Name:    "k8saudit",
								Version: "0.7.0",
								Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{
									{Name: "k8saudit-eks", Version: "0.5.0"},
								},
							},
						},
					},
				},
			},
			want: []string{"k8saudit", "k8saudit-eks"},
		},
		{
			name: "duplicate names across dependencies are deduplicated",
			rulesfile: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: "rf", Namespace: testNamespace},
				Status: artifactv1alpha1.RulesfileStatus{
					ArtifactMeta: &commonv1alpha1.ArtifactMeta{
						Dependencies: []commonv1alpha1.ArtifactMetaDependency{
							{Name: "k8saudit", Version: "0.7.0"},
							{Name: "k8saudit", Version: "0.8.0"},
						},
					},
				},
			},
			want: []string{"k8saudit"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, index.RulesfileByPluginDependency(tt.rulesfile))
		})
	}
}

func TestRulesfileByPluginDependency_WrongType(t *testing.T) {
	assert.Nil(t, index.RulesfileByPluginDependency(&artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "my-plugin", Namespace: testNamespace},
	}))
}
