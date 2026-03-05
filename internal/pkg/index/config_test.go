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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
)

const testNamespace = "test-ns"

func TestConfigByConfigMapRef(t *testing.T) {
	tests := []struct {
		name   string
		config *artifactv1alpha1.Config
		want   []string
	}{
		{
			name: "no configmap ref returns nil",
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{Name: "my-config", Namespace: testNamespace},
			},
			want: nil,
		},
		{
			name: "with configmap ref returns index key",
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{Name: "my-config", Namespace: testNamespace},
				Spec: artifactv1alpha1.ConfigSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-cm"},
				},
			},
			want: []string{testNamespace + "/my-cm"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, index.ConfigByConfigMapRef(tt.config))
		})
	}
}

func TestConfigByConfigMapRef_WrongType(t *testing.T) {
	// Passing a wrong object type must return nil (the !ok branch).
	got := index.ConfigByConfigMapRef(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: testNamespace},
	})
	assert.Nil(t, got)
}
