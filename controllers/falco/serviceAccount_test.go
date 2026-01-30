// Copyright (C) 2025 The Falco Authors
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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

func TestGenerateServiceAccount(t *testing.T) {
	// Create a test scheme.
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = instancev1alpha1.AddToScheme(scheme)

	tests := []struct {
		name           string
		falco          *instancev1alpha1.Falco
		wantErr        bool
		expectedLabels map[string]string
	}{
		{
			name: "successful service account generation",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
					Labels: map[string]string{
						"app": "falco",
					},
				},
			},
			wantErr: false,
			expectedLabels: map[string]string{
				"app": "falco",
			},
		},
		{
			name: "service account with custom labels",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "custom-namespace",
					Labels: map[string]string{
						"app":         "falco",
						"environment": "test",
						"custom":      "label",
					},
				},
			},
			wantErr: false,
			expectedLabels: map[string]string{
				"app":         "falco",
				"environment": "test",
				"custom":      "label",
			},
		},
		{
			name:    "nil falco instance",
			falco:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().WithScheme(scheme).Build()
			got, err := generateServiceAccount(cl, tt.falco)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, got)

			// Convert unstructured to ServiceAccount.
			sa := &corev1.ServiceAccount{}
			err = runtime.DefaultUnstructuredConverter.FromUnstructured(got.Object, sa)
			assert.NoError(t, err)

			// Verify service account properties.
			assert.Equal(t, tt.falco.Name, sa.Name)
			assert.Equal(t, tt.falco.Namespace, sa.Namespace)
			assert.Equal(t, tt.falco.Labels, sa.Labels)
			assert.Equal(t, "ServiceAccount", sa.Kind)
			assert.Equal(t, "v1", sa.APIVersion)

			// Verify labels if expected.
			if tt.expectedLabels != nil {
				assert.Equal(t, tt.expectedLabels, sa.Labels)
			}
		})
	}
}

func TestGenerateServiceAccountWithNilClient(t *testing.T) {
	falco := &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-falco",
			Namespace: "default",
		},
	}

	_, err := generateServiceAccount(nil, falco)
	assert.Error(t, err)
}
