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
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

func TestGenerateClusterRoleBinding(t *testing.T) {
	tests := []struct {
		name           string
		falco          *instancev1alpha1.Falco
		expectedFields map[string]interface{}
		wantErr        bool
	}{
		{
			name: "basic cluster role binding",
			falco: &instancev1alpha1.Falco{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "instance.falcosecurity.dev/v1alpha1",
					Kind:       "Falco",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "test-namespace",
					Labels: map[string]string{
						"app": "falco",
					},
				},
			},
			expectedFields: map[string]interface{}{
				"apiVersion": "rbac.authorization.k8s.io/v1",
				"kind":       "ClusterRoleBinding",
				"metadata": map[string]interface{}{
					"name": "test-falco--test-namespace",
					"labels": map[string]interface{}{
						"app": "falco",
					},
				},
				"subjects": []interface{}{
					map[string]interface{}{
						"kind":      "ServiceAccount",
						"name":      "test-falco",
						"namespace": "test-namespace",
					},
				},
				"roleRef": map[string]interface{}{
					"kind":     "ClusterRole",
					"name":     "test-falco--test-namespace",
					"apiGroup": "rbac.authorization.k8s.io",
				},
			},
			wantErr: false,
		},
		{
			name: "cluster role binding with multiple labels",
			falco: &instancev1alpha1.Falco{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "instance.falcosecurity.dev/v1alpha1",
					Kind:       "Falco",
				},
				ObjectMeta: metav1.ObjectMeta{

					Name:      "test-falco",
					Namespace: "test-namespace",
					Labels: map[string]string{
						"app":     "falco",
						"version": "v1",
						"env":     "test",
					},
				},
			},
			expectedFields: map[string]interface{}{
				"metadata": map[string]interface{}{
					"name": "test-falco--test-namespace",
					"labels": map[string]interface{}{
						"app":     "falco",
						"version": "v1",
						"env":     "test",
					},
				},
			},
			wantErr: false,
		},
	}

	scheme := runtime.NewScheme()
	_ = rbacv1.AddToScheme(scheme)
	_ = instancev1alpha1.AddToScheme(scheme)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).Build()

			result, err := generateClusterRoleBinding(client, tt.falco)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)

			// Verify TypeMeta.
			assert.Equal(t, "ClusterRoleBinding", result.GetKind())
			assert.Equal(t, "rbac.authorization.k8s.io/v1", result.GetAPIVersion())

			// Verify basic metadata.
			assert.Equal(t, GenerateUniqueName(tt.falco.Name, tt.falco.Namespace), result.GetName())
			assert.Equal(t, "", result.GetNamespace())
			assert.Equal(t, tt.falco.Labels, result.GetLabels())

			// Verify subjects.
			subjects, found, err := unstructured.NestedSlice(result.Object, "subjects")
			assert.NoError(t, err)
			assert.True(t, found)
			assert.Len(t, subjects, 1)
			subject := subjects[0].(map[string]interface{})
			assert.Equal(t, "ServiceAccount", subject["kind"])
			assert.Equal(t, tt.falco.Name, subject["name"])
			assert.Equal(t, tt.falco.Namespace, subject["namespace"])

			// Verify roleRef.
			roleRef, found, err := unstructured.NestedMap(result.Object, "roleRef")
			assert.NoError(t, err)
			assert.True(t, found)
			assert.Equal(t, "ClusterRole", roleRef["kind"])
			assert.Equal(t, GenerateUniqueName(tt.falco.Name, tt.falco.Namespace), roleRef["name"])
			assert.Equal(t, "rbac.authorization.k8s.io", roleRef["apiGroup"])

			// Verify additional expected fields if specified
			for key, expectedValue := range tt.expectedFields {
				value, found, err := unstructured.NestedFieldNoCopy(result.Object, key)
				assert.NoError(t, err)
				assert.True(t, found)
				assert.Equal(t, expectedValue, value)
			}
		})
	}
}
