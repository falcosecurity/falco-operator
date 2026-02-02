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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

func TestGenerateConfigmap(t *testing.T) {
	// Create a new scheme and add the necessary types
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = instancev1alpha1.AddToScheme(scheme)

	tests := []struct {
		name        string
		falco       *instancev1alpha1.Falco
		wantErr     bool
		errContains string
	}{
		{
			name: "deployment type configmap",
			falco: &instancev1alpha1.Falco{
				TypeMeta: metav1.TypeMeta{
					APIVersion: instancev1alpha1.GroupVersion.String(),
					Kind:       "Falco",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
					Labels: map[string]string{
						"app": "falco",
					},
				},
				Spec: instancev1alpha1.FalcoSpec{
					Type: resourceTypeDeployment,
				},
			},
			wantErr: false,
		},
		{
			name: "daemonset type configmap",
			falco: &instancev1alpha1.Falco{
				TypeMeta: metav1.TypeMeta{
					APIVersion: instancev1alpha1.GroupVersion.String(),
					Kind:       "Falco",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
					Labels: map[string]string{
						"app": "falco",
					},
				},
				Spec: instancev1alpha1.FalcoSpec{
					Type: resourceTypeDaemonSet,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid type configmap",
			falco: &instancev1alpha1.Falco{
				TypeMeta: metav1.TypeMeta{
					APIVersion: instancev1alpha1.GroupVersion.String(),
					Kind:       "Falco",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
				},
				Spec: instancev1alpha1.FalcoSpec{
					Type: "invalid-type",
				},
			},
			wantErr:     true,
			errContains: "unsupported falco type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fake client.
			client := fake.NewClientBuilder().WithScheme(scheme).Build()

			// Call the function.
			result, err := generateConfigmap(client, tt.falco)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, result)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)

			// Verify the basic structure of the configmap.
			name, _, err := unstructured.NestedString(result.Object, "metadata", "name")
			assert.NoError(t, err)
			assert.Equal(t, tt.falco.Name, name)

			namespace, _, err := unstructured.NestedString(result.Object, "metadata", "namespace")
			assert.NoError(t, err)
			assert.Equal(t, tt.falco.Namespace, namespace)

			// Verify the config data exists.
			data, _, err := unstructured.NestedStringMap(result.Object, "data")
			assert.NoError(t, err)
			assert.Contains(t, data, "falco.yaml")

			// Verify config content based on type.
			expectedConfig := ""
			switch tt.falco.Spec.Type {
			case resourceTypeDeployment:
				expectedConfig = deploymentFalcoConfig
			case resourceTypeDaemonSet:
				expectedConfig = daemonsetFalcoConfig
			}
			assert.Equal(t, expectedConfig, data["falco.yaml"])

			// Verify labels.
			labels, _, err := unstructured.NestedStringMap(result.Object, "metadata", "labels")
			assert.NoError(t, err)
			assert.Equal(t, tt.falco.Labels, labels)

			// Verify controller reference.
			ownerRefs, exists, err := unstructured.NestedSlice(result.Object, "metadata", "ownerReferences")
			assert.NoError(t, err)
			assert.True(t, exists)
			assert.Len(t, ownerRefs, 1)

			ownerRef := ownerRefs[0].(map[string]interface{})
			assert.Equal(t, tt.falco.Name, ownerRef["name"])
			assert.Equal(t, tt.falco.Kind, ownerRef["kind"])
			assert.Equal(t, tt.falco.APIVersion, ownerRef["apiVersion"])
			assert.Equal(t, string(tt.falco.UID), ownerRef["uid"])
			assert.True(t, ownerRef["controller"].(bool))
			assert.True(t, ownerRef["blockOwnerDeletion"].(bool))
		})
	}
}
