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
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

func TestGenerateService(t *testing.T) {
	// Create a test scheme.
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = instancev1alpha1.AddToScheme(scheme)

	tests := []struct {
		name           string
		falco          *instancev1alpha1.Falco
		wantErr        bool
		expectedPorts  []corev1.ServicePort
		expectedLabels map[string]string
	}{
		{
			name: "successful service generation with defaults",
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
			expectedPorts: []corev1.ServicePort{
				{
					Name:       "web",
					Protocol:   corev1.ProtocolTCP,
					Port:       8765,
					TargetPort: intstr.FromInt32(8765),
				},
			},
			expectedLabels: map[string]string{
				"app": "falco",
			},
		},
		{
			name: "service with custom labels",
			falco: &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-falco",
					Namespace: "default",
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
			got, err := generateService(cl, tt.falco)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, got)

			// Convert unstructured to Service.
			service := &corev1.Service{}
			err = runtime.DefaultUnstructuredConverter.FromUnstructured(got.Object, service)
			assert.NoError(t, err)

			// Verify service properties.
			assert.Equal(t, tt.falco.Name, service.Name)
			assert.Equal(t, tt.falco.Namespace, service.Namespace)
			assert.Equal(t, tt.falco.Labels, service.Labels)
			assert.Equal(t, "Service", service.Kind)
			assert.Equal(t, "v1", service.APIVersion)

			// Verify service type is ClusterIP by default.
			assert.Equal(t, corev1.ServiceTypeClusterIP, service.Spec.Type)

			// Verify selector.
			assert.Equal(t, map[string]string{
				"app.kubernetes.io/name":     tt.falco.Name,
				"app.kubernetes.io/instance": tt.falco.Name,
			}, service.Spec.Selector)

			// Verify ports if expected.
			if tt.expectedPorts != nil {
				assert.Equal(t, tt.expectedPorts, service.Spec.Ports)
			}

			// Verify labels if expected.
			if tt.expectedLabels != nil {
				assert.Equal(t, tt.expectedLabels, service.Labels)
			}
		})
	}
}

func TestGenerateServiceWithNilClient(t *testing.T) {
	falco := &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-falco",
			Namespace: "default",
		},
	}

	_, err := generateService(nil, falco)
	assert.Error(t, err)
}
