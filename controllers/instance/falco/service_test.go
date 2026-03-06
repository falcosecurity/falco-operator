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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
)

func TestGenerateService(t *testing.T) {
	tests := []struct {
		name           string
		falco          *instancev1alpha1.Falco
		expectedPorts  []corev1.ServicePort
		expectedLabels map[string]string
	}{
		{
			name:  "service generation with defaults",
			falco: builders.NewFalco().WithName("test-falco").WithNamespace("default").WithLabels(map[string]string{"app": "falco"}).Build(),
			expectedPorts: []corev1.ServicePort{
				{
					Name:       "web",
					Protocol:   corev1.ProtocolTCP,
					Port:       8765,
					TargetPort: intstr.FromInt32(8765),
				},
			},
			expectedLabels: map[string]string{"app": "falco"},
		},
		{
			name: "service with custom labels",
			falco: builders.NewFalco().WithName("test-falco").WithNamespace("default").
				WithLabels(map[string]string{"app": "falco", "environment": "test", "custom": "label"}).Build(),
			expectedLabels: map[string]string{"app": "falco", "environment": "test", "custom": "label"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateService(tt.falco)
			require.NotNil(t, result)

			svc := result.(*corev1.Service)
			assert.Equal(t, tt.falco.Name, svc.Name)
			assert.Equal(t, tt.falco.Namespace, svc.Namespace)
			assert.Equal(t, tt.expectedLabels, svc.Labels)
			assert.Equal(t, "Service", svc.Kind)
			assert.Equal(t, "v1", svc.APIVersion)
			assert.Equal(t, corev1.ServiceTypeClusterIP, svc.Spec.Type)

			assert.Equal(t, map[string]string{
				"app.kubernetes.io/name":     tt.falco.Name,
				"app.kubernetes.io/instance": tt.falco.Name,
			}, svc.Spec.Selector)

			if tt.expectedPorts != nil {
				assert.Equal(t, tt.expectedPorts, svc.Spec.Ports)
			}
		})
	}
}

func TestEnsureService(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	falco := builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).Build()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(falco).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

	require.NoError(t, r.ensureService(context.Background(), falco))

	svc := &corev1.Service{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(falco), svc))
	assert.Equal(t, falco.Name, svc.Name)
	assert.NotEmpty(t, svc.Spec.Ports)
}
