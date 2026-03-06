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

package metacollector

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
)

func TestGenerateService(t *testing.T) {
	tests := []struct {
		name         string
		mc           *instancev1alpha1.Metacollector
		wantName     string
		wantSelector map[string]string
	}{
		{
			name:     "basic Service creation with 3 ports",
			mc:       builders.NewMetacollector().WithName("test-mc").WithNamespace("default").WithLabels(map[string]string{"app": "metacollector"}).Build(),
			wantName: "test-mc",
			wantSelector: map[string]string{
				"app.kubernetes.io/name":     "test-mc",
				"app.kubernetes.io/instance": "test-mc",
			},
		},
		{
			name:     "Service has correct selector",
			mc:       builders.NewMetacollector().WithName("my-mc").WithNamespace("default").Build(),
			wantName: "my-mc",
			wantSelector: map[string]string{
				"app.kubernetes.io/name":     "my-mc",
				"app.kubernetes.io/instance": "my-mc",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateService(tt.mc)
			require.NotNil(t, result)

			svc := result.(*corev1.Service)
			assert.Equal(t, tt.wantName, svc.Name)
			assert.Equal(t, "Service", svc.Kind)
			assert.Equal(t, "v1", svc.APIVersion)
			assert.Equal(t, tt.wantSelector, svc.Spec.Selector)

			require.Len(t, svc.Spec.Ports, 3)
			portMap := make(map[string]int32)
			for _, p := range svc.Spec.Ports {
				portMap[p.Name] = p.Port
			}
			assert.Equal(t, int32(8080), portMap["metrics"])
			assert.Equal(t, int32(8081), portMap["health-probe"])
			assert.Equal(t, int32(45000), portMap["broker-grpc"])
		})
	}
}

func TestEnsureService(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	mc := builders.NewMetacollector().WithName("test-mc").WithNamespace(testutil.TestNamespace).Build()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mc).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

	require.NoError(t, r.ensureService(context.Background(), mc))

	svc := &corev1.Service{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(mc), svc))
	assert.Equal(t, mc.Name, svc.Name)
	require.Len(t, svc.Spec.Ports, 3)
	portNames := make(map[string]int32)
	for _, p := range svc.Spec.Ports {
		portNames[p.Name] = p.Port
	}
	assert.Equal(t, int32(8080), portNames["metrics"])
	assert.Equal(t, int32(8081), portNames["health-probe"])
	assert.Equal(t, int32(45000), portNames["broker-grpc"])
}
