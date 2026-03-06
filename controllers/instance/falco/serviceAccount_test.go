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
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
)

func TestGenerateServiceAccount(t *testing.T) {
	tests := []struct {
		name           string
		falco          *instancev1alpha1.Falco
		expectedLabels map[string]string
	}{
		{
			name:           "basic service account generation",
			falco:          builders.NewFalco().WithName("test-falco").WithNamespace("default").WithLabels(map[string]string{"app": "falco"}).Build(),
			expectedLabels: map[string]string{"app": "falco"},
		},
		{
			name: "service account with custom labels",
			falco: builders.NewFalco().WithName("test-falco").WithNamespace("custom-namespace").
				WithLabels(map[string]string{"app": "falco", "environment": "test", "custom": "label"}).Build(),
			expectedLabels: map[string]string{"app": "falco", "environment": "test", "custom": "label"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateServiceAccount(tt.falco)
			require.NotNil(t, result)

			sa := result.(*corev1.ServiceAccount)
			assert.Equal(t, tt.falco.Name, sa.Name)
			assert.Equal(t, tt.falco.Namespace, sa.Namespace)
			assert.Equal(t, tt.expectedLabels, sa.Labels)
			assert.Equal(t, "ServiceAccount", sa.Kind)
			assert.Equal(t, "v1", sa.APIVersion)
		})
	}
}

func TestEnsureServiceAccount(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	tests := []struct {
		name         string
		falco        *instancev1alpha1.Falco
		existingObjs []client.Object
		wantLabels   map[string]string
	}{
		{
			name:  "creates with correct name and namespace",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).Build(),
		},
		{
			name:  "applies new labels on existing ServiceAccount",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithLabels(map[string]string{"new": "label"}).Build(),
			existingObjs: []client.Object{
				builders.NewServiceAccount().WithName("test").
					WithNamespace(testutil.TestNamespace).
					WithLabels(map[string]string{"old": "label"}).Build(),
			},
			wantLabels: map[string]string{"new": "label"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := append([]client.Object{tt.falco}, tt.existingObjs...)
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

			require.NoError(t, r.ensureServiceAccount(context.Background(), tt.falco))

			sa := &corev1.ServiceAccount{}
			require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), sa))
			assert.Equal(t, tt.falco.Name, sa.Name)
			assert.Equal(t, tt.falco.Namespace, sa.Namespace)
			for k, v := range tt.wantLabels {
				assert.Equal(t, v, sa.Labels[k], "label %s", k)
			}
		})
	}
}
