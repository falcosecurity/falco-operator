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
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

func TestConfigmapGenerator(t *testing.T) {
	tests := []struct {
		name       string
		config     string
		wantConfig string
	}{
		{
			name:       "deployment config",
			config:     deploymentFalcoConfig,
			wantConfig: deploymentFalcoConfig,
		},
		{
			name:       "daemonset config",
			config:     daemonsetFalcoConfig,
			wantConfig: daemonsetFalcoConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			falco := builders.NewFalco().WithName("test-falco").WithNamespace("default").WithLabels(map[string]string{"app": "falco"}).Build()

			generator := configmapGenerator(tt.config)
			result := generator(falco)
			require.NotNil(t, result)

			cm := result.(*corev1.ConfigMap)
			assert.Equal(t, falco.Name, cm.Name)
			assert.Equal(t, falco.Namespace, cm.Namespace)
			assert.Equal(t, falco.Labels, cm.Labels)
			assert.Equal(t, "ConfigMap", cm.Kind)
			assert.Equal(t, "v1", cm.APIVersion)
			assert.Contains(t, cm.Data, "falco.yaml")
			assert.Equal(t, tt.wantConfig, cm.Data["falco.yaml"])
		})
	}
}

func TestEnsureConfigMap(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	falco := builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType(instance.ResourceTypeDeployment).Build()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(falco).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

	require.NoError(t, r.ensureConfigMap(context.Background(), falco))

	cm := &corev1.ConfigMap{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(falco), cm))
	assert.Equal(t, falco.Name, cm.Name)
	assert.Contains(t, cm.Data, "falco.yaml")
}

func TestEnsureConfigMapInvalidType(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	falco := builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType("invalid-type").Build()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(falco).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

	err := r.ensureConfigMap(context.Background(), falco)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported falco type")
}
