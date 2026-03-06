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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
	"github.com/falcosecurity/falco-operator/internal/pkg/image"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

func TestBaseDeployment(t *testing.T) {
	mc := builders.NewMetacollector().WithName("test-mc").WithNamespace("default").
		WithLabels(map[string]string{"app": "metacollector"}).WithVersion("0.2.0").Build()

	dep := baseDeployment(mc)

	assert.Equal(t, "test-mc", dep.Name)
	assert.Equal(t, "default", dep.Namespace)
	assert.Equal(t, map[string]string{"app": "metacollector"}, dep.Labels)
	assert.Equal(t, "test-mc", dep.Spec.Selector.MatchLabels["app.kubernetes.io/name"])
	require.Len(t, dep.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, "metacollector", dep.Spec.Template.Spec.Containers[0].Name)
	assert.Equal(t, image.BuildMetacollectorImageStringFromVersion("0.2.0"), dep.Spec.Template.Spec.Containers[0].Image)
	assert.Equal(t, "test-mc", dep.Spec.Template.Spec.ServiceAccountName)

	// Verify pod template spec labels include selector labels
	assert.Equal(t, "test-mc", dep.Spec.Template.Labels["app.kubernetes.io/name"])
	assert.Equal(t, "test-mc", dep.Spec.Template.Labels["app.kubernetes.io/instance"])
	// Base labels should also be present
	assert.Equal(t, "metacollector", dep.Spec.Template.Labels["app"])
}

func TestGenerateApplyConfiguration(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	tests := []struct {
		name    string
		mc      *instancev1alpha1.Metacollector
		verify  func(*testing.T, *unstructured.Unstructured)
		wantErr bool
	}{
		{
			name: "generates valid Deployment configuration",
			mc:   builders.NewMetacollector().WithName("test-mc").WithNamespace("default").Build(),
			verify: func(t *testing.T, obj *unstructured.Unstructured) {
				assert.Equal(t, instance.ResourceTypeDeployment, obj.GetKind())
				assert.Equal(t, "apps/v1", obj.GetAPIVersion())
				assert.Equal(t, "test-mc", obj.GetName())
			},
		},
		{
			name: "generates with custom version",
			mc:   builders.NewMetacollector().WithName("test-mc").WithNamespace("default").WithVersion("0.2.0").Build(),
			verify: func(t *testing.T, obj *unstructured.Unstructured) {
				containers, found, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
				require.NoError(t, err)
				require.True(t, found)
				require.NotEmpty(t, containers)

				c0 := containers[0].(map[string]any)
				assert.Equal(t, image.BuildMetacollectorImageStringFromVersion("0.2.0"), c0["image"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().WithScheme(scheme).Build()
			obj, err := generateApplyConfiguration(cl, tt.mc)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, obj)
			tt.verify(t, obj)
		})
	}
}
