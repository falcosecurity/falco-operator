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

package builders

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

func TestNewConfig_Empty(t *testing.T) {
	c := NewConfig().Build()
	assert.Empty(t, c.Name)
	assert.Empty(t, c.Namespace)
	assert.Nil(t, c.Spec.Config)
	assert.Nil(t, c.Spec.ConfigMapRef)
	assert.Zero(t, c.Spec.Priority)
	assert.Nil(t, c.Spec.Selector)
}

func TestConfigBuilder(t *testing.T) {
	labels := map[string]string{"app": "falco"}
	now := metav1.Now()
	cfgJSON := &apiextensionsv1.JSON{Raw: []byte(`{"key":"value"}`)}
	cmRef := &commonv1alpha1.ConfigMapRef{Name: "my-cm"}
	selector := &metav1.LabelSelector{
		MatchLabels: map[string]string{"node": "worker"},
	}

	c := NewConfig().
		WithName("my-config").
		WithNamespace("ns").
		WithLabels(labels).
		WithFinalizers([]string{"config.falcosecurity.dev/finalizer"}).
		WithDeletionTimestamp(&now).
		WithGeneration(3).
		WithConfig(cfgJSON).
		WithConfigMapRef(cmRef).
		WithPriority(75).
		WithSelector(selector).
		Build()

	assert.Equal(t, "my-config", c.Name)
	assert.Equal(t, "ns", c.Namespace)
	assert.Equal(t, labels, c.Labels)
	assert.Equal(t, []string{"config.falcosecurity.dev/finalizer"}, c.Finalizers)
	assert.Equal(t, &now, c.DeletionTimestamp)
	assert.Equal(t, int64(3), c.Generation)
	require.NotNil(t, c.Spec.Config)
	assert.Equal(t, cfgJSON, c.Spec.Config)
	require.NotNil(t, c.Spec.ConfigMapRef)
	assert.Equal(t, "my-cm", c.Spec.ConfigMapRef.Name)
	assert.Equal(t, int32(75), c.Spec.Priority)
	require.NotNil(t, c.Spec.Selector)
	assert.Equal(t, selector, c.Spec.Selector)
}
