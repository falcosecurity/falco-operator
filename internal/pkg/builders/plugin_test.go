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

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

func TestNewPlugin_Empty(t *testing.T) {
	p := NewPlugin().Build()
	assert.Empty(t, p.Name)
	assert.Empty(t, p.Namespace)
	assert.Nil(t, p.Spec.OCIArtifact)
	assert.Nil(t, p.Spec.Config)
	assert.Nil(t, p.Spec.Selector)
}

func TestPluginBuilder(t *testing.T) {
	labels := map[string]string{"app": "falco"}
	now := metav1.Now()
	ociArtifact := commonv1alpha1.OCIArtifact{
		Image: commonv1alpha1.ImageSpec{
			Repository: "falcosecurity/plugins/my-plugin",
			Tag:        "0.1.0",
		},
	}
	pluginCfg := &artifactv1alpha1.PluginConfig{
		Name:        "my-plugin",
		LibraryPath: "/usr/share/falco/plugins/my-plugin.so",
		InitConfig:  &apiextensionsv1.JSON{Raw: []byte(`{"key":"value"}`)},
		OpenParams:  "param1=value1",
	}
	selector := &metav1.LabelSelector{
		MatchLabels: map[string]string{"node": "worker"},
	}

	p := NewPlugin().
		WithName("my-plugin").
		WithNamespace("ns").
		WithLabels(labels).
		WithFinalizers([]string{"plugin.falcosecurity.dev/finalizer"}).
		WithDeletionTimestamp(&now).
		WithGeneration(5).
		WithOCIArtifact(ociArtifact).
		WithPluginConfig(pluginCfg).
		WithSelector(selector).
		Build()

	assert.Equal(t, "my-plugin", p.Name)
	assert.Equal(t, "ns", p.Namespace)
	assert.Equal(t, labels, p.Labels)
	assert.Equal(t, []string{"plugin.falcosecurity.dev/finalizer"}, p.Finalizers)
	assert.Equal(t, &now, p.DeletionTimestamp)
	assert.Equal(t, int64(5), p.Generation)
	require.NotNil(t, p.Spec.OCIArtifact)
	assert.Equal(t, "falcosecurity/plugins/my-plugin", p.Spec.OCIArtifact.Image.Repository)
	assert.Equal(t, "0.1.0", p.Spec.OCIArtifact.Image.Tag)
	require.NotNil(t, p.Spec.Config)
	assert.Equal(t, "my-plugin", p.Spec.Config.Name)
	assert.Equal(t, "/usr/share/falco/plugins/my-plugin.so", p.Spec.Config.LibraryPath)
	assert.Equal(t, "param1=value1", p.Spec.Config.OpenParams)
	require.NotNil(t, p.Spec.Config.InitConfig)
	assert.Equal(t, []byte(`{"key":"value"}`), p.Spec.Config.InitConfig.Raw)
	require.NotNil(t, p.Spec.Selector)
	assert.Equal(t, selector, p.Spec.Selector)
}
