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

package node

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
)

func TestResolveConfigName(t *testing.T) {
	tests := []struct {
		name     string
		plugin   *artifactv1alpha1.Plugin
		expected string
	}{
		{
			name: "uses CR name when config is nil",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
			},
			expected: "my-plugin",
		},
		{
			name: "uses CR name when config name is empty",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{},
				},
			},
			expected: "my-plugin",
		},
		{
			name: "uses config name when set",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{Name: "custom-name"},
				},
			},
			expected: "custom-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, resolveConfigName(tt.plugin))
		})
	}
}
