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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestNeedsUpdate(t *testing.T) {
	t.Run("nil current returns needs update", func(t *testing.T) {
		desired := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "ConfigMap",
			},
		}
		result, err := needsUpdate(nil, desired)
		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("nil desired returns needs update", func(t *testing.T) {
		current := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
		}
		result, err := needsUpdate(current, nil)
		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("no managed fields returns needs update", func(t *testing.T) {
		current := &appsv1.DaemonSet{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "apps/v1",
				Kind:       "DaemonSet",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "test",
				// No ManagedFields set
			},
		}
		desired := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "DaemonSet",
				"metadata": map[string]interface{}{
					"name": "test",
				},
			},
		}
		result, err := needsUpdate(current, desired)
		assert.NoError(t, err)
		assert.True(t, result) // No managed fields means we need to apply
	})
}

func TestDiff(t *testing.T) {
	t.Run("nil current returns error", func(t *testing.T) {
		desired := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "ConfigMap",
			},
		}
		result, err := diff(nil, desired)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("nil desired returns error", func(t *testing.T) {
		current := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
		}
		result, err := diff(current, nil)
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}
