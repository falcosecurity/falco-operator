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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/structured-merge-diff/v4/fieldpath"
	"sigs.k8s.io/structured-merge-diff/v4/typed"
)

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

	t.Run("no managed fields returns ErrNoManagedFields", func(t *testing.T) {
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
		result, err := diff(current, desired)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNoManagedFields)
		assert.Nil(t, result)
	})
}

func TestErrNoManagedFields(t *testing.T) {
	t.Run("error message is descriptive", func(t *testing.T) {
		assert.Contains(t, ErrNoManagedFields.Error(), "no managed fields")
	})

	t.Run("can be wrapped and unwrapped", func(t *testing.T) {
		wrapped := fmt.Errorf("failed to compare: %w", ErrNoManagedFields)
		assert.ErrorIs(t, wrapped, ErrNoManagedFields)
	})

	t.Run("is distinguishable from other errors", func(t *testing.T) {
		otherErr := fmt.Errorf("some other error")
		assert.NotErrorIs(t, otherErr, ErrNoManagedFields)
	})
}

func TestFormatChangedFields(t *testing.T) {
	t.Run("nil comparison returns empty string", func(t *testing.T) {
		result := formatChangedFields(nil)
		assert.Equal(t, "", result)
	})

	t.Run("empty comparison returns no changes", func(t *testing.T) {
		comparison := &typed.Comparison{
			Added:    &fieldpath.Set{},
			Modified: &fieldpath.Set{},
			Removed:  &fieldpath.Set{},
		}
		result := formatChangedFields(comparison)
		assert.Equal(t, "no changes", result)
	})

	t.Run("only added fields", func(t *testing.T) {
		added := fieldpath.NewSet(fieldpath.MakePathOrDie("spec", "replicas"))
		comparison := &typed.Comparison{
			Added:    added,
			Modified: &fieldpath.Set{},
			Removed:  &fieldpath.Set{},
		}
		result := formatChangedFields(comparison)
		assert.Contains(t, result, "added:")
		assert.Contains(t, result, "spec")
		assert.NotContains(t, result, "modified:")
		assert.NotContains(t, result, "removed:")
	})

	t.Run("only modified fields", func(t *testing.T) {
		modified := fieldpath.NewSet(fieldpath.MakePathOrDie("spec", "template", "spec", "containers"))
		comparison := &typed.Comparison{
			Added:    &fieldpath.Set{},
			Modified: modified,
			Removed:  &fieldpath.Set{},
		}
		result := formatChangedFields(comparison)
		assert.Contains(t, result, "modified:")
		assert.Contains(t, result, "spec")
		assert.NotContains(t, result, "added:")
		assert.NotContains(t, result, "removed:")
	})

	t.Run("only removed fields", func(t *testing.T) {
		removed := fieldpath.NewSet(fieldpath.MakePathOrDie("metadata", "labels"))
		comparison := &typed.Comparison{
			Added:    &fieldpath.Set{},
			Modified: &fieldpath.Set{},
			Removed:  removed,
		}
		result := formatChangedFields(comparison)
		assert.Contains(t, result, "removed:")
		assert.Contains(t, result, "metadata")
		assert.NotContains(t, result, "added:")
		assert.NotContains(t, result, "modified:")
	})

	t.Run("multiple change types", func(t *testing.T) {
		added := fieldpath.NewSet(fieldpath.MakePathOrDie("spec", "newField"))
		modified := fieldpath.NewSet(fieldpath.MakePathOrDie("spec", "replicas"))
		removed := fieldpath.NewSet(fieldpath.MakePathOrDie("metadata", "annotations"))
		comparison := &typed.Comparison{
			Added:    added,
			Modified: modified,
			Removed:  removed,
		}
		result := formatChangedFields(comparison)
		assert.Contains(t, result, "added:")
		assert.Contains(t, result, "modified:")
		assert.Contains(t, result, "removed:")
		assert.Contains(t, result, "; ")
	})
}
