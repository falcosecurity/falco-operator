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

package managedfields

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestMerge(t *testing.T) {
	base := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		Data:       map[string]string{"keep": "base", "replace": "old"},
	}
	overrides := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		Data:     map[string]string{"replace": "new", "add": "user"},
	}
	baseMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(base)
	require.NoError(t, err)
	overridesMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(overrides)
	require.NoError(t, err)
	for baseName, baseObj := range map[string]runtime.Object{
		"structured": base, "unstructured": &unstructured.Unstructured{Object: baseMap},
	} {
		for overridesName, overridesObj := range map[string]runtime.Object{
			"structured": overrides, "unstructured": &unstructured.Unstructured{Object: overridesMap},
		} {
			t.Run(baseName+"/"+overridesName, func(t *testing.T) {
				beforeBase, beforeOverrides := baseObj.DeepCopyObject(), overridesObj.DeepCopyObject()
				merged, err := Merge(baseObj, overridesObj)
				require.NoError(t, err)
				var result corev1.ConfigMap
				require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(merged.Object, &result))
				expected := base.DeepCopy()
				expected.Data = map[string]string{"keep": "base", "replace": "new", "add": "user"}
				require.Equal(t, *expected, result)
				require.Equal(t, beforeBase, baseObj)
				require.Equal(t, beforeOverrides, overridesObj)
			})
		}
	}
}

func TestMergeRejectsInvalidObjects(t *testing.T) {
	valid := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap"}}
	invalid := valid.DeepCopy()
	invalid.Object["data"] = map[string]any{"key": int64(1)}
	tests := []struct {
		name            string
		base, overrides runtime.Object
	}{
		{"invalid base", invalid, valid},
		{"invalid overrides", valid, invalid},
		{"missing type", valid, &unstructured.Unstructured{Object: map[string]any{"data": map[string]any{"key": "value"}}}},
		{"different types", valid, &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Secret"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			merged, err := Merge(tt.base, tt.overrides)
			require.Error(t, err)
			require.Nil(t, merged)
		})
	}
}
