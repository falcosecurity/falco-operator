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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/structured-merge-diff/v6/fieldpath"
)

func TestExtractAsUnstructuredPreservesFieldOwnership(t *testing.T) {
	imagePath := fieldpath.MakePathOrDie("spec", "template", "spec", "containers", fieldpath.KeyByFields("name", "app"), "image")
	owned := fieldpath.NewSet(imagePath, fieldpath.MakePathOrDie(
		"spec", "template", "spec", "containers", fieldpath.KeyByFields("name", "app"), "name"))
	fields, err := owned.ToJSON()
	require.NoError(t, err)
	live := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test", Namespace: "default",
			ManagedFields: []metav1.ManagedFieldsEntry{{
				Manager: "operator", Operation: metav1.ManagedFieldsOperationApply, APIVersion: "apps/v1",
				FieldsType: "FieldsV1", FieldsV1: &metav1.FieldsV1{Raw: fields},
			}},
		},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "app:v1", Args: []string{"--user-owned"}},
				{Name: "user-sidecar", Image: "sidecar:v1"},
			},
		}}},
	}
	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(live)
	require.NoError(t, err)
	for name, obj := range map[string]runtime.Object{
		"structured": live, "unstructured": &unstructured.Unstructured{Object: object},
	} {
		t.Run(name, func(t *testing.T) {
			before := obj.DeepCopyObject()
			extracted, err := ExtractAsUnstructured(obj, "operator")
			require.NoError(t, err)
			require.NotNil(t, extracted)
			expected := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "apps/v1", "kind": "Deployment",
				"metadata": map[string]any{"name": "test", "namespace": "default"},
				"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
					"containers": []any{map[string]any{"name": "app", "image": "app:v1"}},
				}}},
			}}
			require.Equal(t, expected, extracted, "unowned arguments and sidecars must not be extracted")
			comparison, err := Compare(extracted, expected)
			require.NoError(t, err)
			require.True(t, comparison.IsSame())
			require.NoError(t, unstructured.SetNestedSlice(expected.Object,
				[]any{map[string]any{"name": "app", "image": "app:v2"}}, "spec", "template", "spec", "containers"))
			comparison, err = Compare(extracted, expected)
			require.NoError(t, err)
			require.True(t, comparison.Added.Empty())
			require.True(t, comparison.Removed.Empty())
			require.True(t, comparison.Modified.Equals(fieldpath.NewSet(imagePath)), "only the owned image field should change")
			missing, err := ExtractAsUnstructured(obj, "absent-manager")
			require.NoError(t, err)
			require.Nil(t, missing)
			require.Equal(t, before, obj)
		})
	}
}
