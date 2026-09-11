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
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestToTyped(t *testing.T) {
	tests := []struct {
		gvk schema.GroupVersionKind
		obj runtime.Object
	}{
		{corev1.SchemeGroupVersion.WithKind("ConfigMap"), &corev1.ConfigMap{Data: map[string]string{"key": "value"}}},
		{appsv1.SchemeGroupVersion.WithKind("Deployment"), &appsv1.Deployment{}},
		{appsv1.SchemeGroupVersion.WithKind("DaemonSet"), &appsv1.DaemonSet{}},
		{rbacv1.SchemeGroupVersion.WithKind("Role"), &rbacv1.Role{}},
		{networkingv1.SchemeGroupVersion.WithKind("NetworkPolicy"), &networkingv1.NetworkPolicy{}},
		{corev1.SchemeGroupVersion.WithKind("Service"), &corev1.Service{}},
		{corev1.SchemeGroupVersion.WithKind("ServiceAccount"), &corev1.ServiceAccount{}},
	}
	for _, tt := range tests {
		t.Run(tt.gvk.Kind, func(t *testing.T) {
			tt.obj.GetObjectKind().SetGroupVersionKind(tt.gvk)
			before := tt.obj.DeepCopyObject()
			structured, err := toTyped(tt.obj)
			require.NoError(t, err)
			object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tt.obj)
			require.NoError(t, err)
			u := &unstructured.Unstructured{Object: object}
			beforeUnstructured := u.DeepCopy()
			unstructuredValue, err := toTyped(u)
			require.NoError(t, err)
			comparison, err := structured.Compare(unstructuredValue)
			require.NoError(t, err)
			require.True(t, comparison.IsSame(), "structured and unstructured objects must use the same schema")
			require.Equal(t, before, tt.obj)
			require.Equal(t, beforeUnstructured, u)
		})
	}
}

func TestToTypedRejectsInvalidObjects(t *testing.T) {
	tests := map[string]map[string]any{
		"missing kind":    {"apiVersion": "v1"},
		"missing version": {"kind": "ConfigMap"},
		"unknown type":    {"apiVersion": "unknown.example.com/v1", "kind": "UnknownKind"},
		"unknown version": {"apiVersion": "apps/v999", "kind": "Deployment"},
		"unknown field":   {"apiVersion": "v1", "kind": "ConfigMap", "notAField": "value"},
		"invalid value":   {"apiVersion": "v1", "kind": "ConfigMap", "data": map[string]any{"key": int64(1)}},
	}
	for name, object := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := toTyped(&unstructured.Unstructured{Object: object})
			require.Error(t, err)
		})
	}
}
