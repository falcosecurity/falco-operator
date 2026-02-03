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
	"bytes"
	"fmt"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/structured-merge-diff/v4/fieldpath"
	"sigs.k8s.io/structured-merge-diff/v4/typed"
)

// ExtractAsUnstructured extracts the managed fields for a given field manager from a runtime.Object,
// returning an unstructured.Unstructured containing only the fields managed by that manager.
// Returns nil if no managed fields entry is found, or an error if extraction fails.
func ExtractAsUnstructured(obj runtime.Object, fieldManager string) (*unstructured.Unstructured, error) {
	objectType, err := GetObjectType(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to get object type for managed fields extraction: %w", err)
	}

	typedObj, err := toTyped(obj, objectType)
	if err != nil {
		return nil, fmt.Errorf("error converting obj to typed: %w", err)
	}

	accessor, err := apimeta.Accessor(obj)
	if err != nil {
		return nil, fmt.Errorf("error accessing metadata: %w", err)
	}

	fieldsEntry, ok := findManagedFields(accessor, fieldManager)
	if !ok {
		return nil, nil
	}

	fieldset := &fieldpath.Set{}
	if err := fieldset.FromJSON(bytes.NewReader(fieldsEntry.FieldsV1.Raw)); err != nil {
		return nil, fmt.Errorf("error parsing FieldsV1 JSON: %w", err)
	}

	u := typedObj.ExtractItems(fieldset.Leaves()).AsValue().Unstructured()
	m, ok := u.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unable to convert managed fields for %s to unstructured, expected map, got %T", fieldManager, u)
	}

	// Set the same GVK for the extracted object
	gvk := obj.GetObjectKind().GroupVersionKind()
	m["apiVersion"] = gvk.GroupVersion().String()
	m["kind"] = gvk.Kind

	// Copy identity fields (name, namespace) from the original object.
	// Managed fields don't track these as they're part of the object key,
	// but we need them for accurate comparison with desired state.
	if meta, ok := m["metadata"].(map[string]any); ok {
		meta["name"] = accessor.GetName()
		if ns := accessor.GetNamespace(); ns != "" {
			meta["namespace"] = ns
		}
	} else {
		m["metadata"] = map[string]any{
			"name":      accessor.GetName(),
			"namespace": accessor.GetNamespace(),
		}
	}

	return &unstructured.Unstructured{Object: m}, nil
}

// findManagedFields searches the managed fields of a Kubernetes object for an entry
// matching the given field manager with Apply operation.
func findManagedFields(accessor metav1.Object, fieldManager string) (metav1.ManagedFieldsEntry, bool) {
	for _, mf := range accessor.GetManagedFields() {
		if mf.Manager == fieldManager && mf.Operation == metav1.ManagedFieldsOperationApply && mf.Subresource == "" {
			return mf, true
		}
	}
	return metav1.ManagedFieldsEntry{}, false
}

// toTyped converts a runtime.Object to a *typed.TypedValue using the provided ParseableType.
func toTyped(obj runtime.Object, objectType typed.ParseableType) (*typed.TypedValue, error) {
	switch o := obj.(type) {
	case *unstructured.Unstructured:
		return objectType.FromUnstructured(o.Object)
	default:
		return objectType.FromStructured(o)
	}
}
