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

package instance

import (
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/falcosecurity/falco-operator/internal/pkg/scheme"
)

// MergeApplyConfiguration merges a base structured resource with user-defined
// overrides using structured merge diff, and returns the result as unstructured.
// The kind parameter must be an apps/v1 resource kind (e.g., "Deployment", "DaemonSet").
func MergeApplyConfiguration(kind string, baseResource runtime.Object, userOverrides *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	schemaType := "io.k8s.api.apps.v1." + kind
	parser := scheme.Parser()

	baseTyped, err := parser.Type(schemaType).FromStructured(baseResource)
	if err != nil {
		return nil, err
	}

	userTyped, err := parser.Type(schemaType).FromUnstructured(userOverrides.Object)
	if err != nil {
		return nil, err
	}

	desiredTyped, err := baseTyped.Merge(userTyped)
	if err != nil {
		return nil, err
	}

	mergedUnstructured := (desiredTyped.AsValue().Unstructured()).(map[string]any)

	result := &unstructured.Unstructured{
		Object: mergedUnstructured,
	}

	result.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   appsv1.GroupName,
		Version: appsv1.SchemeGroupVersion.Version,
		Kind:    kind,
	})

	return result, nil
}
