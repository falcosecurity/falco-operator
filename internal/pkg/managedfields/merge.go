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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// Merge combines built-in Kubernetes objects using the schema bundled with client-go.
// Both objects must have the same GroupVersionKind set. Overrides take precedence
// according to the schema's map and list semantics; neither input is modified.
func Merge(base, overrides runtime.Object) (*unstructured.Unstructured, error) {
	baseTyped, err := toTyped(base)
	if err != nil {
		return nil, err
	}

	overridesTyped, err := toTyped(overrides)
	if err != nil {
		return nil, err
	}

	merged, err := baseTyped.Merge(overridesTyped)
	if err != nil {
		return nil, err
	}

	return &unstructured.Unstructured{Object: merged.AsValue().Unstructured().(map[string]any)}, nil
}
