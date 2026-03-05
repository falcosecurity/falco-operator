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

// Package index defines field indexes for artifact CRDs.
package index

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

// Entry contains the information needed to set up an index for a field on an object.
type Entry struct {
	// Object is the object type to index.
	Object client.Object

	// Field is the name of the index to create.
	Field string

	// ExtractValueFn is a function that extracts the value to index on from the object.
	ExtractValueFn client.IndexerFunc
}

// All aggregates all field indexes defined in this package.
var All []Entry = append(ConfigIndexes, RulesfileIndexes...)

// IndexByConfigMapRef returns a client.IndexerFunc that indexes objects by their ConfigMapRef name.
// The getRef function extracts the ConfigMapRef from the typed object; return nil when not set.
func IndexByConfigMapRef[T client.Object](getRef func(T) *commonv1alpha1.ConfigMapRef) client.IndexerFunc {
	return func(obj client.Object) []string {
		typed, ok := obj.(T)
		if !ok {
			return nil
		}
		ref := getRef(typed)
		if ref == nil {
			return nil
		}
		return []string{typed.GetNamespace() + "/" + ref.Name}
	}
}
