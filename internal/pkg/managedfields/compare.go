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
	"sigs.k8s.io/structured-merge-diff/v4/typed"
)

// Compare calculates the difference between the current (extracted) and desired objects.
// Returns a typed.Comparison that contains Added, Modified, and Removed field sets.
func Compare(current, desired *unstructured.Unstructured) (*typed.Comparison, error) {
	currentParsable, err := GetObjectType(current)
	if err != nil {
		return nil, err
	}

	desiredParsable, err := GetObjectType(desired)
	if err != nil {
		return nil, err
	}

	currentTyped, err := currentParsable.FromUnstructured(current.Object)
	if err != nil {
		return nil, err
	}

	desiredTyped, err := desiredParsable.FromUnstructured(desired.Object)
	if err != nil {
		return nil, err
	}

	return currentTyped.Compare(desiredTyped)
}

// NeedsUpdate checks if the current object needs to be updated to match the desired state.
// Returns true if there are any differences (additions, modifications, or removals).
func NeedsUpdate(current, desired *unstructured.Unstructured) (bool, error) {
	comparison, err := Compare(current, desired)
	if err != nil {
		return true, err
	}

	// If any fields were added, modified, or removed, we need an update
	return !comparison.Added.Empty() || !comparison.Modified.Empty() || !comparison.Removed.Empty(), nil
}
