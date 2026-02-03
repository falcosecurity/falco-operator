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
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/structured-merge-diff/v4/typed"

	"github.com/falcosecurity/falco-operator/internal/pkg/managedfields"
)

const (
	// fieldManager is the name used to identify the controller's managed fields.
	fieldManager = "falco-controller"
)

// needsUpdate checks if the current object needs to be updated to match the desired state.
// It extracts only the fields managed by this controller and compares them with the desired config.
//
// This avoids unnecessary API writes on Kubernetes versions < 1.31 where Server-Side Apply
// may cause spurious resourceVersion bumps on no-op patches.
// See: https://github.com/kubernetes/kubernetes/issues/124605
func needsUpdate(current runtime.Object, desired *unstructured.Unstructured) (bool, error) {
	if current == nil || desired == nil {
		return true, nil
	}

	// Extract only the fields managed by our field manager from the current object
	extracted, err := managedfields.ExtractAsUnstructured(current, fieldManager)
	if err != nil {
		return true, fmt.Errorf("failed to extract managed fields: %w", err)
	}

	// If no managed fields found, we need to apply
	if extracted == nil {
		return true, nil
	}

	// Prune empty fields from both objects before comparison
	managedfields.PruneEmptyFields(extracted)
	managedfields.PruneEmptyFields(desired)

	// Compare the extracted managed fields with the desired state
	return managedfields.NeedsUpdate(extracted, desired)
}

// diff calculates the difference between the current and desired objects.
// Returns a typed.Comparison that contains Added, Modified, and Removed field sets.
func diff(current runtime.Object, desired *unstructured.Unstructured) (*typed.Comparison, error) {
	if current == nil || desired == nil {
		return nil, fmt.Errorf("current and desired objects cannot be nil")
	}

	// Extract only the fields managed by our field manager
	extracted, err := managedfields.ExtractAsUnstructured(current, fieldManager)
	if err != nil {
		return nil, fmt.Errorf("failed to extract managed fields: %w", err)
	}

	if extracted == nil {
		return nil, fmt.Errorf("no managed fields found for field manager %s", fieldManager)
	}

	// Deep copy desired to avoid modifying the original
	desiredCopy := desired.DeepCopy()

	// Prune empty fields before comparison
	managedfields.PruneEmptyFields(extracted)
	managedfields.PruneEmptyFields(desiredCopy)

	return managedfields.Compare(extracted, desiredCopy)
}
