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
	"errors"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/structured-merge-diff/v4/typed"

	"github.com/falcosecurity/falco-operator/internal/pkg/managedfields"
)

const (
	// fieldManager is the name used to identify the controller's managed fields.
	fieldManager = "falco-controller"
)

// ErrNoManagedFields is returned when no managed fields are found for the field manager.
// This is not a fatal error - it indicates the resource was never managed by this controller
// and should be applied.
var ErrNoManagedFields = errors.New("no managed fields found for field manager")

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
		return nil, ErrNoManagedFields
	}

	// Deep copy desired to avoid modifying the original
	desiredCopy := desired.DeepCopy()

	// Prune empty fields before comparison
	managedfields.PruneEmptyFields(extracted)
	managedfields.PruneEmptyFields(desiredCopy)

	return managedfields.Compare(extracted, desiredCopy)
}

// formatChangedFields returns a human-readable summary of the changed fields from a comparison.
func formatChangedFields(comparison *typed.Comparison) string {
	if comparison == nil {
		return ""
	}

	var parts []string

	if !comparison.Added.Empty() {
		parts = append(parts, fmt.Sprintf("added: %s", comparison.Added.String()))
	}
	if !comparison.Modified.Empty() {
		parts = append(parts, fmt.Sprintf("modified: %s", comparison.Modified.String()))
	}
	if !comparison.Removed.Empty() {
		parts = append(parts, fmt.Sprintf("removed: %s", comparison.Removed.String()))
	}

	if len(parts) == 0 {
		return "no changes"
	}

	return strings.Join(parts, "; ")
}
