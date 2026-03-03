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

package controllerhelper

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/structured-merge-diff/v4/fieldpath"
	"sigs.k8s.io/structured-merge-diff/v4/typed"

	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
)

func TestDiff(t *testing.T) {
	tests := []struct {
		name            string
		current         runtime.Object
		desired         *unstructured.Unstructured
		wantErr         bool
		wantErrIs       error
		wantErrContains string
		wantNil         bool
	}{
		{
			name:    "nil current returns error",
			current: nil,
			desired: &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
				},
			},
			wantErr: true,
			wantNil: true,
		},
		{
			name:    "nil desired returns error",
			current: builders.NewConfigMap().WithName("test").Build(),
			desired: nil,
			wantErr: true,
			wantNil: true,
		},
		{
			name:    "no managed fields returns ErrNoManagedFields",
			current: builders.NewDaemonSet().WithName("test").Build(),
			desired: &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "apps/v1",
					"kind":       "DaemonSet",
					"metadata": map[string]any{
						"name": "test",
					},
				},
			},
			wantErr:   true,
			wantErrIs: ErrNoManagedFields,
			wantNil:   true,
		},
		{
			name: "unresolvable object schema returns extraction error",
			current: &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "custom.example.com/v1",
					"kind":       "UnknownResource",
					"metadata": map[string]any{
						"name": "test",
					},
				},
			},
			desired: &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "custom.example.com/v1",
					"kind":       "UnknownResource",
					"metadata": map[string]any{
						"name": "test",
					},
				},
			},
			wantErr:         true,
			wantErrContains: "failed to extract managed fields",
			wantNil:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Diff(tt.current, tt.desired, "test-controller")

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantNil {
				assert.Nil(t, result)
			}

			if tt.wantErrIs != nil {
				assert.ErrorIs(t, err, tt.wantErrIs)
			} else if tt.wantErr && tt.wantErrIs == nil && tt.wantErrContains == "" {
				// Generic error, no specific check beyond wantErr
				assert.NotErrorIs(t, err, ErrNoManagedFields)
			}

			if tt.wantErrContains != "" {
				assert.Contains(t, err.Error(), tt.wantErrContains)
				assert.NotErrorIs(t, err, ErrNoManagedFields)
			}
		})
	}
}

func TestErrNoManagedFields(t *testing.T) {
	t.Run("error message is descriptive", func(t *testing.T) {
		assert.Contains(t, ErrNoManagedFields.Error(), "no managed fields")
	})

	t.Run("can be wrapped and unwrapped", func(t *testing.T) {
		wrapped := fmt.Errorf("failed to compare: %w", ErrNoManagedFields)
		assert.ErrorIs(t, wrapped, ErrNoManagedFields)
	})

	t.Run("is distinguishable from other errors", func(t *testing.T) {
		otherErr := fmt.Errorf("some other error")
		assert.NotErrorIs(t, otherErr, ErrNoManagedFields)
	})
}

func TestFormatChangedFields(t *testing.T) {
	t.Run("nil comparison returns empty string", func(t *testing.T) {
		result := FormatChangedFields(nil)
		assert.Empty(t, result)
	})

	t.Run("empty comparison returns no changes", func(t *testing.T) {
		comparison := &typed.Comparison{
			Added:    &fieldpath.Set{},
			Modified: &fieldpath.Set{},
			Removed:  &fieldpath.Set{},
		}
		result := FormatChangedFields(comparison)
		assert.Equal(t, "no changes", result)
	})

	t.Run("only added fields", func(t *testing.T) {
		added := fieldpath.NewSet(fieldpath.MakePathOrDie("spec", "replicas"))
		comparison := &typed.Comparison{
			Added:    added,
			Modified: &fieldpath.Set{},
			Removed:  &fieldpath.Set{},
		}
		result := FormatChangedFields(comparison)
		assert.Contains(t, result, "added:")
		assert.Contains(t, result, "spec")
		assert.NotContains(t, result, "modified:")
		assert.NotContains(t, result, "removed:")
	})

	t.Run("only modified fields", func(t *testing.T) {
		modified := fieldpath.NewSet(fieldpath.MakePathOrDie("spec", "template", "spec", "containers"))
		comparison := &typed.Comparison{
			Added:    &fieldpath.Set{},
			Modified: modified,
			Removed:  &fieldpath.Set{},
		}
		result := FormatChangedFields(comparison)
		assert.Contains(t, result, "modified:")
		assert.Contains(t, result, "spec")
		assert.NotContains(t, result, "added:")
		assert.NotContains(t, result, "removed:")
	})

	t.Run("only removed fields", func(t *testing.T) {
		removed := fieldpath.NewSet(fieldpath.MakePathOrDie("metadata", "labels"))
		comparison := &typed.Comparison{
			Added:    &fieldpath.Set{},
			Modified: &fieldpath.Set{},
			Removed:  removed,
		}
		result := FormatChangedFields(comparison)
		assert.Contains(t, result, "removed:")
		assert.Contains(t, result, "metadata")
		assert.NotContains(t, result, "added:")
		assert.NotContains(t, result, "modified:")
	})

	t.Run("multiple change types", func(t *testing.T) {
		added := fieldpath.NewSet(fieldpath.MakePathOrDie("spec", "newField"))
		modified := fieldpath.NewSet(fieldpath.MakePathOrDie("spec", "replicas"))
		removed := fieldpath.NewSet(fieldpath.MakePathOrDie("metadata", "annotations"))
		comparison := &typed.Comparison{
			Added:    added,
			Modified: modified,
			Removed:  removed,
		}
		result := FormatChangedFields(comparison)
		assert.Contains(t, result, "added:")
		assert.Contains(t, result, "modified:")
		assert.Contains(t, result, "removed:")
		assert.Contains(t, result, "; ")
	})
}
