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

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestCompare(t *testing.T) {
	tests := []struct {
		name    string
		current *unstructured.Unstructured
		desired *unstructured.Unstructured
		wantErr bool
	}{
		{
			name: "same objects",
			current: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata": map[string]interface{}{
						"name": "test",
					},
					"data": map[string]interface{}{
						"key": "value",
					},
				},
			},
			desired: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata": map[string]interface{}{
						"name": "test",
					},
					"data": map[string]interface{}{
						"key": "value",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "different values",
			current: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata": map[string]interface{}{
						"name": "test",
					},
					"data": map[string]interface{}{
						"key": "value1",
					},
				},
			},
			desired: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata": map[string]interface{}{
						"name": "test",
					},
					"data": map[string]interface{}{
						"key": "value2",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "unknown type fails",
			current: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "unknown.example.com/v1",
					"kind":       "UnknownKind",
				},
			},
			desired: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "unknown.example.com/v1",
					"kind":       "UnknownKind",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Compare(tt.current, tt.desired)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestNeedsUpdate(t *testing.T) {
	tests := []struct {
		name           string
		current        *unstructured.Unstructured
		desired        *unstructured.Unstructured
		expectedUpdate bool
		wantErr        bool
	}{
		{
			name: "same objects - no update needed",
			current: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata": map[string]interface{}{
						"name": "test",
					},
					"data": map[string]interface{}{
						"key": "value",
					},
				},
			},
			desired: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata": map[string]interface{}{
						"name": "test",
					},
					"data": map[string]interface{}{
						"key": "value",
					},
				},
			},
			expectedUpdate: false,
			wantErr:        false,
		},
		{
			name: "different values - update needed",
			current: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata": map[string]interface{}{
						"name": "test",
					},
					"data": map[string]interface{}{
						"key": "value1",
					},
				},
			},
			desired: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata": map[string]interface{}{
						"name": "test",
					},
					"data": map[string]interface{}{
						"key": "value2",
					},
				},
			},
			expectedUpdate: true,
			wantErr:        false,
		},
		{
			name: "added field - update needed",
			current: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata": map[string]interface{}{
						"name": "test",
					},
				},
			},
			desired: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata": map[string]interface{}{
						"name": "test",
					},
					"data": map[string]interface{}{
						"key": "value",
					},
				},
			},
			expectedUpdate: true,
			wantErr:        false,
		},
		{
			name: "removed field - update needed",
			current: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata": map[string]interface{}{
						"name": "test",
					},
					"data": map[string]interface{}{
						"key": "value",
					},
				},
			},
			desired: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata": map[string]interface{}{
						"name": "test",
					},
				},
			},
			expectedUpdate: true,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NeedsUpdate(tt.current, tt.desired)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedUpdate, result)
			}
		})
	}
}
