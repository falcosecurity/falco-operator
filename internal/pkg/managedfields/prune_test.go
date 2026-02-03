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

func TestPruneEmptyFields(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		expected map[string]any
	}{
		{
			name: "removes empty maps",
			input: map[string]any{
				"metadata": map[string]any{
					"name":   "test",
					"labels": map[string]any{},
				},
			},
			expected: map[string]any{
				"metadata": map[string]any{
					"name": "test",
				},
			},
		},
		{
			name: "removes empty slices",
			input: map[string]any{
				"spec": map[string]any{
					"containers": []any{},
				},
			},
			expected: map[string]any{},
		},
		{
			name: "removes nested empty maps",
			input: map[string]any{
				"spec": map[string]any{
					"template": map[string]any{
						"spec": map[string]any{
							"containers": []any{
								map[string]any{
									"name": "test",
								},
							},
						},
					},
				},
			},
			expected: map[string]any{
				"spec": map[string]any{
					"template": map[string]any{
						"spec": map[string]any{
							"containers": []any{
								map[string]any{
									"name": "test",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "keeps boolean false values",
			input: map[string]any{
				"spec": map[string]any{
					"enabled": false,
				},
			},
			expected: map[string]any{
				"spec": map[string]any{
					"enabled": false,
				},
			},
		},
		{
			name: "removes zero values for non-bool types",
			input: map[string]any{
				"spec": map[string]any{
					"replicas": 0,
					"name":     "",
				},
			},
			expected: map[string]any{},
		},
		{
			name: "removes empty maps from slices",
			input: map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{},
						map[string]any{"name": "test"},
					},
				},
			},
			expected: map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{"name": "test"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &unstructured.Unstructured{Object: tt.input}
			PruneEmptyFields(u)
			assert.Equal(t, tt.expected, u.Object)
		})
	}
}
