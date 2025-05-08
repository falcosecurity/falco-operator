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

package common_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/falcosecurity/falco-operator/internal/pkg/common"
)

func TestNodeMatchesSelector(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name          string
		nodeName      string
		nodeLabels    map[string]string
		labelSelector *metav1.LabelSelector
		expectedMatch bool
		expectedError bool
	}{
		{
			name:     "Node matches labelSelector",
			nodeName: "node1",
			nodeLabels: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			labelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"key1": "value1",
				},
			},
			expectedMatch: true,
			expectedError: false,
		},
		{
			name:     "Node does not match labelSelector",
			nodeName: "node2",
			nodeLabels: map[string]string{
				"key1": "value1",
			},
			labelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"key2": "value2",
				},
			},
			expectedMatch: false,
			expectedError: false,
		},
		{
			name:     "Invalid labelSelector",
			nodeName: "node3",
			nodeLabels: map[string]string{
				"key1": "value1",
			},
			labelSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "key1",
						Operator: "InvalidOperator",
					},
				},
			},
			expectedMatch: false,
			expectedError: true,
		},
		{
			name:          "Nil labelSelector (matches all nodes)",
			nodeName:      "node4",
			nodeLabels:    map[string]string{},
			labelSelector: nil,
			expectedMatch: true,
			expectedError: false,
		},
		{
			name:       "Node not found",
			nodeName:   "nonexistent-node",
			nodeLabels: map[string]string{},
			labelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"key1": "value1",
				},
			},
			expectedMatch: false,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fakeClient client.Client
			if tt.name != "Node not found" { // Only add the node if it exists
				node := &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   tt.nodeName,
						Labels: tt.nodeLabels,
					},
				}
				fakeClient = fake.NewClientBuilder().WithScheme(scheme).WithObjects(node).Build()
			} else {
				// Create a fake client without any objects, to simulate a node not found.
				fakeClient = fake.NewClientBuilder().WithScheme(scheme).Build()
			}

			match, err := common.NodeMatchesSelector(context.TODO(), fakeClient, tt.nodeName, tt.labelSelector)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedMatch, match)
		})
	}
}
