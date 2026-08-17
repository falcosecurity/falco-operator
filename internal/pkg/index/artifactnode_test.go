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

package index_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
)

func TestArtifactNodeOwnerKindIndexer(t *testing.T) {
	tests := []struct {
		name string
		node *artifactv1alpha1.ArtifactNode
		want []string
	}{
		{
			name: "no controller owner reference returns nil",
			node: &artifactv1alpha1.ArtifactNode{},
			want: nil,
		},
		{
			name: "controller owner reference returns its Kind",
			node: &artifactv1alpha1.ArtifactNode{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "Plugin", Controller: new(true)},
					},
				},
			},
			want: []string{"Plugin"},
		},
		{
			name: "non-controller owner reference is ignored",
			node: &artifactv1alpha1.ArtifactNode{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "Plugin", Controller: new(false)},
					},
				},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, index.ArtifactNodeOwnerKindIndexer(tt.node))
		})
	}
}

func TestArtifactNodeOwnerKindIndexer_WrongType(t *testing.T) {
	// A client.Object of a different type with no owner references returns nil.
	got := index.ArtifactNodeOwnerKindIndexer(builders.NewConfigMap().WithName("cm").WithNamespace(testNamespace).Build())
	assert.Nil(t, got)
}

func TestArtifactNodeNodeNameIndexer(t *testing.T) {
	tests := []struct {
		name string
		node *artifactv1alpha1.ArtifactNode
		want []string
	}{
		{
			name: "node name set returns it",
			node: &artifactv1alpha1.ArtifactNode{
				Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "node-1"},
			},
			want: []string{"node-1"},
		},
		{
			name: "empty node name returns the empty string",
			node: &artifactv1alpha1.ArtifactNode{},
			want: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, index.ArtifactNodeNodeNameIndexer(tt.node))
		})
	}
}

func TestArtifactNodeNodeNameIndexer_WrongType(t *testing.T) {
	// Passing a wrong object type must return nil (the !ok branch).
	got := index.ArtifactNodeNodeNameIndexer(builders.NewConfigMap().WithName("cm").WithNamespace(testNamespace).Build())
	assert.Nil(t, got)
}
