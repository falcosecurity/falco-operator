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
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
)

func TestIndexByConfigMapRef(t *testing.T) {
	indexer := index.IndexByConfigMapRef(func(c *artifactv1alpha1.Config) *commonv1alpha1.ConfigMapRef {
		return c.Spec.ConfigMapRef
	})

	tests := []struct {
		name string
		obj  client.Object
		want []string
	}{
		{
			name: "nil ref returns nil",
			obj:  &artifactv1alpha1.Config{ObjectMeta: metav1.ObjectMeta{Name: "cfg", Namespace: "ns"}},
			want: nil,
		},
		{
			name: "ref set returns namespace/name key",
			obj: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{Name: "cfg", Namespace: "ns"},
				Spec:       artifactv1alpha1.ConfigSpec{ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-cm"}},
			},
			want: []string{"ns/my-cm"},
		},
		{
			name: "wrong object type returns nil",
			obj:  &artifactv1alpha1.Rulesfile{ObjectMeta: metav1.ObjectMeta{Name: "rf", Namespace: "ns"}},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, indexer(tt.obj))
		})
	}
}

func TestAll(t *testing.T) {
	expected := make([]index.Entry, 0, len(index.ConfigIndexes)+len(index.RulesfileIndexes)+len(index.PluginIndexes))
	expected = append(expected, index.ConfigIndexes...)
	expected = append(expected, index.RulesfileIndexes...)
	expected = append(expected, index.PluginIndexes...)
	require.Len(t, index.All, len(expected), "All must contain exactly one entry per resource index")

	for i, entry := range index.All {
		assert.Equal(t, expected[i].Field, entry.Field, "entry %d: field mismatch", i)
		assert.NotNil(t, entry.Object, "entry %d: Object must not be nil", i)
		assert.NotNil(t, entry.ExtractValueFn, "entry %d: ExtractValueFn must not be nil", i)
	}
}
