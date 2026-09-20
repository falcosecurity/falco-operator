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

package component

import (
	"context"
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestComponentSpecValidation(t *testing.T) {
	for _, tt := range []struct {
		name      string
		fields    map[string]any
		wantField string
	}{
		{name: "missing-spec", wantField: "spec"},
		{name: "null-spec", fields: map[string]any{"spec": nil}, wantField: "spec"},
		{name: "empty-spec", fields: map[string]any{"spec": map[string]any{}}, wantField: "spec.component"},
		{name: "empty-component", fields: map[string]any{"spec": map[string]any{"component": map[string]any{}}}, wantField: "spec.component.type"},
		{name: "valid", fields: map[string]any{"spec": map[string]any{"component": map[string]any{"type": "metacollector"}}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Use unstructured objects so Go serialization cannot turn an omitted spec
			// into an empty ComponentSpec and mask the admission regression.
			obj := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "instance.falcosecurity.dev/v1alpha1",
				"kind":       "Component",
				"metadata": map[string]any{
					"name":      "validation-" + tt.name,
					"namespace": "default",
				},
			}}
			maps.Copy(obj.Object, tt.fields)
			err := k8sClient.Create(context.Background(), obj)
			if err == nil {
				t.Cleanup(func() {
					require.NoError(t, k8sClient.Delete(context.Background(), obj))
				})
			}
			if tt.wantField == "" {
				require.NoError(t, err)
				return
			}
			require.Truef(t, k8serrors.IsInvalid(err), "expected Invalid, got %v", err)
			var statusErr *k8serrors.StatusError
			require.ErrorAs(t, err, &statusErr)
			require.NotNil(t, statusErr.ErrStatus.Details)
			for _, cause := range statusErr.ErrStatus.Details.Causes {
				if cause.Field == tt.wantField && cause.Type == metav1.CauseTypeFieldValueRequired {
					return
				}
			}
			assert.Failf(t, "missing required-field error", "wanted %s, got %+v", tt.wantField, statusErr.ErrStatus.Details.Causes)
		})
	}
}
