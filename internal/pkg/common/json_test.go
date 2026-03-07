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

package common

import (
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestJSONRawToYAML(t *testing.T) {
	tests := []struct {
		name    string
		raw     *apiextensionsv1.JSON
		want    *string
		wantErr bool
	}{
		{
			name: "nil input returns nil",
			raw:  nil,
			want: nil,
		},
		{
			name: "empty raw bytes returns nil",
			raw:  &apiextensionsv1.JSON{Raw: []byte{}},
			want: nil,
		},
		{
			name: "valid JSON object is converted to YAML",
			raw:  &apiextensionsv1.JSON{Raw: []byte(`{"key":"value"}`)},
			want: new("key: value\n"),
		},
		{
			name:    "invalid JSON returns error",
			raw:     &apiextensionsv1.JSON{Raw: []byte(`{invalid`)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JSONRawToYAML(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.want == nil {
				if got != nil {
					t.Errorf("expected nil, got %q", *got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil result, got nil")
			}
			if *got != *tt.want {
				t.Errorf("got %q, want %q", *got, *tt.want)
			}
		})
	}
}
