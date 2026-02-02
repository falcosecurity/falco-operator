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
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_generatesUniqueNameCorrectly(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		expected  string
	}{
		{"simple", "default", "simple--default"},
		{"name--with--dashes", "namespace--with--dashes", "name__DASH__with__DASH__dashes--namespace__DASH__with__DASH__dashes"},
		{"", "namespace", "--namespace"},
		{"name", "", "name--"},
		{"name--", "namespace--", "name__DASH__--namespace__DASH__"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_"+tt.namespace, func(t *testing.T) {
			result := GenerateUniqueName(tt.name, tt.namespace)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func Test_parsesUniqueNameCorrectly(t *testing.T) {
	tests := []struct {
		uniqueName        string
		expectedName      string
		expectedNamespace string
		expectError       bool
	}{
		{"simple--default", "simple", "default", false},
		{"name__DASH__with__DASH__dashes--namespace__DASH__with__DASH__dashes", "name--with--dashes", "namespace--with--dashes", false},
		{"--namespace", "", "namespace", false},
		{"name--", "name", "", false},
		{"invalid-name", "", "", true},
		{"name__DASH__--namespace__DASH__", "name--", "namespace--", false},
	}

	for _, tt := range tests {
		t.Run(tt.uniqueName, func(t *testing.T) {
			name, namespace, err := ParseUniqueName(tt.uniqueName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedName, name)
				assert.Equal(t, tt.expectedNamespace, namespace)
			}
		})
	}
}

func Test_handlesInvalidUniqueNameFormats(t *testing.T) {
	tests := []struct {
		uniqueName  string
		expectError bool
	}{
		{"", true},
		{"--", true},
		{"invalid--name--format--", true},
		{"name--namespace--extra", true},
	}

	for _, tt := range tests {
		t.Run(tt.uniqueName, func(t *testing.T) {
			_, _, err := ParseUniqueName(tt.uniqueName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
