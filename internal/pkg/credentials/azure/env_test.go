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

package azure

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveString(t *testing.T) {
	const envVar = "AZURE_TEST_RESOLVE_STRING"

	t.Run("returns config value when set, ignoring the environment", func(t *testing.T) {
		t.Setenv(envVar, "from-env")
		assert.Equal(t, "from-config", resolveString("from-config", envVar))
	})

	t.Run("falls back to the environment variable when config is empty", func(t *testing.T) {
		t.Setenv(envVar, "from-env")
		assert.Equal(t, "from-env", resolveString("", envVar))
	})

	t.Run("returns empty when neither is set", func(t *testing.T) {
		t.Setenv(envVar, "")
		assert.Empty(t, resolveString("", envVar))
	})
}

func TestResolveBool(t *testing.T) {
	const envVar = "AZURE_TEST_RESOLVE_BOOL"

	trueVal := true
	falseVal := false

	t.Run("an explicit true in config wins over a conflicting env value", func(t *testing.T) {
		t.Setenv(envVar, "false")
		assert.True(t, resolveBool(&trueVal, envVar))
	})

	t.Run("an explicit false in config wins over a conflicting env value", func(t *testing.T) {
		t.Setenv(envVar, "true")
		assert.False(t, resolveBool(&falseVal, envVar))
	})

	t.Run(`falls back to the environment variable "1"`, func(t *testing.T) {
		t.Setenv(envVar, "1")
		assert.True(t, resolveBool(nil, envVar))
	})

	t.Run(`falls back to the environment variable "true", case-insensitive`, func(t *testing.T) {
		t.Setenv(envVar, "TRUE")
		assert.True(t, resolveBool(nil, envVar))
	})

	t.Run("defaults to false when config is nil and the environment variable is unset", func(t *testing.T) {
		t.Setenv(envVar, "")
		assert.False(t, resolveBool(nil, envVar))
	})

	t.Run(`defaults to false for an unrecognized environment value`, func(t *testing.T) {
		t.Setenv(envVar, "yes")
		assert.False(t, resolveBool(nil, envVar))
	})
}
