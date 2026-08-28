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

package fake

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockVersionsFetcher(t *testing.T) {
	t.Run("returns configured capabilities", func(t *testing.T) {
		m := NewMockVersionsFetcher(map[string]string{"falco_version": "0.44.1"})
		v, err := m.Fetch(context.Background())
		require.NoError(t, err)
		val, found := v.Capability("falco_version")
		assert.True(t, found)
		assert.Equal(t, "0.44.1", val)
	})

	t.Run("returns configured error", func(t *testing.T) {
		m := &MockVersionsFetcher{FetchErr: errors.New("fetch failed")}
		_, err := m.Fetch(context.Background())
		require.EqualError(t, err, "fetch failed")
	})
}

func TestNewMockVersionsFetcherWithPlugins(t *testing.T) {
	m := NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"})
	v, err := m.Fetch(context.Background())
	require.NoError(t, err)

	assert.Equal(t, map[string]string{"container": "0.7.1"}, v.PluginVersions())
	val, found := v.Capability("container")
	assert.True(t, found, "plugin entries must also be flattened into capabilities, matching real Fetch behavior")
	assert.Equal(t, "0.7.1", val)
}
