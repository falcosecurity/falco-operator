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

// Package fake provides test doubles for compat.VersionsFetcher.
package fake

import (
	"context"
	"maps"

	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
)

// MockVersionsFetcher is a test double for compat.VersionsFetcher.
type MockVersionsFetcher struct {
	Result   *compat.Versions
	FetchErr error
}

// NewMockVersionsFetcher creates a MockVersionsFetcher that returns the given capabilities on Fetch.
func NewMockVersionsFetcher(caps map[string]string) *MockVersionsFetcher {
	return &MockVersionsFetcher{Result: compat.NewVersions(caps, nil)}
}

// NewMockVersionsFetcherWithPlugins creates a MockVersionsFetcher whose result reports pluginVersions
// as loaded plugins — flattened into capabilities too, matching HTTPVersionsFetcher's real behavior —
// for tests that need PluginVersions() populated, not just Capability()/All().
func NewMockVersionsFetcherWithPlugins(pluginVersions map[string]string) *MockVersionsFetcher {
	caps := make(map[string]string, len(pluginVersions))
	maps.Copy(caps, pluginVersions)
	return &MockVersionsFetcher{Result: compat.NewVersions(caps, pluginVersions)}
}

// Fetch returns the preset result or error.
func (m *MockVersionsFetcher) Fetch(_ context.Context) (*compat.Versions, error) {
	if m.FetchErr != nil {
		return nil, m.FetchErr
	}
	return m.Result, nil
}
